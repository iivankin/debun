use std::{collections::HashSet, error::Error};

use super::{
    ModuleRecordLayout, RawStringPointer, STRING_POINTER_SIZE, TRAILER, is_bunfs_virtual_path,
    normalize_virtual_path, parse_offsets, parse_string_pointer, slice_optional_pointer,
    slice_pointer,
};
use crate::standalone::{
    StandaloneContainer, StandaloneInspection, StandaloneModule,
    container::{ContainerLocation, ContainerPayload},
};

#[derive(Debug)]
struct ParsedModuleRecord {
    name: String,
    contents_ptr: RawStringPointer,
    sourcemap_ptr: RawStringPointer,
    bytecode_ptr: RawStringPointer,
    module_info_ptr: RawStringPointer,
    bytecode_origin_path: Option<String>,
    encoding: u8,
    loader: u8,
    module_format: u8,
    side: u8,
}

struct OptionalPart {
    bytes: Option<Vec<u8>>,
    offset: Option<usize>,
}

pub(super) fn parse_payload(
    payload: ContainerPayload<'_>,
) -> Result<StandaloneInspection, Box<dyn Error>> {
    let payload_len = payload.payload_bytes.len();
    if payload_len < TRAILER.len() + payload.offsets_layout.size() {
        return Err("standalone payload was too small".into());
    }

    let trailer_start = payload_len - TRAILER.len();
    if payload.payload_bytes.get(trailer_start..) != Some(TRAILER) {
        return Err("standalone payload trailer was invalid".into());
    }

    let offsets_start = trailer_start - payload.offsets_layout.size();
    let offsets_bytes = payload
        .payload_bytes
        .get(offsets_start..trailer_start)
        .ok_or("standalone payload offsets were out of bounds")?;
    let offsets = parse_offsets(offsets_bytes, payload.offsets_layout)
        .ok_or("standalone payload offsets were invalid")?;
    if offsets.byte_count != offsets_start {
        return Err("standalone payload byte_count did not match the payload layout".into());
    }

    let body = &payload.payload_bytes[..offsets.byte_count];
    let modules_bytes = slice_pointer(body, offsets.modules_ptr)
        .ok_or("standalone payload module list pointer was out of bounds")?;
    let (record_layout, records) =
        parse_module_records(body, modules_bytes, offsets.entry_point_id)?;
    let compile_exec_argv =
        slice_optional_pointer(body, offsets.compile_exec_argv_ptr).map(<[u8]>::to_vec);
    let entry_point_index = usize::try_from(offsets.entry_point_id)
        .map_err(|_| "standalone payload entry point id exceeded usize")?;

    let mut modules = Vec::with_capacity(records.len());
    let mut entry_point_path = None;
    let mut entry_point_source = None;

    for (index, record) in records.iter().enumerate() {
        let module = build_module(body, record)?;

        if index == entry_point_index {
            entry_point_path = Some(module.virtual_path.clone());
            if looks_like_javascript_source(&module.bytes) {
                entry_point_source = std::str::from_utf8(&module.bytes).ok().map(str::to_string);
            }
        }

        modules.push(module);
    }

    let mut module_paths = HashSet::with_capacity(modules.len());
    if let Some(duplicate) = modules
        .iter()
        .find(|module| !module_paths.insert(module.virtual_path.as_str()))
    {
        return Err(format!(
            "standalone payload contained duplicate module path {}",
            duplicate.virtual_path
        )
        .into());
    }

    let container = match payload.location {
        ContainerLocation::Appended => StandaloneContainer::Appended {
            payload_file_offset: payload.payload_file_offset,
        },
        ContainerLocation::Section {
            kind,
            name,
            file_offset,
            bytes,
            length_width,
        } => StandaloneContainer::Section {
            kind,
            name: name.to_string(),
            file_offset,
            bytes: bytes.to_vec(),
            payload_file_offset: payload.payload_file_offset,
            length_width,
        },
    };

    Ok(StandaloneInspection {
        container,
        payload_bytes: payload.payload_bytes.to_vec(),
        offsets_layout: payload.offsets_layout,
        record_layout,
        entry_point_path,
        entry_point_source,
        entry_point_id: offsets.entry_point_id,
        compile_exec_argv,
        flags_bits: offsets.flags_bits,
        modules,
    })
}

fn build_module(
    body: &[u8],
    record: &ParsedModuleRecord,
) -> Result<StandaloneModule, Box<dyn Error>> {
    let contents_bytes = slice_pointer(body, record.contents_ptr)
        .ok_or("standalone module contents pointer was out of bounds")?;
    let source_offset = usize::try_from(record.contents_ptr.offset)
        .map_err(|_| "standalone module contents offset exceeded usize")?;
    let sourcemap = optional_part(body, record.sourcemap_ptr, "sourcemap")?;
    let bytecode = optional_part(body, record.bytecode_ptr, "bytecode")?;
    let module_info = optional_part(body, record.module_info_ptr, "module info")?;

    Ok(StandaloneModule {
        original_path: record.name.clone(),
        virtual_path: normalize_virtual_path(&record.name),
        source_offset,
        bytes: contents_bytes.to_vec(),
        sourcemap: sourcemap.bytes,
        sourcemap_offset: sourcemap.offset,
        bytecode: bytecode.bytes,
        bytecode_offset: bytecode.offset,
        module_info: module_info.bytes,
        module_info_offset: module_info.offset,
        bytecode_origin_path: record.bytecode_origin_path.clone(),
        encoding: record.encoding,
        loader: record.loader,
        module_format: record.module_format,
        side: record.side,
    })
}

fn optional_part(
    body: &[u8],
    pointer: RawStringPointer,
    name: &str,
) -> Result<OptionalPart, Box<dyn Error>> {
    if pointer.length == 0 {
        return Ok(OptionalPart {
            bytes: None,
            offset: None,
        });
    }
    let bytes = slice_pointer(body, pointer)
        .ok_or_else(|| format!("standalone module {name} pointer was out of bounds"))?;
    let offset = usize::try_from(pointer.offset)
        .map_err(|_| format!("standalone module {name} offset exceeded usize"))?;
    Ok(OptionalPart {
        bytes: Some(bytes.to_vec()),
        offset: Some(offset),
    })
}

fn parse_module_records(
    body: &[u8],
    modules_bytes: &[u8],
    entry_point_id: u32,
) -> Result<(ModuleRecordLayout, Vec<ParsedModuleRecord>), Box<dyn Error>> {
    let mut best_layout = None;

    // Bun's standalone graph record format changed across releases.
    // We only need the leading name/contents pointers, so detect the layout
    // by validating known record sizes against the actual module names.
    for layout in [
        ModuleRecordLayout::Extended,
        ModuleRecordLayout::WithModuleInfo,
        ModuleRecordLayout::Compact,
        ModuleRecordLayout::LegacyEncoding,
        ModuleRecordLayout::LegacyLoader,
    ] {
        let Some(candidate) = try_parse_module_records(body, modules_bytes, entry_point_id, layout)
        else {
            continue;
        };

        let score = candidate
            .iter()
            .filter(|record| is_bunfs_virtual_path(&record.name))
            .count();

        match &best_layout {
            Some((best_score, _, _)) if *best_score >= score => {}
            _ => best_layout = Some((score, layout, candidate)),
        }
    }

    if let Some((_, layout, records)) = best_layout {
        Ok((layout, records))
    } else {
        Err("standalone payload module list did not match any supported record layout".into())
    }
}

fn try_parse_module_records(
    body: &[u8],
    modules_bytes: &[u8],
    entry_point_id: u32,
    layout: ModuleRecordLayout,
) -> Option<Vec<ParsedModuleRecord>> {
    let record_size = layout.size();
    if !modules_bytes.len().is_multiple_of(record_size) {
        return None;
    }

    let mut records = Vec::with_capacity(modules_bytes.len() / record_size);
    for module_bytes in modules_bytes.chunks_exact(record_size) {
        let name_ptr = parse_string_pointer(module_bytes.get(0..STRING_POINTER_SIZE)?)?;
        let contents_ptr =
            parse_string_pointer(module_bytes.get(STRING_POINTER_SIZE..STRING_POINTER_SIZE * 2)?)?;
        let sourcemap_ptr = parse_string_pointer(
            module_bytes.get(STRING_POINTER_SIZE * 2..STRING_POINTER_SIZE * 3)?,
        )?;
        let empty_pointer = RawStringPointer::EMPTY;
        let (
            bytecode_ptr,
            module_info_ptr,
            bytecode_origin_path,
            encoding,
            loader,
            module_format,
            side,
        ) = match layout {
            ModuleRecordLayout::LegacyLoader => (
                empty_pointer,
                empty_pointer,
                None,
                0,
                *module_bytes.get(STRING_POINTER_SIZE * 3)?,
                0,
                0,
            ),
            ModuleRecordLayout::LegacyEncoding => (
                empty_pointer,
                empty_pointer,
                None,
                *module_bytes.get(STRING_POINTER_SIZE * 3)?,
                *module_bytes.get(STRING_POINTER_SIZE * 3 + 1)?,
                0,
                0,
            ),
            ModuleRecordLayout::Compact => {
                let bytecode_ptr = parse_string_pointer(
                    module_bytes.get(STRING_POINTER_SIZE * 3..STRING_POINTER_SIZE * 4)?,
                )?;
                let tail =
                    module_bytes.get(STRING_POINTER_SIZE * 4..STRING_POINTER_SIZE * 4 + 4)?;
                (
                    bytecode_ptr,
                    empty_pointer,
                    None,
                    *tail.first()?,
                    *tail.get(1)?,
                    *tail.get(2)?,
                    *tail.get(3)?,
                )
            }
            ModuleRecordLayout::WithModuleInfo => {
                let bytecode_ptr = parse_string_pointer(
                    module_bytes.get(STRING_POINTER_SIZE * 3..STRING_POINTER_SIZE * 4)?,
                )?;
                let module_info_ptr = parse_string_pointer(
                    module_bytes.get(STRING_POINTER_SIZE * 4..STRING_POINTER_SIZE * 5)?,
                )?;
                let tail =
                    module_bytes.get(STRING_POINTER_SIZE * 5..STRING_POINTER_SIZE * 5 + 4)?;
                (
                    bytecode_ptr,
                    module_info_ptr,
                    None,
                    *tail.first()?,
                    *tail.get(1)?,
                    *tail.get(2)?,
                    *tail.get(3)?,
                )
            }
            ModuleRecordLayout::Extended => {
                let bytecode_ptr = parse_string_pointer(
                    module_bytes.get(STRING_POINTER_SIZE * 3..STRING_POINTER_SIZE * 4)?,
                )?;
                let module_info_ptr = parse_string_pointer(
                    module_bytes.get(STRING_POINTER_SIZE * 4..STRING_POINTER_SIZE * 5)?,
                )?;
                let origin_path_ptr = parse_string_pointer(
                    module_bytes.get(STRING_POINTER_SIZE * 5..STRING_POINTER_SIZE * 6)?,
                )?;
                let bytecode_origin_path = if origin_path_ptr.length > 0 {
                    Some(
                        std::str::from_utf8(slice_pointer(body, origin_path_ptr)?)
                            .ok()?
                            .to_string(),
                    )
                } else {
                    None
                };
                let tail =
                    module_bytes.get(STRING_POINTER_SIZE * 6..STRING_POINTER_SIZE * 6 + 4)?;
                (
                    bytecode_ptr,
                    module_info_ptr,
                    bytecode_origin_path,
                    *tail.first()?,
                    *tail.get(1)?,
                    *tail.get(2)?,
                    *tail.get(3)?,
                )
            }
        };
        if encoding > 2 || module_format > 2 || side > 1 {
            return None;
        }
        slice_pointer(body, contents_ptr)?;
        validate_optional_pointer(body, sourcemap_ptr)?;
        validate_optional_pointer(body, bytecode_ptr)?;
        validate_optional_pointer(body, module_info_ptr)?;
        let name_bytes = slice_pointer(body, name_ptr)?;
        let name = std::str::from_utf8(name_bytes).ok()?.to_string();
        if name.is_empty() || name.chars().any(char::is_control) {
            return None;
        }
        records.push(ParsedModuleRecord {
            name,
            contents_ptr,
            sourcemap_ptr,
            bytecode_ptr,
            module_info_ptr,
            bytecode_origin_path,
            encoding,
            loader,
            module_format,
            side,
        });
    }

    let entry_index = usize::try_from(entry_point_id).ok()?;
    if entry_index >= records.len() {
        return None;
    }

    Some(records)
}

fn validate_optional_pointer(body: &[u8], pointer: RawStringPointer) -> Option<()> {
    if pointer.length == 0 {
        Some(())
    } else {
        slice_pointer(body, pointer).map(|_| ())
    }
}

fn looks_like_javascript_source(bytes: &[u8]) -> bool {
    let Ok(text) = std::str::from_utf8(bytes) else {
        return false;
    };
    let trimmed = text.trim_start();
    trimmed.starts_with("// @bun")
        || trimmed.starts_with("import ")
        || trimmed.starts_with("export ")
        || trimmed.starts_with("var ")
        || trimmed.starts_with("let ")
        || trimmed.starts_with("const ")
        || trimmed.starts_with("function ")
}
