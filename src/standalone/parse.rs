use std::error::Error;

use super::{
    BUNFS_ROOT_PREFIX, ModuleRecordLayout, RawStringPointer, STRING_POINTER_SIZE, StandaloneModule,
    TRAILER, WINDOWS_BUNFS_ROOT_PREFIX, parse_offsets, parse_string_pointer,
};
use crate::standalone::{StandaloneFile, StandaloneInspection, container::ContainerPayload};

#[derive(Debug, Clone)]
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

pub(super) fn parse_payload(
    payload: ContainerPayload<'_>,
) -> Result<StandaloneInspection, Box<dyn Error>> {
    let payload_len = payload.payload_bytes.len();
    if payload_len < TRAILER.len() + super::OFFSETS_SIZE_64 {
        return Err("standalone payload was too small".into());
    }

    let trailer_start = payload_len - TRAILER.len();
    if payload.payload_bytes.get(trailer_start..) != Some(TRAILER) {
        return Err("standalone payload trailer was invalid".into());
    }

    let offsets_start = trailer_start - super::OFFSETS_SIZE_64;
    let offsets_bytes = payload
        .payload_bytes
        .get(offsets_start..trailer_start)
        .ok_or("standalone payload offsets were out of bounds")?;
    let offsets = parse_offsets(offsets_bytes).ok_or("standalone payload offsets were invalid")?;
    if offsets.byte_count != offsets_start {
        return Err("standalone payload byte_count did not match the payload layout".into());
    }

    let body = &payload.payload_bytes[..offsets.byte_count];
    let modules_bytes = slice_pointer(body, offsets.modules_ptr)
        .ok_or("standalone payload module list pointer was out of bounds")?;
    let (record_layout, records) =
        parse_module_records(body, modules_bytes, offsets.entry_point_id)?;
    let compile_exec_argv =
        slice_optional_pointer(body, offsets._compile_exec_argv_ptr).map(<[u8]>::to_vec);

    let mut files = Vec::new();
    let mut modules = Vec::with_capacity(records.len());
    let mut entry_point_path = None;
    let mut entry_point_source = None;

    for (index, record) in records.iter().enumerate() {
        let Some(contents_bytes) = slice_pointer(body, record.contents_ptr) else {
            continue;
        };

        let normalized_path = normalize_virtual_path(&record.name);
        if index == offsets.entry_point_id as usize {
            entry_point_path = Some(normalized_path.clone());
            if looks_like_javascript_source(contents_bytes) {
                entry_point_source = std::str::from_utf8(contents_bytes).ok().map(str::to_string);
            }
        }

        let module = StandaloneModule {
            original_path: record.name.clone(),
            virtual_path: normalized_path,
            source_offset: record.contents_ptr.offset as usize,
            bytes: contents_bytes.to_vec(),
            sourcemap: slice_optional_pointer(body, record.sourcemap_ptr).map(<[u8]>::to_vec),
            sourcemap_offset: non_empty_pointer_offset(record.sourcemap_ptr),
            bytecode: slice_optional_pointer(body, record.bytecode_ptr).map(<[u8]>::to_vec),
            bytecode_offset: non_empty_pointer_offset(record.bytecode_ptr),
            module_info: slice_optional_pointer(body, record.module_info_ptr).map(<[u8]>::to_vec),
            module_info_offset: non_empty_pointer_offset(record.module_info_ptr),
            bytecode_origin_path: record.bytecode_origin_path.clone(),
            encoding: record.encoding,
            loader: record.loader,
            module_format: record.module_format,
            side: record.side,
        };

        if is_bunfs_virtual_path(&record.name) {
            files.push(StandaloneFile {
                virtual_path: module.virtual_path.clone(),
                source_offset: module.source_offset,
                bytes: module.bytes.clone(),
                sourcemap: module.sourcemap.clone(),
                sourcemap_offset: module.sourcemap_offset,
                bytecode: module.bytecode.clone(),
                bytecode_offset: module.bytecode_offset,
                module_info: module.module_info.clone(),
                module_info_offset: module.module_info_offset,
                bytecode_origin_path: module.bytecode_origin_path.clone(),
                encoding: module.encoding,
                loader: module.loader,
                module_format: module.module_format,
                side: module.side,
            });
        }

        modules.push(module);
    }

    Ok(StandaloneInspection {
        container_name: payload.container_name.map(str::to_string),
        raw_container_file_offset: payload.raw_container_file_offset,
        raw_container_bytes: payload.raw_container_bytes.map(<[u8]>::to_vec),
        payload_file_offset: payload.payload_file_offset,
        payload_bytes: payload.payload_bytes.to_vec(),
        record_layout: record_layout.label(),
        record_size: record_layout.size(),
        files,
        entry_point_path,
        entry_point_source,
        entry_point_id: offsets.entry_point_id,
        compile_exec_argv,
        flags_bits: offsets._flags_bits,
        record_layout_kind: record_layout,
        modules,
    })
}

fn parse_module_records(
    body: &[u8],
    modules_bytes: &[u8],
    entry_point_id: u32,
) -> Result<(ModuleRecordLayout, Vec<ParsedModuleRecord>), Box<dyn Error>> {
    let mut best_match = None;

    // Bun's standalone graph record format changed across releases.
    // We only need the leading name/contents pointers, so detect the layout
    // by validating known record sizes against the actual module names.
    for layout in [
        ModuleRecordLayout::Extended,
        ModuleRecordLayout::WithModuleInfo,
        ModuleRecordLayout::Compact,
    ] {
        let Some(candidate) = try_parse_module_records(body, modules_bytes, entry_point_id, layout)
        else {
            continue;
        };

        let score = candidate
            .iter()
            .filter(|record| is_bunfs_virtual_path(&record.name))
            .count();

        match &best_match {
            Some((best_score, _, _)) if *best_score >= score => {}
            _ => best_match = Some((score, layout, candidate)),
        }
    }

    if let Some((_, layout, records)) = best_match {
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
        let bytecode_ptr = parse_string_pointer(
            module_bytes.get(STRING_POINTER_SIZE * 3..STRING_POINTER_SIZE * 4)?,
        )?;
        let (module_info_ptr, bytecode_origin_path, tail_start) = match layout {
            ModuleRecordLayout::Compact => (
                RawStringPointer {
                    offset: 0,
                    length: 0,
                },
                None,
                STRING_POINTER_SIZE * 4,
            ),
            ModuleRecordLayout::WithModuleInfo => (
                parse_string_pointer(
                    module_bytes.get(STRING_POINTER_SIZE * 4..STRING_POINTER_SIZE * 5)?,
                )?,
                None,
                STRING_POINTER_SIZE * 5,
            ),
            ModuleRecordLayout::Extended => {
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
                (
                    module_info_ptr,
                    bytecode_origin_path,
                    STRING_POINTER_SIZE * 6,
                )
            }
        };
        let tail = module_bytes.get(tail_start..tail_start + 4)?;
        let encoding = *tail.first()?;
        let loader = *tail.get(1)?;
        let module_format = *tail.get(2)?;
        let side = *tail.get(3)?;
        if encoding > 2 || module_format > 2 || side > 1 {
            return None;
        }
        let name_bytes = slice_pointer(body, name_ptr)?;
        let name = std::str::from_utf8(name_bytes).ok()?.to_string();
        if name.is_empty() || name.chars().any(|ch| ch.is_control()) {
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

fn slice_pointer(bytes: &[u8], pointer: RawStringPointer) -> Option<&[u8]> {
    let start = pointer.offset as usize;
    let end = start.checked_add(pointer.length as usize)?;
    bytes.get(start..end)
}

fn slice_optional_pointer(bytes: &[u8], pointer: RawStringPointer) -> Option<&[u8]> {
    (pointer.length > 0)
        .then(|| slice_pointer(bytes, pointer))
        .flatten()
}

fn non_empty_pointer_offset(pointer: RawStringPointer) -> Option<usize> {
    (pointer.length > 0).then_some(pointer.offset as usize)
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

fn normalize_virtual_path(path: &str) -> String {
    if let Some(rest) = path.strip_prefix(WINDOWS_BUNFS_ROOT_PREFIX) {
        format!("{BUNFS_ROOT_PREFIX}{rest}")
    } else {
        path.to_string()
    }
}

fn is_bunfs_virtual_path(path: &str) -> bool {
    path.starts_with(BUNFS_ROOT_PREFIX) || path.starts_with(WINDOWS_BUNFS_ROOT_PREFIX)
}
