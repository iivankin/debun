use std::{collections::HashMap, error::Error, mem::size_of};

use super::{
    ModuleRecordLayout, RepackedExecutable, ReplacementCounts, ReplacementParts,
    StandaloneInspection, StandaloneModule, TRAILER,
};

#[derive(Debug, Clone, Copy)]
struct RawStringPointer {
    offset: u32,
    length: u32,
}

#[derive(Debug, Clone, Copy)]
struct ResolvedRequiredPart<'a> {
    bytes: &'a [u8],
    replaced: bool,
}

#[derive(Debug, Clone, Copy)]
struct ResolvedOptionalPart<'a> {
    bytes: Option<&'a [u8]>,
    replaced: bool,
}

#[derive(Debug, Clone, Copy)]
struct ResolvedModuleParts<'a> {
    contents: ResolvedRequiredPart<'a>,
    sourcemap: ResolvedOptionalPart<'a>,
    bytecode: ResolvedOptionalPart<'a>,
    module_info: ResolvedOptionalPart<'a>,
}

impl<'a> ResolvedRequiredPart<'a> {
    fn resolve(replacement: Option<&'a [u8]>, original: &'a [u8]) -> Self {
        match replacement {
            Some(bytes) => Self {
                bytes,
                replaced: true,
            },
            None => Self {
                bytes: original,
                replaced: false,
            },
        }
    }
}

impl<'a> ResolvedOptionalPart<'a> {
    fn resolve(replacement: Option<&'a [u8]>, original: Option<&'a [u8]>) -> Self {
        match replacement {
            Some(bytes) => Self {
                bytes: Some(bytes),
                replaced: true,
            },
            None => Self {
                bytes: original,
                replaced: false,
            },
        }
    }
}

impl<'a> ResolvedModuleParts<'a> {
    fn new(module: &'a StandaloneModule, replacement: Option<&'a ReplacementParts>) -> Self {
        Self {
            contents: ResolvedRequiredPart::resolve(
                replacement.and_then(|parts| parts.contents.as_deref()),
                &module.bytes,
            ),
            sourcemap: ResolvedOptionalPart::resolve(
                replacement.and_then(|parts| parts.sourcemap.as_deref()),
                module.sourcemap.as_deref(),
            ),
            bytecode: ResolvedOptionalPart::resolve(
                replacement.and_then(|parts| parts.bytecode.as_deref()),
                module.bytecode.as_deref(),
            ),
            module_info: ResolvedOptionalPart::resolve(
                replacement.and_then(|parts| parts.module_info.as_deref()),
                module.module_info.as_deref(),
            ),
        }
    }

    fn record(self, counts: &mut ReplacementCounts) {
        counts.contents += usize::from(self.contents.replaced);
        counts.sourcemaps += usize::from(self.sourcemap.replaced);
        counts.bytecodes += usize::from(self.bytecode.replaced);
        counts.module_infos += usize::from(self.module_info.replaced);
    }
}

pub(super) fn repack_executable(
    original_bytes: &[u8],
    inspection: StandaloneInspection,
    replacements: &HashMap<String, ReplacementParts>,
) -> Result<RepackedExecutable, Box<dyn Error>> {
    let mut body = Vec::new();
    let compile_exec_argv_ptr =
        push_optional_bytes(&mut body, inspection.compile_exec_argv.as_deref())?;
    let record_layout = inspection.record_layout;
    let record_size = record_layout.size();
    let mut modules = Vec::with_capacity(inspection.modules.len() * record_size);

    let mut replacement_counts = ReplacementCounts::default();

    for module in inspection.modules {
        let parts = ResolvedModuleParts::new(&module, replacements.get(&module.virtual_path));
        parts.record(&mut replacement_counts);

        let name_ptr = push_bytes(&mut body, module.original_path.as_bytes())?;
        let contents_ptr = push_bytes(&mut body, parts.contents.bytes)?;
        let sourcemap_ptr = push_optional_bytes(&mut body, parts.sourcemap.bytes)?;
        let bytecode_ptr = push_optional_bytes(&mut body, parts.bytecode.bytes)?;

        push_string_pointer(&mut modules, name_ptr);
        push_string_pointer(&mut modules, contents_ptr);
        push_string_pointer(&mut modules, sourcemap_ptr);
        push_string_pointer(&mut modules, bytecode_ptr);

        match record_layout {
            ModuleRecordLayout::Compact => {}
            ModuleRecordLayout::WithModuleInfo => {
                let module_info_ptr = push_optional_bytes(&mut body, parts.module_info.bytes)?;
                push_string_pointer(&mut modules, module_info_ptr);
            }
            ModuleRecordLayout::Extended => {
                let module_info_ptr = push_optional_bytes(&mut body, parts.module_info.bytes)?;
                let origin_ptr = push_optional_bytes(
                    &mut body,
                    module.bytecode_origin_path.as_deref().map(str::as_bytes),
                )?;
                push_string_pointer(&mut modules, module_info_ptr);
                push_string_pointer(&mut modules, origin_ptr);
            }
        }

        modules.extend_from_slice(&[
            module.encoding,
            module.loader,
            module.module_format,
            module.side,
        ]);
        debug_assert_eq!(modules.len() % record_size, 0);
    }

    let modules_offset =
        u32::try_from(body.len()).map_err(|_| "standalone payload body exceeded u32 offsets")?;
    let modules_len =
        u32::try_from(modules.len()).map_err(|_| "standalone module table exceeded u32 offsets")?;
    body.extend_from_slice(&modules);

    let byte_count =
        u64::try_from(body.len()).map_err(|_| "standalone payload body exceeded u64 length")?;
    let mut payload = body;
    payload.extend_from_slice(&byte_count.to_le_bytes());
    push_string_pointer(
        &mut payload,
        RawStringPointer {
            offset: modules_offset,
            length: modules_len,
        },
    );
    payload.extend_from_slice(&inspection.entry_point_id.to_le_bytes());
    push_string_pointer(&mut payload, compile_exec_argv_ptr);
    payload.extend_from_slice(&inspection.flags_bits.to_le_bytes());
    payload.extend_from_slice(TRAILER);

    let bytes = if let (Some(raw_offset), Some(raw_container)) = (
        inspection.raw_container_file_offset,
        inspection.raw_container_bytes.as_ref(),
    ) {
        write_sectioned_executable(original_bytes, raw_offset, raw_container.len(), &payload)?
    } else {
        write_appended_executable(original_bytes, inspection.payload_file_offset, &payload)?
    };

    Ok(RepackedExecutable {
        bytes,
        replacement_counts,
    })
}

fn write_sectioned_executable(
    original_bytes: &[u8],
    raw_offset: usize,
    raw_container_len: usize,
    payload: &[u8],
) -> Result<Vec<u8>, Box<dyn Error>> {
    let required_len = size_of::<u64>()
        .checked_add(payload.len())
        .ok_or("standalone section payload size overflowed")?;
    if required_len > raw_container_len {
        return Err(format!(
            "repacked payload ({required_len} bytes) no longer fits in the original Bun section ({raw_container_len} bytes)"
        )
        .into());
    }

    let end = raw_offset
        .checked_add(raw_container_len)
        .ok_or("standalone section offset overflowed")?;
    let Some(_) = original_bytes.get(raw_offset..end) else {
        return Err("standalone section was out of bounds in the original executable".into());
    };

    let mut out = original_bytes.to_vec();
    let mut raw_section = Vec::with_capacity(raw_container_len);
    raw_section.extend_from_slice(
        &u64::try_from(payload.len())
            .map_err(|_| "standalone payload length exceeded u64")?
            .to_le_bytes(),
    );
    raw_section.extend_from_slice(payload);
    raw_section.resize(raw_container_len, 0);
    out[raw_offset..end].copy_from_slice(&raw_section);
    Ok(out)
}

fn write_appended_executable(
    original_bytes: &[u8],
    payload_offset: usize,
    payload: &[u8],
) -> Result<Vec<u8>, Box<dyn Error>> {
    let Some(prefix) = original_bytes.get(..payload_offset) else {
        return Err(
            "standalone payload offset was out of bounds in the original executable".into(),
        );
    };

    let mut out = Vec::with_capacity(
        prefix
            .len()
            .checked_add(payload.len())
            .and_then(|value| value.checked_add(size_of::<u64>()))
            .ok_or("standalone executable size overflowed")?,
    );
    out.extend_from_slice(prefix);
    out.extend_from_slice(payload);
    let total_size = out
        .len()
        .checked_add(size_of::<u64>())
        .ok_or("standalone executable size overflowed")?;
    let total_size =
        u64::try_from(total_size).map_err(|_| "standalone executable length exceeded u64")?;
    out.extend_from_slice(&total_size.to_le_bytes());
    Ok(out)
}

fn push_bytes(out: &mut Vec<u8>, bytes: &[u8]) -> Result<RawStringPointer, Box<dyn Error>> {
    let offset =
        u32::try_from(out.len()).map_err(|_| "standalone payload body exceeded u32 offsets")?;
    let length = u32::try_from(bytes.len()).map_err(|_| "standalone field exceeded u32 length")?;
    out.extend_from_slice(bytes);
    Ok(RawStringPointer { offset, length })
}

fn push_optional_bytes(
    out: &mut Vec<u8>,
    bytes: Option<&[u8]>,
) -> Result<RawStringPointer, Box<dyn Error>> {
    match bytes {
        Some(bytes) => push_bytes(out, bytes),
        None => Ok(RawStringPointer {
            offset: 0,
            length: 0,
        }),
    }
}

fn push_string_pointer(out: &mut Vec<u8>, pointer: RawStringPointer) {
    out.extend_from_slice(&pointer.offset.to_le_bytes());
    out.extend_from_slice(&pointer.length.to_le_bytes());
}
