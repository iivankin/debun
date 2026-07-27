use std::{collections::HashMap, error::Error, mem::size_of};

use super::{
    ModuleRecordLayout, OffsetsLayout, OptionalReplacement, RawStringPointer, RepackedExecutable,
    ReplacementCounts, ReplacementParts, RequiredReplacement, SectionLengthWidth,
    StandaloneContainer, StandaloneInspection, StandaloneModule, StandaloneSectionKind, TRAILER,
    elf, macho, pe,
};

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
    fn resolve(replacement: &'a RequiredReplacement, original: &'a [u8]) -> Self {
        match replacement {
            RequiredReplacement::Replace(bytes) => Self {
                bytes,
                replaced: true,
            },
            RequiredReplacement::Keep => Self {
                bytes: original,
                replaced: false,
            },
        }
    }
}

impl<'a> ResolvedOptionalPart<'a> {
    fn resolve(replacement: &'a OptionalReplacement, original: Option<&'a [u8]>) -> Self {
        match replacement {
            OptionalReplacement::Replace(bytes) => Self {
                bytes: Some(bytes),
                replaced: true,
            },
            OptionalReplacement::Remove => Self {
                bytes: None,
                replaced: true,
            },
            OptionalReplacement::Keep => Self {
                bytes: original,
                replaced: false,
            },
        }
    }
}

impl<'a> ResolvedModuleParts<'a> {
    fn new(module: &'a StandaloneModule, replacement: Option<&'a ReplacementParts>) -> Self {
        match replacement {
            Some(replacement) => Self {
                contents: ResolvedRequiredPart::resolve(&replacement.contents, &module.bytes),
                sourcemap: ResolvedOptionalPart::resolve(
                    &replacement.sourcemap,
                    module.sourcemap.as_deref(),
                ),
                bytecode: ResolvedOptionalPart::resolve(
                    &replacement.bytecode,
                    module.bytecode.as_deref(),
                ),
                module_info: ResolvedOptionalPart::resolve(
                    &replacement.module_info,
                    module.module_info.as_deref(),
                ),
            },
            None => Self {
                contents: ResolvedRequiredPart {
                    bytes: &module.bytes,
                    replaced: false,
                },
                sourcemap: ResolvedOptionalPart {
                    bytes: module.sourcemap.as_deref(),
                    replaced: false,
                },
                bytecode: ResolvedOptionalPart {
                    bytes: module.bytecode.as_deref(),
                    replaced: false,
                },
                module_info: ResolvedOptionalPart {
                    bytes: module.module_info.as_deref(),
                    replaced: false,
                },
            },
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
    let (payload, replacement_counts) = serialize_payload(&inspection, replacements)?;
    let bytes = write_container(original_bytes, &inspection.container, &payload)?;

    Ok(RepackedExecutable {
        bytes,
        replacement_counts,
    })
}

fn serialize_payload(
    inspection: &StandaloneInspection,
    replacements: &HashMap<String, ReplacementParts>,
) -> Result<(Vec<u8>, ReplacementCounts), Box<dyn Error>> {
    let mut body = Vec::new();
    let compile_exec_argv_ptr = match inspection.offsets_layout {
        OffsetsLayout::Legacy => {
            if inspection.compile_exec_argv.is_some() {
                return Err("legacy standalone offsets cannot store compile argv".into());
            }
            RawStringPointer::EMPTY
        }
        OffsetsLayout::WithCompileArgv => {
            push_optional_bytes_z(&mut body, inspection.compile_exec_argv.as_deref())?
        }
    };
    let record_layout = inspection.record_layout;
    let record_size = record_layout.size();
    let mut modules = Vec::with_capacity(inspection.modules.len() * record_size);

    let mut replacement_counts = ReplacementCounts::default();

    for module in &inspection.modules {
        let parts = ResolvedModuleParts::new(module, replacements.get(&module.virtual_path));
        parts.record(&mut replacement_counts);

        let name_ptr = push_bytes_z(&mut body, module.original_path.as_bytes())?;
        let contents_ptr = push_bytes_z(&mut body, parts.contents.bytes)?;
        let sourcemap_ptr = push_optional_bytes(&mut body, parts.sourcemap.bytes)?;

        push_string_pointer(&mut modules, name_ptr);
        push_string_pointer(&mut modules, contents_ptr);
        push_string_pointer(&mut modules, sourcemap_ptr);

        match record_layout {
            ModuleRecordLayout::LegacyLoader => {
                reject_unsupported_legacy_parts(parts)?;
                modules.push(module.loader);
                modules.extend_from_slice(&[0; 7]);
            }
            ModuleRecordLayout::LegacyEncoding => {
                reject_unsupported_legacy_parts(parts)?;
                modules.extend_from_slice(&[module.encoding, module.loader, 0, 0]);
            }
            ModuleRecordLayout::Compact => {
                let bytecode_ptr = push_optional_bytes(&mut body, parts.bytecode.bytes)?;
                push_string_pointer(&mut modules, bytecode_ptr);
                push_module_tail(&mut modules, module);
            }
            ModuleRecordLayout::WithModuleInfo => {
                let bytecode_ptr = push_optional_bytes(&mut body, parts.bytecode.bytes)?;
                let module_info_ptr = push_optional_bytes(&mut body, parts.module_info.bytes)?;
                push_string_pointer(&mut modules, bytecode_ptr);
                push_string_pointer(&mut modules, module_info_ptr);
                push_module_tail(&mut modules, module);
            }
            ModuleRecordLayout::Extended => {
                let bytecode_ptr = push_optional_bytes(&mut body, parts.bytecode.bytes)?;
                let module_info_ptr = push_optional_bytes(&mut body, parts.module_info.bytes)?;
                let origin_ptr = push_optional_bytes_z(
                    &mut body,
                    module.bytecode_origin_path.as_deref().map(str::as_bytes),
                )?;
                push_string_pointer(&mut modules, bytecode_ptr);
                push_string_pointer(&mut modules, module_info_ptr);
                push_string_pointer(&mut modules, origin_ptr);
                push_module_tail(&mut modules, module);
            }
        }

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
    match inspection.offsets_layout {
        OffsetsLayout::Legacy => payload.extend_from_slice(&[0; 4]),
        OffsetsLayout::WithCompileArgv => {
            push_string_pointer(&mut payload, compile_exec_argv_ptr);
            payload.extend_from_slice(&inspection.flags_bits.to_le_bytes());
        }
    }
    payload.extend_from_slice(TRAILER);

    Ok((payload, replacement_counts))
}

fn write_container(
    original_bytes: &[u8],
    container: &StandaloneContainer,
    payload: &[u8],
) -> Result<Vec<u8>, Box<dyn Error>> {
    match container {
        StandaloneContainer::Appended {
            payload_file_offset,
        } => write_appended_executable(original_bytes, *payload_file_offset, payload),
        StandaloneContainer::Section {
            kind,
            file_offset,
            bytes,
            length_width,
            ..
        } => match kind {
            StandaloneSectionKind::Elf => {
                elf::write_bun_section(original_bytes, payload, *length_width)
            }
            StandaloneSectionKind::MachO64 => {
                macho::write_bun_section(original_bytes, payload, *length_width)
            }
            StandaloneSectionKind::Pe64 => {
                pe::write_bun_section(original_bytes, payload, *length_width)
            }
            StandaloneSectionKind::Pe32 => {
                pe::write_bun_section(original_bytes, payload, *length_width)
            }
            StandaloneSectionKind::MachO32 => write_sectioned_executable(
                original_bytes,
                *file_offset,
                bytes.len(),
                payload,
                *length_width,
            ),
        },
    }
}

fn write_sectioned_executable(
    original_bytes: &[u8],
    raw_offset: usize,
    raw_container_len: usize,
    payload: &[u8],
    length_width: SectionLengthWidth,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let required_len = length_width
        .size()
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
    raw_section.resize(length_width.size(), 0);
    length_width.write(&mut raw_section, payload.len())?;
    raw_section.extend_from_slice(payload);
    raw_section.resize(raw_container_len, 0);
    out[raw_offset..end].copy_from_slice(&raw_section);
    Ok(out)
}

fn reject_unsupported_legacy_parts(parts: ResolvedModuleParts<'_>) -> Result<(), Box<dyn Error>> {
    if parts.bytecode.bytes.is_some() || parts.module_info.bytes.is_some() {
        return Err("legacy standalone module records cannot store bytecode or module info".into());
    }
    Ok(())
}

fn push_module_tail(out: &mut Vec<u8>, module: &StandaloneModule) {
    out.extend_from_slice(&[
        module.encoding,
        module.loader,
        module.module_format,
        module.side,
    ]);
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

fn push_bytes_z(out: &mut Vec<u8>, bytes: &[u8]) -> Result<RawStringPointer, Box<dyn Error>> {
    let pointer = push_bytes(out, bytes)?;
    out.push(0);
    Ok(pointer)
}

fn push_optional_bytes(
    out: &mut Vec<u8>,
    bytes: Option<&[u8]>,
) -> Result<RawStringPointer, Box<dyn Error>> {
    match bytes {
        Some(bytes) => push_bytes(out, bytes),
        None => Ok(RawStringPointer::EMPTY),
    }
}

fn push_optional_bytes_z(
    out: &mut Vec<u8>,
    bytes: Option<&[u8]>,
) -> Result<RawStringPointer, Box<dyn Error>> {
    match bytes {
        Some(bytes) => push_bytes_z(out, bytes),
        None => Ok(RawStringPointer::EMPTY),
    }
}

fn push_string_pointer(out: &mut Vec<u8>, pointer: RawStringPointer) {
    out.extend_from_slice(&pointer.offset.to_le_bytes());
    out.extend_from_slice(&pointer.length.to_le_bytes());
}
