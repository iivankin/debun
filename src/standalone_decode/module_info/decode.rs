use std::error::Error;

use super::{
    model::{DecodedExport, DecodedImport, DecodedModuleInfo, DecodedRequestedModule},
    reader::{read_len, read_u32_array, take},
};

const FLAG_CONTAINS_IMPORT_META: u8 = 1 << 0;
const FLAG_IS_TYPESCRIPT: u8 = 1 << 1;
const FETCH_PARAMETERS_NONE: u32 = u32::MAX;
const FETCH_PARAMETERS_JAVASCRIPT: u32 = u32::MAX - 1;
const FETCH_PARAMETERS_WEBASSEMBLY: u32 = u32::MAX - 2;
const FETCH_PARAMETERS_JSON: u32 = u32::MAX - 3;
const STRING_ID_STAR_DEFAULT: u32 = u32::MAX;
const STRING_ID_STAR_NAMESPACE: u32 = u32::MAX - 1;

#[derive(Debug, Clone, Copy)]
enum ModuleInfoRecordKind {
    DeclaredVariable,
    LexicalVariable,
    ImportInfoSingle,
    ImportInfoSingleTypeScript,
    ImportInfoNamespace,
    ExportInfoIndirect,
    ExportInfoLocal,
    ExportInfoNamespace,
    ExportInfoStar,
}

impl ModuleInfoRecordKind {
    fn from_byte(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::DeclaredVariable),
            1 => Some(Self::LexicalVariable),
            2 => Some(Self::ImportInfoSingle),
            3 => Some(Self::ImportInfoSingleTypeScript),
            4 => Some(Self::ImportInfoNamespace),
            5 => Some(Self::ExportInfoIndirect),
            6 => Some(Self::ExportInfoLocal),
            7 => Some(Self::ExportInfoNamespace),
            8 => Some(Self::ExportInfoStar),
            _ => None,
        }
    }

    const fn width(self) -> usize {
        match self {
            Self::DeclaredVariable | Self::LexicalVariable | Self::ExportInfoStar => 1,
            Self::ExportInfoNamespace => 2,
            Self::ImportInfoSingle
            | Self::ImportInfoSingleTypeScript
            | Self::ImportInfoNamespace
            | Self::ExportInfoIndirect
            | Self::ExportInfoLocal => 3,
        }
    }
}

pub fn decode_module_info(bytes: &[u8]) -> Result<DecodedModuleInfo, Box<dyn Error>> {
    let mut cursor = 0usize;

    let record_kinds_len = read_len(bytes, &mut cursor, "record kinds")?;
    let record_kinds = take(bytes, &mut cursor, record_kinds_len, "record kinds")?
        .iter()
        .map(|value| {
            ModuleInfoRecordKind::from_byte(*value)
                .ok_or("module_info contained an unknown record kind")
        })
        .collect::<Result<Vec<_>, _>>()?;
    let record_kind_padding = (4 - (record_kinds_len % 4)) % 4;
    take(
        bytes,
        &mut cursor,
        record_kind_padding,
        "record kind padding",
    )?;

    let strings_buf_len = read_len(bytes, &mut cursor, "strings buffer")?;
    let strings_buf = take(bytes, &mut cursor, strings_buf_len, "strings buffer")?;

    let strings_lens_len = read_len(bytes, &mut cursor, "string lengths")?;
    let strings_lens = read_u32_array(bytes, &mut cursor, strings_lens_len, "string lengths")?;

    let buffer_len = read_len(bytes, &mut cursor, "record buffer")?;
    let buffer = read_u32_array(bytes, &mut cursor, buffer_len, "record buffer")?;

    let requested_modules_len = read_len(bytes, &mut cursor, "requested modules")?;
    let requested_module_keys = read_u32_array(
        bytes,
        &mut cursor,
        requested_modules_len,
        "requested module keys",
    )?;
    let requested_module_values = read_u32_array(
        bytes,
        &mut cursor,
        requested_modules_len,
        "requested module values",
    )?;

    let flags = *take(bytes, &mut cursor, 1, "flags")?
        .first()
        .ok_or("module_info flags were truncated")?;
    take(bytes, &mut cursor, 3, "flags padding")?;

    if cursor != bytes.len() {
        return Err("module_info had trailing bytes".into());
    }

    let strings = decode_strings(strings_buf, &strings_lens)?;
    let mut decoded = decode_requested_modules(
        flags,
        &requested_module_keys,
        &requested_module_values,
        &strings,
    )?;
    decode_records(&mut decoded, &record_kinds, &buffer, &strings)?;

    Ok(decoded)
}

fn decode_requested_modules(
    flags: u8,
    requested_module_keys: &[u32],
    requested_module_values: &[u32],
    strings: &[String],
) -> Result<DecodedModuleInfo, Box<dyn Error>> {
    Ok(DecodedModuleInfo {
        contains_import_meta: flags & FLAG_CONTAINS_IMPORT_META != 0,
        is_typescript: flags & FLAG_IS_TYPESCRIPT != 0,
        declared_variables: Vec::new(),
        lexical_variables: Vec::new(),
        imports: Vec::new(),
        exports: Vec::new(),
        requested_modules: requested_module_keys
            .iter()
            .zip(requested_module_values.iter())
            .map(|(module, attributes)| {
                let module = resolve_string_id(*module, strings)?;
                let (attributes_kind, host_defined) =
                    decode_fetch_parameters(*attributes, strings)?;
                Ok(DecodedRequestedModule {
                    module,
                    attributes_kind,
                    host_defined,
                })
            })
            .collect::<Result<Vec<_>, Box<dyn Error>>>()?,
    })
}

fn decode_records(
    decoded: &mut DecodedModuleInfo,
    record_kinds: &[ModuleInfoRecordKind],
    buffer: &[u32],
    strings: &[String],
) -> Result<(), Box<dyn Error>> {
    let mut buffer_cursor = 0usize;
    for record_kind in record_kinds {
        let width = record_kind.width();
        let record = buffer
            .get(buffer_cursor..buffer_cursor + width)
            .ok_or("module_info record buffer was truncated")?;
        buffer_cursor += width;

        match record_kind {
            ModuleInfoRecordKind::DeclaredVariable => {
                decoded
                    .declared_variables
                    .push(resolve_string_id(record[0], strings)?);
            }
            ModuleInfoRecordKind::LexicalVariable => {
                decoded
                    .lexical_variables
                    .push(resolve_string_id(record[0], strings)?);
            }
            ModuleInfoRecordKind::ImportInfoSingle => decoded.imports.push(DecodedImport {
                kind: "single",
                module: resolve_string_id(record[0], strings)?,
                import_name: resolve_string_id(record[1], strings)?,
                local_name: resolve_string_id(record[2], strings)?,
                type_only: false,
            }),
            ModuleInfoRecordKind::ImportInfoSingleTypeScript => {
                decoded.imports.push(DecodedImport {
                    kind: "single",
                    module: resolve_string_id(record[0], strings)?,
                    import_name: resolve_string_id(record[1], strings)?,
                    local_name: resolve_string_id(record[2], strings)?,
                    type_only: true,
                })
            }
            ModuleInfoRecordKind::ImportInfoNamespace => decoded.imports.push(DecodedImport {
                kind: "namespace",
                module: resolve_string_id(record[0], strings)?,
                import_name: resolve_string_id(record[1], strings)?,
                local_name: resolve_string_id(record[2], strings)?,
                type_only: false,
            }),
            ModuleInfoRecordKind::ExportInfoIndirect => decoded.exports.push(DecodedExport {
                kind: "indirect",
                export_name: Some(resolve_string_id(record[0], strings)?),
                import_name: Some(resolve_string_id(record[1], strings)?),
                local_name: None,
                module: Some(resolve_string_id(record[2], strings)?),
            }),
            ModuleInfoRecordKind::ExportInfoLocal => decoded.exports.push(DecodedExport {
                kind: "local",
                export_name: Some(resolve_string_id(record[0], strings)?),
                import_name: None,
                local_name: Some(resolve_string_id(record[1], strings)?),
                module: None,
            }),
            ModuleInfoRecordKind::ExportInfoNamespace => decoded.exports.push(DecodedExport {
                kind: "namespace",
                export_name: Some(resolve_string_id(record[0], strings)?),
                import_name: None,
                local_name: None,
                module: Some(resolve_string_id(record[1], strings)?),
            }),
            ModuleInfoRecordKind::ExportInfoStar => decoded.exports.push(DecodedExport {
                kind: "star",
                export_name: None,
                import_name: None,
                local_name: None,
                module: Some(resolve_string_id(record[0], strings)?),
            }),
        }
    }

    if buffer_cursor != buffer.len() {
        return Err("module_info record buffer had trailing entries".into());
    }

    Ok(())
}

fn decode_strings(strings_buf: &[u8], strings_lens: &[u32]) -> Result<Vec<String>, Box<dyn Error>> {
    let mut offset = 0usize;
    let mut strings = Vec::with_capacity(strings_lens.len());

    for len in strings_lens {
        let len = *len as usize;
        let next = offset
            .checked_add(len)
            .ok_or("module_info string table overflowed")?;
        let bytes = strings_buf
            .get(offset..next)
            .ok_or("module_info string table was truncated")?;
        strings.push(String::from_utf8_lossy(bytes).into_owned());
        offset = next;
    }

    if offset != strings_buf.len() {
        return Err("module_info string table had trailing bytes".into());
    }

    Ok(strings)
}

fn decode_fetch_parameters(
    value: u32,
    strings: &[String],
) -> Result<(&'static str, Option<String>), Box<dyn Error>> {
    match value {
        FETCH_PARAMETERS_NONE => Ok(("none", None)),
        FETCH_PARAMETERS_JAVASCRIPT => Ok(("javascript", None)),
        FETCH_PARAMETERS_WEBASSEMBLY => Ok(("webassembly", None)),
        FETCH_PARAMETERS_JSON => Ok(("json", None)),
        _ => Ok(("host-defined", Some(resolve_string_id(value, strings)?))),
    }
}

fn resolve_string_id(value: u32, strings: &[String]) -> Result<String, Box<dyn Error>> {
    match value {
        STRING_ID_STAR_DEFAULT => Ok("*default*".to_string()),
        STRING_ID_STAR_NAMESPACE => Ok("*namespace*".to_string()),
        _ => strings
            .get(value as usize)
            .cloned()
            .ok_or_else(|| "module_info referenced a string that was out of bounds".into()),
    }
}
