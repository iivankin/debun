use std::{
    error::Error,
    io::{Cursor, Read},
};

use ruzstd::decoding::StreamingDecoder;

const SOURCE_MAP_HEADER_SIZE: usize = 8;
const STRING_POINTER_SIZE: usize = 8;
const FLAG_CONTAINS_IMPORT_META: u8 = 1 << 0;
const FLAG_IS_TYPESCRIPT: u8 = 1 << 1;
const FETCH_PARAMETERS_NONE: u32 = u32::MAX;
const FETCH_PARAMETERS_JAVASCRIPT: u32 = u32::MAX - 1;
const FETCH_PARAMETERS_WEBASSEMBLY: u32 = u32::MAX - 2;
const FETCH_PARAMETERS_JSON: u32 = u32::MAX - 3;
const STRING_ID_STAR_DEFAULT: u32 = u32::MAX;
const STRING_ID_STAR_NAMESPACE: u32 = u32::MAX - 1;

#[derive(Debug, Clone)]
pub struct DecodedSourceMap {
    pub generated_file: String,
    pub sources: Vec<String>,
    pub sources_content: Vec<String>,
    pub mappings: String,
}

impl DecodedSourceMap {
    pub fn render_json(&self) -> String {
        format!(
            concat!(
                "{{",
                "\"version\":3,",
                "\"file\":{},",
                "\"sources\":[{}],",
                "\"sourcesContent\":[{}],",
                "\"names\":[],",
                "\"mappings\":{}",
                "}}\n"
            ),
            json_string(&self.generated_file),
            self.sources
                .iter()
                .map(|source| json_string(source))
                .collect::<Vec<_>>()
                .join(","),
            self.sources_content
                .iter()
                .map(|source| json_string(source))
                .collect::<Vec<_>>()
                .join(","),
            json_string(&self.mappings)
        )
    }
}

#[derive(Debug, Clone)]
pub struct DecodedModuleInfo {
    pub contains_import_meta: bool,
    pub is_typescript: bool,
    pub declared_variables: Vec<String>,
    pub lexical_variables: Vec<String>,
    pub imports: Vec<DecodedImport>,
    pub exports: Vec<DecodedExport>,
    pub requested_modules: Vec<DecodedRequestedModule>,
}

impl DecodedModuleInfo {
    pub fn render_json(&self) -> String {
        let imports = self
            .imports
            .iter()
            .map(DecodedImport::render_json)
            .collect::<Vec<_>>()
            .join(",");
        let exports = self
            .exports
            .iter()
            .map(DecodedExport::render_json)
            .collect::<Vec<_>>()
            .join(",");
        let requested_modules = self
            .requested_modules
            .iter()
            .map(DecodedRequestedModule::render_json)
            .collect::<Vec<_>>()
            .join(",");

        format!(
            concat!(
                "{{",
                "\"flags\":{{\"contains_import_meta\":{},\"is_typescript\":{}}},",
                "\"declared_variables\":[{}],",
                "\"lexical_variables\":[{}],",
                "\"imports\":[{}],",
                "\"exports\":[{}],",
                "\"requested_modules\":[{}]",
                "}}\n"
            ),
            json_bool(self.contains_import_meta),
            json_bool(self.is_typescript),
            render_string_array(&self.declared_variables),
            render_string_array(&self.lexical_variables),
            imports,
            exports,
            requested_modules
        )
    }
}

#[derive(Debug, Clone)]
pub struct DecodedImport {
    pub kind: &'static str,
    pub module: String,
    pub import_name: String,
    pub local_name: String,
    pub type_only: bool,
}

impl DecodedImport {
    fn render_json(&self) -> String {
        format!(
            concat!(
                "{{",
                "\"kind\":{},",
                "\"module\":{},",
                "\"import\":{},",
                "\"local\":{},",
                "\"type_only\":{}",
                "}}"
            ),
            json_string(self.kind),
            json_string(&self.module),
            json_string(&self.import_name),
            json_string(&self.local_name),
            json_bool(self.type_only)
        )
    }
}

#[derive(Debug, Clone)]
pub struct DecodedExport {
    pub kind: &'static str,
    pub export_name: Option<String>,
    pub import_name: Option<String>,
    pub local_name: Option<String>,
    pub module: Option<String>,
}

impl DecodedExport {
    fn render_json(&self) -> String {
        let mut fields = vec![json_field("kind", self.kind)];
        if let Some(export_name) = &self.export_name {
            fields.push(json_field("export", export_name));
        }
        if let Some(import_name) = &self.import_name {
            fields.push(json_field("import", import_name));
        }
        if let Some(local_name) = &self.local_name {
            fields.push(json_field("local", local_name));
        }
        if let Some(module) = &self.module {
            fields.push(json_field("module", module));
        }
        format!("{{{}}}", fields.join(","))
    }
}

#[derive(Debug, Clone)]
pub struct DecodedRequestedModule {
    pub module: String,
    pub attributes_kind: &'static str,
    pub host_defined: Option<String>,
}

impl DecodedRequestedModule {
    fn render_json(&self) -> String {
        let mut fields = vec![
            json_field("module", &self.module),
            json_field("attributes_kind", self.attributes_kind),
        ];
        if let Some(host_defined) = &self.host_defined {
            fields.push(json_field("host_defined", host_defined));
        }
        format!("{{{}}}", fields.join(","))
    }
}

#[derive(Debug, Clone, Copy)]
struct RawStringPointer {
    offset: u32,
    length: u32,
}

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

pub fn decode_serialized_sourcemap(
    bytes: &[u8],
    generated_file: &str,
) -> Result<DecodedSourceMap, Box<dyn Error>> {
    if bytes.len() < SOURCE_MAP_HEADER_SIZE {
        return Err("serialized sourcemap was truncated".into());
    }

    let source_files_count =
        read_u32_le(bytes, 0).ok_or("serialized sourcemap header was truncated")? as usize;
    let map_bytes_length =
        read_u32_le(bytes, 4).ok_or("serialized sourcemap header was truncated")? as usize;

    let pointers_len = source_files_count
        .checked_mul(STRING_POINTER_SIZE)
        .and_then(|value| value.checked_mul(2))
        .ok_or("serialized sourcemap pointer table overflowed")?;
    let names_start = SOURCE_MAP_HEADER_SIZE;
    let contents_start = names_start + source_files_count * STRING_POINTER_SIZE;
    let mappings_start = SOURCE_MAP_HEADER_SIZE + pointers_len;
    let mappings_end = mappings_start
        .checked_add(map_bytes_length)
        .ok_or("serialized sourcemap mappings overflowed")?;
    if mappings_end > bytes.len() {
        return Err("serialized sourcemap mappings were truncated".into());
    }

    let mut sources = Vec::with_capacity(source_files_count);
    let mut sources_content = Vec::with_capacity(source_files_count);

    for index in 0..source_files_count {
        let name_offset = names_start + index * STRING_POINTER_SIZE;
        let contents_offset = contents_start + index * STRING_POINTER_SIZE;

        let name_ptr = parse_string_pointer(
            bytes
                .get(name_offset..name_offset + STRING_POINTER_SIZE)
                .ok_or("serialized sourcemap file-name pointer was truncated")?,
        )
        .ok_or("serialized sourcemap file-name pointer was invalid")?;
        let contents_ptr = parse_string_pointer(
            bytes
                .get(contents_offset..contents_offset + STRING_POINTER_SIZE)
                .ok_or("serialized sourcemap source-content pointer was truncated")?,
        )
        .ok_or("serialized sourcemap source-content pointer was invalid")?;

        let source_name = slice_pointer(bytes, name_ptr)
            .ok_or("serialized sourcemap file name was out of bounds")?;
        let compressed_source = slice_pointer(bytes, contents_ptr)
            .ok_or("serialized sourcemap source content was out of bounds")?;

        sources.push(String::from_utf8_lossy(source_name).into_owned());
        sources_content.push(decompress_zstd_frame(compressed_source)?);
    }

    Ok(DecodedSourceMap {
        generated_file: generated_file.to_string(),
        sources,
        sources_content,
        mappings: String::from_utf8_lossy(&bytes[mappings_start..mappings_end]).into_owned(),
    })
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

    let declared_variables = Vec::new();
    let lexical_variables = Vec::new();
    let imports = Vec::new();
    let exports = Vec::new();

    let mut decoded = DecodedModuleInfo {
        contains_import_meta: flags & FLAG_CONTAINS_IMPORT_META != 0,
        is_typescript: flags & FLAG_IS_TYPESCRIPT != 0,
        declared_variables,
        lexical_variables,
        imports,
        exports,
        requested_modules: requested_module_keys
            .iter()
            .zip(requested_module_values.iter())
            .map(|(module, attributes)| {
                let module = resolve_string_id(*module, &strings)?;
                let (attributes_kind, host_defined) =
                    decode_fetch_parameters(*attributes, &strings)?;
                Ok(DecodedRequestedModule {
                    module,
                    attributes_kind,
                    host_defined,
                })
            })
            .collect::<Result<Vec<_>, Box<dyn Error>>>()?,
    };

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
                    .push(resolve_string_id(record[0], &strings)?);
            }
            ModuleInfoRecordKind::LexicalVariable => {
                decoded
                    .lexical_variables
                    .push(resolve_string_id(record[0], &strings)?);
            }
            ModuleInfoRecordKind::ImportInfoSingle => decoded.imports.push(DecodedImport {
                kind: "single",
                module: resolve_string_id(record[0], &strings)?,
                import_name: resolve_string_id(record[1], &strings)?,
                local_name: resolve_string_id(record[2], &strings)?,
                type_only: false,
            }),
            ModuleInfoRecordKind::ImportInfoSingleTypeScript => {
                decoded.imports.push(DecodedImport {
                    kind: "single",
                    module: resolve_string_id(record[0], &strings)?,
                    import_name: resolve_string_id(record[1], &strings)?,
                    local_name: resolve_string_id(record[2], &strings)?,
                    type_only: true,
                })
            }
            ModuleInfoRecordKind::ImportInfoNamespace => decoded.imports.push(DecodedImport {
                kind: "namespace",
                module: resolve_string_id(record[0], &strings)?,
                import_name: resolve_string_id(record[1], &strings)?,
                local_name: resolve_string_id(record[2], &strings)?,
                type_only: false,
            }),
            ModuleInfoRecordKind::ExportInfoIndirect => decoded.exports.push(DecodedExport {
                kind: "indirect",
                export_name: Some(resolve_string_id(record[0], &strings)?),
                import_name: Some(resolve_string_id(record[1], &strings)?),
                local_name: None,
                module: Some(resolve_string_id(record[2], &strings)?),
            }),
            ModuleInfoRecordKind::ExportInfoLocal => decoded.exports.push(DecodedExport {
                kind: "local",
                export_name: Some(resolve_string_id(record[0], &strings)?),
                import_name: None,
                local_name: Some(resolve_string_id(record[1], &strings)?),
                module: None,
            }),
            ModuleInfoRecordKind::ExportInfoNamespace => decoded.exports.push(DecodedExport {
                kind: "namespace",
                export_name: Some(resolve_string_id(record[0], &strings)?),
                import_name: None,
                local_name: None,
                module: Some(resolve_string_id(record[1], &strings)?),
            }),
            ModuleInfoRecordKind::ExportInfoStar => decoded.exports.push(DecodedExport {
                kind: "star",
                export_name: None,
                import_name: None,
                local_name: None,
                module: Some(resolve_string_id(record[0], &strings)?),
            }),
        }
    }

    if buffer_cursor != buffer.len() {
        return Err("module_info record buffer had trailing entries".into());
    }

    Ok(decoded)
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

fn decompress_zstd_frame(bytes: &[u8]) -> Result<String, Box<dyn Error>> {
    let mut decoder = StreamingDecoder::new(Cursor::new(bytes))?;
    let mut decompressed = Vec::new();
    decoder.read_to_end(&mut decompressed)?;
    Ok(String::from_utf8_lossy(&decompressed).into_owned())
}

fn read_len(bytes: &[u8], cursor: &mut usize, label: &str) -> Result<usize, Box<dyn Error>> {
    let len = read_u32_le(bytes, *cursor)
        .ok_or_else(|| invalid_data(format!("module_info {label} length was truncated")))?;
    *cursor += 4;
    Ok(len as usize)
}

fn read_u32_array(
    bytes: &[u8],
    cursor: &mut usize,
    len: usize,
    label: &str,
) -> Result<Vec<u32>, Box<dyn Error>> {
    let byte_len = len
        .checked_mul(4)
        .ok_or_else(|| invalid_data(format!("module_info {label} length overflowed")))?;
    let raw = take(bytes, cursor, byte_len, label)?;
    let mut values = Vec::with_capacity(len);
    for chunk in raw.chunks_exact(4) {
        values.push(u32::from_le_bytes(
            chunk.try_into().expect("chunk size is fixed"),
        ));
    }
    Ok(values)
}

fn take<'a>(
    bytes: &'a [u8],
    cursor: &mut usize,
    len: usize,
    label: &str,
) -> Result<&'a [u8], Box<dyn Error>> {
    let end = cursor
        .checked_add(len)
        .ok_or_else(|| invalid_data(format!("{label} slice overflowed")))?;
    let slice = bytes
        .get(*cursor..end)
        .ok_or_else(|| invalid_data(format!("{label} slice was truncated")))?;
    *cursor = end;
    Ok(slice)
}

fn parse_string_pointer(bytes: &[u8]) -> Option<RawStringPointer> {
    let offset = read_u32_le(bytes, 0)?;
    let length = read_u32_le(bytes, 4)?;
    Some(RawStringPointer { offset, length })
}

fn slice_pointer(bytes: &[u8], pointer: RawStringPointer) -> Option<&[u8]> {
    let start = pointer.offset as usize;
    let end = start.checked_add(pointer.length as usize)?;
    bytes.get(start..end)
}

fn read_u32_le(bytes: &[u8], offset: usize) -> Option<u32> {
    let chunk = bytes.get(offset..offset + 4)?;
    Some(u32::from_le_bytes(chunk.try_into().ok()?))
}

fn invalid_data(message: impl Into<String>) -> Box<dyn Error> {
    std::io::Error::other(message.into()).into()
}

fn render_string_array(values: &[String]) -> String {
    values
        .iter()
        .map(|value| json_string(value))
        .collect::<Vec<_>>()
        .join(",")
}

fn json_field(name: &str, value: &str) -> String {
    format!("{}:{}", json_string(name), json_string(value))
}

fn json_bool(value: bool) -> &'static str {
    if value { "true" } else { "false" }
}

fn json_string(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            _ if ch.is_control() => out.push_str(&format!("\\u{:04x}", ch as u32)),
            _ => out.push(ch),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::{FLAG_CONTAINS_IMPORT_META, decode_module_info, decode_serialized_sourcemap};

    const ZSTD_CONSOLE_LOG: &[u8] = &[
        0x28, 0xb5, 0x2f, 0xfd, 0x04, 0x48, 0x81, 0x00, 0x00, 0x63, 0x6f, 0x6e, 0x73, 0x6f, 0x6c,
        0x65, 0x2e, 0x6c, 0x6f, 0x67, 0x28, 0x31, 0x29, 0x3b, 0x0a, 0xb2, 0xaa, 0x89, 0x55,
    ];

    fn push_u32(out: &mut Vec<u8>, value: u32) {
        out.extend_from_slice(&value.to_le_bytes());
    }

    fn push_pointer(out: &mut Vec<u8>, offset: u32, length: u32) {
        push_u32(out, offset);
        push_u32(out, length);
    }

    #[test]
    fn decodes_serialized_sourcemap_into_standard_json_shape() {
        let name = b"src/app.ts";
        let mappings = b"AAAA";
        let string_payload_start = 8 + 8 + 8 + mappings.len();
        let name_offset = string_payload_start as u32;
        let contents_offset = (string_payload_start + name.len()) as u32;

        let mut raw = Vec::new();
        push_u32(&mut raw, 1);
        push_u32(&mut raw, mappings.len() as u32);
        push_pointer(&mut raw, name_offset, name.len() as u32);
        push_pointer(&mut raw, contents_offset, ZSTD_CONSOLE_LOG.len() as u32);
        raw.extend_from_slice(mappings);
        raw.extend_from_slice(name);
        raw.extend_from_slice(ZSTD_CONSOLE_LOG);

        let decoded = decode_serialized_sourcemap(&raw, "/$bunfs/root/app.js")
            .expect("sourcemap should decode");

        assert_eq!(decoded.generated_file, "/$bunfs/root/app.js");
        assert_eq!(decoded.sources, vec!["src/app.ts"]);
        assert_eq!(decoded.sources_content, vec!["console.log(1);\n"]);
        assert_eq!(decoded.mappings, "AAAA");

        let rendered = decoded.render_json();
        assert!(rendered.contains("\"version\":3"));
        assert!(rendered.contains("\"file\":\"/$bunfs/root/app.js\""));
        assert!(rendered.contains("\"sources\":[\"src/app.ts\"]"));
        assert!(rendered.contains("\"mappings\":\"AAAA\""));
    }

    #[test]
    fn decodes_module_info_into_structured_json_shape() {
        let mut strings_buf = Vec::new();
        strings_buf.extend_from_slice(b"foo");
        strings_buf.extend_from_slice(b"./dep.js");
        strings_buf.extend_from_slice(b"bar");

        let mut raw = Vec::new();
        push_u32(&mut raw, 3);
        raw.extend_from_slice(&[0, 2, 6]);
        raw.push(0);
        push_u32(&mut raw, strings_buf.len() as u32);
        raw.extend_from_slice(&strings_buf);
        push_u32(&mut raw, 3);
        push_u32(&mut raw, 3);
        push_u32(&mut raw, 8);
        push_u32(&mut raw, 3);
        push_u32(&mut raw, 7);
        push_u32(&mut raw, 0);
        push_u32(&mut raw, 1);
        push_u32(&mut raw, 2);
        push_u32(&mut raw, 0);
        push_u32(&mut raw, 0);
        push_u32(&mut raw, 2);
        push_u32(&mut raw, u32::MAX);
        push_u32(&mut raw, 1);
        push_u32(&mut raw, 1);
        push_u32(&mut raw, u32::MAX - 1);
        raw.push(FLAG_CONTAINS_IMPORT_META);
        raw.extend_from_slice(&[0, 0, 0]);

        let decoded = decode_module_info(&raw).expect("module_info should decode");

        assert!(decoded.contains_import_meta);
        assert!(!decoded.is_typescript);
        assert_eq!(decoded.declared_variables, vec!["foo"]);
        assert_eq!(decoded.lexical_variables.len(), 0);
        assert_eq!(decoded.imports.len(), 1);
        assert_eq!(decoded.imports[0].kind, "single");
        assert_eq!(decoded.imports[0].module, "./dep.js");
        assert_eq!(decoded.imports[0].import_name, "bar");
        assert_eq!(decoded.imports[0].local_name, "foo");
        assert_eq!(decoded.exports.len(), 1);
        assert_eq!(decoded.exports[0].kind, "local");
        assert_eq!(decoded.exports[0].export_name.as_deref(), Some("foo"));
        assert_eq!(decoded.exports[0].local_name.as_deref(), Some("bar"));
        assert_eq!(decoded.requested_modules.len(), 1);
        assert_eq!(decoded.requested_modules[0].module, "./dep.js");
        assert_eq!(decoded.requested_modules[0].attributes_kind, "javascript");

        let rendered = decoded.render_json();
        assert!(rendered.contains("\"contains_import_meta\":true"));
        assert!(rendered.contains("\"declared_variables\":[\"foo\"]"));
        assert!(rendered.contains("\"attributes_kind\":\"javascript\""));
    }
}
