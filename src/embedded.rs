use std::{collections::BTreeMap, error::Error, fs, path::Path};

use crate::{
    standalone::{StandaloneFile, inspect_executable},
    standalone_decode::{decode_module_info, decode_serialized_sourcemap},
};

const MACH_O_MAGIC_64: u32 = 0xfeedfacf;
const MACH_O_MAGIC_32: u32 = 0xfeedface;
const LC_SEGMENT_64: u32 = 0x19;
const LC_SEGMENT: u32 = 0x1;
const LC_SYMTAB: u32 = 0x2;
const LC_DYSYMTAB: u32 = 0xb;

const BUN_SECTION_NAMES: &[&str] = &["__BUN", "__bun"];
const BUN_PATH_PREFIXES: &[&[u8]] = &[b"file:///$bunfs/root/", b"/$bunfs/root/", b"B:/~BUN/root/"];
const JS_MARKER: &[u8] = b"// @bun @bytecode @bun-cjs";
const JS_MARKER_FALLBACK: &[u8] = b"// @bun";
const WASM_MAGIC: &[u8] = b"\0asm\x01\0\0\0";
const PNG_MAGIC: &[u8] = b"\x89PNG\r\n\x1a\n";

#[derive(Debug, Clone)]
pub struct BinaryInspection {
    pub bun_section_name: Option<String>,
    pub bun_section_file_offset: Option<usize>,
    pub bun_section_bytes: Vec<u8>,
    pub bun_section_headerless_offset: Option<usize>,
    pub standalone_graph_file_offset: Option<usize>,
    pub standalone_graph_bytes: Option<Vec<u8>>,
    pub standalone_layout: Option<&'static str>,
    pub standalone_record_size: Option<usize>,
    pub bun_version_hint: Option<&'static str>,
    pub bunfs_paths: Vec<String>,
    pub metadata: Vec<(String, String)>,
    pub files: Vec<EmbeddedFile>,
    pub entry_point_path: Option<String>,
    pub entry_point_source: Option<String>,
}

#[derive(Debug, Clone)]
pub struct EmbeddedFile {
    pub virtual_path: String,
    pub kind: EmbeddedKind,
    pub source_offset: usize,
    pub bytes: Vec<u8>,
    pub derived_from: Option<String>,
    pub standalone_role: Option<&'static str>,
    pub standalone_encoding: Option<&'static str>,
    pub standalone_loader_id: Option<u8>,
    pub standalone_module_format: Option<&'static str>,
    pub standalone_side: Option<&'static str>,
    pub standalone_bytecode_origin_path: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmbeddedKind {
    JsWrapper,
    Wasm,
    MachO,
    Html,
    Css,
    Text,
    WebManifest,
    Png,
    StandaloneSourceMap,
    StandaloneSourceMapJson,
    StandaloneBytecode,
    StandaloneModuleInfo,
    StandaloneModuleInfoJson,
}

impl EmbeddedKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::JsWrapper => "js-wrapper",
            Self::Wasm => "wasm",
            Self::MachO => "mach-o",
            Self::Html => "html",
            Self::Css => "css",
            Self::Text => "text",
            Self::WebManifest => "webmanifest",
            Self::Png => "png",
            Self::StandaloneSourceMap => "standalone-sourcemap",
            Self::StandaloneSourceMapJson => "standalone-sourcemap-json",
            Self::StandaloneBytecode => "standalone-bytecode",
            Self::StandaloneModuleInfo => "standalone-module-info",
            Self::StandaloneModuleInfoJson => "standalone-module-info-json",
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct BunSection {
    name: &'static str,
    fileoff: usize,
    filesize: usize,
}

pub fn inspect_binary(path: &Path) -> Result<Option<BinaryInspection>, Box<dyn Error>> {
    let bytes = fs::read(path)?;
    inspect_binary_bytes(&bytes)
}

fn inspect_binary_bytes(bytes: &[u8]) -> Result<Option<BinaryInspection>, Box<dyn Error>> {
    if let Some(standalone) = inspect_executable(bytes)? {
        let raw_container_bytes = standalone.raw_container_bytes.clone();
        let payload_bytes = standalone.payload_bytes.clone();
        let raw_bytes = raw_container_bytes
            .as_deref()
            .unwrap_or(&payload_bytes)
            .to_vec();
        let bun_strings = printable_strings(&raw_bytes);
        let metadata = collect_metadata(&bun_strings);
        let structured_files = structured_embedded_files(&standalone.files);
        let bunfs_paths = if standalone.files.is_empty() {
            collect_bunfs_paths(&raw_bytes)
        } else {
            standalone
                .files
                .iter()
                .map(|file| file.virtual_path.clone())
                .collect::<Vec<_>>()
        };

        return Ok(Some(BinaryInspection {
            bun_section_name: standalone.container_name,
            bun_section_file_offset: standalone.raw_container_file_offset,
            bun_section_bytes: raw_container_bytes.unwrap_or_default(),
            bun_section_headerless_offset: standalone
                .raw_container_file_offset
                .map(|_| std::mem::size_of::<u64>()),
            standalone_graph_file_offset: Some(standalone.payload_file_offset),
            standalone_graph_bytes: Some(payload_bytes),
            standalone_layout: Some(standalone.record_layout),
            standalone_record_size: Some(standalone.record_size),
            bun_version_hint: Some(standalone.bun_version_hint),
            bunfs_paths,
            metadata,
            files: if structured_files.is_empty() {
                extract_embedded_files(&raw_bytes)
            } else {
                structured_files
            },
            entry_point_path: standalone.entry_point_path,
            entry_point_source: standalone.entry_point_source,
        }));
    }

    let bun_section = find_bun_section(bytes);
    let section_bytes = bun_section
        .and_then(|section| {
            bytes
                .get(section.fileoff..section.fileoff.saturating_add(section.filesize))
                .map(|slice| slice.to_vec())
        })
        .unwrap_or_default();
    if section_bytes.is_empty() {
        return Ok(None);
    }

    let headerless_offset = find_first_text_payload_offset(&section_bytes);
    let bun_strings = printable_strings(&section_bytes);
    let bunfs_paths = collect_bunfs_paths(&section_bytes);
    let metadata = collect_metadata(&bun_strings);
    let files = extract_embedded_files(&section_bytes);

    Ok(Some(BinaryInspection {
        bun_section_name: bun_section.map(|section| section.name.to_string()),
        bun_section_file_offset: bun_section.map(|section| section.fileoff),
        bun_section_bytes: section_bytes,
        bun_section_headerless_offset: headerless_offset,
        standalone_graph_file_offset: None,
        standalone_graph_bytes: None,
        standalone_layout: None,
        standalone_record_size: None,
        bun_version_hint: None,
        bunfs_paths,
        metadata,
        files,
        entry_point_path: None,
        entry_point_source: None,
    }))
}

fn structured_embedded_files(files: &[StandaloneFile]) -> Vec<EmbeddedFile> {
    let mut extracted = Vec::new();

    for file in files {
        let Some(kind) = detect_kind(&file.virtual_path, &file.bytes) else {
            continue;
        };
        let encoding = standalone_encoding_label(file.encoding);
        let module_format = standalone_module_format_label(file.module_format);
        let side = standalone_side_label(file.side);

        extracted.push(EmbeddedFile {
            virtual_path: file.virtual_path.clone(),
            kind,
            source_offset: file.source_offset,
            bytes: file.bytes.clone(),
            derived_from: None,
            standalone_role: Some("contents"),
            standalone_encoding: encoding,
            standalone_loader_id: Some(file.loader),
            standalone_module_format: module_format,
            standalone_side: side,
            standalone_bytecode_origin_path: file.bytecode_origin_path.clone(),
        });

        if let Some(sourcemap) = &file.sourcemap {
            let sourcemap_path = format!("{}.debun-sourcemap.bin", file.virtual_path);
            extracted.push(EmbeddedFile {
                virtual_path: sourcemap_path.clone(),
                kind: EmbeddedKind::StandaloneSourceMap,
                source_offset: file.sourcemap_offset.unwrap_or(file.source_offset),
                bytes: sourcemap.clone(),
                derived_from: Some(file.virtual_path.clone()),
                standalone_role: Some("sourcemap"),
                standalone_encoding: None,
                standalone_loader_id: Some(file.loader),
                standalone_module_format: module_format,
                standalone_side: side,
                standalone_bytecode_origin_path: None,
            });

            if let Ok(decoded) = decode_serialized_sourcemap(sourcemap, &file.virtual_path) {
                extracted.push(EmbeddedFile {
                    virtual_path: format!("{}.debun-sourcemap.json", file.virtual_path),
                    kind: EmbeddedKind::StandaloneSourceMapJson,
                    source_offset: file.sourcemap_offset.unwrap_or(file.source_offset),
                    bytes: decoded.render_json().into_bytes(),
                    derived_from: Some(sourcemap_path),
                    standalone_role: Some("sourcemap-decoded"),
                    standalone_encoding: None,
                    standalone_loader_id: Some(file.loader),
                    standalone_module_format: module_format,
                    standalone_side: side,
                    standalone_bytecode_origin_path: None,
                });
            }
        }

        if let Some(bytecode) = &file.bytecode {
            extracted.push(EmbeddedFile {
                virtual_path: format!("{}.debun-bytecode.bin", file.virtual_path),
                kind: EmbeddedKind::StandaloneBytecode,
                source_offset: file.bytecode_offset.unwrap_or(file.source_offset),
                bytes: bytecode.clone(),
                derived_from: Some(file.virtual_path.clone()),
                standalone_role: Some("bytecode"),
                standalone_encoding: None,
                standalone_loader_id: Some(file.loader),
                standalone_module_format: module_format,
                standalone_side: side,
                standalone_bytecode_origin_path: file.bytecode_origin_path.clone(),
            });
        }

        if let Some(module_info) = &file.module_info {
            let module_info_path = format!("{}.debun-module-info.bin", file.virtual_path);
            extracted.push(EmbeddedFile {
                virtual_path: module_info_path.clone(),
                kind: EmbeddedKind::StandaloneModuleInfo,
                source_offset: file.module_info_offset.unwrap_or(file.source_offset),
                bytes: module_info.clone(),
                derived_from: Some(file.virtual_path.clone()),
                standalone_role: Some("module-info"),
                standalone_encoding: None,
                standalone_loader_id: Some(file.loader),
                standalone_module_format: module_format,
                standalone_side: side,
                standalone_bytecode_origin_path: None,
            });

            if let Ok(decoded) = decode_module_info(module_info) {
                extracted.push(EmbeddedFile {
                    virtual_path: format!("{}.debun-module-info.json", file.virtual_path),
                    kind: EmbeddedKind::StandaloneModuleInfoJson,
                    source_offset: file.module_info_offset.unwrap_or(file.source_offset),
                    bytes: decoded.render_json().into_bytes(),
                    derived_from: Some(module_info_path),
                    standalone_role: Some("module-info-decoded"),
                    standalone_encoding: None,
                    standalone_loader_id: Some(file.loader),
                    standalone_module_format: module_format,
                    standalone_side: side,
                    standalone_bytecode_origin_path: None,
                });
            }
        }
    }

    extracted
}

fn find_bun_section(bytes: &[u8]) -> Option<BunSection> {
    let magic = read_u32_le(bytes, 0)?;
    let is_64 = match magic {
        MACH_O_MAGIC_64 => true,
        MACH_O_MAGIC_32 => false,
        _ => return None,
    };
    let header_size = if is_64 { 32 } else { 28 };
    let ncmds = read_u32_le(bytes, 16)? as usize;
    let sizeofcmds = read_u32_le(bytes, 20)? as usize;
    if bytes.len() < header_size + sizeofcmds {
        return None;
    }

    let mut cursor = header_size;
    for _ in 0..ncmds {
        let cmd = read_u32_le(bytes, cursor)?;
        let cmdsize = read_u32_le(bytes, cursor + 4)? as usize;
        if cmdsize < 8 || cursor + cmdsize > bytes.len() {
            return None;
        }

        match cmd {
            LC_SEGMENT_64 if is_64 => {
                let segname = read_fixed_string(bytes, cursor + 8, 16)?;
                if BUN_SECTION_NAMES.contains(&segname.as_str()) {
                    let fileoff = read_u64_le(bytes, cursor + 40)? as usize;
                    let filesize = read_u64_le(bytes, cursor + 48)? as usize;
                    return Some(BunSection {
                        name: if segname == "__bun" { "__bun" } else { "__BUN" },
                        fileoff,
                        filesize,
                    });
                }
            }
            LC_SEGMENT if !is_64 => {
                let segname = read_fixed_string(bytes, cursor + 8, 16)?;
                if BUN_SECTION_NAMES.contains(&segname.as_str()) {
                    let fileoff = read_u32_le(bytes, cursor + 32)? as usize;
                    let filesize = read_u32_le(bytes, cursor + 36)? as usize;
                    return Some(BunSection {
                        name: if segname == "__bun" { "__bun" } else { "__BUN" },
                        fileoff,
                        filesize,
                    });
                }
            }
            _ => {}
        }

        cursor += cmdsize;
    }

    None
}

fn extract_embedded_files(bytes: &[u8]) -> Vec<EmbeddedFile> {
    let occurrences = collect_path_occurrences(bytes);
    let mut files = BTreeMap::<String, EmbeddedFile>::new();

    for (index, occurrence) in occurrences.iter().enumerate() {
        let Some(content_start) =
            find_content_start(bytes, occurrence.offset, occurrence.path.len())
        else {
            continue;
        };
        let Some(kind) = detect_kind(
            &occurrence.path,
            bytes.get(content_start..).unwrap_or_default(),
        ) else {
            continue;
        };

        let next_marker_offset = occurrences
            .iter()
            .skip(index + 1)
            .map(|next| next.offset)
            .next()
            .unwrap_or(bytes.len());
        let content_end = match kind {
            EmbeddedKind::JsWrapper => bytes[content_start..]
                .iter()
                .position(|byte| *byte == 0)
                .map(|offset| content_start + offset)
                .unwrap_or(bytes.len()),
            EmbeddedKind::Wasm => {
                let upper_bound = next_marker_offset.saturating_sub(usize::from(
                    next_marker_offset > 0 && bytes[next_marker_offset - 1] == 0,
                ));
                let window = bytes.get(content_start..upper_bound).unwrap_or_default();
                content_start + wasm_length(window).unwrap_or(window.len())
            }
            EmbeddedKind::MachO => {
                let upper_bound = next_marker_offset.saturating_sub(usize::from(
                    next_marker_offset > 0 && bytes[next_marker_offset - 1] == 0,
                ));
                let window = bytes.get(content_start..upper_bound).unwrap_or_default();
                content_start + macho_length(window).unwrap_or(window.len())
            }
            EmbeddedKind::Html
            | EmbeddedKind::Css
            | EmbeddedKind::Text
            | EmbeddedKind::WebManifest
            | EmbeddedKind::StandaloneSourceMap
            | EmbeddedKind::StandaloneSourceMapJson
            | EmbeddedKind::StandaloneBytecode
            | EmbeddedKind::StandaloneModuleInfo
            | EmbeddedKind::StandaloneModuleInfoJson => bytes[content_start..]
                .iter()
                .position(|byte| *byte == 0)
                .map(|offset| content_start + offset)
                .unwrap_or(bytes.len()),
            EmbeddedKind::Png => {
                let upper_bound = next_marker_offset.saturating_sub(usize::from(
                    next_marker_offset > 0 && bytes[next_marker_offset - 1] == 0,
                ));
                let window = bytes.get(content_start..upper_bound).unwrap_or_default();
                content_start + png_length(window).unwrap_or(window.len())
            }
        };
        let Some(content) = bytes.get(content_start..content_end) else {
            continue;
        };
        let normalized_path = occurrence.path.trim_start_matches("file://").to_string();
        files
            .entry(normalized_path.clone())
            .or_insert_with(|| EmbeddedFile {
                virtual_path: normalized_path,
                kind,
                source_offset: occurrence.offset,
                bytes: content.to_vec(),
                derived_from: None,
                standalone_role: None,
                standalone_encoding: None,
                standalone_loader_id: None,
                standalone_module_format: None,
                standalone_side: None,
                standalone_bytecode_origin_path: None,
            });
    }

    files.into_values().collect()
}

fn find_content_start(bytes: &[u8], offset: usize, path_len: usize) -> Option<usize> {
    let mut cursor = offset + path_len;
    if cursor < bytes.len() && bytes[cursor] == 0 {
        cursor += 1;
    }
    if cursor >= bytes.len() {
        return None;
    }

    for marker in [JS_MARKER, JS_MARKER_FALLBACK] {
        if let Some(relative) = bytes[cursor..]
            .windows(marker.len())
            .position(|window| window == marker)
            && relative <= 128
        {
            return Some(cursor + relative);
        }
    }

    Some(cursor)
}

fn detect_kind(path: &str, bytes: &[u8]) -> Option<EmbeddedKind> {
    if bytes.starts_with(JS_MARKER) || bytes.starts_with(JS_MARKER_FALLBACK) {
        return Some(EmbeddedKind::JsWrapper);
    }
    if bytes.starts_with(WASM_MAGIC) {
        return Some(EmbeddedKind::Wasm);
    }
    if bytes.starts_with(PNG_MAGIC) {
        return Some(EmbeddedKind::Png);
    }

    if path.ends_with(".js") && is_likely_javascript(bytes) {
        return Some(EmbeddedKind::JsWrapper);
    }
    if path.ends_with(".html") && is_likely_html(bytes) {
        return Some(EmbeddedKind::Html);
    }
    if path.ends_with(".css") && is_likely_css(bytes) {
        return Some(EmbeddedKind::Css);
    }
    if path.ends_with(".webmanifest") && is_likely_json(bytes) {
        return Some(EmbeddedKind::WebManifest);
    }
    if path.ends_with(".txt") && is_likely_text(bytes) {
        return Some(EmbeddedKind::Text);
    }

    let magic = read_u32_le(bytes, 0)?;
    match magic {
        MACH_O_MAGIC_64 | MACH_O_MAGIC_32 => Some(EmbeddedKind::MachO),
        _ => None,
    }
}

fn standalone_encoding_label(value: u8) -> Option<&'static str> {
    match value {
        0 => Some("binary"),
        1 => Some("latin1"),
        2 => Some("utf8"),
        _ => None,
    }
}

fn standalone_module_format_label(value: u8) -> Option<&'static str> {
    match value {
        0 => Some("none"),
        1 => Some("esm"),
        2 => Some("cjs"),
        _ => None,
    }
}

fn standalone_side_label(value: u8) -> Option<&'static str> {
    match value {
        0 => Some("server"),
        1 => Some("client"),
        _ => None,
    }
}

fn macho_length(bytes: &[u8]) -> Option<usize> {
    let magic = read_u32_le(bytes, 0)?;
    let is_64 = match magic {
        MACH_O_MAGIC_64 => true,
        MACH_O_MAGIC_32 => false,
        _ => return None,
    };
    let header_size = if is_64 { 32 } else { 28 };
    let ncmds = read_u32_le(bytes, 16)? as usize;
    let sizeofcmds = read_u32_le(bytes, 20)? as usize;
    if bytes.len() < header_size + sizeofcmds {
        return None;
    }

    let mut cursor = header_size;
    let mut max_end = header_size + sizeofcmds;
    for _ in 0..ncmds {
        let cmd = read_u32_le(bytes, cursor)?;
        let cmdsize = read_u32_le(bytes, cursor + 4)? as usize;
        if cmdsize < 8 || cursor + cmdsize > bytes.len() {
            return None;
        }

        match cmd {
            LC_SEGMENT_64 if is_64 => {
                let fileoff = read_u64_le(bytes, cursor + 40)? as usize;
                let filesize = read_u64_le(bytes, cursor + 48)? as usize;
                max_end = max_end.max(fileoff.saturating_add(filesize));
            }
            LC_SEGMENT if !is_64 => {
                let fileoff = read_u32_le(bytes, cursor + 32)? as usize;
                let filesize = read_u32_le(bytes, cursor + 36)? as usize;
                max_end = max_end.max(fileoff.saturating_add(filesize));
            }
            LC_SYMTAB => {
                let symoff = read_u32_le(bytes, cursor + 8)? as usize;
                let nsyms = read_u32_le(bytes, cursor + 12)? as usize;
                let stroff = read_u32_le(bytes, cursor + 16)? as usize;
                let strsize = read_u32_le(bytes, cursor + 20)? as usize;
                let nlist_size = if is_64 { 16 } else { 12 };
                max_end = max_end.max(symoff.saturating_add(nsyms.saturating_mul(nlist_size)));
                max_end = max_end.max(stroff.saturating_add(strsize));
            }
            LC_DYSYMTAB => {
                let extreloff = read_u32_le(bytes, cursor + 48)? as usize;
                let nextrel = read_u32_le(bytes, cursor + 52)? as usize;
                let locreloff = read_u32_le(bytes, cursor + 56)? as usize;
                let nlocrel = read_u32_le(bytes, cursor + 60)? as usize;
                let indirectsymoff = read_u32_le(bytes, cursor + 32)? as usize;
                let nindirectsyms = read_u32_le(bytes, cursor + 36)? as usize;
                max_end =
                    max_end.max(indirectsymoff.saturating_add(nindirectsyms.saturating_mul(4)));
                max_end = max_end.max(extreloff.saturating_add(nextrel.saturating_mul(8)));
                max_end = max_end.max(locreloff.saturating_add(nlocrel.saturating_mul(8)));
            }
            0x1d | 0x1e | 0x26 | 0x29 | 0x2b | 0x2e | 0x33 | 0x34 => {
                let dataoff = read_u32_le(bytes, cursor + 8)? as usize;
                let datasize = read_u32_le(bytes, cursor + 12)? as usize;
                max_end = max_end.max(dataoff.saturating_add(datasize));
            }
            _ => {}
        }

        cursor += cmdsize;
    }

    Some(max_end.min(bytes.len()))
}

fn wasm_length(bytes: &[u8]) -> Option<usize> {
    if !bytes.starts_with(WASM_MAGIC) {
        return None;
    }

    let mut cursor = WASM_MAGIC.len();
    let mut last_good = cursor;
    let mut section_order = Vec::new();
    while cursor < bytes.len() {
        let section_id = *bytes.get(cursor)?;
        if section_id > 12 {
            break;
        }
        cursor += 1;
        let (section_len, consumed) = read_uleb128(bytes.get(cursor..)?)?;
        cursor += consumed;
        let end = cursor.checked_add(section_len as usize)?;
        if end > bytes.len() {
            break;
        }
        if section_id != 0 {
            if let Some(previous) = section_order.last().copied()
                && section_id < previous
            {
                break;
            }
            section_order.push(section_id);
        }
        cursor = end;
        last_good = end;
    }

    Some(last_good)
}

fn png_length(bytes: &[u8]) -> Option<usize> {
    if !bytes.starts_with(PNG_MAGIC) {
        return None;
    }

    let mut cursor = PNG_MAGIC.len();
    while cursor.checked_add(12)? <= bytes.len() {
        let length = read_u32_be(bytes, cursor)? as usize;
        let chunk_type = bytes.get(cursor + 4..cursor + 8)?;
        cursor = cursor.checked_add(8)?.checked_add(length)?.checked_add(4)?;
        if chunk_type == b"IEND" {
            return Some(cursor);
        }
    }

    None
}

fn read_uleb128(bytes: &[u8]) -> Option<(u64, usize)> {
    let mut value = 0u64;
    let mut shift = 0u32;
    for (index, byte) in bytes.iter().copied().enumerate() {
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Some((value, index + 1));
        }
        shift = shift.checked_add(7)?;
        if shift > 63 {
            return None;
        }
    }
    None
}

fn printable_strings(bytes: &[u8]) -> String {
    let mut out = String::new();
    let mut current = Vec::new();

    for byte in bytes.iter().copied() {
        if byte == b'\n' || byte == b'\r' || byte == b'\t' || (0x20..=0x7e).contains(&byte) {
            current.push(byte);
        } else {
            flush_printable_run(&mut out, &mut current);
        }
    }
    flush_printable_run(&mut out, &mut current);
    out
}

fn flush_printable_run(out: &mut String, current: &mut Vec<u8>) {
    if current.len() >= 4 {
        if !out.is_empty() {
            out.push('\n');
        }
        out.push_str(String::from_utf8_lossy(current).trim_end_matches('\0'));
    }
    current.clear();
}

fn is_likely_html(bytes: &[u8]) -> bool {
    let text = leading_text(bytes);
    let lower = text.to_ascii_lowercase();
    lower.starts_with("<!doctype html") || lower.starts_with("<html")
}

fn is_likely_javascript(bytes: &[u8]) -> bool {
    let text = leading_text(bytes);
    let trimmed = text.trim_start();
    trimmed.starts_with("import")
        || trimmed.starts_with("export")
        || trimmed.starts_with("var ")
        || trimmed.starts_with("let ")
        || trimmed.starts_with("const ")
        || trimmed.starts_with("function ")
        || trimmed.starts_with("(function")
        || trimmed.starts_with("(()=>")
        || trimmed.starts_with("console.")
        || trimmed.starts_with("\"use strict\"")
        || trimmed.starts_with("'use strict'")
}

fn is_likely_css(bytes: &[u8]) -> bool {
    let text = leading_text(bytes);
    text.starts_with("/*")
        || text.starts_with("@import")
        || text.starts_with("@layer")
        || text.starts_with(":root")
}

fn is_likely_json(bytes: &[u8]) -> bool {
    matches!(
        leading_text(bytes)
            .chars()
            .find(|ch| !ch.is_ascii_whitespace()),
        Some('{') | Some('[')
    )
}

fn is_likely_text(bytes: &[u8]) -> bool {
    let text = leading_text(bytes);
    !text.is_empty()
        && text.bytes().all(|byte| {
            byte == b'\n' || byte == b'\r' || byte == b'\t' || (0x20..=0x7e).contains(&byte)
        })
}

fn leading_text(bytes: &[u8]) -> String {
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len())
        .min(128);
    String::from_utf8_lossy(&bytes[..end])
        .trim_start()
        .to_string()
}

fn collect_bunfs_paths(bytes: &[u8]) -> Vec<String> {
    let mut paths = collect_path_occurrences(bytes)
        .into_iter()
        .map(|occurrence| occurrence.path.trim_start_matches("file://").to_string())
        .collect::<Vec<_>>();
    paths.sort();
    paths.dedup();
    paths
}

#[derive(Debug, Clone)]
struct PathOccurrence {
    offset: usize,
    path: String,
}

fn collect_path_occurrences(bytes: &[u8]) -> Vec<PathOccurrence> {
    let mut occurrences = Vec::new();
    for prefix in BUN_PATH_PREFIXES {
        let mut search_from = 0usize;
        while let Some(relative_offset) = find_subslice(&bytes[search_from..], prefix) {
            let offset = search_from + relative_offset;
            if let Some(path) = read_c_string_like(bytes, offset) {
                occurrences.push(PathOccurrence { offset, path });
            }
            search_from = offset + prefix.len();
        }
    }
    occurrences.sort_by_key(|occurrence| occurrence.offset);
    occurrences.dedup_by_key(|occurrence| occurrence.offset);
    occurrences
}

fn read_c_string_like(bytes: &[u8], start: usize) -> Option<String> {
    let mut end = start;
    while end < bytes.len() {
        let byte = bytes[end];
        if byte == 0 {
            break;
        }
        if !(0x20..=0x7e).contains(&byte) {
            return None;
        }
        end += 1;
    }
    if end == start {
        return None;
    }
    String::from_utf8(bytes.get(start..end)?.to_vec()).ok()
}

fn collect_metadata(strings: &str) -> Vec<(String, String)> {
    let mut metadata = Vec::new();
    for key in [
        "PACKAGE_NAME",
        "PACKAGE_URL",
        "VERSION",
        "BUILD_TIME",
        "README_URL",
        "REPOSITORY_URL",
        "HOMEPAGE_URL",
        "API_URL",
        "BASE_API_URL",
    ] {
        if let Some(value) = find_best_quoted_value(strings, key) {
            metadata.push((key.to_string(), value));
        }
    }
    metadata.sort();
    metadata.dedup();
    metadata
}

fn find_best_quoted_value(haystack: &str, key: &str) -> Option<String> {
    let needle = format!("{key}:");
    let mut best: Option<(usize, String)> = None;
    let mut search_from = 0usize;

    while let Some(relative_start) = haystack[search_from..].find(&needle) {
        let start = search_from + relative_start + needle.len();
        let Some(value) = find_next_quoted_literal(&haystack[start..]) else {
            search_from = start;
            continue;
        };
        let score = metadata_value_score(key, &value);
        if score > 0 {
            let should_replace = best
                .as_ref()
                .map(|(best_score, best_value)| {
                    score > *best_score || (score == *best_score && value.len() < best_value.len())
                })
                .unwrap_or(true);
            if should_replace {
                best = Some((score, value));
            }
        }
        search_from = start;
    }

    best.map(|(_, value)| value)
}

fn find_next_quoted_literal(haystack: &str) -> Option<String> {
    let quote_offset = haystack
        .char_indices()
        .find(|(_, ch)| *ch == '"' || *ch == '\'')?
        .0;
    let quote = haystack[quote_offset..].chars().next()?;
    let value_start = quote_offset + quote.len_utf8();
    let rest = haystack.get(value_start..)?;
    let value_end = rest.find(quote)?;
    Some(rest[..value_end].to_string())
}

fn metadata_value_score(key: &str, value: &str) -> usize {
    match key {
        "PACKAGE_NAME" => {
            let trimmed = value.trim();
            if trimmed.is_empty() {
                0
            } else if trimmed.len() <= 64 && trimmed.chars().all(|ch| !ch.is_control()) {
                10
            } else {
                1
            }
        }
        "VERSION" => {
            if let Some((major, minor, patch)) = parse_semver(value) {
                1_000_000_000usize
                    .saturating_add(major.saturating_mul(1_000_000))
                    .saturating_add(minor.saturating_mul(1_000))
                    .saturating_add(patch)
            } else if value.chars().any(|ch| ch.is_ascii_digit()) {
                2
            } else {
                1
            }
        }
        "BUILD_TIME" => {
            if value.contains('T') && value.ends_with('Z') && value.contains('-') {
                5
            } else if value.chars().any(|ch| ch.is_ascii_digit()) {
                2
            } else {
                1
            }
        }
        key if key.ends_with("_URL") || key.ends_with("_URI") => {
            let mut score = 0usize;
            if value.starts_with("https://") {
                score += 50;
            } else if value.starts_with("http://") {
                score += 10;
            }
            if value.contains("localhost") || value.contains("127.0.0.1") {
                score = score.saturating_sub(40);
            }
            if value.contains("github.com") {
                score += 10;
            }
            if value.contains("/docs") || value.contains("/readme") {
                score += 10;
            }
            if score > 0 { score } else { 1 }
        }
        _ => 1,
    }
}

fn parse_semver(value: &str) -> Option<(usize, usize, usize)> {
    let trimmed = value.split(['-', '+']).next().unwrap_or(value).trim();
    let mut parts = trimmed.split('.');
    let major = parts.next();
    let minor = parts.next();
    let patch = parts.next();
    let extra = parts.next();
    match (major, minor, patch, extra) {
        (Some(major), Some(minor), Some(patch), None)
            if major.chars().all(|ch| ch.is_ascii_digit())
                && minor.chars().all(|ch| ch.is_ascii_digit())
                && patch.chars().all(|ch| ch.is_ascii_digit()) =>
        {
            Some((
                major.parse().ok()?,
                minor.parse().ok()?,
                patch.parse().ok()?,
            ))
        }
        _ => None,
    }
}

fn find_first_text_payload_offset(bytes: &[u8]) -> Option<usize> {
    find_subslice(bytes, JS_MARKER).or_else(|| find_subslice(bytes, JS_MARKER_FALLBACK))
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn read_fixed_string(bytes: &[u8], start: usize, len: usize) -> Option<String> {
    let slice = bytes.get(start..start + len)?;
    let end = slice
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(slice.len());
    String::from_utf8(slice[..end].to_vec()).ok()
}

fn read_u32_le(bytes: &[u8], start: usize) -> Option<u32> {
    let slice = bytes.get(start..start + 4)?;
    Some(u32::from_le_bytes(slice.try_into().ok()?))
}

fn read_u32_be(bytes: &[u8], start: usize) -> Option<u32> {
    let slice = bytes.get(start..start + 4)?;
    Some(u32::from_be_bytes(slice.try_into().ok()?))
}

fn read_u64_le(bytes: &[u8], start: usize) -> Option<u64> {
    let slice = bytes.get(start..start + 8)?;
    Some(u64::from_le_bytes(slice.try_into().ok()?))
}

#[cfg(test)]
mod tests {
    use super::{EmbeddedKind, structured_embedded_files};
    use crate::standalone::StandaloneFile;

    #[test]
    fn structured_standalone_files_include_sidecars() {
        let files = structured_embedded_files(&[StandaloneFile {
            virtual_path: "/$bunfs/root/index.js".to_string(),
            source_offset: 123,
            bytes: b"// @bun\nconsole.log('entry');\n".to_vec(),
            sourcemap: Some(b"SMAP".to_vec()),
            sourcemap_offset: Some(456),
            bytecode: Some(b"BYTE".to_vec()),
            bytecode_offset: Some(789),
            module_info: Some(b"META".to_vec()),
            module_info_offset: Some(999),
            bytecode_origin_path: Some("B:/~BUN/root/index.js".to_string()),
            encoding: 1,
            loader: 1,
            module_format: 1,
            side: 0,
        }]);

        assert_eq!(files.len(), 4);
        assert_eq!(files[0].kind, EmbeddedKind::JsWrapper);
        assert_eq!(files[0].standalone_role, Some("contents"));
        assert_eq!(
            files[0].standalone_bytecode_origin_path.as_deref(),
            Some("B:/~BUN/root/index.js")
        );
        assert_eq!(files[1].kind, EmbeddedKind::StandaloneSourceMap);
        assert_eq!(
            files[1].derived_from.as_deref(),
            Some("/$bunfs/root/index.js")
        );
        assert_eq!(files[1].source_offset, 456);
        assert_eq!(files[2].kind, EmbeddedKind::StandaloneBytecode);
        assert_eq!(files[2].source_offset, 789);
        assert_eq!(files[3].kind, EmbeddedKind::StandaloneModuleInfo);
        assert_eq!(files[3].source_offset, 999);
    }
}
