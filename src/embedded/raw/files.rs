use std::collections::BTreeMap;

use super::super::{
    BUN_PATH_PREFIXES, EmbeddedFile, EmbeddedKind, JS_MARKER, JS_MARKER_FALLBACK,
    detect::{detect_kind, macho_length, png_length, wasm_length},
};

#[derive(Debug, Clone)]
struct PathOccurrence {
    offset: usize,
    path: String,
}

pub(crate) fn extract_embedded_files(bytes: &[u8]) -> Vec<EmbeddedFile> {
    let occurrences = collect_path_occurrences(bytes);
    let mut files = BTreeMap::<String, EmbeddedFile>::new();

    for (index, occurrence) in occurrences.iter().enumerate() {
        let Some(content_start) =
            find_content_start(bytes, occurrence.offset, occurrence.path.len())
        else {
            continue;
        };
        let Some(kind) = detect_kind(&occurrence.path, &bytes[content_start..]) else {
            continue;
        };

        let next_path_offset = occurrences
            .get(index + 1)
            .map_or(bytes.len(), |next| next.offset);
        let content_end = match kind {
            EmbeddedKind::JsWrapper
            | EmbeddedKind::Html
            | EmbeddedKind::Css
            | EmbeddedKind::Text
            | EmbeddedKind::WebManifest
            | EmbeddedKind::StandaloneSourceMap
            | EmbeddedKind::StandaloneSourceMapJson
            | EmbeddedKind::StandaloneBytecode
            | EmbeddedKind::StandaloneModuleInfo
            | EmbeddedKind::StandaloneModuleInfoJson => nul_terminated_end(bytes, content_start),
            EmbeddedKind::Wasm => {
                bounded_content_end(bytes, content_start, next_path_offset, wasm_length)
            }
            EmbeddedKind::MachO => {
                bounded_content_end(bytes, content_start, next_path_offset, macho_length)
            }
            EmbeddedKind::Png => {
                bounded_content_end(bytes, content_start, next_path_offset, png_length)
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

pub(crate) fn find_first_text_payload_offset(bytes: &[u8]) -> Option<usize> {
    find_subslice(bytes, JS_MARKER).or_else(|| find_subslice(bytes, JS_MARKER_FALLBACK))
}

pub(crate) fn printable_strings(bytes: &[u8]) -> String {
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

pub(crate) fn collect_bunfs_paths(bytes: &[u8]) -> Vec<String> {
    let mut paths = collect_path_occurrences(bytes)
        .into_iter()
        .map(|occurrence| occurrence.path.trim_start_matches("file://").to_string())
        .collect::<Vec<_>>();
    paths.sort();
    paths.dedup();
    paths
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

fn nul_terminated_end(bytes: &[u8], content_start: usize) -> usize {
    bytes[content_start..]
        .iter()
        .position(|byte| *byte == 0)
        .map_or(bytes.len(), |offset| content_start + offset)
}

fn bounded_content_end(
    bytes: &[u8],
    content_start: usize,
    next_path_offset: usize,
    length: impl Fn(&[u8]) -> Option<usize>,
) -> usize {
    let upper_bound = next_path_offset.saturating_sub(usize::from(
        next_path_offset > 0 && bytes[next_path_offset - 1] == 0,
    ));
    let window = bytes.get(content_start..upper_bound).unwrap_or_default();
    content_start + length(window).unwrap_or(window.len())
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

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}
