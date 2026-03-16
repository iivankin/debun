use std::collections::BTreeMap;

use super::{
    BUN_PATH_PREFIXES, BUN_SECTION_NAMES, EmbeddedFile, EmbeddedKind, JS_MARKER,
    JS_MARKER_FALLBACK, LC_SEGMENT, LC_SEGMENT_64, MACH_O_MAGIC_32, MACH_O_MAGIC_64,
    detect::{
        detect_kind, macho_length, png_length, read_fixed_string, read_u32_le, read_u64_le,
        wasm_length,
    },
};

#[derive(Debug, Clone, Copy)]
pub(super) struct BunSection {
    pub(super) name: &'static str,
    pub(super) fileoff: usize,
    pub(super) filesize: usize,
}

#[derive(Debug, Clone)]
struct PathOccurrence {
    offset: usize,
    path: String,
}

pub(super) fn find_bun_section(bytes: &[u8]) -> Option<BunSection> {
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

pub(super) fn version_scan_regions(bytes: &[u8]) -> Vec<&[u8]> {
    // Bun bakes CLI/runtime version strings into regular read-only text
    // sections of the host executable, not into the standalone payload.
    const VERSION_TEXT_SECTIONS: [(&str, &str); 2] =
        [("__TEXT", "__const"), ("__TEXT", "__cstring")];

    let sections = collect_mach_o_sections(bytes, &VERSION_TEXT_SECTIONS);
    if sections.is_empty() {
        vec![bytes]
    } else {
        sections
    }
}

pub(super) fn extract_embedded_files(bytes: &[u8]) -> Vec<EmbeddedFile> {
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

pub(super) fn find_first_text_payload_offset(bytes: &[u8]) -> Option<usize> {
    find_subslice(bytes, JS_MARKER).or_else(|| find_subslice(bytes, JS_MARKER_FALLBACK))
}

pub(super) fn printable_strings(bytes: &[u8]) -> String {
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

pub(super) fn collect_bunfs_paths(bytes: &[u8]) -> Vec<String> {
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

fn collect_mach_o_sections<'a>(bytes: &'a [u8], wanted: &[(&str, &str)]) -> Vec<&'a [u8]> {
    let Some(magic) = read_u32_le(bytes, 0) else {
        return Vec::new();
    };
    let is_64 = match magic {
        MACH_O_MAGIC_64 => true,
        MACH_O_MAGIC_32 => false,
        _ => return Vec::new(),
    };
    let header_size = if is_64 { 32 } else { 28 };
    let Some(ncmds) = read_u32_le(bytes, 16).map(|value| value as usize) else {
        return Vec::new();
    };
    let Some(sizeofcmds) = read_u32_le(bytes, 20).map(|value| value as usize) else {
        return Vec::new();
    };
    if bytes.len() < header_size + sizeofcmds {
        return Vec::new();
    }

    let mut cursor = header_size;
    let mut sections = Vec::new();
    for _ in 0..ncmds {
        let Some(cmd) = read_u32_le(bytes, cursor) else {
            return Vec::new();
        };
        let Some(cmdsize) = read_u32_le(bytes, cursor + 4).map(|value| value as usize) else {
            return Vec::new();
        };
        if cmdsize < 8 || cursor + cmdsize > bytes.len() {
            return Vec::new();
        }

        match cmd {
            LC_SEGMENT_64 if is_64 => {
                let Some(nsects) = read_u32_le(bytes, cursor + 64).map(|value| value as usize)
                else {
                    return Vec::new();
                };
                let section_start = cursor + 72;
                let section_size = 80;
                if section_start + nsects.saturating_mul(section_size) > cursor + cmdsize {
                    return Vec::new();
                }
                for index in 0..nsects {
                    let section_offset = section_start + index * section_size;
                    collect_matching_section(
                        bytes,
                        wanted,
                        &mut sections,
                        section_offset,
                        40,
                        48,
                        true,
                    );
                }
            }
            LC_SEGMENT if !is_64 => {
                let Some(nsects) = read_u32_le(bytes, cursor + 48).map(|value| value as usize)
                else {
                    return Vec::new();
                };
                let section_start = cursor + 56;
                let section_size = 68;
                if section_start + nsects.saturating_mul(section_size) > cursor + cmdsize {
                    return Vec::new();
                }
                for index in 0..nsects {
                    let section_offset = section_start + index * section_size;
                    collect_matching_section(
                        bytes,
                        wanted,
                        &mut sections,
                        section_offset,
                        36,
                        40,
                        false,
                    );
                }
            }
            _ => {}
        }

        cursor += cmdsize;
    }

    sections
}

fn collect_matching_section<'a>(
    bytes: &'a [u8],
    wanted: &[(&str, &str)],
    sections: &mut Vec<&'a [u8]>,
    section_offset: usize,
    size_offset: usize,
    file_offset_offset: usize,
    is_64: bool,
) {
    let Some(section_name) = read_fixed_string(bytes, section_offset, 16) else {
        return;
    };
    let Some(segment_name) = read_fixed_string(bytes, section_offset + 16, 16) else {
        return;
    };
    if !wanted.iter().any(|(segment, section)| {
        *segment == segment_name.as_str() && *section == section_name.as_str()
    }) {
        return;
    }

    let size = if is_64 {
        read_u64_le(bytes, section_offset + size_offset).map(|value| value as usize)
    } else {
        read_u32_le(bytes, section_offset + size_offset).map(|value| value as usize)
    };
    let Some(size) = size else {
        return;
    };
    let Some(file_offset) =
        read_u32_le(bytes, section_offset + file_offset_offset).map(|value| value as usize)
    else {
        return;
    };
    let Some(slice) = bytes.get(file_offset..file_offset.saturating_add(size)) else {
        return;
    };
    sections.push(slice);
}
