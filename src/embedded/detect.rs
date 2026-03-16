use super::{
    EmbeddedKind, JS_MARKER, JS_MARKER_FALLBACK, LC_DYSYMTAB, LC_SEGMENT, LC_SEGMENT_64, LC_SYMTAB,
    MACH_O_MAGIC_32, MACH_O_MAGIC_64, PNG_MAGIC, WASM_MAGIC,
};

pub(super) fn detect_kind(path: &str, bytes: &[u8]) -> Option<EmbeddedKind> {
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

pub(super) fn standalone_encoding_label(value: u8) -> Option<&'static str> {
    match value {
        0 => Some("binary"),
        1 => Some("latin1"),
        2 => Some("utf8"),
        _ => None,
    }
}

pub(super) fn standalone_module_format_label(value: u8) -> Option<&'static str> {
    match value {
        0 => Some("none"),
        1 => Some("esm"),
        2 => Some("cjs"),
        _ => None,
    }
}

pub(super) fn standalone_side_label(value: u8) -> Option<&'static str> {
    match value {
        0 => Some("server"),
        1 => Some("client"),
        _ => None,
    }
}

pub(super) fn macho_length(bytes: &[u8]) -> Option<usize> {
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

pub(super) fn wasm_length(bytes: &[u8]) -> Option<usize> {
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

pub(super) fn png_length(bytes: &[u8]) -> Option<usize> {
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

pub(super) fn read_fixed_string(bytes: &[u8], start: usize, len: usize) -> Option<String> {
    let slice = bytes.get(start..start + len)?;
    let end = slice
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(slice.len());
    String::from_utf8(slice[..end].to_vec()).ok()
}

pub(super) fn read_u32_le(bytes: &[u8], start: usize) -> Option<u32> {
    let slice = bytes.get(start..start + 4)?;
    Some(u32::from_le_bytes(slice.try_into().ok()?))
}

fn read_u32_be(bytes: &[u8], start: usize) -> Option<u32> {
    let slice = bytes.get(start..start + 4)?;
    Some(u32::from_be_bytes(slice.try_into().ok()?))
}

pub(super) fn read_u64_le(bytes: &[u8], start: usize) -> Option<u64> {
    let slice = bytes.get(start..start + 8)?;
    Some(u64::from_le_bytes(slice.try_into().ok()?))
}
