use crate::binary::{read_fixed_string, read_u32_le, read_u64_le};

use super::super::{
    BUN_SECTION_NAMES, LC_SEGMENT, LC_SEGMENT_64, MACH_O_MAGIC_32, MACH_O_MAGIC_64,
};

#[derive(Debug, Clone, Copy)]
pub(crate) struct BunSection {
    pub(crate) name: &'static str,
    pub(crate) fileoff: usize,
    pub(crate) filesize: usize,
}

pub(crate) fn find_bun_section(bytes: &[u8]) -> Option<BunSection> {
    let magic = read_u32_le(bytes, 0)?;
    let is_64 = match magic {
        MACH_O_MAGIC_64 => true,
        MACH_O_MAGIC_32 => false,
        _ => return None,
    };
    let header_size = if is_64 { 32 } else { 28 };
    let ncmds = usize::try_from(read_u32_le(bytes, 16)?).ok()?;
    let sizeofcmds = usize::try_from(read_u32_le(bytes, 20)?).ok()?;
    if bytes.len() < header_size + sizeofcmds {
        return None;
    }

    let mut cursor = header_size;
    for _ in 0..ncmds {
        let cmd = read_u32_le(bytes, cursor)?;
        let cmdsize = usize::try_from(read_u32_le(bytes, cursor + 4)?).ok()?;
        if cmdsize < 8 || cursor + cmdsize > bytes.len() {
            return None;
        }

        match cmd {
            LC_SEGMENT_64 if is_64 => {
                let segname = read_fixed_string(bytes, cursor + 8, 16)?;
                if BUN_SECTION_NAMES.contains(&segname.as_str()) {
                    return Some(BunSection {
                        name: canonical_bun_section_name(&segname),
                        fileoff: usize::try_from(read_u64_le(bytes, cursor + 40)?).ok()?,
                        filesize: usize::try_from(read_u64_le(bytes, cursor + 48)?).ok()?,
                    });
                }
            }
            LC_SEGMENT if !is_64 => {
                let segname = read_fixed_string(bytes, cursor + 8, 16)?;
                if BUN_SECTION_NAMES.contains(&segname.as_str()) {
                    return Some(BunSection {
                        name: canonical_bun_section_name(&segname),
                        fileoff: usize::try_from(read_u32_le(bytes, cursor + 32)?).ok()?,
                        filesize: usize::try_from(read_u32_le(bytes, cursor + 36)?).ok()?,
                    });
                }
            }
            _ => {}
        }

        cursor += cmdsize;
    }

    None
}

pub(crate) fn version_scan_regions(bytes: &[u8]) -> Vec<&[u8]> {
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
    let Some(ncmds) = read_u32_le(bytes, 16).and_then(|value| usize::try_from(value).ok()) else {
        return Vec::new();
    };
    let Some(sizeofcmds) = read_u32_le(bytes, 20).and_then(|value| usize::try_from(value).ok())
    else {
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
        let Some(cmdsize) =
            read_u32_le(bytes, cursor + 4).and_then(|value| usize::try_from(value).ok())
        else {
            return Vec::new();
        };
        if cmdsize < 8 || cursor + cmdsize > bytes.len() {
            return Vec::new();
        }

        match cmd {
            LC_SEGMENT_64 if is_64 => {
                let Some(nsects) =
                    read_u32_le(bytes, cursor + 64).and_then(|value| usize::try_from(value).ok())
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
                let Some(nsects) =
                    read_u32_le(bytes, cursor + 48).and_then(|value| usize::try_from(value).ok())
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
        read_u64_le(bytes, section_offset + size_offset)
            .and_then(|value| usize::try_from(value).ok())
    } else {
        read_u32_le(bytes, section_offset + size_offset)
            .and_then(|value| usize::try_from(value).ok())
    };
    let Some(size) = size else {
        return;
    };
    let Some(file_offset) = read_u32_le(bytes, section_offset + file_offset_offset)
        .and_then(|value| usize::try_from(value).ok())
    else {
        return;
    };
    let Some(slice) = bytes.get(file_offset..file_offset.saturating_add(size)) else {
        return;
    };
    sections.push(slice);
}

fn canonical_bun_section_name(segname: &str) -> &'static str {
    if segname == "__bun" { "__bun" } else { "__BUN" }
}
