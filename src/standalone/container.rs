use std::{error::Error, mem::size_of};

use super::{
    BUN_SECTION_NAME, BUN_SEGMENT_NAMES, DOS_MAGIC, LC_SEGMENT, LC_SEGMENT_64, MACH_O_MAGIC_32,
    MACH_O_MAGIC_64, OFFSETS_SIZE_64, PE_MAGIC, TRAILER, parse_offsets, read_fixed_string,
    read_u16_le, read_u32_le, read_u64_le,
};

#[derive(Debug, Clone, Copy)]
pub(super) struct ContainerPayload<'a> {
    pub(super) container_name: Option<&'static str>,
    pub(super) raw_container_file_offset: Option<usize>,
    pub(super) raw_container_bytes: Option<&'a [u8]>,
    pub(super) payload_file_offset: usize,
    pub(super) payload_bytes: &'a [u8],
}

#[derive(Debug, Clone, Copy)]
struct MachoBunSection {
    name: &'static str,
    fileoff: usize,
    filesize: usize,
}

#[derive(Debug, Clone, Copy)]
struct PeBunSection {
    pointer_to_raw_data: usize,
    size_of_raw_data: usize,
}

pub(super) fn extract_container_payload(
    bytes: &[u8],
) -> Result<Option<ContainerPayload<'_>>, Box<dyn Error>> {
    if let Some(payload) = extract_macho_payload(bytes)? {
        return Ok(Some(payload));
    }
    if let Some(payload) = extract_pe_payload(bytes)? {
        return Ok(Some(payload));
    }
    if let Some(payload) = extract_appended_payload(bytes)? {
        return Ok(Some(payload));
    }

    Ok(None)
}

fn extract_macho_payload(bytes: &[u8]) -> Result<Option<ContainerPayload<'_>>, Box<dyn Error>> {
    let Some(section) = find_macho_bun_section(bytes) else {
        return Ok(None);
    };
    let Some(raw_section) =
        bytes.get(section.fileoff..section.fileoff.saturating_add(section.filesize))
    else {
        return Ok(None);
    };
    let Some(payload_bytes) = parse_length_prefixed_payload(raw_section) else {
        return Ok(None);
    };

    Ok(Some(ContainerPayload {
        container_name: Some(section.name),
        raw_container_file_offset: Some(section.fileoff),
        raw_container_bytes: Some(raw_section),
        payload_file_offset: section.fileoff + size_of::<u64>(),
        payload_bytes,
    }))
}

fn extract_pe_payload(bytes: &[u8]) -> Result<Option<ContainerPayload<'_>>, Box<dyn Error>> {
    let Some(section) = find_pe_bun_section(bytes)? else {
        return Ok(None);
    };
    let Some(raw_section) = bytes
        .get(section.pointer_to_raw_data..section.pointer_to_raw_data + section.size_of_raw_data)
    else {
        return Ok(None);
    };
    let Some(payload_bytes) = parse_length_prefixed_payload(raw_section) else {
        return Ok(None);
    };

    Ok(Some(ContainerPayload {
        container_name: Some(".bun"),
        raw_container_file_offset: Some(section.pointer_to_raw_data),
        raw_container_bytes: Some(raw_section),
        payload_file_offset: section.pointer_to_raw_data + size_of::<u64>(),
        payload_bytes,
    }))
}

fn extract_appended_payload(bytes: &[u8]) -> Result<Option<ContainerPayload<'_>>, Box<dyn Error>> {
    if size_of::<usize>() != size_of::<u64>() {
        return Ok(None);
    }

    let footer_size = size_of::<u64>() + OFFSETS_SIZE_64 + TRAILER.len();
    if bytes.len() < footer_size {
        return Ok(None);
    }

    let total_size_offset = bytes.len() - size_of::<u64>();
    let Some(total_byte_count) = read_u64_le(bytes, total_size_offset).map(|value| value as usize)
    else {
        return Ok(None);
    };
    if total_byte_count != bytes.len() {
        return Ok(None);
    }

    let trailer_start = total_size_offset.saturating_sub(TRAILER.len());
    if bytes.get(trailer_start..total_size_offset) != Some(TRAILER) {
        return Ok(None);
    }

    let offsets_start = trailer_start.saturating_sub(OFFSETS_SIZE_64);
    let Some(offsets_bytes) = bytes.get(offsets_start..trailer_start) else {
        return Ok(None);
    };
    let Some(offsets) = parse_offsets(offsets_bytes) else {
        return Ok(None);
    };
    if offsets.byte_count > offsets_start {
        return Ok(None);
    }

    let payload_start = offsets_start - offsets.byte_count;
    let Some(payload_bytes) = bytes.get(payload_start..total_size_offset) else {
        return Ok(None);
    };

    Ok(Some(ContainerPayload {
        container_name: None,
        raw_container_file_offset: None,
        raw_container_bytes: None,
        payload_file_offset: payload_start,
        payload_bytes,
    }))
}

fn parse_length_prefixed_payload(raw_section: &[u8]) -> Option<&[u8]> {
    let len = read_u64_le(raw_section, 0)? as usize;
    raw_section.get(size_of::<u64>()..size_of::<u64>() + len)
}

fn find_macho_bun_section(bytes: &[u8]) -> Option<MachoBunSection> {
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
                if BUN_SEGMENT_NAMES.contains(&segname.as_str()) {
                    return Some(MachoBunSection {
                        name: if segname == "__bun" { "__bun" } else { "__BUN" },
                        fileoff: read_u64_le(bytes, cursor + 40)? as usize,
                        filesize: read_u64_le(bytes, cursor + 48)? as usize,
                    });
                }
            }
            LC_SEGMENT if !is_64 => {
                let segname = read_fixed_string(bytes, cursor + 8, 16)?;
                if BUN_SEGMENT_NAMES.contains(&segname.as_str()) {
                    return Some(MachoBunSection {
                        name: if segname == "__bun" { "__bun" } else { "__BUN" },
                        fileoff: read_u32_le(bytes, cursor + 32)? as usize,
                        filesize: read_u32_le(bytes, cursor + 36)? as usize,
                    });
                }
            }
            _ => {}
        }

        cursor += cmdsize;
    }

    None
}

fn find_pe_bun_section(bytes: &[u8]) -> Result<Option<PeBunSection>, Box<dyn Error>> {
    if read_u16_le(bytes, 0) != Some(DOS_MAGIC) {
        return Ok(None);
    }

    let pe_header_offset = read_u32_le(bytes, 0x3c).ok_or("PE header offset was missing")? as usize;
    if read_u32_le(bytes, pe_header_offset) != Some(PE_MAGIC) {
        return Ok(None);
    }

    let coff_header_offset = pe_header_offset + 4;
    let number_of_sections =
        read_u16_le(bytes, coff_header_offset + 2).ok_or("PE section count was missing")? as usize;
    let optional_header_size = read_u16_le(bytes, coff_header_offset + 16)
        .ok_or("PE optional header size was missing")? as usize;
    let section_headers_offset = coff_header_offset + 20 + optional_header_size;

    for index in 0..number_of_sections {
        let offset = section_headers_offset + index * 40;
        let Some(name) = bytes.get(offset..offset + 8) else {
            break;
        };
        if name != BUN_SECTION_NAME {
            continue;
        }

        let size_of_raw_data =
            read_u32_le(bytes, offset + 16).ok_or("PE bun section size was missing")? as usize;
        let pointer_to_raw_data =
            read_u32_le(bytes, offset + 20).ok_or("PE bun section offset was missing")? as usize;
        return Ok(Some(PeBunSection {
            pointer_to_raw_data,
            size_of_raw_data,
        }));
    }

    Ok(None)
}
