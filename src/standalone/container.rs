use std::{error::Error, mem::size_of};

use super::{
    OffsetsLayout, SectionLengthWidth, StandaloneSectionKind, TRAILER,
    elf::find_bun_section as find_elf_bun_section, macho,
    macho::find_bun_section as find_macho_bun_section, parse_offsets, pe,
    pe::find_bun_section as find_pe_bun_section, read_u64_le,
};

#[derive(Debug, Clone, Copy)]
pub(super) struct ContainerPayload<'a> {
    pub(super) location: ContainerLocation<'a>,
    pub(super) payload_file_offset: usize,
    pub(super) payload_bytes: &'a [u8],
    pub(super) offsets_layout: OffsetsLayout,
}

#[cfg(test)]
impl ContainerPayload<'_> {
    pub(super) fn container_name(&self) -> Option<&str> {
        match self.location {
            ContainerLocation::Appended => None,
            ContainerLocation::Section { name, .. } => Some(name),
        }
    }

    pub(super) const fn raw_container_file_offset(&self) -> Option<usize> {
        match self.location {
            ContainerLocation::Appended => None,
            ContainerLocation::Section { file_offset, .. } => Some(file_offset),
        }
    }

    pub(super) const fn section_length_width(&self) -> Option<SectionLengthWidth> {
        match self.location {
            ContainerLocation::Appended => None,
            ContainerLocation::Section { length_width, .. } => Some(length_width),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub(super) enum ContainerLocation<'a> {
    Appended,
    Section {
        kind: StandaloneSectionKind,
        name: &'static str,
        file_offset: usize,
        bytes: &'a [u8],
        length_width: SectionLengthWidth,
    },
}

#[derive(Debug, Clone, Copy)]
struct LengthPrefixedPayload<'a> {
    bytes: &'a [u8],
    length_width: SectionLengthWidth,
    offsets_layout: OffsetsLayout,
}

pub(super) fn extract_container_payload(
    bytes: &[u8],
) -> Result<Option<ContainerPayload<'_>>, Box<dyn Error>> {
    if let Some(payload) = extract_macho_payload(bytes) {
        return Ok(Some(payload));
    }
    if let Some(payload) = extract_pe_payload(bytes)? {
        return Ok(Some(payload));
    }
    if let Some(payload) = extract_elf_payload(bytes) {
        return Ok(Some(payload));
    }
    if let Some(payload) = extract_appended_payload(bytes) {
        return Ok(Some(payload));
    }

    Ok(None)
}

fn extract_macho_payload(bytes: &[u8]) -> Option<ContainerPayload<'_>> {
    let section = find_macho_bun_section(bytes)?;
    let raw_section = bytes.get(section.fileoff..section.fileoff.checked_add(section.filesize)?)?;
    let payload = parse_length_prefixed_payload(raw_section)?;

    Some(ContainerPayload {
        location: ContainerLocation::Section {
            kind: if macho::is_macho64(bytes) {
                StandaloneSectionKind::MachO64
            } else {
                StandaloneSectionKind::MachO32
            },
            name: section.name,
            file_offset: section.fileoff,
            bytes: raw_section,
            length_width: payload.length_width,
        },
        payload_file_offset: section.fileoff + payload.length_width.size(),
        payload_bytes: payload.bytes,
        offsets_layout: payload.offsets_layout,
    })
}

fn extract_pe_payload(bytes: &[u8]) -> Result<Option<ContainerPayload<'_>>, Box<dyn Error>> {
    let Some(section) = find_pe_bun_section(bytes)? else {
        return Ok(None);
    };
    let Some(section_end) = section
        .pointer_to_raw_data
        .checked_add(section.size_of_raw_data)
    else {
        return Ok(None);
    };
    let Some(raw_section) = bytes.get(section.pointer_to_raw_data..section_end) else {
        return Ok(None);
    };
    let Some(payload) = parse_length_prefixed_payload(raw_section) else {
        return Ok(None);
    };

    Ok(Some(ContainerPayload {
        location: ContainerLocation::Section {
            kind: if pe::is_pe64(bytes) {
                StandaloneSectionKind::Pe64
            } else {
                StandaloneSectionKind::Pe32
            },
            name: ".bun",
            file_offset: section.pointer_to_raw_data,
            bytes: raw_section,
            length_width: payload.length_width,
        },
        payload_file_offset: section.pointer_to_raw_data + payload.length_width.size(),
        payload_bytes: payload.bytes,
        offsets_layout: payload.offsets_layout,
    }))
}

fn extract_elf_payload(bytes: &[u8]) -> Option<ContainerPayload<'_>> {
    let section = find_elf_bun_section(bytes)?;
    let raw_section = bytes.get(section.fileoff..section.fileoff.checked_add(section.filesize)?)?;
    let payload = parse_length_prefixed_payload(raw_section)?;

    Some(ContainerPayload {
        location: ContainerLocation::Section {
            kind: StandaloneSectionKind::Elf,
            name: ".bun",
            file_offset: section.fileoff,
            bytes: raw_section,
            length_width: payload.length_width,
        },
        payload_file_offset: section.fileoff + payload.length_width.size(),
        payload_bytes: payload.bytes,
        offsets_layout: payload.offsets_layout,
    })
}

fn extract_appended_payload(bytes: &[u8]) -> Option<ContainerPayload<'_>> {
    let footer_size = size_of::<u64>() + OffsetsLayout::Legacy.size() + TRAILER.len();
    if bytes.len() < footer_size {
        return None;
    }

    let total_size_offset = bytes.len() - size_of::<u64>();
    let total_byte_count =
        read_u64_le(bytes, total_size_offset).and_then(|value| usize::try_from(value).ok())?;
    if total_byte_count != bytes.len() {
        return None;
    }

    let trailer_start = total_size_offset.saturating_sub(TRAILER.len());
    if bytes.get(trailer_start..total_size_offset) != Some(TRAILER) {
        return None;
    }

    for offsets_layout in OffsetsLayout::ALL {
        let Some(offsets_start) = trailer_start.checked_sub(offsets_layout.size()) else {
            continue;
        };
        let Some(offsets_bytes) = bytes.get(offsets_start..trailer_start) else {
            continue;
        };
        let Some(offsets) = parse_offsets(offsets_bytes, offsets_layout) else {
            continue;
        };
        let Some(payload_start) = offsets_start.checked_sub(offsets.byte_count) else {
            continue;
        };
        let Some(payload_bytes) = bytes.get(payload_start..total_size_offset) else {
            continue;
        };
        if detect_offsets_layout(payload_bytes) != Some(offsets_layout) {
            continue;
        }

        return Some(ContainerPayload {
            location: ContainerLocation::Appended,
            payload_file_offset: payload_start,
            payload_bytes,
            offsets_layout,
        });
    }

    None
}

fn parse_length_prefixed_payload(raw_section: &[u8]) -> Option<LengthPrefixedPayload<'_>> {
    for length_width in [SectionLengthWidth::U64, SectionLengthWidth::U32] {
        let Some(len) = length_width.read(raw_section) else {
            continue;
        };
        let payload_start = length_width.size();
        let Some(payload_end) = payload_start.checked_add(len) else {
            continue;
        };
        let Some(bytes) = raw_section.get(payload_start..payload_end) else {
            continue;
        };
        let Some(offsets_layout) = detect_offsets_layout(bytes) else {
            continue;
        };

        return Some(LengthPrefixedPayload {
            bytes,
            length_width,
            offsets_layout,
        });
    }

    None
}

fn detect_offsets_layout(payload: &[u8]) -> Option<OffsetsLayout> {
    let trailer_start = payload.len().checked_sub(TRAILER.len())?;
    if payload.get(trailer_start..) != Some(TRAILER) {
        return None;
    }

    for offsets_layout in OffsetsLayout::ALL {
        let Some(offsets_start) = trailer_start.checked_sub(offsets_layout.size()) else {
            continue;
        };
        let Some(offsets) = payload
            .get(offsets_start..trailer_start)
            .and_then(|bytes| parse_offsets(bytes, offsets_layout))
        else {
            continue;
        };
        if offsets.byte_count == offsets_start
            && pointer_fits_body(offsets.modules_ptr, offsets.byte_count)
            && pointer_fits_body(offsets.compile_exec_argv_ptr, offsets.byte_count)
        {
            return Some(offsets_layout);
        }
    }

    None
}

fn pointer_fits_body(pointer: super::RawStringPointer, body_len: usize) -> bool {
    let Ok(offset) = usize::try_from(pointer.offset) else {
        return false;
    };
    let Ok(length) = usize::try_from(pointer.length) else {
        return false;
    };

    offset
        .checked_add(length)
        .is_some_and(|end| end <= body_len)
}
