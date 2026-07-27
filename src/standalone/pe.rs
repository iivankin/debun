use std::{error::Error, mem::size_of};

use crate::binary::{read_u16_le, read_u32_le};

use super::layout::{BUN_SECTION_NAME, DOS_MAGIC, PE_MAGIC, SectionLengthWidth};

const COFF_HEADER_SIZE: usize = 20;
const SECTION_HEADER_SIZE: usize = 40;
const OPTIONAL_HEADER_32_MAGIC: u16 = 0x10b;
const OPTIONAL_HEADER_64_MAGIC: u16 = 0x20b;
const OPTIONAL_SECTION_ALIGNMENT: usize = 32;
const OPTIONAL_FILE_ALIGNMENT: usize = 36;
const OPTIONAL_SIZE_OF_IMAGE: usize = 56;
const OPTIONAL_CHECKSUM: usize = 64;
const OPTIONAL_NUMBER_OF_DIRECTORIES_32: usize = 92;
const OPTIONAL_DATA_DIRECTORIES_32: usize = 96;
const OPTIONAL_NUMBER_OF_DIRECTORIES_64: usize = 108;
const OPTIONAL_DATA_DIRECTORIES_64: usize = 112;
const IMAGE_DIRECTORY_ENTRY_SECURITY: usize = 4;
const IMAGE_DIRECTORY_ENTRY_DEBUG: usize = 6;
const DEBUG_DIRECTORY_SIZE: usize = 28;

const SECTION_VIRTUAL_SIZE: usize = 8;
const SECTION_VIRTUAL_ADDRESS: usize = 12;
const SECTION_RAW_SIZE: usize = 16;
const SECTION_RAW_POINTER: usize = 20;
const SECTION_RELOCATIONS_POINTER: usize = 24;
const SECTION_LINE_NUMBERS_POINTER: usize = 28;

#[derive(Debug, Clone, Copy)]
pub(super) struct PeBunSection {
    pub(super) pointer_to_raw_data: usize,
    pub(super) size_of_raw_data: usize,
    header_offset: usize,
    virtual_address: usize,
}

#[derive(Debug, Clone)]
struct PeLayout {
    coff_header_offset: usize,
    optional_header_offset: usize,
    optional_header_size: usize,
    section_headers_end: usize,
    format: PeFormat,
    sections: Vec<PeSection>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PeFormat {
    Pe32,
    Pe64,
}

impl PeFormat {
    const fn data_directories(self) -> (usize, usize) {
        match self {
            Self::Pe32 => (
                OPTIONAL_NUMBER_OF_DIRECTORIES_32,
                OPTIONAL_DATA_DIRECTORIES_32,
            ),
            Self::Pe64 => (
                OPTIONAL_NUMBER_OF_DIRECTORIES_64,
                OPTIONAL_DATA_DIRECTORIES_64,
            ),
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct PeSection {
    header_offset: usize,
    virtual_size: usize,
    virtual_address: usize,
    raw_size: usize,
    raw_pointer: usize,
}

pub(super) fn is_pe64(bytes: &[u8]) -> bool {
    let Some(pe_header_offset) =
        read_u32_le(bytes, 0x3c).and_then(|value| usize::try_from(value).ok())
    else {
        return false;
    };
    if read_u16_le(bytes, 0) != Some(DOS_MAGIC)
        || read_u32_le(bytes, pe_header_offset) != Some(PE_MAGIC)
    {
        return false;
    }
    read_u16_le(bytes, pe_header_offset + 4 + COFF_HEADER_SIZE) == Some(OPTIONAL_HEADER_64_MAGIC)
}

pub(super) fn find_bun_section(bytes: &[u8]) -> Result<Option<PeBunSection>, Box<dyn Error>> {
    let Some(layout) = parse_layout(bytes)? else {
        return Ok(None);
    };
    Ok(find_bun_section_in_layout(bytes, &layout))
}

pub(super) fn write_bun_section(
    bytes: &[u8],
    payload: &[u8],
    length_width: SectionLengthWidth,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let layout = parse_layout(bytes)?.ok_or("PE headers were missing")?;

    let bun = find_bun_section_in_layout(bytes, &layout).ok_or("PE .bun section was missing")?;
    let section_alignment = read_usize_u32(
        bytes,
        layout.optional_header_offset + OPTIONAL_SECTION_ALIGNMENT,
        "PE section alignment",
    )?;
    let file_alignment = read_usize_u32(
        bytes,
        layout.optional_header_offset + OPTIONAL_FILE_ALIGNMENT,
        "PE file alignment",
    )?;
    if !section_alignment.is_power_of_two() || !file_alignment.is_power_of_two() {
        return Err("PE file or section alignment was invalid".into());
    }
    validate_unsigned(bytes, &layout)?;

    let required_len = length_width
        .size()
        .checked_add(payload.len())
        .ok_or("PE .bun payload size overflowed")?;
    let aligned_required =
        align_up(required_len, file_alignment).ok_or("expanded PE .bun size overflowed")?;
    let new_raw_size = bun.size_of_raw_data.max(aligned_required);
    let growth = new_raw_size
        .checked_sub(bun.size_of_raw_data)
        .ok_or("expanded PE .bun size did not grow")?;
    validate_bun_file_range(bytes, &layout, bun)?;
    if growth != 0 {
        if layout.format != PeFormat::Pe64 {
            return Err("full PE .bun growth requires a PE32+ executable".into());
        }
        validate_bun_is_last(&layout, bun, section_alignment)?;
    }
    let old_bun_end = bun
        .pointer_to_raw_data
        .checked_add(bun.size_of_raw_data)
        .ok_or("PE .bun file range overflowed")?;
    let new_bun_end = old_bun_end
        .checked_add(growth)
        .ok_or("expanded PE .bun file range overflowed")?;
    let new_file_len = bytes
        .len()
        .checked_add(growth)
        .ok_or("expanded PE file size overflowed")?;

    // `.bun` is Bun's final PE section. Grow its raw range in place and move
    // any unsigned overlay so user data after the image is preserved.
    let mut out = bytes.to_vec();
    if growth != 0 {
        out.resize(new_file_len, 0);
        out.copy_within(old_bun_end..bytes.len(), new_bun_end);
        out[old_bun_end..new_bun_end].fill(0);
        shift_overlay_file_pointers(bytes, &mut out, &layout, old_bun_end, growth)?;
    }

    write_u32_field(
        &mut out,
        bun.header_offset + SECTION_VIRTUAL_SIZE,
        required_len,
        "PE .bun virtual size",
    )?;
    write_u32_field(
        &mut out,
        bun.header_offset + SECTION_RAW_SIZE,
        new_raw_size,
        "PE .bun raw size",
    )?;
    write_payload(
        &mut out,
        bun.pointer_to_raw_data,
        new_raw_size,
        payload,
        length_width,
    )?;

    let size_of_image = calculate_size_of_image(
        &layout,
        bun.header_offset,
        required_len,
        new_raw_size,
        section_alignment,
    )?;
    write_u32_field(
        &mut out,
        layout.optional_header_offset + OPTIONAL_SIZE_OF_IMAGE,
        size_of_image,
        "PE SizeOfImage",
    )?;
    recompute_checksum(&mut out, layout.optional_header_offset + OPTIONAL_CHECKSUM)?;
    Ok(out)
}

fn parse_layout(bytes: &[u8]) -> Result<Option<PeLayout>, Box<dyn Error>> {
    if read_u16_le(bytes, 0) != Some(DOS_MAGIC) {
        return Ok(None);
    }
    let pe_header_offset =
        usize::try_from(read_u32_le(bytes, 0x3c).ok_or("PE header offset was missing")?)?;
    if read_u32_le(bytes, pe_header_offset) != Some(PE_MAGIC) {
        return Ok(None);
    }

    let coff_header_offset = pe_header_offset
        .checked_add(size_of::<u32>())
        .ok_or("PE COFF header offset overflowed")?;
    let section_count = usize::from(
        read_u16_le(bytes, coff_header_offset + 2).ok_or("PE section count was missing")?,
    );
    let optional_header_size = usize::from(
        read_u16_le(bytes, coff_header_offset + 16).ok_or("PE optional header size was missing")?,
    );
    let optional_header_offset = coff_header_offset
        .checked_add(COFF_HEADER_SIZE)
        .ok_or("PE optional header offset overflowed")?;
    let section_headers_offset = optional_header_offset
        .checked_add(optional_header_size)
        .ok_or("PE section header offset overflowed")?;
    let section_headers_end = section_headers_offset
        .checked_add(
            section_count
                .checked_mul(SECTION_HEADER_SIZE)
                .ok_or("PE section header table size overflowed")?,
        )
        .ok_or("PE section header table range overflowed")?;
    if bytes
        .get(optional_header_offset..section_headers_end)
        .is_none()
    {
        return Err("PE headers were out of bounds".into());
    }
    if optional_header_size < size_of::<u16>() {
        return Err("PE optional header was too short".into());
    }
    let format = match read_u16_le(bytes, optional_header_offset) {
        Some(OPTIONAL_HEADER_32_MAGIC) => PeFormat::Pe32,
        Some(OPTIONAL_HEADER_64_MAGIC) => PeFormat::Pe64,
        _ => return Err("unsupported PE optional header format".into()),
    };
    let (directory_count_offset, _) = format.data_directories();
    if optional_header_size < directory_count_offset + size_of::<u32>() {
        return Err("PE optional header was too short for its data directories".into());
    }

    let mut sections = Vec::with_capacity(section_count);
    for index in 0..section_count {
        let header_offset = section_headers_offset
            .checked_add(
                index
                    .checked_mul(SECTION_HEADER_SIZE)
                    .ok_or("PE section header offset overflowed")?,
            )
            .ok_or("PE section header offset overflowed")?;
        sections.push(PeSection {
            header_offset,
            virtual_size: read_usize_u32(
                bytes,
                header_offset + SECTION_VIRTUAL_SIZE,
                "PE section virtual size",
            )?,
            virtual_address: read_usize_u32(
                bytes,
                header_offset + SECTION_VIRTUAL_ADDRESS,
                "PE section virtual address",
            )?,
            raw_size: read_usize_u32(
                bytes,
                header_offset + SECTION_RAW_SIZE,
                "PE section raw size",
            )?,
            raw_pointer: read_usize_u32(
                bytes,
                header_offset + SECTION_RAW_POINTER,
                "PE section raw pointer",
            )?,
        });
    }

    Ok(Some(PeLayout {
        coff_header_offset,
        optional_header_offset,
        optional_header_size,
        section_headers_end,
        format,
        sections,
    }))
}

fn find_bun_section_in_layout(bytes: &[u8], layout: &PeLayout) -> Option<PeBunSection> {
    for section in &layout.sections {
        if bytes.get(section.header_offset..section.header_offset.checked_add(8)?)
            != Some(BUN_SECTION_NAME)
        {
            continue;
        }
        return Some(PeBunSection {
            pointer_to_raw_data: section.raw_pointer,
            size_of_raw_data: section.raw_size,
            header_offset: section.header_offset,
            virtual_address: section.virtual_address,
        });
    }
    None
}

fn validate_unsigned(bytes: &[u8], layout: &PeLayout) -> Result<(), Box<dyn Error>> {
    let (directory_count_offset, _) = layout.format.data_directories();
    let directories_count = read_usize_u32(
        bytes,
        layout.optional_header_offset + directory_count_offset,
        "PE data directory count",
    )?;
    if directories_count <= IMAGE_DIRECTORY_ENTRY_SECURITY {
        return Ok(());
    }
    let security_entry = data_directory_offset(layout, IMAGE_DIRECTORY_ENTRY_SECURITY)?;
    let certificate_offset =
        read_u32_le(bytes, security_entry).ok_or("PE security directory offset was missing")?;
    let certificate_size =
        read_u32_le(bytes, security_entry + 4).ok_or("PE security directory size was missing")?;
    if certificate_offset != 0 || certificate_size != 0 {
        return Err(
            "signed PE .bun sections cannot be modified without replacing Authenticode".into(),
        );
    }
    Ok(())
}

fn validate_bun_file_range(
    bytes: &[u8],
    layout: &PeLayout,
    bun: PeBunSection,
) -> Result<(), Box<dyn Error>> {
    let bun_end = bun
        .pointer_to_raw_data
        .checked_add(bun.size_of_raw_data)
        .ok_or("PE .bun file range overflowed")?;
    if bun_end > bytes.len() {
        return Err("PE .bun file range was out of bounds".into());
    }
    if bun.pointer_to_raw_data < layout.section_headers_end {
        return Err("PE .bun file range overlapped the PE headers".into());
    }

    for section in &layout.sections {
        if section.header_offset == bun.header_offset {
            continue;
        }
        if section.raw_size != 0 {
            let raw_end = section
                .raw_pointer
                .checked_add(section.raw_size)
                .ok_or("PE section file range overflowed")?;
            if raw_end > bytes.len() {
                return Err("PE section file range was out of bounds".into());
            }
            if bun.pointer_to_raw_data < raw_end && section.raw_pointer < bun_end {
                return Err("another PE section overlapped the .bun file range".into());
            }
        }
    }
    Ok(())
}

fn validate_bun_is_last(
    layout: &PeLayout,
    bun: PeBunSection,
    section_alignment: usize,
) -> Result<(), Box<dyn Error>> {
    let bun_end = bun
        .pointer_to_raw_data
        .checked_add(bun.size_of_raw_data)
        .ok_or("PE .bun file range overflowed")?;
    for section in &layout.sections {
        if section.header_offset == bun.header_offset {
            continue;
        }
        if section.raw_size != 0 && section.raw_pointer >= bun_end {
            return Err("PE .bun was not the final raw section".into());
        }
        let effective_size = section.virtual_size.max(section.raw_size);
        let virtual_end = section
            .virtual_address
            .checked_add(
                align_up(effective_size, section_alignment)
                    .ok_or("PE section virtual size overflowed")?,
            )
            .ok_or("PE section virtual range overflowed")?;
        if section.virtual_address >= bun.virtual_address || virtual_end > bun.virtual_address {
            return Err("PE .bun was not the final virtual section".into());
        }
    }
    Ok(())
}

fn shift_overlay_file_pointers(
    original: &[u8],
    out: &mut [u8],
    layout: &PeLayout,
    overlay_start: usize,
    growth: usize,
) -> Result<(), Box<dyn Error>> {
    shift_u32_pointer(
        original,
        out,
        layout.coff_header_offset + 8,
        overlay_start,
        growth,
        "PE COFF symbol table pointer",
    )?;
    for section in &layout.sections {
        shift_u32_pointer(
            original,
            out,
            section.header_offset + SECTION_RELOCATIONS_POINTER,
            overlay_start,
            growth,
            "PE section relocations pointer",
        )?;
        shift_u32_pointer(
            original,
            out,
            section.header_offset + SECTION_LINE_NUMBERS_POINTER,
            overlay_start,
            growth,
            "PE section line numbers pointer",
        )?;
    }
    shift_debug_directory_pointers(original, out, layout, overlay_start, growth)
}

fn shift_debug_directory_pointers(
    original: &[u8],
    out: &mut [u8],
    layout: &PeLayout,
    overlay_start: usize,
    growth: usize,
) -> Result<(), Box<dyn Error>> {
    let (directory_count_offset, _) = layout.format.data_directories();
    let directories_count = read_usize_u32(
        original,
        layout.optional_header_offset + directory_count_offset,
        "PE data directory count",
    )?;
    if directories_count <= IMAGE_DIRECTORY_ENTRY_DEBUG {
        return Ok(());
    }
    let debug_entry = data_directory_offset(layout, IMAGE_DIRECTORY_ENTRY_DEBUG)?;
    let debug_rva = read_usize_u32(original, debug_entry, "PE debug directory RVA")?;
    let debug_size = read_usize_u32(original, debug_entry + 4, "PE debug directory size")?;
    if debug_rva == 0 || debug_size == 0 {
        return Ok(());
    }
    if !debug_size.is_multiple_of(DEBUG_DIRECTORY_SIZE) {
        return Err("PE debug directory size was invalid".into());
    }
    let debug_fileoff = rva_to_file_offset(layout, debug_rva, debug_size)
        .ok_or("PE debug directory was not inside a section")?;
    if debug_fileoff >= overlay_start {
        return Err("PE debug directory itself was inside the moved overlay".into());
    }
    for index in 0..debug_size / DEBUG_DIRECTORY_SIZE {
        let entry = debug_fileoff
            .checked_add(
                index
                    .checked_mul(DEBUG_DIRECTORY_SIZE)
                    .ok_or("PE debug directory offset overflowed")?,
            )
            .ok_or("PE debug directory offset overflowed")?;
        shift_u32_pointer(
            original,
            out,
            entry + 24,
            overlay_start,
            growth,
            "PE debug data file pointer",
        )?;
    }
    Ok(())
}

fn rva_to_file_offset(layout: &PeLayout, rva: usize, size: usize) -> Option<usize> {
    for section in &layout.sections {
        let Some(delta) = rva.checked_sub(section.virtual_address) else {
            continue;
        };
        let end = delta.checked_add(size)?;
        if end <= section.raw_size {
            return section.raw_pointer.checked_add(delta);
        }
    }
    None
}

fn data_directory_offset(layout: &PeLayout, index: usize) -> Result<usize, Box<dyn Error>> {
    let (_, directories_offset) = layout.format.data_directories();
    let relative = directories_offset
        .checked_add(
            index
                .checked_mul(8)
                .ok_or("PE data directory offset overflowed")?,
        )
        .ok_or("PE data directory offset overflowed")?;
    if relative
        .checked_add(8)
        .is_none_or(|end| end > layout.optional_header_size)
    {
        return Err("PE optional header did not contain the requested data directory".into());
    }
    layout
        .optional_header_offset
        .checked_add(relative)
        .ok_or_else(|| "PE data directory offset overflowed".into())
}

fn calculate_size_of_image(
    layout: &PeLayout,
    bun_header_offset: usize,
    bun_virtual_size: usize,
    bun_raw_size: usize,
    section_alignment: usize,
) -> Result<usize, Box<dyn Error>> {
    let mut image_end = 0;
    for section in &layout.sections {
        let (virtual_size, raw_size) = if section.header_offset == bun_header_offset {
            (bun_virtual_size, bun_raw_size)
        } else {
            (section.virtual_size, section.raw_size)
        };
        let effective_size = virtual_size.max(raw_size);
        let end = section
            .virtual_address
            .checked_add(
                align_up(effective_size, section_alignment)
                    .ok_or("PE section virtual size overflowed")?,
            )
            .ok_or("PE section virtual range overflowed")?;
        image_end = image_end.max(end);
    }
    align_up(image_end, section_alignment).ok_or_else(|| "PE SizeOfImage overflowed".into())
}

fn shift_u32_pointer(
    original: &[u8],
    out: &mut [u8],
    field_offset: usize,
    overlay_start: usize,
    growth: usize,
    name: &str,
) -> Result<(), Box<dyn Error>> {
    let value = read_usize_u32(original, field_offset, name)?;
    if value == 0 || value < overlay_start {
        return Ok(());
    }
    write_u32_field(
        out,
        field_offset,
        value
            .checked_add(growth)
            .ok_or_else(|| format!("{name} overflowed"))?,
        name,
    )
}

fn write_payload(
    out: &mut [u8],
    fileoff: usize,
    capacity: usize,
    payload: &[u8],
    length_width: SectionLengthWidth,
) -> Result<(), Box<dyn Error>> {
    let required_len = length_width
        .size()
        .checked_add(payload.len())
        .ok_or("PE .bun payload size overflowed")?;
    let end = fileoff
        .checked_add(capacity)
        .ok_or("PE .bun file range overflowed")?;
    let payload_start = fileoff
        .checked_add(length_width.size())
        .ok_or("PE .bun payload offset overflowed")?;
    let payload_end = payload_start
        .checked_add(payload.len())
        .ok_or("PE .bun payload range overflowed")?;
    if required_len > capacity || out.get(fileoff..end).is_none() {
        return Err("PE .bun payload did not fit its prepared section".into());
    }
    length_width.write(&mut out[fileoff..payload_start], payload.len())?;
    out[payload_start..payload_end].copy_from_slice(payload);
    out[payload_end..end].fill(0);
    Ok(())
}

fn recompute_checksum(bytes: &mut [u8], checksum_offset: usize) -> Result<(), Box<dyn Error>> {
    write_u32_field(bytes, checksum_offset, 0, "PE checksum")?;
    let mut sum = 0_u64;
    let mut index = 0;
    while index + 1 < bytes.len() {
        sum += u64::from(u16::from_le_bytes([bytes[index], bytes[index + 1]]));
        sum = (sum & 0xffff) + (sum >> 16);
        index += 2;
    }
    if index < bytes.len() {
        sum += u64::from(bytes[index]);
    }
    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);
    sum = sum
        .checked_add(u64::try_from(bytes.len())?)
        .ok_or("PE checksum overflowed")?;
    sum = (sum & 0xffff) + (sum >> 16);
    let checksum = (sum & 0xffff) + (sum >> 16);
    write_u32_field(
        bytes,
        checksum_offset,
        usize::try_from(checksum)?,
        "PE checksum",
    )
}

fn read_usize_u32(bytes: &[u8], offset: usize, name: &str) -> Result<usize, Box<dyn Error>> {
    usize::try_from(read_u32_le(bytes, offset).ok_or_else(|| format!("{name} was missing"))?)
        .map_err(Into::into)
}

fn align_up(value: usize, alignment: usize) -> Option<usize> {
    let remainder = value % alignment;
    if remainder == 0 {
        Some(value)
    } else {
        value.checked_add(alignment.checked_sub(remainder)?)
    }
}

fn write_u32_field(
    bytes: &mut [u8],
    offset: usize,
    value: usize,
    name: &str,
) -> Result<(), Box<dyn Error>> {
    let end = offset
        .checked_add(size_of::<u32>())
        .ok_or_else(|| format!("{name} field offset overflowed"))?;
    let field = bytes
        .get_mut(offset..end)
        .ok_or_else(|| format!("{name} field was out of bounds"))?;
    field.copy_from_slice(&u32::try_from(value)?.to_le_bytes());
    Ok(())
}

#[cfg(test)]
#[path = "pe_tests.rs"]
mod tests;
