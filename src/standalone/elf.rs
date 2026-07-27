use std::{error::Error, mem::size_of};

use crate::binary::{read_u16_le, read_u32_le, read_u64_le};
use crate::standalone::SectionLengthWidth;

const ELF_MAGIC: &[u8; 4] = b"\x7fELF";
const ELF_CLASS_64: u8 = 2;
const ELF_DATA_LITTLE_ENDIAN: u8 = 1;
const ELF64_PROGRAM_HEADER_SIZE: usize = 56;
const ELF64_SECTION_HEADER_SIZE: usize = 64;
const ELF64_E_MACHINE: usize = 18;
const ELF64_E_PHOFF: usize = 32;
const ELF64_E_SHOFF: usize = 40;
const ELF64_E_PHENTSIZE: usize = 54;
const ELF64_E_PHNUM: usize = 56;
const ELF64_E_SHENTSIZE: usize = 58;
const ELF64_E_SHNUM: usize = 60;
const ELF64_E_SHSTRNDX: usize = 62;
const ELF64_P_TYPE: usize = 0;
const ELF64_P_FLAGS: usize = 4;
const ELF64_P_OFFSET: usize = 8;
const ELF64_P_VADDR: usize = 16;
const ELF64_P_FILESZ: usize = 32;
const ELF64_P_MEMSZ: usize = 40;
const ELF64_SH_TYPE: usize = 4;
const ELF64_SH_ADDR: usize = 16;
const ELF64_SH_OFFSET: usize = 24;
const ELF64_SH_SIZE: usize = 32;
const PT_LOAD: u32 = 1;
const PF_W: u32 = 2;
const SHT_NOBITS: u32 = 8;
const EM_X86_64: u16 = 62;
const EM_AARCH64: u16 = 183;

#[derive(Debug, Clone, Copy)]
pub(super) struct ElfBunSection {
    pub(super) fileoff: usize,
    pub(super) filesize: usize,
    header_offset: usize,
    section_index: usize,
    vaddr: u64,
}

#[derive(Debug, Clone, Copy)]
struct ElfLoadSegment {
    header_offset: usize,
    fileoff: usize,
    vaddr: u64,
    filesize: usize,
    memsize: usize,
    flags: u32,
}

pub(super) fn is_elf(bytes: &[u8]) -> bool {
    // Bun's Linux compile targets are 64-bit little-endian (x64 and arm64),
    // which is also the only ELF shape accepted by Bun's own section writer.
    bytes.get(..ELF_MAGIC.len()) == Some(ELF_MAGIC)
        && bytes.get(4) == Some(&ELF_CLASS_64)
        && bytes.get(5) == Some(&ELF_DATA_LITTLE_ENDIAN)
}

pub(super) fn find_bun_section(bytes: &[u8]) -> Option<ElfBunSection> {
    if !is_elf(bytes) {
        return None;
    }

    let section_headers_offset = usize::try_from(read_u64_le(bytes, ELF64_E_SHOFF)?).ok()?;
    let section_header_size = usize::from(read_u16_le(bytes, ELF64_E_SHENTSIZE)?);
    let section_count = usize::from(read_u16_le(bytes, ELF64_E_SHNUM)?);
    let names_section_index = usize::from(read_u16_le(bytes, ELF64_E_SHSTRNDX)?);
    if section_header_size != ELF64_SECTION_HEADER_SIZE
        || section_count == 0
        || names_section_index >= section_count
    {
        return None;
    }

    let section_headers_len = section_count.checked_mul(section_header_size)?;
    let section_headers_end = section_headers_offset.checked_add(section_headers_len)?;
    bytes.get(section_headers_offset..section_headers_end)?;

    let names_header_offset = section_header_offset(
        section_headers_offset,
        section_header_size,
        names_section_index,
    )?;
    let names = section_bytes(bytes, names_header_offset)?;

    for index in 0..section_count {
        let header_offset =
            section_header_offset(section_headers_offset, section_header_size, index)?;
        let name_offset = usize::try_from(read_u32_le(bytes, header_offset)?).ok()?;
        let name_bytes = names.get(name_offset..)?;
        let name_end = name_bytes.iter().position(|byte| *byte == 0)?;
        if name_bytes.get(..name_end) != Some(b".bun") {
            continue;
        }

        let vaddr = read_u64_le(bytes, header_offset.checked_add(ELF64_SH_ADDR)?)?;
        let fileoff = usize::try_from(read_u64_le(
            bytes,
            header_offset.checked_add(ELF64_SH_OFFSET)?,
        )?)
        .ok()?;
        let filesize = usize::try_from(read_u64_le(
            bytes,
            header_offset.checked_add(ELF64_SH_SIZE)?,
        )?)
        .ok()?;
        let end = fileoff.checked_add(filesize)?;
        bytes.get(fileoff..end)?;
        return Some(ElfBunSection {
            fileoff,
            filesize,
            header_offset,
            section_index: index,
            vaddr,
        });
    }

    None
}

pub(super) fn write_bun_section(
    bytes: &[u8],
    payload: &[u8],
    length_width: SectionLengthWidth,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let section = find_bun_section(bytes).ok_or("ELF .bun section was missing")?;
    let segment = find_bun_load_segment(bytes, section)
        .ok_or("ELF .bun section was not inside a unique PT_LOAD segment")?;
    let capacity = bun_section_capacity(bytes, section, segment)
        .ok_or("ELF .bun section was not safely expandable inside a PT_LOAD segment")?;
    let required_len = length_width
        .size()
        .checked_add(payload.len())
        .ok_or("standalone section payload size overflowed")?;
    if required_len <= capacity {
        let mut out = bytes.to_vec();
        write_bun_payload(
            &mut out,
            section.fileoff,
            section.header_offset,
            capacity,
            payload,
            length_width,
        )?;
        return Ok(out);
    }

    relocate_elf_tail(
        bytes,
        payload,
        section,
        segment,
        capacity,
        required_len,
        length_width,
    )
}

fn relocate_elf_tail(
    bytes: &[u8],
    payload: &[u8],
    section: ElfBunSection,
    segment: ElfLoadSegment,
    safe_capacity: usize,
    required_len: usize,
    length_width: SectionLengthWidth,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let segment_end = segment
        .fileoff
        .checked_add(segment.filesize)
        .ok_or("ELF PT_LOAD file range overflowed")?;
    let mapped_capacity = segment_end
        .checked_sub(section.fileoff)
        .ok_or("ELF .bun mapping was invalid")?;
    if safe_capacity != mapped_capacity {
        return Err(format!(
            "repacked ELF payload ({required_len} bytes) exceeds the safe .bun capacity \
             ({safe_capacity} bytes; full relocation requires a zero-filled .bun tail)"
        )
        .into());
    }
    if segment.flags & PF_W == 0 {
        return Err("ELF .bun PT_LOAD segment was not writable".into());
    }
    if segment.filesize != segment.memsize {
        return Err(
            "ELF .bun PT_LOAD has additional zero-filled memory and cannot be safely relocated"
                .into(),
        );
    }

    let page_size = elf_page_size(bytes).ok_or("unsupported ELF machine for .bun relocation")?;
    let vaddr_is_aligned =
        usize::try_from(section.vaddr).is_ok_and(|vaddr| vaddr.is_multiple_of(page_size));
    if !section.fileoff.is_multiple_of(page_size) || !vaddr_is_aligned {
        return Err("ELF .bun section was not page-aligned".into());
    }
    let new_capacity =
        align_up(required_len, page_size).ok_or("expanded ELF .bun capacity overflowed")?;
    let growth = new_capacity
        .checked_sub(mapped_capacity)
        .ok_or("expanded ELF .bun capacity did not grow")?;
    if growth == 0 {
        return Err("expanded ELF .bun capacity did not grow".into());
    }

    let new_segment_end = segment_end
        .checked_add(growth)
        .ok_or("expanded ELF PT_LOAD range overflowed")?;
    let new_file_len = bytes
        .len()
        .checked_add(growth)
        .ok_or("expanded ELF file size overflowed")?;
    validate_relocation_layout(bytes, segment, segment_end, growth)?;

    let section_headers_offset = usize::try_from(
        read_u64_le(bytes, ELF64_E_SHOFF).ok_or("ELF section header offset was missing")?,
    )
    .map_err(|_| "ELF section header offset exceeded usize")?;
    let new_section_headers_offset = section_headers_offset
        .checked_add(growth)
        .ok_or("relocated ELF section header offset overflowed")?;
    let section_header_size = usize::from(
        read_u16_le(bytes, ELF64_E_SHENTSIZE).ok_or("ELF section header size was missing")?,
    );
    let section_count = usize::from(
        read_u16_le(bytes, ELF64_E_SHNUM).ok_or("ELF section header count was missing")?,
    );

    // Keep `.bun` at the same file offset and virtual address so Bun's
    // compiled-in pointer remains valid. Only the file-only tail after the
    // writable PT_LOAD moves; the existing segment grows over the new gap.
    let mut out = bytes.to_vec();
    out.resize(new_file_len, 0);
    out.copy_within(segment_end..bytes.len(), new_segment_end);
    out[segment_end..new_segment_end].fill(0);

    write_u64_field(
        &mut out,
        ELF64_E_SHOFF,
        new_section_headers_offset,
        "relocated ELF section header offset",
    )?;
    write_u64_field(
        &mut out,
        segment.header_offset + ELF64_P_FILESZ,
        segment
            .filesize
            .checked_add(growth)
            .ok_or("expanded ELF PT_LOAD file size overflowed")?,
        "expanded ELF PT_LOAD file size",
    )?;
    write_u64_field(
        &mut out,
        segment.header_offset + ELF64_P_MEMSZ,
        segment
            .memsize
            .checked_add(growth)
            .ok_or("expanded ELF PT_LOAD memory size overflowed")?,
        "expanded ELF PT_LOAD memory size",
    )?;

    for index in 0..section_count {
        let old_header_offset =
            section_header_offset(section_headers_offset, section_header_size, index)
                .ok_or("ELF section header offset overflowed")?;
        let new_header_offset =
            section_header_offset(new_section_headers_offset, section_header_size, index)
                .ok_or("relocated ELF section header offset overflowed")?;
        let section_type = read_u32_le(
            bytes,
            old_header_offset
                .checked_add(ELF64_SH_TYPE)
                .ok_or("ELF section type offset overflowed")?,
        )
        .ok_or("ELF section type was out of bounds")?;
        let old_offset = usize::try_from(
            read_u64_le(
                bytes,
                old_header_offset
                    .checked_add(ELF64_SH_OFFSET)
                    .ok_or("ELF section offset field overflowed")?,
            )
            .ok_or("ELF section offset was out of bounds")?,
        )
        .map_err(|_| "ELF section offset exceeded usize")?;
        if section_type != SHT_NOBITS && old_offset >= segment_end && old_offset <= bytes.len() {
            let new_offset = old_offset
                .checked_add(growth)
                .ok_or("relocated ELF section offset overflowed")?;
            write_u64_field(
                &mut out,
                new_header_offset + ELF64_SH_OFFSET,
                new_offset,
                "relocated ELF section offset",
            )?;
        }
    }

    let bun_header_offset = section_header_offset(
        new_section_headers_offset,
        section_header_size,
        section.section_index,
    )
    .ok_or("relocated ELF .bun section header offset overflowed")?;
    write_bun_payload(
        &mut out,
        section.fileoff,
        bun_header_offset,
        new_capacity,
        payload,
        length_width,
    )?;
    Ok(out)
}

fn write_bun_payload(
    out: &mut [u8],
    section_fileoff: usize,
    section_header_offset: usize,
    capacity: usize,
    payload: &[u8],
    length_width: SectionLengthWidth,
) -> Result<(), Box<dyn Error>> {
    let required_len = length_width
        .size()
        .checked_add(payload.len())
        .ok_or("standalone section payload size overflowed")?;
    if required_len > capacity {
        return Err("ELF .bun replacement exceeded its prepared capacity".into());
    }

    let section_end = section_fileoff
        .checked_add(capacity)
        .ok_or("ELF .bun capacity overflowed")?;
    let payload_start = section_fileoff
        .checked_add(length_width.size())
        .ok_or("ELF .bun payload offset overflowed")?;
    let payload_end = payload_start
        .checked_add(payload.len())
        .ok_or("ELF .bun payload size overflowed")?;
    let size_field_end = section_header_offset
        .checked_add(ELF64_SH_SIZE + size_of::<u64>())
        .ok_or("ELF .bun section header overflowed")?;
    if out.get(section_fileoff..section_end).is_none()
        || out
            .get(section_header_offset + ELF64_SH_SIZE..size_field_end)
            .is_none()
    {
        return Err("ELF .bun replacement range was out of bounds".into());
    }

    let section_len =
        u64::try_from(required_len).map_err(|_| "ELF .bun section size exceeded u64")?;
    length_width.write(&mut out[section_fileoff..payload_start], payload.len())?;
    out[payload_start..payload_end].copy_from_slice(payload);
    out[payload_end..section_end].fill(0);
    out[section_header_offset + ELF64_SH_SIZE..size_field_end]
        .copy_from_slice(&section_len.to_le_bytes());
    Ok(())
}

fn find_bun_load_segment(bytes: &[u8], section: ElfBunSection) -> Option<ElfLoadSegment> {
    let section_end = section.fileoff.checked_add(section.filesize)?;
    let program_headers_offset = usize::try_from(read_u64_le(bytes, ELF64_E_PHOFF)?).ok()?;
    let program_header_size = usize::from(read_u16_le(bytes, ELF64_E_PHENTSIZE)?);
    let program_header_count = usize::from(read_u16_le(bytes, ELF64_E_PHNUM)?);
    if program_header_size != ELF64_PROGRAM_HEADER_SIZE || program_header_count == 0 {
        return None;
    }

    let program_headers_len = program_header_count.checked_mul(program_header_size)?;
    let program_headers_end = program_headers_offset.checked_add(program_headers_len)?;
    bytes.get(program_headers_offset..program_headers_end)?;

    // Match both file offsets and virtual addresses so an overlapping but
    // unrelated PT_LOAD cannot be mistaken for the mapping used by `.bun`.
    let mut matched = None;
    for index in 0..program_header_count {
        let header_offset =
            program_header_offset(program_headers_offset, program_header_size, index)?;
        if read_u32_le(bytes, header_offset.checked_add(ELF64_P_TYPE)?)? != PT_LOAD {
            continue;
        }

        let segment_offset = usize::try_from(read_u64_le(
            bytes,
            header_offset.checked_add(ELF64_P_OFFSET)?,
        )?)
        .ok()?;
        let segment_vaddr = read_u64_le(bytes, header_offset.checked_add(ELF64_P_VADDR)?)?;
        let segment_size = usize::try_from(read_u64_le(
            bytes,
            header_offset.checked_add(ELF64_P_FILESZ)?,
        )?)
        .ok()?;
        let segment_end = segment_offset.checked_add(segment_size)?;
        if section.fileoff < segment_offset || section_end > segment_end {
            continue;
        }

        let section_delta = section.fileoff.checked_sub(segment_offset)?;
        let mapped_vaddr = segment_vaddr.checked_add(u64::try_from(section_delta).ok()?)?;
        if mapped_vaddr != section.vaddr {
            continue;
        }

        if matched.is_some() {
            return None;
        }
        let memsize = usize::try_from(read_u64_le(
            bytes,
            header_offset.checked_add(ELF64_P_MEMSZ)?,
        )?)
        .ok()?;
        let flags = read_u32_le(bytes, header_offset.checked_add(ELF64_P_FLAGS)?)?;
        matched = Some(ElfLoadSegment {
            header_offset,
            fileoff: segment_offset,
            vaddr: segment_vaddr,
            filesize: segment_size,
            memsize,
            flags,
        });
    }

    matched
}

fn bun_section_capacity(
    bytes: &[u8],
    section: ElfBunSection,
    segment: ElfLoadSegment,
) -> Option<usize> {
    let section_end = section.fileoff.checked_add(section.filesize)?;
    let program_headers_offset = usize::try_from(read_u64_le(bytes, ELF64_E_PHOFF)?).ok()?;
    let program_header_size = usize::from(read_u16_le(bytes, ELF64_E_PHENTSIZE)?);
    let program_header_count = usize::from(read_u16_le(bytes, ELF64_E_PHNUM)?);
    if program_header_size != ELF64_PROGRAM_HEADER_SIZE || program_header_count == 0 {
        return None;
    }
    let program_headers_len = program_header_count.checked_mul(program_header_size)?;
    let program_headers_end = program_headers_offset.checked_add(program_headers_len)?;
    bytes.get(program_headers_offset..program_headers_end)?;

    let mut capacity_end = segment.fileoff.checked_add(segment.filesize)?;
    capacity_end = clamp_before_range(
        section.fileoff,
        section_end,
        program_headers_offset,
        program_headers_end,
        capacity_end,
    )?;

    let section_headers_offset = usize::try_from(read_u64_le(bytes, ELF64_E_SHOFF)?).ok()?;
    let section_header_size = usize::from(read_u16_le(bytes, ELF64_E_SHENTSIZE)?);
    let section_count = usize::from(read_u16_le(bytes, ELF64_E_SHNUM)?);
    if section_header_size != ELF64_SECTION_HEADER_SIZE || section_count == 0 {
        return None;
    }
    let section_headers_len = section_count.checked_mul(section_header_size)?;
    let section_headers_end = section_headers_offset.checked_add(section_headers_len)?;
    bytes.get(section_headers_offset..section_headers_end)?;
    capacity_end = clamp_before_range(
        section.fileoff,
        section_end,
        section_headers_offset,
        section_headers_end,
        capacity_end,
    )?;

    // Section tables are normally after the mapped padding, but explicitly
    // clamp before any file-backed section in case the ELF layout changes.
    for index in 0..section_count {
        let header_offset =
            section_header_offset(section_headers_offset, section_header_size, index)?;
        if header_offset == section.header_offset
            || read_u32_le(bytes, header_offset.checked_add(ELF64_SH_TYPE)?)? == SHT_NOBITS
        {
            continue;
        }
        let other_offset = usize::try_from(read_u64_le(
            bytes,
            header_offset.checked_add(ELF64_SH_OFFSET)?,
        )?)
        .ok()?;
        let other_size = usize::try_from(read_u64_le(
            bytes,
            header_offset.checked_add(ELF64_SH_SIZE)?,
        )?)
        .ok()?;
        if other_size == 0 {
            continue;
        }
        let other_end = other_offset.checked_add(other_size)?;
        capacity_end = clamp_before_range(
            section.fileoff,
            section_end,
            other_offset,
            other_end,
            capacity_end,
        )?;
    }

    // Bun zero-fills the page-aligned tail. Unknown non-zero bytes may belong
    // to data not represented by section headers, so never overwrite them.
    let padding = bytes.get(section_end..capacity_end)?;
    if padding.iter().any(|byte| *byte != 0) {
        return Some(section.filesize);
    }

    capacity_end.checked_sub(section.fileoff)
}

fn validate_relocation_layout(
    bytes: &[u8],
    segment: ElfLoadSegment,
    segment_end: usize,
    growth: usize,
) -> Result<(), Box<dyn Error>> {
    let program_headers_offset = usize::try_from(
        read_u64_le(bytes, ELF64_E_PHOFF).ok_or("ELF program header offset was missing")?,
    )
    .map_err(|_| "ELF program header offset exceeded usize")?;
    let program_header_size = usize::from(
        read_u16_le(bytes, ELF64_E_PHENTSIZE).ok_or("ELF program header size was missing")?,
    );
    let program_header_count = usize::from(
        read_u16_le(bytes, ELF64_E_PHNUM).ok_or("ELF program header count was missing")?,
    );
    if program_header_size != ELF64_PROGRAM_HEADER_SIZE || program_header_count == 0 {
        return Err("unsupported ELF program header table".into());
    }
    let program_headers_end = program_headers_offset
        .checked_add(
            program_header_count
                .checked_mul(program_header_size)
                .ok_or("ELF program header table size overflowed")?,
        )
        .ok_or("ELF program header table range overflowed")?;
    if bytes
        .get(program_headers_offset..program_headers_end)
        .is_none()
        || program_headers_end > segment_end
    {
        return Err("ELF program header table cannot be kept in place during relocation".into());
    }

    let section_headers_offset = usize::try_from(
        read_u64_le(bytes, ELF64_E_SHOFF).ok_or("ELF section header offset was missing")?,
    )
    .map_err(|_| "ELF section header offset exceeded usize")?;
    let section_header_size = usize::from(
        read_u16_le(bytes, ELF64_E_SHENTSIZE).ok_or("ELF section header size was missing")?,
    );
    let section_count = usize::from(
        read_u16_le(bytes, ELF64_E_SHNUM).ok_or("ELF section header count was missing")?,
    );
    if section_header_size != ELF64_SECTION_HEADER_SIZE || section_count == 0 {
        return Err("unsupported ELF section header table".into());
    }
    let section_headers_end = section_headers_offset
        .checked_add(
            section_count
                .checked_mul(section_header_size)
                .ok_or("ELF section header table size overflowed")?,
        )
        .ok_or("ELF section header table range overflowed")?;
    if section_headers_offset < segment_end
        || bytes
            .get(section_headers_offset..section_headers_end)
            .is_none()
    {
        return Err("ELF section header table was not wholly in the relocatable file tail".into());
    }

    for index in 0..section_count {
        let header_offset =
            section_header_offset(section_headers_offset, section_header_size, index)
                .ok_or("ELF section header offset overflowed")?;
        let section_type = read_u32_le(
            bytes,
            header_offset
                .checked_add(ELF64_SH_TYPE)
                .ok_or("ELF section type offset overflowed")?,
        )
        .ok_or("ELF section type was out of bounds")?;
        if section_type == SHT_NOBITS {
            continue;
        }
        let offset = usize::try_from(
            read_u64_le(
                bytes,
                header_offset
                    .checked_add(ELF64_SH_OFFSET)
                    .ok_or("ELF section offset field overflowed")?,
            )
            .ok_or("ELF section offset was out of bounds")?,
        )
        .map_err(|_| "ELF section offset exceeded usize")?;
        let size = usize::try_from(
            read_u64_le(
                bytes,
                header_offset
                    .checked_add(ELF64_SH_SIZE)
                    .ok_or("ELF section size field overflowed")?,
            )
            .ok_or("ELF section size was out of bounds")?,
        )
        .map_err(|_| "ELF section size exceeded usize")?;
        if size == 0 {
            continue;
        }
        let end = offset
            .checked_add(size)
            .ok_or("ELF section file range overflowed")?;
        if end > bytes.len() {
            return Err("ELF section file range was out of bounds".into());
        }
        if offset < segment_end && end > segment_end {
            return Err("an ELF section straddled the relocation boundary".into());
        }
    }

    let old_virtual_end = segment
        .vaddr
        .checked_add(u64::try_from(segment.memsize).map_err(|_| "ELF PT_LOAD size exceeded u64")?)
        .ok_or("ELF PT_LOAD virtual range overflowed")?;
    let new_virtual_end = old_virtual_end
        .checked_add(u64::try_from(growth).map_err(|_| "ELF relocation growth exceeded u64")?)
        .ok_or("expanded ELF PT_LOAD virtual range overflowed")?;
    for index in 0..program_header_count {
        let header_offset =
            program_header_offset(program_headers_offset, program_header_size, index)
                .ok_or("ELF program header offset overflowed")?;
        if header_offset == segment.header_offset {
            continue;
        }

        let fileoff = usize::try_from(
            read_u64_le(
                bytes,
                header_offset
                    .checked_add(ELF64_P_OFFSET)
                    .ok_or("ELF program offset field overflowed")?,
            )
            .ok_or("ELF program offset was out of bounds")?,
        )
        .map_err(|_| "ELF program offset exceeded usize")?;
        let filesize = usize::try_from(
            read_u64_le(
                bytes,
                header_offset
                    .checked_add(ELF64_P_FILESZ)
                    .ok_or("ELF program size field overflowed")?,
            )
            .ok_or("ELF program size was out of bounds")?,
        )
        .map_err(|_| "ELF program size exceeded usize")?;
        if filesize != 0 {
            let file_end = fileoff
                .checked_add(filesize)
                .ok_or("ELF program file range overflowed")?;
            if file_end > bytes.len() {
                return Err("ELF program file range was out of bounds".into());
            }
            if fileoff < bytes.len() && file_end > segment_end {
                return Err("an ELF program header referenced the relocatable file tail".into());
            }
        }

        let program_type = read_u32_le(
            bytes,
            header_offset
                .checked_add(ELF64_P_TYPE)
                .ok_or("ELF program type offset overflowed")?,
        )
        .ok_or("ELF program type was out of bounds")?;
        if program_type != PT_LOAD {
            continue;
        }
        let vaddr = read_u64_le(
            bytes,
            header_offset
                .checked_add(ELF64_P_VADDR)
                .ok_or("ELF program address field overflowed")?,
        )
        .ok_or("ELF program address was out of bounds")?;
        let memsize = read_u64_le(
            bytes,
            header_offset
                .checked_add(ELF64_P_MEMSZ)
                .ok_or("ELF program memory size field overflowed")?,
        )
        .ok_or("ELF program memory size was out of bounds")?;
        let virtual_end = vaddr
            .checked_add(memsize)
            .ok_or("ELF program virtual range overflowed")?;
        if vaddr < new_virtual_end && virtual_end > old_virtual_end {
            return Err("expanded ELF .bun PT_LOAD would overlap another PT_LOAD".into());
        }
    }

    Ok(())
}

fn elf_page_size(bytes: &[u8]) -> Option<usize> {
    match read_u16_le(bytes, ELF64_E_MACHINE)? {
        EM_X86_64 => Some(4 * 1024),
        EM_AARCH64 => Some(64 * 1024),
        _ => None,
    }
}

fn align_up(value: usize, alignment: usize) -> Option<usize> {
    let remainder = value % alignment;
    if remainder == 0 {
        Some(value)
    } else {
        value.checked_add(alignment.checked_sub(remainder)?)
    }
}

fn write_u64_field(
    bytes: &mut [u8],
    offset: usize,
    value: usize,
    field_name: &str,
) -> Result<(), Box<dyn Error>> {
    let end = offset
        .checked_add(size_of::<u64>())
        .ok_or_else(|| format!("{field_name} field overflowed"))?;
    let field = bytes
        .get_mut(offset..end)
        .ok_or_else(|| format!("{field_name} field was out of bounds"))?;
    field.copy_from_slice(
        &u64::try_from(value)
            .map_err(|_| format!("{field_name} exceeded u64"))?
            .to_le_bytes(),
    );
    Ok(())
}

fn clamp_before_range(
    section_start: usize,
    section_end: usize,
    range_start: usize,
    range_end: usize,
    capacity_end: usize,
) -> Option<usize> {
    if range_start < section_end && range_end > section_start {
        None
    } else if range_start >= section_end {
        Some(capacity_end.min(range_start))
    } else {
        Some(capacity_end)
    }
}

fn program_header_offset(table_offset: usize, header_size: usize, index: usize) -> Option<usize> {
    table_offset.checked_add(index.checked_mul(header_size)?)
}

fn section_header_offset(table_offset: usize, header_size: usize, index: usize) -> Option<usize> {
    table_offset.checked_add(index.checked_mul(header_size)?)
}

fn section_bytes(bytes: &[u8], header_offset: usize) -> Option<&[u8]> {
    let offset = usize::try_from(read_u64_le(
        bytes,
        header_offset.checked_add(ELF64_SH_OFFSET)?,
    )?)
    .ok()?;
    let size = usize::try_from(read_u64_le(
        bytes,
        header_offset.checked_add(ELF64_SH_SIZE)?,
    )?)
    .ok()?;
    bytes.get(offset..offset.checked_add(size)?)
}

#[cfg(test)]
mod tests {
    use super::super::container::extract_container_payload;
    use super::super::tests::build_container_payload;
    use super::*;

    #[test]
    fn extracts_length_prefixed_payload_from_elf_bun_section() {
        let payload = build_container_payload(0, b'g');
        let elf = build_elf_with_bun_section(&payload, 64);

        let container = extract_container_payload(&elf)
            .expect("container parsing should not fail")
            .expect("ELF .bun section should be found");

        assert_eq!(container.container_name(), Some(".bun"));
        assert_eq!(container.payload_bytes, payload);
        assert_eq!(
            container.payload_file_offset,
            container.raw_container_file_offset().unwrap() + 8
        );
    }

    #[test]
    fn expands_bun_section_within_existing_load_segment() {
        let elf = build_elf_with_bun_section(b"original", 64);
        let replacement = build_container_payload(0, b'x');

        let repacked = write_bun_section(&elf, &replacement, SectionLengthWidth::U64)
            .expect("replacement should fit");
        let section = find_bun_section(&repacked).expect("repacked section should remain valid");
        let container = extract_container_payload(&repacked)
            .expect("container parsing should not fail")
            .expect("repacked .bun section should be found");

        assert_eq!(repacked.len(), elf.len());
        assert_eq!(section.filesize, size_of::<u64>() + replacement.len());
        assert_eq!(container.payload_bytes, replacement);
        assert!(
            repacked[section.fileoff + section.filesize..section.fileoff + 64]
                .iter()
                .all(|byte| *byte == 0)
        );
    }

    #[test]
    fn relocates_elf_tail_when_bun_section_outgrows_load_segment() {
        let elf = build_elf_with_bun_section(b"original", 64);
        let replacement = build_container_payload(9, b'x');
        let old_section = find_bun_section(&elf).expect("section should exist");
        let old_section_headers_offset =
            usize::try_from(read_u64_le(&elf, ELF64_E_SHOFF).unwrap()).unwrap();
        let old_segment_size =
            usize::try_from(read_u64_le(&elf, ELF_HEADER_SIZE_FOR_TESTS + ELF64_P_FILESZ).unwrap())
                .unwrap();
        let old_names_offset = old_section.fileoff + 64;
        let expected_growth = 4096 - 64;

        let repacked = write_bun_section(&elf, &replacement, SectionLengthWidth::U64)
            .expect("ELF tail should be relocated");
        let section = find_bun_section(&repacked).expect("repacked section should remain valid");
        let new_section_headers_offset =
            usize::try_from(read_u64_le(&repacked, ELF64_E_SHOFF).unwrap()).unwrap();
        let new_names_header = new_section_headers_offset + ELF64_SECTION_HEADER_SIZE;
        let new_names_offset =
            usize::try_from(read_u64_le(&repacked, new_names_header + ELF64_SH_OFFSET).unwrap())
                .unwrap();
        let new_segment_size = usize::try_from(
            read_u64_le(&repacked, ELF_HEADER_SIZE_FOR_TESTS + ELF64_P_FILESZ).unwrap(),
        )
        .unwrap();
        let new_segment_memsize = usize::try_from(
            read_u64_le(&repacked, ELF_HEADER_SIZE_FOR_TESTS + ELF64_P_MEMSZ).unwrap(),
        )
        .unwrap();

        assert_eq!(section.fileoff, old_section.fileoff);
        assert_eq!(section.vaddr, old_section.vaddr);
        assert_eq!(section.filesize, 8 + replacement.len());
        assert_eq!(repacked.len(), elf.len() + expected_growth);
        assert_eq!(
            new_section_headers_offset,
            old_section_headers_offset + expected_growth
        );
        assert_eq!(new_names_offset, old_names_offset + expected_growth);
        assert_eq!(new_segment_size, old_segment_size + expected_growth);
        assert_eq!(new_segment_memsize, new_segment_size);
        assert_eq!(
            &repacked[new_names_offset..new_names_offset + SECTION_NAMES_FOR_TESTS.len()],
            SECTION_NAMES_FOR_TESTS
        );
        assert_eq!(
            extract_container_payload(&repacked)
                .unwrap()
                .unwrap()
                .payload_bytes,
            replacement
        );
    }

    #[test]
    fn uses_aarch64_page_size_for_full_relocation() {
        let elf = build_elf_with_bun_section_for_machine(b"original", 64, EM_AARCH64);
        let replacement = build_container_payload(9, b'x');

        let repacked = write_bun_section(&elf, &replacement, SectionLengthWidth::U64)
            .expect("AArch64 ELF tail should be relocated");

        assert_eq!(repacked.len(), elf.len() + (64 * 1024 - 64));
        assert_eq!(
            extract_container_payload(&repacked)
                .unwrap()
                .unwrap()
                .payload_bytes,
            replacement
        );
    }

    #[test]
    fn can_relocate_an_already_relocated_elf_again() {
        let elf = build_elf_with_bun_section(b"original", 64);
        let first_replacement = build_container_payload(5000, b'a');
        let second_replacement = build_container_payload(9000, b'b');

        let first = write_bun_section(&elf, &first_replacement, SectionLengthWidth::U64)
            .expect("first relocation should succeed");
        let second = write_bun_section(&first, &second_replacement, SectionLengthWidth::U64)
            .expect("second relocation should succeed");

        assert_eq!(first.len(), elf.len() + (8192 - 64));
        assert_eq!(second.len(), first.len() + 4096);
        assert_eq!(
            extract_container_payload(&second)
                .unwrap()
                .unwrap()
                .payload_bytes,
            second_replacement
        );
    }

    #[test]
    fn refuses_to_overwrite_nonzero_load_padding() {
        let mut elf = build_elf_with_bun_section(b"original", 64);
        let section = find_bun_section(&elf).expect("section should exist");
        elf[section.fileoff + section.filesize] = 0xff;

        let error = write_bun_section(&elf, b"original!", SectionLengthWidth::U64)
            .expect_err("non-zero bytes after the section must not be overwritten");

        assert!(
            error
                .to_string()
                .contains("safe .bun capacity (16 bytes; full relocation requires")
        );
    }

    fn build_elf_with_bun_section(payload: &[u8], bun_capacity: usize) -> Vec<u8> {
        build_elf_with_bun_section_for_machine(payload, bun_capacity, EM_X86_64)
    }

    const ELF_HEADER_SIZE_FOR_TESTS: usize = 64;
    const SECTION_NAMES_FOR_TESTS: &[u8] = b"\0.shstrtab\0.bun\0";

    fn build_elf_with_bun_section_for_machine(
        payload: &[u8],
        bun_capacity: usize,
        machine: u16,
    ) -> Vec<u8> {
        const SECTION_COUNT: usize = 3;
        const BASE_VADDR: u64 = 0x0040_0000;

        let page_size = match machine {
            EM_X86_64 => 4 * 1024,
            EM_AARCH64 => 64 * 1024,
            _ => panic!("unsupported test machine"),
        };
        let program_headers_offset = ELF_HEADER_SIZE_FOR_TESTS;
        let bun_offset = page_size;
        let bun_size = 8 + payload.len();
        assert!(bun_size <= bun_capacity);
        let segment_end = bun_offset + bun_capacity;
        let names_offset = segment_end;
        let section_headers_offset = names_offset + SECTION_NAMES_FOR_TESTS.len();
        let mut elf = vec![0; section_headers_offset + SECTION_COUNT * ELF64_SECTION_HEADER_SIZE];

        elf[..4].copy_from_slice(ELF_MAGIC);
        elf[4] = ELF_CLASS_64;
        elf[5] = ELF_DATA_LITTLE_ENDIAN;
        write_u16(&mut elf, ELF64_E_MACHINE, usize::from(machine));
        write_u64(&mut elf, ELF64_E_PHOFF, program_headers_offset);
        write_u64(&mut elf, ELF64_E_SHOFF, section_headers_offset);
        write_u16(&mut elf, 52, ELF_HEADER_SIZE_FOR_TESTS);
        write_u16(&mut elf, ELF64_E_PHENTSIZE, ELF64_PROGRAM_HEADER_SIZE);
        write_u16(&mut elf, ELF64_E_PHNUM, 1);
        write_u16(&mut elf, ELF64_E_SHENTSIZE, ELF64_SECTION_HEADER_SIZE);
        write_u16(&mut elf, ELF64_E_SHNUM, SECTION_COUNT);
        write_u16(&mut elf, ELF64_E_SHSTRNDX, 1);

        write_u32(
            &mut elf,
            program_headers_offset + ELF64_P_TYPE,
            PT_LOAD as usize,
        );
        write_u32(
            &mut elf,
            program_headers_offset + ELF64_P_FLAGS,
            PF_W as usize,
        );
        write_u64(&mut elf, program_headers_offset + ELF64_P_OFFSET, 0);
        write_u64(
            &mut elf,
            program_headers_offset + ELF64_P_VADDR,
            usize::try_from(BASE_VADDR).unwrap(),
        );
        write_u64(
            &mut elf,
            program_headers_offset + ELF64_P_FILESZ,
            segment_end,
        );
        write_u64(
            &mut elf,
            program_headers_offset + ELF64_P_MEMSZ,
            segment_end,
        );

        write_u64(&mut elf, bun_offset, payload.len());
        elf[bun_offset + 8..bun_offset + bun_size].copy_from_slice(payload);
        elf[names_offset..section_headers_offset].copy_from_slice(SECTION_NAMES_FOR_TESTS);

        let names_header = section_headers_offset + ELF64_SECTION_HEADER_SIZE;
        write_u32(&mut elf, names_header, 1);
        write_u64(&mut elf, names_header + 24, names_offset);
        write_u64(&mut elf, names_header + 32, SECTION_NAMES_FOR_TESTS.len());

        let bun_header = names_header + ELF64_SECTION_HEADER_SIZE;
        write_u32(&mut elf, bun_header, 11);
        write_u64(
            &mut elf,
            bun_header + ELF64_SH_ADDR,
            usize::try_from(BASE_VADDR).unwrap() + bun_offset,
        );
        write_u64(&mut elf, bun_header + ELF64_SH_OFFSET, bun_offset);
        write_u64(&mut elf, bun_header + ELF64_SH_SIZE, bun_size);

        elf
    }

    fn write_u16(bytes: &mut [u8], offset: usize, value: usize) {
        bytes[offset..offset + 2].copy_from_slice(&u16::try_from(value).unwrap().to_le_bytes());
    }

    fn write_u32(bytes: &mut [u8], offset: usize, value: usize) {
        bytes[offset..offset + 4].copy_from_slice(&u32::try_from(value).unwrap().to_le_bytes());
    }

    fn write_u64(bytes: &mut [u8], offset: usize, value: usize) {
        bytes[offset..offset + 8].copy_from_slice(&u64::try_from(value).unwrap().to_le_bytes());
    }
}
