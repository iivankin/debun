use std::{error::Error, mem::size_of};

use crate::binary::{read_fixed_string, read_u32_le, read_u64_le};

use super::layout::{
    BUN_SEGMENT_NAMES, LC_SEGMENT, LC_SEGMENT_64, MACH_O_MAGIC_32, MACH_O_MAGIC_64,
    SectionLengthWidth,
};

const MACH_HEADER_32_SIZE: usize = 28;
const MACH_HEADER_64_SIZE: usize = 32;
const SEGMENT_COMMAND_64_SIZE: usize = 72;
const SECTION_64_SIZE: usize = 80;
const BUN_ALIGNMENT: usize = 16 * 1024;

const LC_SYMTAB: u32 = 0x2;
const LC_DYSYMTAB: u32 = 0xb;
const LC_TWOLEVEL_HINTS: u32 = 0x16;
const LC_CODE_SIGNATURE: u32 = 0x1d;
const LC_SEGMENT_SPLIT_INFO: u32 = 0x1e;
const LC_ENCRYPTION_INFO: u32 = 0x21;
const LC_DYLD_INFO: u32 = 0x22;
const LC_DYLD_INFO_ONLY: u32 = 0x8000_0022;
const LC_FUNCTION_STARTS: u32 = 0x26;
const LC_DATA_IN_CODE: u32 = 0x29;
const LC_DYLIB_CODE_SIGN_DRS: u32 = 0x2b;
const LC_ENCRYPTION_INFO_64: u32 = 0x2c;
const LC_LINKER_OPTIMIZATION_HINT: u32 = 0x2e;
const LC_NOTE: u32 = 0x31;
const LC_DYLD_EXPORTS_TRIE: u32 = 0x8000_0033;
const LC_DYLD_CHAINED_FIXUPS: u32 = 0x8000_0034;
const LC_FILESET_ENTRY: u32 = 0x8000_0035;
const LC_ATOM_INFO: u32 = 0x36;
const LC_FUNCTION_VARIANTS: u32 = 0x37;
const LC_FUNCTION_VARIANT_FIXUPS: u32 = 0x38;
const LC_LAZY_LOAD_DYLIB_INFO: u32 = 0x3a;

const SEGMENT_VMADDR: usize = 24;
const SEGMENT_VMSIZE: usize = 32;
const SEGMENT_FILEOFF: usize = 40;
const SEGMENT_FILESIZE: usize = 48;
const SEGMENT_NSECTS: usize = 64;

const SECTION_ADDR: usize = 32;
const SECTION_SIZE: usize = 40;
const SECTION_OFFSET: usize = 48;

#[derive(Debug, Clone, Copy)]
pub(super) struct MachoBunSection {
    pub(super) name: &'static str,
    pub(super) fileoff: usize,
    pub(super) filesize: usize,
    segment_header_offset: Option<usize>,
    section_header_offset: Option<usize>,
    vmaddr: u64,
    vmsize: u64,
}

#[derive(Debug, Clone, Copy)]
struct LoadCommand {
    command: u32,
    offset: usize,
    size: usize,
}

#[derive(Debug, Clone, Copy)]
struct LinkeditSegment {
    header_offset: usize,
    fileoff: usize,
    filesize: usize,
    vmaddr: u64,
}

#[derive(Debug, Clone, Copy)]
struct FileTailShift {
    start: usize,
    growth: usize,
}

pub(super) fn is_macho64(bytes: &[u8]) -> bool {
    read_u32_le(bytes, 0) == Some(MACH_O_MAGIC_64)
}

pub(super) fn find_bun_section(bytes: &[u8]) -> Option<MachoBunSection> {
    let magic = read_u32_le(bytes, 0)?;
    let is_64 = match magic {
        MACH_O_MAGIC_64 => true,
        MACH_O_MAGIC_32 => false,
        _ => return None,
    };

    let header_size = if is_64 {
        MACH_HEADER_64_SIZE
    } else {
        MACH_HEADER_32_SIZE
    };
    let commands = load_commands(bytes, header_size)?;

    for command in commands {
        match command.command {
            LC_SEGMENT_64 if is_64 => {
                let segname = read_fixed_string(bytes, command.offset.checked_add(8)?, 16)?;
                if !BUN_SEGMENT_NAMES.contains(&segname.as_str())
                    || command.size < SEGMENT_COMMAND_64_SIZE
                {
                    continue;
                }

                let fileoff = usize::try_from(read_u64_le(
                    bytes,
                    command.offset.checked_add(SEGMENT_FILEOFF)?,
                )?)
                .ok()?;
                let filesize = usize::try_from(read_u64_le(
                    bytes,
                    command.offset.checked_add(SEGMENT_FILESIZE)?,
                )?)
                .ok()?;
                bytes.get(fileoff..fileoff.checked_add(filesize)?)?;

                let section_header_offset = find_bun_section_header(bytes, command)?;
                return Some(MachoBunSection {
                    name: canonical_bun_segment_name(&segname),
                    fileoff,
                    filesize,
                    segment_header_offset: Some(command.offset),
                    section_header_offset,
                    vmaddr: read_u64_le(bytes, command.offset.checked_add(SEGMENT_VMADDR)?)?,
                    vmsize: read_u64_le(bytes, command.offset.checked_add(SEGMENT_VMSIZE)?)?,
                });
            }
            LC_SEGMENT if !is_64 => {
                let segname = read_fixed_string(bytes, command.offset.checked_add(8)?, 16)?;
                if !BUN_SEGMENT_NAMES.contains(&segname.as_str()) {
                    continue;
                }
                let fileoff =
                    usize::try_from(read_u32_le(bytes, command.offset.checked_add(32)?)?).ok()?;
                let filesize =
                    usize::try_from(read_u32_le(bytes, command.offset.checked_add(36)?)?).ok()?;
                bytes.get(fileoff..fileoff.checked_add(filesize)?)?;
                return Some(MachoBunSection {
                    name: canonical_bun_segment_name(&segname),
                    fileoff,
                    filesize,
                    segment_header_offset: None,
                    section_header_offset: None,
                    vmaddr: 0,
                    vmsize: 0,
                });
            }
            _ => {}
        }
    }

    None
}

pub(super) fn write_bun_section(
    bytes: &[u8],
    payload: &[u8],
    length_width: SectionLengthWidth,
) -> Result<Vec<u8>, Box<dyn Error>> {
    if !is_macho64(bytes) {
        return Err("full Mach-O .bun growth requires a 64-bit little-endian binary".into());
    }

    let section = find_bun_section(bytes).ok_or("Mach-O Bun segment was missing")?;
    let segment_header_offset = section
        .segment_header_offset
        .ok_or("Mach-O Bun segment header was missing")?;
    let section_header_offset = section
        .section_header_offset
        .ok_or("Mach-O __BUN,__bun section header was missing")?;
    let required_len = length_width
        .size()
        .checked_add(payload.len())
        .ok_or("Mach-O Bun payload size overflowed")?;

    validate_bun_mapping(bytes, section, section_header_offset)?;
    if required_len <= section.filesize {
        let mut out = bytes.to_vec();
        write_payload(
            &mut out,
            section.fileoff,
            section.filesize,
            section_header_offset,
            payload,
            length_width,
        )?;
        return Ok(out);
    }

    if !section.fileoff.is_multiple_of(BUN_ALIGNMENT)
        || !section.filesize.is_multiple_of(BUN_ALIGNMENT)
        || section.vmsize != u64::try_from(section.filesize)?
    {
        return Err("Mach-O Bun segment did not have Bun's expected 16 KiB layout".into());
    }

    let new_capacity =
        align_up(required_len, BUN_ALIGNMENT).ok_or("expanded Mach-O Bun size overflowed")?;
    let growth = new_capacity
        .checked_sub(section.filesize)
        .ok_or("expanded Mach-O Bun size did not grow")?;
    let old_bun_end = section
        .fileoff
        .checked_add(section.filesize)
        .ok_or("Mach-O Bun segment range overflowed")?;
    let new_bun_end = old_bun_end
        .checked_add(growth)
        .ok_or("expanded Mach-O Bun segment range overflowed")?;
    let new_file_len = bytes
        .len()
        .checked_add(growth)
        .ok_or("expanded Mach-O file size overflowed")?;

    let commands =
        load_commands(bytes, MACH_HEADER_64_SIZE).ok_or("invalid Mach-O load command table")?;
    let linkedit =
        find_linkedit_segment(bytes, &commands).ok_or("Mach-O __LINKEDIT segment was missing")?;
    validate_growth_layout(bytes, section, linkedit, &commands, old_bun_end)?;

    // Preserve the compiled-in pointer to `__BUN` by growing that segment in
    // place. Everything from __LINKEDIT onward moves as one file tail.
    let mut out = bytes.to_vec();
    out.resize(new_file_len, 0);
    out.copy_within(old_bun_end..bytes.len(), new_bun_end);
    out[old_bun_end..new_bun_end].fill(0);

    write_u64_field(
        &mut out,
        segment_header_offset + SEGMENT_VMSIZE,
        new_capacity,
        "Mach-O Bun segment virtual size",
    )?;
    write_u64_field(
        &mut out,
        segment_header_offset + SEGMENT_FILESIZE,
        new_capacity,
        "Mach-O Bun segment file size",
    )?;
    write_u64_field(
        &mut out,
        linkedit.header_offset + SEGMENT_VMADDR,
        usize::try_from(
            linkedit
                .vmaddr
                .checked_add(u64::try_from(growth)?)
                .ok_or("Mach-O __LINKEDIT virtual address overflowed")?,
        )?,
        "Mach-O __LINKEDIT virtual address",
    )?;
    write_u64_field(
        &mut out,
        linkedit.header_offset + SEGMENT_FILEOFF,
        linkedit
            .fileoff
            .checked_add(growth)
            .ok_or("Mach-O __LINKEDIT file offset overflowed")?,
        "Mach-O __LINKEDIT file offset",
    )?;
    shift_linkedit_offsets(
        bytes,
        &mut out,
        &commands,
        old_bun_end,
        linkedit
            .fileoff
            .checked_add(linkedit.filesize)
            .ok_or("Mach-O __LINKEDIT range overflowed")?,
        growth,
    )?;
    write_payload(
        &mut out,
        section.fileoff,
        new_capacity,
        section_header_offset,
        payload,
        length_width,
    )?;
    Ok(out)
}

fn canonical_bun_segment_name(name: &str) -> &'static str {
    if name == "__bun" { "__bun" } else { "__BUN" }
}

fn load_commands(bytes: &[u8], header_size: usize) -> Option<Vec<LoadCommand>> {
    let command_count = usize::try_from(read_u32_le(bytes, 16)?).ok()?;
    let commands_size = usize::try_from(read_u32_le(bytes, 20)?).ok()?;
    let commands_end = header_size.checked_add(commands_size)?;
    bytes.get(header_size..commands_end)?;

    let mut commands = Vec::with_capacity(command_count);
    let mut cursor = header_size;
    for _ in 0..command_count {
        let command = read_u32_le(bytes, cursor)?;
        let size = usize::try_from(read_u32_le(bytes, cursor.checked_add(4)?)?).ok()?;
        let end = cursor.checked_add(size)?;
        if size < 8 || end > commands_end {
            return None;
        }
        commands.push(LoadCommand {
            command,
            offset: cursor,
            size,
        });
        cursor = end;
    }
    (cursor == commands_end).then_some(commands)
}

fn find_bun_section_header(bytes: &[u8], segment: LoadCommand) -> Option<Option<usize>> {
    let section_count = usize::try_from(read_u32_le(
        bytes,
        segment.offset.checked_add(SEGMENT_NSECTS)?,
    )?)
    .ok()?;
    let sections_size = section_count.checked_mul(SECTION_64_SIZE)?;
    let sections_start = segment.offset.checked_add(SEGMENT_COMMAND_64_SIZE)?;
    let sections_end = sections_start.checked_add(sections_size)?;
    if sections_end > segment.offset.checked_add(segment.size)? {
        return None;
    }

    for index in 0..section_count {
        let offset = sections_start.checked_add(index.checked_mul(SECTION_64_SIZE)?)?;
        if read_fixed_string(bytes, offset, 16)?.as_str() == "__bun" {
            return Some(Some(offset));
        }
    }
    Some(None)
}

fn validate_bun_mapping(
    bytes: &[u8],
    section: MachoBunSection,
    section_header_offset: usize,
) -> Result<(), Box<dyn Error>> {
    let load_commands_end = MACH_HEADER_64_SIZE
        .checked_add(usize::try_from(
            read_u32_le(bytes, 20).ok_or("Mach-O load command size was missing")?,
        )?)
        .ok_or("Mach-O load command range overflowed")?;
    if section.fileoff < load_commands_end {
        return Err("Mach-O Bun segment overlapped the load commands".into());
    }
    let section_fileoff = usize::try_from(
        read_u32_le(bytes, section_header_offset + SECTION_OFFSET)
            .ok_or("Mach-O Bun section offset was missing")?,
    )?;
    let section_vmaddr = read_u64_le(bytes, section_header_offset + SECTION_ADDR)
        .ok_or("Mach-O Bun section address was missing")?;
    if section_fileoff != section.fileoff || section_vmaddr != section.vmaddr {
        return Err("Mach-O Bun section did not match its containing segment".into());
    }
    Ok(())
}

fn find_linkedit_segment(bytes: &[u8], commands: &[LoadCommand]) -> Option<LinkeditSegment> {
    let mut found = None;
    for command in commands {
        if command.command != LC_SEGMENT_64
            || read_fixed_string(bytes, command.offset.checked_add(8)?, 16)? != "__LINKEDIT"
        {
            continue;
        }
        if found.is_some() {
            return None;
        }
        found = Some(LinkeditSegment {
            header_offset: command.offset,
            fileoff: usize::try_from(read_u64_le(
                bytes,
                command.offset.checked_add(SEGMENT_FILEOFF)?,
            )?)
            .ok()?,
            filesize: usize::try_from(read_u64_le(
                bytes,
                command.offset.checked_add(SEGMENT_FILESIZE)?,
            )?)
            .ok()?,
            vmaddr: read_u64_le(bytes, command.offset.checked_add(SEGMENT_VMADDR)?)?,
        });
    }
    found
}

fn validate_growth_layout(
    bytes: &[u8],
    bun: MachoBunSection,
    linkedit: LinkeditSegment,
    commands: &[LoadCommand],
    old_bun_end: usize,
) -> Result<(), Box<dyn Error>> {
    let expected_linkedit_vmaddr = bun
        .vmaddr
        .checked_add(bun.vmsize)
        .ok_or("Mach-O Bun virtual range overflowed")?;
    if linkedit.fileoff != old_bun_end || linkedit.vmaddr != expected_linkedit_vmaddr {
        return Err("Mach-O __LINKEDIT was not directly after the Bun segment".into());
    }
    let linkedit_end = linkedit
        .fileoff
        .checked_add(linkedit.filesize)
        .ok_or("Mach-O __LINKEDIT range overflowed")?;
    if linkedit_end > bytes.len() {
        return Err("Mach-O __LINKEDIT range was out of bounds".into());
    }

    for command in commands {
        if command.command != LC_SEGMENT_64
            || bun.segment_header_offset == Some(command.offset)
            || command.offset == linkedit.header_offset
        {
            continue;
        }
        let fileoff = usize::try_from(
            read_u64_le(bytes, command.offset + SEGMENT_FILEOFF)
                .ok_or("Mach-O segment file offset was missing")?,
        )?;
        let filesize = usize::try_from(
            read_u64_le(bytes, command.offset + SEGMENT_FILESIZE)
                .ok_or("Mach-O segment file size was missing")?,
        )?;
        if filesize != 0
            && fileoff
                .checked_add(filesize)
                .ok_or("Mach-O segment range overflowed")?
                > bun.fileoff
        {
            return Err("another Mach-O segment overlapped the Bun growth boundary".into());
        }
    }
    Ok(())
}

fn shift_linkedit_offsets(
    original: &[u8],
    out: &mut [u8],
    commands: &[LoadCommand],
    range_start: usize,
    range_end: usize,
    growth: usize,
) -> Result<(), Box<dyn Error>> {
    let tail_shift = FileTailShift {
        start: range_start,
        growth,
    };
    for command in commands {
        match command.command {
            LC_SYMTAB => {
                shift_command_u32(original, out, *command, 8, range_start, range_end, growth)?;
                shift_command_u32(original, out, *command, 16, range_start, range_end, growth)?;
            }
            LC_DYSYMTAB => {
                for field in [32, 40, 48, 56, 64, 72] {
                    shift_command_u32(
                        original,
                        out,
                        *command,
                        field,
                        range_start,
                        range_end,
                        growth,
                    )?;
                }
            }
            LC_CODE_SIGNATURE
            | LC_SEGMENT_SPLIT_INFO
            | LC_FUNCTION_STARTS
            | LC_DATA_IN_CODE
            | LC_DYLIB_CODE_SIGN_DRS
            | LC_LINKER_OPTIMIZATION_HINT
            | LC_DYLD_EXPORTS_TRIE
            | LC_DYLD_CHAINED_FIXUPS
            | LC_ATOM_INFO
            | LC_FUNCTION_VARIANTS
            | LC_FUNCTION_VARIANT_FIXUPS
            | LC_LAZY_LOAD_DYLIB_INFO
            | LC_TWOLEVEL_HINTS => {
                shift_command_u32(original, out, *command, 8, range_start, range_end, growth)?;
            }
            LC_DYLD_INFO | LC_DYLD_INFO_ONLY => {
                for field in [8, 16, 24, 32, 40] {
                    shift_command_u32(
                        original,
                        out,
                        *command,
                        field,
                        range_start,
                        range_end,
                        growth,
                    )?;
                }
            }
            LC_NOTE => {
                shift_command_u64_range(
                    original,
                    out,
                    *command,
                    24,
                    32,
                    tail_shift,
                    "Mach-O note",
                )?;
            }
            LC_ENCRYPTION_INFO | LC_ENCRYPTION_INFO_64 => {
                validate_command_field(*command, 16, size_of::<u32>())?;
                let cryptid_offset = command
                    .offset
                    .checked_add(16)
                    .ok_or("Mach-O encryption command offset overflowed")?;
                if read_u32_le(original, cryptid_offset)
                    .ok_or("Mach-O encryption identifier was missing")?
                    != 0
                {
                    return Err("encrypted Mach-O binaries cannot be repacked safely".into());
                }
                shift_command_u32_range(
                    original,
                    out,
                    *command,
                    8,
                    12,
                    tail_shift,
                    "Mach-O encryption range",
                )?;
            }
            LC_FILESET_ENTRY => {
                return Err(
                    "Mach-O fileset entries are unsupported during Bun segment growth".into(),
                );
            }
            _ => {}
        }
    }
    Ok(())
}

fn shift_command_u32_range(
    original: &[u8],
    out: &mut [u8],
    command: LoadCommand,
    offset_field: usize,
    size_field: usize,
    tail_shift: FileTailShift,
    name: &str,
) -> Result<(), Box<dyn Error>> {
    validate_command_field(command, offset_field, size_of::<u32>())?;
    validate_command_field(command, size_field, size_of::<u32>())?;
    let field_offset = command
        .offset
        .checked_add(offset_field)
        .ok_or("Mach-O load command field offset overflowed")?;
    let size_offset = command
        .offset
        .checked_add(size_field)
        .ok_or("Mach-O load command size offset overflowed")?;
    let value = usize::try_from(
        read_u32_le(original, field_offset).ok_or("Mach-O file offset was missing")?,
    )?;
    let size =
        usize::try_from(read_u32_le(original, size_offset).ok_or("Mach-O file size was missing")?)?;
    if let Some(shifted) = shifted_file_range(original, value, size, tail_shift, name)? {
        write_u32_field(out, field_offset, shifted, name)?;
    }
    Ok(())
}

fn shift_command_u64_range(
    original: &[u8],
    out: &mut [u8],
    command: LoadCommand,
    offset_field: usize,
    size_field: usize,
    tail_shift: FileTailShift,
    name: &str,
) -> Result<(), Box<dyn Error>> {
    validate_command_field(command, offset_field, size_of::<u64>())?;
    validate_command_field(command, size_field, size_of::<u64>())?;
    let field_offset = command
        .offset
        .checked_add(offset_field)
        .ok_or("Mach-O load command field offset overflowed")?;
    let size_offset = command
        .offset
        .checked_add(size_field)
        .ok_or("Mach-O load command size offset overflowed")?;
    let value = usize::try_from(
        read_u64_le(original, field_offset).ok_or("Mach-O file offset was missing")?,
    )?;
    let size =
        usize::try_from(read_u64_le(original, size_offset).ok_or("Mach-O file size was missing")?)?;
    if let Some(shifted) = shifted_file_range(original, value, size, tail_shift, name)? {
        write_u64_field(out, field_offset, shifted, name)?;
    }
    Ok(())
}

fn shifted_file_range(
    original: &[u8],
    value: usize,
    size: usize,
    tail_shift: FileTailShift,
    name: &str,
) -> Result<Option<usize>, Box<dyn Error>> {
    if value == 0 || size == 0 {
        return Ok(None);
    }
    let end = value
        .checked_add(size)
        .ok_or_else(|| format!("{name} overflowed"))?;
    if end > original.len() {
        return Err(format!("{name} was out of bounds").into());
    }
    if value < tail_shift.start {
        if end > tail_shift.start {
            return Err(format!("{name} crossed the Bun growth boundary").into());
        }
        return Ok(None);
    }
    Ok(Some(
        value
            .checked_add(tail_shift.growth)
            .ok_or_else(|| format!("{name} offset overflowed"))?,
    ))
}

fn validate_command_field(
    command: LoadCommand,
    relative_offset: usize,
    size: usize,
) -> Result<(), Box<dyn Error>> {
    if relative_offset
        .checked_add(size)
        .is_none_or(|end| end > command.size)
    {
        return Err("Mach-O load command was shorter than expected".into());
    }
    Ok(())
}

fn shift_command_u32(
    original: &[u8],
    out: &mut [u8],
    command: LoadCommand,
    relative_offset: usize,
    range_start: usize,
    range_end: usize,
    growth: usize,
) -> Result<(), Box<dyn Error>> {
    validate_command_field(command, relative_offset, size_of::<u32>())?;
    let field_offset = command
        .offset
        .checked_add(relative_offset)
        .ok_or("Mach-O load command field offset overflowed")?;
    let value = usize::try_from(
        read_u32_le(original, field_offset).ok_or("Mach-O linkedit offset was missing")?,
    )?;
    if value == 0 {
        return Ok(());
    }
    if value < range_start || value > range_end {
        return Err("Mach-O linkedit offset was outside __LINKEDIT".into());
    }
    write_u32_field(
        out,
        field_offset,
        value
            .checked_add(growth)
            .ok_or("Mach-O linkedit offset overflowed")?,
        "Mach-O linkedit offset",
    )
}

fn write_payload(
    out: &mut [u8],
    fileoff: usize,
    capacity: usize,
    section_header_offset: usize,
    payload: &[u8],
    length_width: SectionLengthWidth,
) -> Result<(), Box<dyn Error>> {
    let required_len = length_width
        .size()
        .checked_add(payload.len())
        .ok_or("Mach-O Bun payload size overflowed")?;
    let end = fileoff
        .checked_add(capacity)
        .ok_or("Mach-O Bun segment range overflowed")?;
    let payload_start = fileoff
        .checked_add(length_width.size())
        .ok_or("Mach-O Bun payload offset overflowed")?;
    let payload_end = payload_start
        .checked_add(payload.len())
        .ok_or("Mach-O Bun payload range overflowed")?;
    if required_len > capacity || out.get(fileoff..end).is_none() {
        return Err("Mach-O Bun payload did not fit its prepared segment".into());
    }

    length_width.write(&mut out[fileoff..payload_start], payload.len())?;
    out[payload_start..payload_end].copy_from_slice(payload);
    out[payload_end..end].fill(0);
    write_u64_field(
        out,
        section_header_offset + SECTION_SIZE,
        required_len,
        "Mach-O Bun section size",
    )
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
    let field = bytes
        .get_mut(
            offset
                ..offset
                    .checked_add(size_of::<u32>())
                    .ok_or("field overflow")?,
        )
        .ok_or_else(|| format!("{name} field was out of bounds"))?;
    field.copy_from_slice(&u32::try_from(value)?.to_le_bytes());
    Ok(())
}

fn write_u64_field(
    bytes: &mut [u8],
    offset: usize,
    value: usize,
    name: &str,
) -> Result<(), Box<dyn Error>> {
    let field = bytes
        .get_mut(
            offset
                ..offset
                    .checked_add(size_of::<u64>())
                    .ok_or("field overflow")?,
        )
        .ok_or_else(|| format!("{name} field was out of bounds"))?;
    field.copy_from_slice(&u64::try_from(value)?.to_le_bytes());
    Ok(())
}

#[cfg(test)]
#[path = "macho_tests.rs"]
mod tests;
