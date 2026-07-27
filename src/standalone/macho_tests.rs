use super::super::container::extract_container_payload;
use super::super::tests::build_container_payload;
use super::*;

const BUN_SEGMENT_OFFSET: usize = MACH_HEADER_64_SIZE;
const BUN_COMMAND_SIZE: usize = SEGMENT_COMMAND_64_SIZE + SECTION_64_SIZE;
const LINKEDIT_SEGMENT_OFFSET: usize = BUN_SEGMENT_OFFSET + BUN_COMMAND_SIZE;
const SYMTAB_OFFSET: usize = LINKEDIT_SEGMENT_OFFSET + SEGMENT_COMMAND_64_SIZE;
const DYSYMTAB_OFFSET: usize = SYMTAB_OFFSET + 24;
const FUNCTION_STARTS_OFFSET: usize = DYSYMTAB_OFFSET + 80;
const CODE_SIGNATURE_OFFSET: usize = FUNCTION_STARTS_OFFSET + 16;
const ATOM_INFO_OFFSET: usize = CODE_SIGNATURE_OFFSET + 16;
const NOTE_OFFSET: usize = ATOM_INFO_OFFSET + 16;
const LOAD_COMMANDS_END: usize = NOTE_OFFSET + 40;
const BUN_FILEOFF: usize = BUN_ALIGNMENT;
const ORIGINAL_CAPACITY: usize = BUN_ALIGNMENT;
const LINKEDIT_FILEOFF: usize = BUN_FILEOFF + ORIGINAL_CAPACITY;
const LINKEDIT_SIZE: usize = 0x200;
const BUN_VMADDR: u64 = 0x1_0000_4000;

#[test]
fn relocates_linkedit_when_bun_segment_grows() {
    let original = build_macho(b"original");
    let replacement = build_container_payload(20_000, b'x');
    let old_tail = original[LINKEDIT_FILEOFF..].to_vec();

    let repacked = write_bun_section(&original, &replacement, SectionLengthWidth::U64)
        .expect("Mach-O Bun segment should be expanded");
    let section = find_bun_section(&repacked).expect("Bun segment should remain discoverable");
    let expected_capacity = 2 * BUN_ALIGNMENT;
    let growth = BUN_ALIGNMENT;

    assert_eq!(repacked.len(), original.len() + growth);
    assert_eq!(section.fileoff, BUN_FILEOFF);
    assert_eq!(section.filesize, expected_capacity);
    assert_eq!(
        read_u64_le(&repacked, BUN_SEGMENT_OFFSET + SEGMENT_VMSIZE),
        Some(u64::try_from(expected_capacity).unwrap())
    );
    assert_eq!(
        read_u64_le(&repacked, LINKEDIT_SEGMENT_OFFSET + SEGMENT_FILEOFF),
        Some(u64::try_from(LINKEDIT_FILEOFF + growth).unwrap())
    );
    assert_eq!(
        read_u64_le(&repacked, LINKEDIT_SEGMENT_OFFSET + SEGMENT_VMADDR),
        Some(BUN_VMADDR + u64::try_from(expected_capacity).unwrap())
    );
    assert_eq!(
        read_u32_le(&repacked, SYMTAB_OFFSET + 8),
        Some(u32::try_from(LINKEDIT_FILEOFF + growth).unwrap())
    );
    assert_eq!(
        read_u32_le(&repacked, FUNCTION_STARTS_OFFSET + 8),
        Some(u32::try_from(LINKEDIT_FILEOFF + growth + 0xc0).unwrap())
    );
    assert_eq!(
        read_u32_le(&repacked, ATOM_INFO_OFFSET + 8),
        Some(u32::try_from(LINKEDIT_FILEOFF + growth + 0x180).unwrap())
    );
    assert_eq!(
        read_u64_le(&repacked, NOTE_OFFSET + 24),
        Some(u64::try_from(LINKEDIT_FILEOFF + growth + 0x190).unwrap())
    );
    assert_eq!(&repacked[LINKEDIT_FILEOFF + growth..], old_tail.as_slice());
    assert_eq!(
        extract_container_payload(&repacked)
            .unwrap()
            .unwrap()
            .payload_bytes,
        replacement
    );
}

#[test]
fn rejects_fileset_entries_during_growth() {
    let mut original = build_macho(b"original");
    write_command(&mut original, NOTE_OFFSET, LC_FILESET_ENTRY, 40);
    let replacement = build_container_payload(20_000, b'x');

    let error = write_bun_section(&original, &replacement, SectionLengthWidth::U64)
        .expect_err("fileset entries need nested Mach-O relocation");

    assert!(error.to_string().contains("fileset"));
}

#[test]
fn rejects_encrypted_macho_during_growth() {
    let mut original = build_macho(b"original");
    write_command(&mut original, NOTE_OFFSET, LC_ENCRYPTION_INFO_64, 40);
    write_u32(&mut original, NOTE_OFFSET + 8, LINKEDIT_FILEOFF);
    write_u32(&mut original, NOTE_OFFSET + 12, 0x10);
    write_u32(&mut original, NOTE_OFFSET + 16, 1);
    let replacement = build_container_payload(20_000, b'x');

    let error = write_bun_section(&original, &replacement, SectionLengthWidth::U64)
        .expect_err("encrypted Mach-O contents cannot be relocated safely");

    assert!(error.to_string().contains("encrypted"));
}

#[test]
fn rejects_a_bun_segment_that_overlaps_load_commands() {
    let mut original = build_macho(b"original");
    write_u64(
        &mut original,
        BUN_SEGMENT_OFFSET + SEGMENT_FILEOFF,
        MACH_HEADER_64_SIZE,
    );
    write_u32(
        &mut original,
        BUN_SEGMENT_OFFSET + SEGMENT_COMMAND_64_SIZE + SECTION_OFFSET,
        MACH_HEADER_64_SIZE,
    );
    let replacement = build_container_payload(32, b'x');

    let error = write_bun_section(&original, &replacement, SectionLengthWidth::U64)
        .expect_err("load commands must not be overwritten");

    assert!(error.to_string().contains("load commands"));
}

#[test]
fn can_grow_an_already_expanded_macho_again() {
    let original = build_macho(b"original");
    let first_payload = build_container_payload(20_000, b'a');
    let second_payload = build_container_payload(40_000, b'b');

    let first = write_bun_section(&original, &first_payload, SectionLengthWidth::U64)
        .expect("first growth should succeed");
    let second = write_bun_section(&first, &second_payload, SectionLengthWidth::U64)
        .expect("second growth should succeed");

    assert_eq!(first.len(), original.len() + BUN_ALIGNMENT);
    assert_eq!(second.len(), first.len() + BUN_ALIGNMENT);
    assert_eq!(
        extract_container_payload(&second)
            .unwrap()
            .unwrap()
            .payload_bytes,
        second_payload
    );
}

#[test]
fn preserves_legacy_u32_length_prefix() {
    let original = build_macho_with_width(b"original", SectionLengthWidth::U32);
    let replacement = build_container_payload(20_000, b'x');

    let repacked = write_bun_section(&original, &replacement, SectionLengthWidth::U32)
        .expect("legacy Mach-O Bun segment should be expanded");
    let container = extract_container_payload(&repacked)
        .unwrap()
        .expect("repacked __BUN section should be found");

    assert_eq!(
        container.section_length_width(),
        Some(SectionLengthWidth::U32)
    );
    assert_eq!(container.payload_bytes, replacement);
    assert_eq!(
        read_u32_le(&repacked, BUN_FILEOFF),
        Some(u32::try_from(replacement.len()).unwrap())
    );
}

fn build_macho(payload: &[u8]) -> Vec<u8> {
    build_macho_with_width(payload, SectionLengthWidth::U64)
}

fn build_macho_with_width(payload: &[u8], length_width: SectionLengthWidth) -> Vec<u8> {
    let mut bytes = vec![0; LINKEDIT_FILEOFF + LINKEDIT_SIZE];
    write_u32(&mut bytes, 0, usize::try_from(MACH_O_MAGIC_64).unwrap());
    write_u32(&mut bytes, 16, 8);
    write_u32(&mut bytes, 20, LOAD_COMMANDS_END - MACH_HEADER_64_SIZE);

    write_segment(
        &mut bytes,
        BUN_SEGMENT_OFFSET,
        "__BUN",
        BUN_VMADDR,
        ORIGINAL_CAPACITY,
        BUN_FILEOFF,
        ORIGINAL_CAPACITY,
        1,
        BUN_COMMAND_SIZE,
    );
    let section_offset = BUN_SEGMENT_OFFSET + SEGMENT_COMMAND_64_SIZE;
    write_name(&mut bytes, section_offset, "__bun");
    write_name(&mut bytes, section_offset + 16, "__BUN");
    write_u64(
        &mut bytes,
        section_offset + SECTION_ADDR,
        usize::try_from(BUN_VMADDR).unwrap(),
    );
    write_u64(
        &mut bytes,
        section_offset + SECTION_SIZE,
        length_width.size() + payload.len(),
    );
    write_u32(&mut bytes, section_offset + SECTION_OFFSET, BUN_FILEOFF);

    write_segment(
        &mut bytes,
        LINKEDIT_SEGMENT_OFFSET,
        "__LINKEDIT",
        BUN_VMADDR + u64::try_from(ORIGINAL_CAPACITY).unwrap(),
        LINKEDIT_SIZE,
        LINKEDIT_FILEOFF,
        LINKEDIT_SIZE,
        0,
        SEGMENT_COMMAND_64_SIZE,
    );
    write_command(&mut bytes, SYMTAB_OFFSET, LC_SYMTAB, 24);
    write_u32(&mut bytes, SYMTAB_OFFSET + 8, LINKEDIT_FILEOFF);
    write_u32(&mut bytes, SYMTAB_OFFSET + 16, LINKEDIT_FILEOFF + 0x40);

    write_command(&mut bytes, DYSYMTAB_OFFSET, LC_DYSYMTAB, 80);
    write_u32(&mut bytes, DYSYMTAB_OFFSET + 56, LINKEDIT_FILEOFF + 0x80);

    write_command(&mut bytes, FUNCTION_STARTS_OFFSET, LC_FUNCTION_STARTS, 16);
    write_u32(
        &mut bytes,
        FUNCTION_STARTS_OFFSET + 8,
        LINKEDIT_FILEOFF + 0xc0,
    );
    write_u32(&mut bytes, FUNCTION_STARTS_OFFSET + 12, 0x20);

    write_command(&mut bytes, CODE_SIGNATURE_OFFSET, LC_CODE_SIGNATURE, 16);
    write_u32(
        &mut bytes,
        CODE_SIGNATURE_OFFSET + 8,
        LINKEDIT_FILEOFF + 0x100,
    );
    write_u32(&mut bytes, CODE_SIGNATURE_OFFSET + 12, 0x100);

    write_command(&mut bytes, ATOM_INFO_OFFSET, LC_ATOM_INFO, 16);
    write_u32(&mut bytes, ATOM_INFO_OFFSET + 8, LINKEDIT_FILEOFF + 0x180);
    write_u32(&mut bytes, ATOM_INFO_OFFSET + 12, 0x10);

    write_command(&mut bytes, NOTE_OFFSET, LC_NOTE, 40);
    write_name(&mut bytes, NOTE_OFFSET + 8, "debun");
    write_u64(&mut bytes, NOTE_OFFSET + 24, LINKEDIT_FILEOFF + 0x190);
    write_u64(&mut bytes, NOTE_OFFSET + 32, 0x10);

    length_width
        .write(&mut bytes[BUN_FILEOFF..], payload.len())
        .unwrap();
    let payload_start = BUN_FILEOFF + length_width.size();
    bytes[payload_start..payload_start + payload.len()].copy_from_slice(payload);
    for (index, byte) in bytes[LINKEDIT_FILEOFF..].iter_mut().enumerate() {
        *byte = u8::try_from(index % 251).unwrap();
    }
    bytes
}

#[expect(clippy::too_many_arguments)]
fn write_segment(
    bytes: &mut [u8],
    offset: usize,
    name: &str,
    vmaddr: u64,
    vmsize: usize,
    fileoff: usize,
    filesize: usize,
    section_count: usize,
    command_size: usize,
) {
    write_command(bytes, offset, LC_SEGMENT_64, command_size);
    write_name(bytes, offset + 8, name);
    write_u64(
        bytes,
        offset + SEGMENT_VMADDR,
        usize::try_from(vmaddr).unwrap(),
    );
    write_u64(bytes, offset + SEGMENT_VMSIZE, vmsize);
    write_u64(bytes, offset + SEGMENT_FILEOFF, fileoff);
    write_u64(bytes, offset + SEGMENT_FILESIZE, filesize);
    write_u32(bytes, offset + SEGMENT_NSECTS, section_count);
}

fn write_command(bytes: &mut [u8], offset: usize, command: u32, size: usize) {
    write_u32(bytes, offset, usize::try_from(command).unwrap());
    write_u32(bytes, offset + 4, size);
}

fn write_name(bytes: &mut [u8], offset: usize, name: &str) {
    bytes[offset..offset + name.len()].copy_from_slice(name.as_bytes());
}

fn write_u32(bytes: &mut [u8], offset: usize, value: usize) {
    bytes[offset..offset + 4].copy_from_slice(&u32::try_from(value).unwrap().to_le_bytes());
}

fn write_u64(bytes: &mut [u8], offset: usize, value: usize) {
    bytes[offset..offset + 8].copy_from_slice(&u64::try_from(value).unwrap().to_le_bytes());
}
