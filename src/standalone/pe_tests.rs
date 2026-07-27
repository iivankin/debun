use super::super::container::extract_container_payload;
use super::super::tests::build_container_payload;
use super::*;

const PE_HEADER_OFFSET: usize = 0x80;
const COFF_OFFSET: usize = PE_HEADER_OFFSET + 4;
const OPTIONAL_OFFSET: usize = COFF_OFFSET + COFF_HEADER_SIZE;
const OPTIONAL_SIZE: usize = 240;
const SECTION_HEADERS_OFFSET: usize = OPTIONAL_OFFSET + OPTIONAL_SIZE;
const TEXT_HEADER_OFFSET: usize = SECTION_HEADERS_OFFSET;
const BUN_HEADER_OFFSET: usize = TEXT_HEADER_OFFSET + SECTION_HEADER_SIZE;
const TEXT_RAW_POINTER: usize = 0x400;
const TEXT_RAW_SIZE: usize = 0x200;
const BUN_RAW_POINTER: usize = 0x600;
const BUN_RAW_SIZE: usize = 0x200;
const OVERLAY_START: usize = BUN_RAW_POINTER + BUN_RAW_SIZE;
const OVERLAY: &[u8] = b"preserved PE overlay after the final Bun section";

#[test]
fn expands_final_bun_section_and_moves_overlay() {
    let original = build_pe(b"original");
    let replacement = build_container_payload(5000, b'x');
    let expected_raw_size = 0x1400;
    let growth = expected_raw_size - BUN_RAW_SIZE;

    let repacked = write_bun_section(&original, &replacement, SectionLengthWidth::U64)
        .expect("PE .bun growth should succeed");

    assert_eq!(repacked.len(), original.len() + growth);
    assert_eq!(
        read_u32_le(&repacked, BUN_HEADER_OFFSET + SECTION_VIRTUAL_SIZE),
        Some(u32::try_from(8 + replacement.len()).unwrap())
    );
    assert_eq!(
        read_u32_le(&repacked, BUN_HEADER_OFFSET + SECTION_RAW_SIZE),
        Some(u32::try_from(expected_raw_size).unwrap())
    );
    assert_eq!(
        read_u32_le(&repacked, OPTIONAL_OFFSET + OPTIONAL_SIZE_OF_IMAGE),
        Some(0x4000)
    );
    assert_eq!(
        &repacked[OVERLAY_START + growth..OVERLAY_START + growth + OVERLAY.len()],
        OVERLAY
    );
    assert_eq!(
        read_u32_le(&repacked, COFF_OFFSET + 8),
        Some(u32::try_from(OVERLAY_START + growth + 8).unwrap())
    );
    assert_eq!(
        read_u32_le(&repacked, TEXT_RAW_POINTER + 0x100 + 24),
        Some(u32::try_from(OVERLAY_START + growth + 4).unwrap())
    );
    assert_ne!(
        read_u32_le(&repacked, OPTIONAL_OFFSET + OPTIONAL_CHECKSUM),
        Some(0)
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
fn can_expand_an_already_expanded_pe_again() {
    let original = build_pe(b"original");
    let first_payload = build_container_payload(5000, b'a');
    let second_payload = build_container_payload(9000, b'b');

    let first = write_bun_section(&original, &first_payload, SectionLengthWidth::U64)
        .expect("first growth should succeed");
    let second = write_bun_section(&first, &second_payload, SectionLengthWidth::U64)
        .expect("second growth should succeed");

    assert_eq!(
        extract_container_payload(&second)
            .unwrap()
            .unwrap()
            .payload_bytes,
        second_payload
    );
    let second_section = find_bun_section(&second).unwrap().unwrap();
    assert_eq!(second_section.size_of_raw_data, 0x2400);
}

#[test]
fn preserves_legacy_u32_length_prefix() {
    let original = build_pe_with_width(b"original", SectionLengthWidth::U32);
    let replacement = build_container_payload(5000, b'x');

    let repacked = write_bun_section(&original, &replacement, SectionLengthWidth::U32)
        .expect("legacy PE .bun growth should succeed");
    let container = extract_container_payload(&repacked)
        .unwrap()
        .expect("repacked .bun section should be found");

    assert_eq!(
        container.section_length_width(),
        Some(SectionLengthWidth::U32)
    );
    assert_eq!(container.payload_bytes, replacement);
    assert_eq!(
        read_u32_le(&repacked, BUN_RAW_POINTER),
        Some(u32::try_from(replacement.len()).unwrap())
    );
}

#[test]
fn replaces_in_place_in_pe32() {
    let original = build_pe32(b"original");
    let replacement = build_container_payload(32, b'x');

    let repacked = write_bun_section(&original, &replacement, SectionLengthWidth::U64)
        .expect("a PE32 in-place replacement should succeed");

    assert_eq!(repacked.len(), original.len());
    assert_eq!(
        extract_container_payload(&repacked)
            .unwrap()
            .unwrap()
            .payload_bytes,
        replacement
    );
}

#[test]
fn replaces_in_place_when_bun_is_not_the_final_section() {
    let mut original = build_pe(b"original");
    let overlay = original.split_off(OVERLAY_START);
    let tail_raw_pointer = OVERLAY_START;
    let tail_raw_size = 0x200;
    original.resize(tail_raw_pointer + tail_raw_size, 0);
    original.extend_from_slice(&overlay);

    write_u16(&mut original, COFF_OFFSET + 2, 3);
    write_section(
        &mut original,
        BUN_HEADER_OFFSET + SECTION_HEADER_SIZE,
        b".tail\0\0\0",
        0x100,
        0x3000,
        tail_raw_size,
        tail_raw_pointer,
    );

    let replacement = build_container_payload(32, b'x');
    let repacked = write_bun_section(&original, &replacement, SectionLengthWidth::U64)
        .expect("an in-place replacement should not require .bun to be final");

    assert_eq!(repacked.len(), original.len());
    assert_eq!(
        extract_container_payload(&repacked)
            .unwrap()
            .unwrap()
            .payload_bytes,
        replacement
    );
}

#[test]
fn rejects_an_overlapping_section_during_in_place_replacement() {
    let mut original = build_pe(b"original");
    write_u16(&mut original, COFF_OFFSET + 2, 3);
    write_section(
        &mut original,
        BUN_HEADER_OFFSET + SECTION_HEADER_SIZE,
        b".bad\0\0\0\0",
        0x80,
        0x3000,
        0x80,
        BUN_RAW_POINTER + 0x100,
    );

    let replacement = build_container_payload(32, b'x');
    let error = write_bun_section(&original, &replacement, SectionLengthWidth::U64)
        .expect_err("overlapping PE sections must not be overwritten");

    assert!(error.to_string().contains("overlapped"));
}

#[test]
fn rejects_a_bun_section_that_overlaps_pe_headers() {
    let mut original = build_pe(b"original");
    write_u32(
        &mut original,
        BUN_HEADER_OFFSET + SECTION_RAW_POINTER,
        SECTION_HEADERS_OFFSET,
    );
    let replacement = build_container_payload(32, b'x');

    let error = write_bun_section(&original, &replacement, SectionLengthWidth::U64)
        .expect_err("the PE headers must not be overwritten");

    assert!(error.to_string().contains("headers"));
}

#[test]
fn refuses_to_invalidate_authenticode() {
    let mut signed = build_pe(b"original");
    let security_entry =
        OPTIONAL_OFFSET + OPTIONAL_DATA_DIRECTORIES_64 + IMAGE_DIRECTORY_ENTRY_SECURITY * 8;
    write_u32(&mut signed, security_entry, OVERLAY_START);
    write_u32(&mut signed, security_entry + 4, OVERLAY.len());

    let error = write_bun_section(&signed, b"replacement", SectionLengthWidth::U64)
        .expect_err("signed PE should require an external signing policy");

    assert!(error.to_string().contains("Authenticode"));
}

#[test]
fn refuses_to_invalidate_pe32_authenticode() {
    let mut signed = build_pe32(b"original");
    let security_entry =
        OPTIONAL_OFFSET + OPTIONAL_DATA_DIRECTORIES_32 + IMAGE_DIRECTORY_ENTRY_SECURITY * 8;
    write_u32(&mut signed, security_entry, OVERLAY_START);
    write_u32(&mut signed, security_entry + 4, OVERLAY.len());

    let error = write_bun_section(&signed, b"replacement", SectionLengthWidth::U64)
        .expect_err("signed PE32 should require an external signing policy");

    assert!(error.to_string().contains("Authenticode"));
}

fn build_pe(payload: &[u8]) -> Vec<u8> {
    build_pe_with_width(payload, SectionLengthWidth::U64)
}

fn build_pe32(payload: &[u8]) -> Vec<u8> {
    let mut bytes = build_pe(payload);
    write_u16(
        &mut bytes,
        OPTIONAL_OFFSET,
        usize::from(OPTIONAL_HEADER_32_MAGIC),
    );
    write_u32(
        &mut bytes,
        OPTIONAL_OFFSET + OPTIONAL_NUMBER_OF_DIRECTORIES_64,
        0,
    );
    write_u32(
        &mut bytes,
        OPTIONAL_OFFSET + OPTIONAL_NUMBER_OF_DIRECTORIES_32,
        16,
    );
    bytes
}

fn build_pe_with_width(payload: &[u8], length_width: SectionLengthWidth) -> Vec<u8> {
    let mut bytes = vec![0; OVERLAY_START + OVERLAY.len()];
    bytes[..2].copy_from_slice(&DOS_MAGIC.to_le_bytes());
    write_u32(&mut bytes, 0x3c, PE_HEADER_OFFSET);
    write_u32(
        &mut bytes,
        PE_HEADER_OFFSET,
        usize::try_from(PE_MAGIC).unwrap(),
    );
    write_u16(&mut bytes, COFF_OFFSET, 0x8664);
    write_u16(&mut bytes, COFF_OFFSET + 2, 2);
    write_u32(&mut bytes, COFF_OFFSET + 8, OVERLAY_START + 8);
    write_u16(&mut bytes, COFF_OFFSET + 16, OPTIONAL_SIZE);

    write_u16(
        &mut bytes,
        OPTIONAL_OFFSET,
        usize::from(OPTIONAL_HEADER_64_MAGIC),
    );
    write_u32(
        &mut bytes,
        OPTIONAL_OFFSET + OPTIONAL_SECTION_ALIGNMENT,
        0x1000,
    );
    write_u32(&mut bytes, OPTIONAL_OFFSET + OPTIONAL_FILE_ALIGNMENT, 0x200);
    write_u32(&mut bytes, OPTIONAL_OFFSET + OPTIONAL_SIZE_OF_IMAGE, 0x3000);
    write_u32(&mut bytes, OPTIONAL_OFFSET + 60, 0x400);
    write_u32(
        &mut bytes,
        OPTIONAL_OFFSET + OPTIONAL_NUMBER_OF_DIRECTORIES_64,
        16,
    );
    let debug_directory =
        OPTIONAL_OFFSET + OPTIONAL_DATA_DIRECTORIES_64 + IMAGE_DIRECTORY_ENTRY_DEBUG * 8;
    write_u32(&mut bytes, debug_directory, 0x1100);
    write_u32(&mut bytes, debug_directory + 4, DEBUG_DIRECTORY_SIZE);

    write_section(
        &mut bytes,
        TEXT_HEADER_OFFSET,
        b".text\0\0\0",
        0x180,
        0x1000,
        TEXT_RAW_SIZE,
        TEXT_RAW_POINTER,
    );
    write_u32(
        &mut bytes,
        TEXT_HEADER_OFFSET + SECTION_RELOCATIONS_POINTER,
        OVERLAY_START + 12,
    );
    write_section(
        &mut bytes,
        BUN_HEADER_OFFSET,
        BUN_SECTION_NAME,
        length_width.size() + payload.len(),
        0x2000,
        BUN_RAW_SIZE,
        BUN_RAW_POINTER,
    );

    let debug_entry = TEXT_RAW_POINTER + 0x100;
    write_u32(&mut bytes, debug_entry + 16, 16);
    write_u32(&mut bytes, debug_entry + 24, OVERLAY_START + 4);

    length_width
        .write(&mut bytes[BUN_RAW_POINTER..], payload.len())
        .unwrap();
    let payload_start = BUN_RAW_POINTER + length_width.size();
    bytes[payload_start..payload_start + payload.len()].copy_from_slice(payload);
    bytes[OVERLAY_START..].copy_from_slice(OVERLAY);
    bytes
}

fn write_section(
    bytes: &mut [u8],
    offset: usize,
    name: &[u8; 8],
    virtual_size: usize,
    virtual_address: usize,
    raw_size: usize,
    raw_pointer: usize,
) {
    bytes[offset..offset + name.len()].copy_from_slice(name);
    write_u32(bytes, offset + SECTION_VIRTUAL_SIZE, virtual_size);
    write_u32(bytes, offset + SECTION_VIRTUAL_ADDRESS, virtual_address);
    write_u32(bytes, offset + SECTION_RAW_SIZE, raw_size);
    write_u32(bytes, offset + SECTION_RAW_POINTER, raw_pointer);
}

fn write_u16(bytes: &mut [u8], offset: usize, value: usize) {
    bytes[offset..offset + 2].copy_from_slice(&u16::try_from(value).unwrap().to_le_bytes());
}

fn write_u32(bytes: &mut [u8], offset: usize, value: usize) {
    bytes[offset..offset + 4].copy_from_slice(&u32::try_from(value).unwrap().to_le_bytes());
}
