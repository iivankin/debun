use std::mem::size_of;

pub(super) use crate::binary::{read_fixed_string, read_u16_le, read_u32_le, read_u64_le};

pub(super) const MACH_O_MAGIC_64: u32 = 0xfeed_facf;
pub(super) const MACH_O_MAGIC_32: u32 = 0xfeed_face;
pub(super) const LC_SEGMENT_64: u32 = 0x19;
pub(super) const LC_SEGMENT: u32 = 0x1;

pub(super) const DOS_MAGIC: u16 = 0x5a4d;
pub(super) const PE_MAGIC: u32 = 0x0000_4550;

pub(super) const BUN_SEGMENT_NAMES: &[&str] = &["__BUN", "__bun"];
pub(super) const BUN_SECTION_NAME: &[u8; 8] = b".bun\0\0\0\0";
pub(super) const BUNFS_ROOT_PREFIX: &str = "/$bunfs/root/";
pub(super) const WINDOWS_BUNFS_ROOT_PREFIX: &str = "B:/~BUN/root/";
pub(super) const TRAILER: &[u8] = b"\n---- Bun! ----\n";

pub(super) const STRING_POINTER_SIZE: usize = size_of::<u32>() * 2;
pub(super) const MODULE_RECORD_SIZE_COMPACT: usize = 36;
pub(super) const MODULE_RECORD_SIZE_WITH_MODULE_INFO: usize = 44;
pub(super) const MODULE_RECORD_SIZE_EXTENDED: usize = 52;
pub(super) const OFFSETS_SIZE_64: usize = 32;

#[derive(Debug, Clone, Copy)]
pub(super) struct RawStringPointer {
    pub(super) offset: u32,
    pub(super) length: u32,
}

#[derive(Debug, Clone, Copy)]
pub(super) struct RawOffsets {
    pub(super) byte_count: usize,
    pub(super) modules_ptr: RawStringPointer,
    pub(super) entry_point_id: u32,
    pub(super) compile_exec_argv_ptr: RawStringPointer,
    pub(super) flags_bits: u32,
}

pub(super) fn parse_string_pointer(bytes: &[u8]) -> Option<RawStringPointer> {
    Some(RawStringPointer {
        offset: read_u32_le(bytes, 0)?,
        length: read_u32_le(bytes, 4)?,
    })
}

pub(super) fn parse_offsets(bytes: &[u8]) -> Option<RawOffsets> {
    if size_of::<usize>() != size_of::<u64>() || bytes.len() != OFFSETS_SIZE_64 {
        return None;
    }

    Some(RawOffsets {
        byte_count: usize::try_from(read_u64_le(bytes, 0)?).ok()?,
        modules_ptr: parse_string_pointer(bytes.get(8..16)?)?,
        entry_point_id: read_u32_le(bytes, 16)?,
        compile_exec_argv_ptr: parse_string_pointer(bytes.get(20..28)?)?,
        flags_bits: read_u32_le(bytes, 28)?,
    })
}

pub(super) fn slice_pointer(bytes: &[u8], pointer: RawStringPointer) -> Option<&[u8]> {
    let start = usize::try_from(pointer.offset).ok()?;
    let len = usize::try_from(pointer.length).ok()?;
    let end = start.checked_add(len)?;
    bytes.get(start..end)
}

pub(super) fn slice_optional_pointer(bytes: &[u8], pointer: RawStringPointer) -> Option<&[u8]> {
    (pointer.length > 0)
        .then(|| slice_pointer(bytes, pointer))
        .flatten()
}

pub(super) fn non_empty_pointer_offset(pointer: RawStringPointer) -> Option<usize> {
    (pointer.length > 0)
        .then(|| usize::try_from(pointer.offset).ok())
        .flatten()
}

pub(super) fn normalize_virtual_path(path: &str) -> String {
    if let Some(rest) = path.strip_prefix(WINDOWS_BUNFS_ROOT_PREFIX) {
        format!("{BUNFS_ROOT_PREFIX}{rest}")
    } else {
        path.to_string()
    }
}

pub(super) fn is_bunfs_virtual_path(path: &str) -> bool {
    path.starts_with(BUNFS_ROOT_PREFIX) || path.starts_with(WINDOWS_BUNFS_ROOT_PREFIX)
}
