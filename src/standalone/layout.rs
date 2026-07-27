use std::mem::size_of;

pub(super) use crate::binary::{read_u32_le, read_u64_le};

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
pub(super) const LEGACY_BUNFS_ROOT_PREFIX: &str = "compiled://root/";
pub(super) const TRAILER: &[u8] = b"\n---- Bun! ----\n";

pub(super) const STRING_POINTER_SIZE: usize = size_of::<u32>() * 2;
pub(super) const MODULE_RECORD_SIZE_LEGACY_LOADER: usize = 32;
pub(super) const MODULE_RECORD_SIZE_LEGACY_ENCODING: usize = 28;
pub(super) const MODULE_RECORD_SIZE_COMPACT: usize = 36;
pub(super) const MODULE_RECORD_SIZE_WITH_MODULE_INFO: usize = 44;
pub(super) const MODULE_RECORD_SIZE_EXTENDED: usize = 52;
pub(super) const OFFSETS_SIZE_LEGACY: usize = 24;
pub(super) const OFFSETS_SIZE_WITH_COMPILE_ARGV: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SectionLengthWidth {
    U32,
    U64,
}

impl SectionLengthWidth {
    pub(crate) const fn size(self) -> usize {
        match self {
            Self::U32 => size_of::<u32>(),
            Self::U64 => size_of::<u64>(),
        }
    }

    pub(super) fn read(self, bytes: &[u8]) -> Option<usize> {
        match self {
            Self::U32 => usize::try_from(read_u32_le(bytes, 0)?).ok(),
            Self::U64 => usize::try_from(read_u64_le(bytes, 0)?).ok(),
        }
    }

    pub(super) fn write(self, bytes: &mut [u8], value: usize) -> Result<(), &'static str> {
        match self {
            Self::U32 => {
                let value =
                    u32::try_from(value).map_err(|_| "standalone payload length exceeded u32")?;
                let target = bytes
                    .get_mut(..size_of::<u32>())
                    .ok_or("standalone section length prefix was out of bounds")?;
                target.copy_from_slice(&value.to_le_bytes());
            }
            Self::U64 => {
                let value =
                    u64::try_from(value).map_err(|_| "standalone payload length exceeded u64")?;
                let target = bytes
                    .get_mut(..size_of::<u64>())
                    .ok_or("standalone section length prefix was out of bounds")?;
                target.copy_from_slice(&value.to_le_bytes());
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OffsetsLayout {
    Legacy,
    WithCompileArgv,
}

impl OffsetsLayout {
    pub(super) const ALL: [Self; 2] = [Self::WithCompileArgv, Self::Legacy];

    pub(crate) const fn size(self) -> usize {
        match self {
            Self::Legacy => OFFSETS_SIZE_LEGACY,
            Self::WithCompileArgv => OFFSETS_SIZE_WITH_COMPILE_ARGV,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(super) struct RawStringPointer {
    pub(super) offset: u32,
    pub(super) length: u32,
}

impl RawStringPointer {
    pub(super) const EMPTY: Self = Self {
        offset: 0,
        length: 0,
    };
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

pub(super) fn parse_offsets(bytes: &[u8], layout: OffsetsLayout) -> Option<RawOffsets> {
    if size_of::<usize>() != size_of::<u64>() || bytes.len() != layout.size() {
        return None;
    }

    let (compile_exec_argv_ptr, flags_bits) = match layout {
        OffsetsLayout::Legacy => (RawStringPointer::EMPTY, 0),
        OffsetsLayout::WithCompileArgv => (
            parse_string_pointer(bytes.get(20..28)?)?,
            read_u32_le(bytes, 28)?,
        ),
    };

    Some(RawOffsets {
        byte_count: usize::try_from(read_u64_le(bytes, 0)?).ok()?,
        modules_ptr: parse_string_pointer(bytes.get(8..16)?)?,
        entry_point_id: read_u32_le(bytes, 16)?,
        compile_exec_argv_ptr,
        flags_bits,
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

pub(crate) fn normalize_virtual_path(path: &str) -> String {
    if let Some(rest) = path.strip_prefix(WINDOWS_BUNFS_ROOT_PREFIX) {
        format!("{BUNFS_ROOT_PREFIX}{rest}")
    } else if let Some(rest) = path.strip_prefix(LEGACY_BUNFS_ROOT_PREFIX) {
        format!("{BUNFS_ROOT_PREFIX}{rest}")
    } else {
        path.to_string()
    }
}

pub(super) fn is_bunfs_virtual_path(path: &str) -> bool {
    path.starts_with(BUNFS_ROOT_PREFIX)
        || path.starts_with(WINDOWS_BUNFS_ROOT_PREFIX)
        || path.starts_with(LEGACY_BUNFS_ROOT_PREFIX)
}
