use std::{collections::HashMap, error::Error};

mod container;
mod parse;
#[cfg(test)]
mod tests;
mod write;

const MACH_O_MAGIC_64: u32 = 0xfeedfacf;
const MACH_O_MAGIC_32: u32 = 0xfeedface;
const LC_SEGMENT_64: u32 = 0x19;
const LC_SEGMENT: u32 = 0x1;

const DOS_MAGIC: u16 = 0x5a4d;
const PE_MAGIC: u32 = 0x0000_4550;

const BUN_SEGMENT_NAMES: &[&str] = &["__BUN", "__bun"];
const BUN_SECTION_NAME: &[u8; 8] = b".bun\0\0\0\0";
const BUNFS_ROOT_PREFIX: &str = "/$bunfs/root/";
const WINDOWS_BUNFS_ROOT_PREFIX: &str = "B:/~BUN/root/";
const TRAILER: &[u8] = b"\n---- Bun! ----\n";

const STRING_POINTER_SIZE: usize = 8;
const MODULE_RECORD_SIZE_COMPACT: usize = 36;
const MODULE_RECORD_SIZE_WITH_MODULE_INFO: usize = 44;
const MODULE_RECORD_SIZE_EXTENDED: usize = 52;
const OFFSETS_SIZE_64: usize = 32;

#[derive(Debug, Clone)]
pub struct StandaloneInspection {
    pub container_name: Option<String>,
    pub raw_container_file_offset: Option<usize>,
    pub raw_container_bytes: Option<Vec<u8>>,
    pub payload_file_offset: usize,
    pub payload_bytes: Vec<u8>,
    pub record_layout: &'static str,
    pub record_size: usize,
    pub files: Vec<StandaloneFile>,
    pub entry_point_path: Option<String>,
    pub entry_point_source: Option<String>,
    pub(crate) entry_point_id: u32,
    pub(crate) compile_exec_argv: Option<Vec<u8>>,
    pub(crate) flags_bits: u32,
    pub(crate) record_layout_kind: ModuleRecordLayout,
    pub(crate) modules: Vec<StandaloneModule>,
}

#[derive(Debug, Clone)]
pub struct StandaloneFile {
    pub virtual_path: String,
    pub source_offset: usize,
    pub bytes: Vec<u8>,
    pub sourcemap: Option<Vec<u8>>,
    pub sourcemap_offset: Option<usize>,
    pub bytecode: Option<Vec<u8>>,
    pub bytecode_offset: Option<usize>,
    pub module_info: Option<Vec<u8>>,
    pub module_info_offset: Option<usize>,
    pub bytecode_origin_path: Option<String>,
    pub encoding: u8,
    pub loader: u8,
    pub module_format: u8,
    pub side: u8,
}

#[derive(Debug, Clone)]
pub(crate) struct StandaloneModule {
    pub original_path: String,
    pub virtual_path: String,
    pub source_offset: usize,
    pub bytes: Vec<u8>,
    pub sourcemap: Option<Vec<u8>>,
    pub sourcemap_offset: Option<usize>,
    pub bytecode: Option<Vec<u8>>,
    pub bytecode_offset: Option<usize>,
    pub module_info: Option<Vec<u8>>,
    pub module_info_offset: Option<usize>,
    pub bytecode_origin_path: Option<String>,
    pub encoding: u8,
    pub loader: u8,
    pub module_format: u8,
    pub side: u8,
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum ModuleRecordLayout {
    Compact,
    WithModuleInfo,
    Extended,
}

impl ModuleRecordLayout {
    pub(crate) const fn size(self) -> usize {
        match self {
            Self::Compact => MODULE_RECORD_SIZE_COMPACT,
            Self::WithModuleInfo => MODULE_RECORD_SIZE_WITH_MODULE_INFO,
            Self::Extended => MODULE_RECORD_SIZE_EXTENDED,
        }
    }

    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::Compact => "compact",
            Self::WithModuleInfo => "with-module-info",
            Self::Extended => "extended",
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct ReplacementParts {
    pub contents: Option<Vec<u8>>,
    pub sourcemap: Option<Vec<u8>>,
    pub bytecode: Option<Vec<u8>>,
    pub module_info: Option<Vec<u8>>,
}

#[derive(Debug, Clone)]
pub struct RepackedExecutable {
    pub bytes: Vec<u8>,
    pub replaced_contents: usize,
    pub replaced_sourcemaps: usize,
    pub replaced_bytecodes: usize,
    pub replaced_module_infos: usize,
}

#[derive(Debug, Clone, Copy)]
struct RawStringPointer {
    offset: u32,
    length: u32,
}

#[derive(Debug, Clone, Copy)]
struct RawOffsets {
    byte_count: usize,
    modules_ptr: RawStringPointer,
    entry_point_id: u32,
    _compile_exec_argv_ptr: RawStringPointer,
    _flags_bits: u32,
}

pub fn inspect_executable(bytes: &[u8]) -> Result<Option<StandaloneInspection>, Box<dyn Error>> {
    let Some(payload) = container::extract_container_payload(bytes)? else {
        return Ok(None);
    };

    Ok(Some(parse::parse_payload(payload)?))
}

pub fn repack_executable(
    original_bytes: &[u8],
    inspection: StandaloneInspection,
    replacements: &HashMap<String, ReplacementParts>,
) -> Result<RepackedExecutable, Box<dyn Error>> {
    write::repack_executable(original_bytes, inspection, replacements)
}

fn parse_string_pointer(bytes: &[u8]) -> Option<RawStringPointer> {
    Some(RawStringPointer {
        offset: read_u32_le(bytes, 0)?,
        length: read_u32_le(bytes, 4)?,
    })
}

fn parse_offsets(bytes: &[u8]) -> Option<RawOffsets> {
    if size_of::<usize>() != size_of::<u64>() || bytes.len() != OFFSETS_SIZE_64 {
        return None;
    }

    Some(RawOffsets {
        byte_count: read_u64_le(bytes, 0)? as usize,
        modules_ptr: parse_string_pointer(bytes.get(8..16)?)?,
        entry_point_id: read_u32_le(bytes, 16)?,
        _compile_exec_argv_ptr: parse_string_pointer(bytes.get(20..28)?)?,
        _flags_bits: read_u32_le(bytes, 28)?,
    })
}

fn read_fixed_string(bytes: &[u8], start: usize, len: usize) -> Option<String> {
    let slice = bytes.get(start..start + len)?;
    let end = slice
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(slice.len());
    String::from_utf8(slice[..end].to_vec()).ok()
}

fn read_u16_le(bytes: &[u8], start: usize) -> Option<u16> {
    let slice = bytes.get(start..start + 2)?;
    Some(u16::from_le_bytes(slice.try_into().ok()?))
}

fn read_u32_le(bytes: &[u8], start: usize) -> Option<u32> {
    let slice = bytes.get(start..start + 4)?;
    Some(u32::from_le_bytes(slice.try_into().ok()?))
}

fn read_u64_le(bytes: &[u8], start: usize) -> Option<u64> {
    let slice = bytes.get(start..start + 8)?;
    Some(u64::from_le_bytes(slice.try_into().ok()?))
}
