use std::{collections::HashMap, error::Error};

mod container;
mod layout;
mod model;
mod parse;
#[cfg(test)]
mod tests;
mod write;

use self::layout::{
    BUN_SECTION_NAME, BUN_SEGMENT_NAMES, DOS_MAGIC, LC_SEGMENT, LC_SEGMENT_64, MACH_O_MAGIC_32,
    MACH_O_MAGIC_64, OFFSETS_SIZE_64, PE_MAGIC, RawStringPointer, STRING_POINTER_SIZE, TRAILER,
    is_bunfs_virtual_path, non_empty_pointer_offset, normalize_virtual_path, parse_offsets,
    parse_string_pointer, read_fixed_string, read_u16_le, read_u32_le, read_u64_le,
    slice_optional_pointer, slice_pointer,
};
pub(crate) use self::model::{
    ModuleRecordLayout, OptionalReplacement, RepackedExecutable, ReplacementCounts,
    ReplacementParts, RequiredReplacement, StandaloneInspection, StandaloneModule,
    StandaloneSidecarKind,
};

pub(crate) fn inspect_executable(
    bytes: &[u8],
) -> Result<Option<StandaloneInspection>, Box<dyn Error>> {
    let Some(payload) = container::extract_container_payload(bytes)? else {
        return Ok(None);
    };

    Ok(Some(parse::parse_payload(payload)?))
}

pub(crate) fn repack_executable(
    original_bytes: &[u8],
    inspection: StandaloneInspection,
    replacements: &HashMap<String, ReplacementParts>,
) -> Result<RepackedExecutable, Box<dyn Error>> {
    write::repack_executable(original_bytes, inspection, replacements)
}
