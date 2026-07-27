use std::{collections::HashMap, error::Error};

mod container;
mod elf;
mod layout;
mod macho;
mod model;
mod parse;
mod pe;
#[cfg(test)]
mod tests;
mod write;

pub(crate) use self::layout::normalize_virtual_path;
use self::layout::{
    OffsetsLayout, RawStringPointer, STRING_POINTER_SIZE, SectionLengthWidth, TRAILER,
    is_bunfs_virtual_path, parse_offsets, parse_string_pointer, read_u64_le,
    slice_optional_pointer, slice_pointer,
};
pub(crate) use self::model::{
    ModuleRecordLayout, OptionalReplacement, RepackedExecutable, ReplacementCounts,
    ReplacementParts, RequiredReplacement, StandaloneContainer, StandaloneInspection,
    StandaloneModule, StandaloneSectionKind, StandaloneSidecarKind,
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
