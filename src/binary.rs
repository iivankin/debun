pub(crate) fn read_fixed_string(bytes: &[u8], start: usize, len: usize) -> Option<String> {
    let slice = bytes.get(start..start + len)?;
    let end = slice
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(slice.len());
    String::from_utf8(slice[..end].to_vec()).ok()
}

pub(crate) fn read_u16_le(bytes: &[u8], start: usize) -> Option<u16> {
    let slice = bytes.get(start..start + 2)?;
    Some(u16::from_le_bytes(slice.try_into().ok()?))
}

pub(crate) fn read_u32_le(bytes: &[u8], start: usize) -> Option<u32> {
    let slice = bytes.get(start..start + 4)?;
    Some(u32::from_le_bytes(slice.try_into().ok()?))
}

pub(crate) fn read_u32_be(bytes: &[u8], start: usize) -> Option<u32> {
    let slice = bytes.get(start..start + 4)?;
    Some(u32::from_be_bytes(slice.try_into().ok()?))
}

pub(crate) fn read_u64_le(bytes: &[u8], start: usize) -> Option<u64> {
    let slice = bytes.get(start..start + 8)?;
    Some(u64::from_le_bytes(slice.try_into().ok()?))
}
