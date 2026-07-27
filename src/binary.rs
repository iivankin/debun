pub(crate) fn read_fixed_string(bytes: &[u8], start: usize, len: usize) -> Option<String> {
    let slice = bytes.get(start..start.checked_add(len)?)?;
    let end = slice
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(slice.len());
    std::str::from_utf8(&slice[..end]).ok().map(str::to_string)
}

pub(crate) fn read_u16_le(bytes: &[u8], start: usize) -> Option<u16> {
    let slice = bytes.get(start..start.checked_add(2)?)?;
    Some(u16::from_le_bytes(slice.try_into().ok()?))
}

pub(crate) fn read_u32_le(bytes: &[u8], start: usize) -> Option<u32> {
    let slice = bytes.get(start..start.checked_add(4)?)?;
    Some(u32::from_le_bytes(slice.try_into().ok()?))
}

pub(crate) fn read_u32_be(bytes: &[u8], start: usize) -> Option<u32> {
    let slice = bytes.get(start..start.checked_add(4)?)?;
    Some(u32::from_be_bytes(slice.try_into().ok()?))
}

pub(crate) fn read_u64_le(bytes: &[u8], start: usize) -> Option<u64> {
    let slice = bytes.get(start..start.checked_add(8)?)?;
    Some(u64::from_le_bytes(slice.try_into().ok()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overflowing_offsets_are_rejected() {
        let bytes = [0; 8];

        assert_eq!(read_fixed_string(&bytes, usize::MAX, 2), None);
        assert_eq!(read_u16_le(&bytes, usize::MAX), None);
        assert_eq!(read_u32_le(&bytes, usize::MAX), None);
        assert_eq!(read_u32_be(&bytes, usize::MAX), None);
        assert_eq!(read_u64_le(&bytes, usize::MAX), None);
    }
}
