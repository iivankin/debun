use std::{error::Error, io};

pub(super) fn read_len(
    bytes: &[u8],
    cursor: &mut usize,
    label: &str,
) -> Result<usize, Box<dyn Error>> {
    let len = read_u32_le(bytes, *cursor)
        .ok_or_else(|| invalid_data(format!("module_info {label} length was truncated")))?;
    *cursor += 4;
    Ok(len as usize)
}

pub(super) fn read_u32_array(
    bytes: &[u8],
    cursor: &mut usize,
    len: usize,
    label: &str,
) -> Result<Vec<u32>, Box<dyn Error>> {
    let byte_len = len
        .checked_mul(4)
        .ok_or_else(|| invalid_data(format!("module_info {label} length overflowed")))?;
    let raw = take(bytes, cursor, byte_len, label)?;
    let mut values = Vec::with_capacity(len);
    for chunk in raw.chunks_exact(4) {
        values.push(u32::from_le_bytes(
            chunk.try_into().expect("chunk size is fixed"),
        ));
    }
    Ok(values)
}

pub(super) fn take<'a>(
    bytes: &'a [u8],
    cursor: &mut usize,
    len: usize,
    label: &str,
) -> Result<&'a [u8], Box<dyn Error>> {
    let end = cursor
        .checked_add(len)
        .ok_or_else(|| invalid_data(format!("{label} slice overflowed")))?;
    let slice = bytes
        .get(*cursor..end)
        .ok_or_else(|| invalid_data(format!("{label} slice was truncated")))?;
    *cursor = end;
    Ok(slice)
}

fn read_u32_le(bytes: &[u8], offset: usize) -> Option<u32> {
    let chunk = bytes.get(offset..offset + 4)?;
    Some(u32::from_le_bytes(chunk.try_into().ok()?))
}

fn invalid_data(message: impl Into<String>) -> Box<dyn Error> {
    io::Error::other(message.into()).into()
}
