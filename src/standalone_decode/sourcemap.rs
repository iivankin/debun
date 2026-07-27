use std::{
    error::Error,
    io::{Cursor, Read},
};

use crate::{binary::read_u32_le, json::json_string};
use ruzstd::decoding::StreamingDecoder;

const SOURCE_MAP_HEADER_SIZE: usize = 8;
const STRING_POINTER_SIZE: usize = 8;
const MAX_DECOMPRESSED_SOURCE_BYTES: usize = 512 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct DecodedSourceMap {
    pub generated_file: String,
    pub sources: Vec<String>,
    pub sources_content: Vec<String>,
    pub mappings: String,
}

impl DecodedSourceMap {
    pub fn render_json(&self) -> String {
        format!(
            concat!(
                "{{",
                "\"version\":3,",
                "\"file\":{},",
                "\"sources\":[{}],",
                "\"sourcesContent\":[{}],",
                "\"names\":[],",
                "\"mappings\":{}",
                "}}\n"
            ),
            json_string(&self.generated_file),
            self.sources
                .iter()
                .map(|source| json_string(source))
                .collect::<Vec<_>>()
                .join(","),
            self.sources_content
                .iter()
                .map(|source| json_string(source))
                .collect::<Vec<_>>()
                .join(","),
            json_string(&self.mappings)
        )
    }
}

#[derive(Debug, Clone, Copy)]
struct RawStringPointer {
    offset: u32,
    length: u32,
}

pub fn decode_serialized_sourcemap(
    bytes: &[u8],
    generated_file: &str,
) -> Result<DecodedSourceMap, Box<dyn Error>> {
    if bytes.len() < SOURCE_MAP_HEADER_SIZE {
        return Err("serialized sourcemap was truncated".into());
    }

    let source_files_count =
        read_u32_le(bytes, 0).ok_or("serialized sourcemap header was truncated")? as usize;
    let map_bytes_length =
        read_u32_le(bytes, 4).ok_or("serialized sourcemap header was truncated")? as usize;

    let pointers_len = source_files_count
        .checked_mul(STRING_POINTER_SIZE)
        .and_then(|value| value.checked_mul(2))
        .ok_or("serialized sourcemap pointer table overflowed")?;
    let names_start = SOURCE_MAP_HEADER_SIZE;
    let contents_start = names_start + source_files_count * STRING_POINTER_SIZE;
    let mappings_start = SOURCE_MAP_HEADER_SIZE + pointers_len;
    let mappings_end = mappings_start
        .checked_add(map_bytes_length)
        .ok_or("serialized sourcemap mappings overflowed")?;
    if mappings_end > bytes.len() {
        return Err("serialized sourcemap mappings were truncated".into());
    }

    let mut sources = Vec::with_capacity(source_files_count);
    let mut sources_content = Vec::with_capacity(source_files_count);

    for index in 0..source_files_count {
        let name_offset = names_start + index * STRING_POINTER_SIZE;
        let contents_offset = contents_start + index * STRING_POINTER_SIZE;

        let name_ptr = parse_string_pointer(
            bytes
                .get(name_offset..name_offset + STRING_POINTER_SIZE)
                .ok_or("serialized sourcemap file-name pointer was truncated")?,
        )
        .ok_or("serialized sourcemap file-name pointer was invalid")?;
        let contents_ptr = parse_string_pointer(
            bytes
                .get(contents_offset..contents_offset + STRING_POINTER_SIZE)
                .ok_or("serialized sourcemap source-content pointer was truncated")?,
        )
        .ok_or("serialized sourcemap source-content pointer was invalid")?;

        let source_name = slice_pointer(bytes, name_ptr)
            .ok_or("serialized sourcemap file name was out of bounds")?;
        let compressed_source = slice_pointer(bytes, contents_ptr)
            .ok_or("serialized sourcemap source content was out of bounds")?;

        sources.push(String::from_utf8_lossy(source_name).into_owned());
        sources_content.push(decompress_zstd_frame(compressed_source)?);
    }

    Ok(DecodedSourceMap {
        generated_file: generated_file.to_string(),
        sources,
        sources_content,
        mappings: String::from_utf8_lossy(&bytes[mappings_start..mappings_end]).into_owned(),
    })
}

fn decompress_zstd_frame(bytes: &[u8]) -> Result<String, Box<dyn Error>> {
    let decoder = StreamingDecoder::new(Cursor::new(bytes))?;
    let decompressed = read_to_end_limited(decoder, MAX_DECOMPRESSED_SOURCE_BYTES)?;
    Ok(String::from_utf8(decompressed)
        .unwrap_or_else(|error| String::from_utf8_lossy(error.as_bytes()).into_owned()))
}

fn read_to_end_limited(reader: impl Read, limit: usize) -> Result<Vec<u8>, Box<dyn Error>> {
    let read_limit = limit
        .checked_add(1)
        .and_then(|value| u64::try_from(value).ok())
        .ok_or("sourcemap decompression limit overflowed")?;
    let mut decompressed = Vec::new();
    reader.take(read_limit).read_to_end(&mut decompressed)?;
    if decompressed.len() > limit {
        return Err(
            format!("decompressed sourcemap source exceeded the {limit}-byte limit").into(),
        );
    }
    Ok(decompressed)
}

fn parse_string_pointer(bytes: &[u8]) -> Option<RawStringPointer> {
    let offset = read_u32_le(bytes, 0)?;
    let length = read_u32_le(bytes, 4)?;
    Some(RawStringPointer { offset, length })
}

fn slice_pointer(bytes: &[u8], pointer: RawStringPointer) -> Option<&[u8]> {
    let start = pointer.offset as usize;
    let end = start.checked_add(pointer.length as usize)?;
    bytes.get(start..end)
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::{decode_serialized_sourcemap, read_to_end_limited};

    const ZSTD_CONSOLE_LOG: &[u8] = &[
        0x28, 0xb5, 0x2f, 0xfd, 0x04, 0x48, 0x81, 0x00, 0x00, 0x63, 0x6f, 0x6e, 0x73, 0x6f, 0x6c,
        0x65, 0x2e, 0x6c, 0x6f, 0x67, 0x28, 0x31, 0x29, 0x3b, 0x0a, 0xb2, 0xaa, 0x89, 0x55,
    ];

    fn push_u32(out: &mut Vec<u8>, value: u32) {
        out.extend_from_slice(&value.to_le_bytes());
    }

    fn push_pointer(out: &mut Vec<u8>, offset: u32, length: u32) {
        push_u32(out, offset);
        push_u32(out, length);
    }

    fn to_u32(value: usize) -> u32 {
        u32::try_from(value).expect("test payload exceeded u32")
    }

    #[test]
    fn decodes_serialized_sourcemap_into_standard_json_shape() {
        let name = b"src/app.ts";
        let mappings = b"AAAA";
        let string_payload_start = 8 + 8 + 8 + mappings.len();
        let name_offset = to_u32(string_payload_start);
        let contents_offset = to_u32(string_payload_start + name.len());

        let mut raw = Vec::new();
        push_u32(&mut raw, 1);
        push_u32(&mut raw, to_u32(mappings.len()));
        push_pointer(&mut raw, name_offset, to_u32(name.len()));
        push_pointer(&mut raw, contents_offset, to_u32(ZSTD_CONSOLE_LOG.len()));
        raw.extend_from_slice(mappings);
        raw.extend_from_slice(name);
        raw.extend_from_slice(ZSTD_CONSOLE_LOG);

        let decoded = decode_serialized_sourcemap(&raw, "/$bunfs/root/app.js")
            .expect("sourcemap should decode");

        assert_eq!(decoded.generated_file, "/$bunfs/root/app.js");
        assert_eq!(decoded.sources, vec!["src/app.ts"]);
        assert_eq!(decoded.sources_content, vec!["console.log(1);\n"]);
        assert_eq!(decoded.mappings, "AAAA");

        let rendered = decoded.render_json();
        assert!(rendered.contains("\"version\":3"));
        assert!(rendered.contains("\"file\":\"/$bunfs/root/app.js\""));
        assert!(rendered.contains("\"sources\":[\"src/app.ts\"]"));
        assert!(rendered.contains("\"mappings\":\"AAAA\""));
    }

    #[test]
    fn limits_decompressed_source_size() {
        assert_eq!(
            read_to_end_limited(Cursor::new(b"1234"), 4).unwrap(),
            b"1234"
        );
        let error = read_to_end_limited(Cursor::new(b"12345"), 4)
            .expect_err("input larger than the limit must be rejected");
        assert!(error.to_string().contains("4-byte limit"));
    }
}
