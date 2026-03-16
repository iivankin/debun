use std::{
    error::Error,
    io::{Cursor, Read},
};

use ruzstd::decoding::StreamingDecoder;

use super::json::json_string;

const SOURCE_MAP_HEADER_SIZE: usize = 8;
const STRING_POINTER_SIZE: usize = 8;

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
    let mut decoder = StreamingDecoder::new(Cursor::new(bytes))?;
    let mut decompressed = Vec::new();
    decoder.read_to_end(&mut decompressed)?;
    Ok(String::from_utf8_lossy(&decompressed).into_owned())
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

fn read_u32_le(bytes: &[u8], offset: usize) -> Option<u32> {
    let chunk = bytes.get(offset..offset + 4)?;
    Some(u32::from_le_bytes(chunk.try_into().ok()?))
}

#[cfg(test)]
mod tests {
    use super::decode_serialized_sourcemap;

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

    #[test]
    fn decodes_serialized_sourcemap_into_standard_json_shape() {
        let name = b"src/app.ts";
        let mappings = b"AAAA";
        let string_payload_start = 8 + 8 + 8 + mappings.len();
        let name_offset = string_payload_start as u32;
        let contents_offset = (string_payload_start + name.len()) as u32;

        let mut raw = Vec::new();
        push_u32(&mut raw, 1);
        push_u32(&mut raw, mappings.len() as u32);
        push_pointer(&mut raw, name_offset, name.len() as u32);
        push_pointer(&mut raw, contents_offset, ZSTD_CONSOLE_LOG.len() as u32);
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
}
