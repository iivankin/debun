use std::{error::Error, mem::size_of};

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
const MODULE_RECORD_SIZE: usize = 52;
const OFFSETS_SIZE_64: usize = 32;

#[derive(Debug, Clone)]
pub struct StandaloneInspection {
    pub container_name: Option<String>,
    pub raw_container_file_offset: Option<usize>,
    pub raw_container_bytes: Option<Vec<u8>>,
    pub payload_file_offset: usize,
    pub payload_bytes: Vec<u8>,
    pub files: Vec<StandaloneFile>,
    pub entry_point_path: Option<String>,
    pub entry_point_source: Option<String>,
}

#[derive(Debug, Clone)]
pub struct StandaloneFile {
    pub virtual_path: String,
    pub source_offset: usize,
    pub bytes: Vec<u8>,
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

#[derive(Debug, Clone, Copy)]
struct ContainerPayload<'a> {
    container_name: Option<&'static str>,
    raw_container_file_offset: Option<usize>,
    raw_container_bytes: Option<&'a [u8]>,
    payload_file_offset: usize,
    payload_bytes: &'a [u8],
}

pub fn inspect_executable(bytes: &[u8]) -> Result<Option<StandaloneInspection>, Box<dyn Error>> {
    let Some(payload) = extract_container_payload(bytes)? else {
        return Ok(None);
    };

    Ok(Some(parse_payload(payload)?))
}

fn extract_container_payload(bytes: &[u8]) -> Result<Option<ContainerPayload<'_>>, Box<dyn Error>> {
    if let Some(payload) = extract_macho_payload(bytes)? {
        return Ok(Some(payload));
    }
    if let Some(payload) = extract_pe_payload(bytes)? {
        return Ok(Some(payload));
    }
    if let Some(payload) = extract_appended_payload(bytes)? {
        return Ok(Some(payload));
    }

    Ok(None)
}

fn extract_macho_payload(bytes: &[u8]) -> Result<Option<ContainerPayload<'_>>, Box<dyn Error>> {
    let Some(section) = find_macho_bun_section(bytes) else {
        return Ok(None);
    };
    let Some(raw_section) =
        bytes.get(section.fileoff..section.fileoff.saturating_add(section.filesize))
    else {
        return Ok(None);
    };
    let Some(payload_bytes) = parse_length_prefixed_payload(raw_section) else {
        return Ok(None);
    };

    Ok(Some(ContainerPayload {
        container_name: Some(section.name),
        raw_container_file_offset: Some(section.fileoff),
        raw_container_bytes: Some(raw_section),
        payload_file_offset: section.fileoff + size_of::<u64>(),
        payload_bytes,
    }))
}

fn extract_pe_payload(bytes: &[u8]) -> Result<Option<ContainerPayload<'_>>, Box<dyn Error>> {
    let Some(section) = find_pe_bun_section(bytes)? else {
        return Ok(None);
    };
    let Some(raw_section) = bytes
        .get(section.pointer_to_raw_data..section.pointer_to_raw_data + section.size_of_raw_data)
    else {
        return Ok(None);
    };
    let Some(payload_bytes) = parse_length_prefixed_payload(raw_section) else {
        return Ok(None);
    };

    Ok(Some(ContainerPayload {
        container_name: Some(".bun"),
        raw_container_file_offset: Some(section.pointer_to_raw_data),
        raw_container_bytes: Some(raw_section),
        payload_file_offset: section.pointer_to_raw_data + size_of::<u64>(),
        payload_bytes,
    }))
}

fn extract_appended_payload(bytes: &[u8]) -> Result<Option<ContainerPayload<'_>>, Box<dyn Error>> {
    if size_of::<usize>() != size_of::<u64>() {
        return Ok(None);
    }

    let footer_size = size_of::<u64>() + OFFSETS_SIZE_64 + TRAILER.len();
    if bytes.len() < footer_size {
        return Ok(None);
    }

    let total_size_offset = bytes.len() - size_of::<u64>();
    let Some(total_byte_count) = read_u64_le(bytes, total_size_offset).map(|value| value as usize)
    else {
        return Ok(None);
    };
    if total_byte_count != bytes.len() {
        return Ok(None);
    }

    let trailer_start = total_size_offset.saturating_sub(TRAILER.len());
    if bytes.get(trailer_start..total_size_offset) != Some(TRAILER) {
        return Ok(None);
    }

    let offsets_start = trailer_start.saturating_sub(OFFSETS_SIZE_64);
    let Some(offsets_bytes) = bytes.get(offsets_start..trailer_start) else {
        return Ok(None);
    };
    let Some(offsets) = parse_offsets(offsets_bytes) else {
        return Ok(None);
    };
    if offsets.byte_count > offsets_start {
        return Ok(None);
    }

    let payload_start = offsets_start - offsets.byte_count;
    let Some(payload_bytes) = bytes.get(payload_start..total_size_offset) else {
        return Ok(None);
    };

    Ok(Some(ContainerPayload {
        container_name: None,
        raw_container_file_offset: None,
        raw_container_bytes: None,
        payload_file_offset: payload_start,
        payload_bytes,
    }))
}

fn parse_payload(payload: ContainerPayload<'_>) -> Result<StandaloneInspection, Box<dyn Error>> {
    let payload_len = payload.payload_bytes.len();
    if payload_len < TRAILER.len() + OFFSETS_SIZE_64 {
        return Err("standalone payload was too small".into());
    }

    let trailer_start = payload_len - TRAILER.len();
    if payload.payload_bytes.get(trailer_start..) != Some(TRAILER) {
        return Err("standalone payload trailer was invalid".into());
    }

    let offsets_start = trailer_start - OFFSETS_SIZE_64;
    let offsets_bytes = payload
        .payload_bytes
        .get(offsets_start..trailer_start)
        .ok_or("standalone payload offsets were out of bounds")?;
    let offsets = parse_offsets(offsets_bytes).ok_or("standalone payload offsets were invalid")?;
    if offsets.byte_count != offsets_start {
        return Err("standalone payload byte_count did not match the payload layout".into());
    }

    let body = &payload.payload_bytes[..offsets.byte_count];
    let modules_bytes = slice_pointer(body, offsets.modules_ptr)
        .ok_or("standalone payload module list pointer was out of bounds")?;
    if modules_bytes.len() % MODULE_RECORD_SIZE != 0 {
        return Err("standalone payload module list had an invalid size".into());
    }

    let mut files = Vec::new();
    let mut entry_point_path = None;
    let mut entry_point_source = None;

    for (index, module_bytes) in modules_bytes.chunks_exact(MODULE_RECORD_SIZE).enumerate() {
        let name_ptr = parse_string_pointer(
            module_bytes
                .get(0..STRING_POINTER_SIZE)
                .ok_or("module name pointer was out of bounds")?,
        )
        .ok_or("module name pointer was invalid")?;
        let contents_ptr = parse_string_pointer(
            module_bytes
                .get(STRING_POINTER_SIZE..STRING_POINTER_SIZE * 2)
                .ok_or("module contents pointer was out of bounds")?,
        )
        .ok_or("module contents pointer was invalid")?;

        let Some(name_bytes) = slice_pointer(body, name_ptr) else {
            continue;
        };
        let Some(contents_bytes) = slice_pointer(body, contents_ptr) else {
            continue;
        };
        let Ok(name) = std::str::from_utf8(name_bytes) else {
            continue;
        };

        let normalized_path = normalize_virtual_path(name);
        if index == offsets.entry_point_id as usize {
            entry_point_path = Some(normalized_path.clone());
            if looks_like_javascript_source(contents_bytes) {
                entry_point_source = std::str::from_utf8(contents_bytes).ok().map(str::to_string);
            }
        }

        if !is_bunfs_virtual_path(name) {
            continue;
        }

        files.push(StandaloneFile {
            virtual_path: normalized_path,
            source_offset: contents_ptr.offset as usize,
            bytes: contents_bytes.to_vec(),
        });
    }

    Ok(StandaloneInspection {
        container_name: payload.container_name.map(str::to_string),
        raw_container_file_offset: payload.raw_container_file_offset,
        raw_container_bytes: payload.raw_container_bytes.map(<[u8]>::to_vec),
        payload_file_offset: payload.payload_file_offset,
        payload_bytes: payload.payload_bytes.to_vec(),
        files,
        entry_point_path,
        entry_point_source,
    })
}

fn slice_pointer<'a>(bytes: &'a [u8], pointer: RawStringPointer) -> Option<&'a [u8]> {
    let start = pointer.offset as usize;
    let end = start.checked_add(pointer.length as usize)?;
    bytes.get(start..end)
}

fn looks_like_javascript_source(bytes: &[u8]) -> bool {
    let Ok(text) = std::str::from_utf8(bytes) else {
        return false;
    };
    let trimmed = text.trim_start();
    trimmed.starts_with("// @bun")
        || trimmed.starts_with("import ")
        || trimmed.starts_with("export ")
        || trimmed.starts_with("var ")
        || trimmed.starts_with("let ")
        || trimmed.starts_with("const ")
        || trimmed.starts_with("function ")
}

fn normalize_virtual_path(path: &str) -> String {
    if let Some(rest) = path.strip_prefix(WINDOWS_BUNFS_ROOT_PREFIX) {
        format!("{BUNFS_ROOT_PREFIX}{rest}")
    } else {
        path.to_string()
    }
}

fn is_bunfs_virtual_path(path: &str) -> bool {
    path.starts_with(BUNFS_ROOT_PREFIX) || path.starts_with(WINDOWS_BUNFS_ROOT_PREFIX)
}

fn parse_length_prefixed_payload(raw_section: &[u8]) -> Option<&[u8]> {
    let len = read_u64_le(raw_section, 0)? as usize;
    raw_section.get(size_of::<u64>()..size_of::<u64>() + len)
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

#[derive(Debug, Clone, Copy)]
struct MachoBunSection {
    name: &'static str,
    fileoff: usize,
    filesize: usize,
}

fn find_macho_bun_section(bytes: &[u8]) -> Option<MachoBunSection> {
    let magic = read_u32_le(bytes, 0)?;
    let is_64 = match magic {
        MACH_O_MAGIC_64 => true,
        MACH_O_MAGIC_32 => false,
        _ => return None,
    };

    let header_size = if is_64 { 32 } else { 28 };
    let ncmds = read_u32_le(bytes, 16)? as usize;
    let sizeofcmds = read_u32_le(bytes, 20)? as usize;
    if bytes.len() < header_size + sizeofcmds {
        return None;
    }

    let mut cursor = header_size;
    for _ in 0..ncmds {
        let cmd = read_u32_le(bytes, cursor)?;
        let cmdsize = read_u32_le(bytes, cursor + 4)? as usize;
        if cmdsize < 8 || cursor + cmdsize > bytes.len() {
            return None;
        }

        match cmd {
            LC_SEGMENT_64 if is_64 => {
                let segname = read_fixed_string(bytes, cursor + 8, 16)?;
                if BUN_SEGMENT_NAMES.contains(&segname.as_str()) {
                    return Some(MachoBunSection {
                        name: if segname == "__bun" { "__bun" } else { "__BUN" },
                        fileoff: read_u64_le(bytes, cursor + 40)? as usize,
                        filesize: read_u64_le(bytes, cursor + 48)? as usize,
                    });
                }
            }
            LC_SEGMENT if !is_64 => {
                let segname = read_fixed_string(bytes, cursor + 8, 16)?;
                if BUN_SEGMENT_NAMES.contains(&segname.as_str()) {
                    return Some(MachoBunSection {
                        name: if segname == "__bun" { "__bun" } else { "__BUN" },
                        fileoff: read_u32_le(bytes, cursor + 32)? as usize,
                        filesize: read_u32_le(bytes, cursor + 36)? as usize,
                    });
                }
            }
            _ => {}
        }

        cursor += cmdsize;
    }

    None
}

#[derive(Debug, Clone, Copy)]
struct PeBunSection {
    pointer_to_raw_data: usize,
    size_of_raw_data: usize,
}

fn find_pe_bun_section(bytes: &[u8]) -> Result<Option<PeBunSection>, Box<dyn Error>> {
    if read_u16_le(bytes, 0) != Some(DOS_MAGIC) {
        return Ok(None);
    }

    let pe_header_offset = read_u32_le(bytes, 0x3c).ok_or("PE header offset was missing")? as usize;
    if read_u32_le(bytes, pe_header_offset) != Some(PE_MAGIC) {
        return Ok(None);
    }

    let coff_header_offset = pe_header_offset + 4;
    let number_of_sections =
        read_u16_le(bytes, coff_header_offset + 2).ok_or("PE section count was missing")? as usize;
    let optional_header_size = read_u16_le(bytes, coff_header_offset + 16)
        .ok_or("PE optional header size was missing")? as usize;
    let section_headers_offset = coff_header_offset + 20 + optional_header_size;

    for index in 0..number_of_sections {
        let offset = section_headers_offset + index * 40;
        let Some(name) = bytes.get(offset..offset + 8) else {
            break;
        };
        if name != BUN_SECTION_NAME {
            continue;
        }

        let size_of_raw_data =
            read_u32_le(bytes, offset + 16).ok_or("PE bun section size was missing")? as usize;
        let pointer_to_raw_data =
            read_u32_le(bytes, offset + 20).ok_or("PE bun section offset was missing")? as usize;
        return Ok(Some(PeBunSection {
            pointer_to_raw_data,
            size_of_raw_data,
        }));
    }

    Ok(None)
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

#[cfg(test)]
mod tests {
    use super::{
        MODULE_RECORD_SIZE, OFFSETS_SIZE_64, STRING_POINTER_SIZE, TRAILER, inspect_executable,
    };

    fn push_bytes(body: &mut Vec<u8>, bytes: &[u8]) -> (u32, u32) {
        let offset = body.len() as u32;
        body.extend_from_slice(bytes);
        (offset, bytes.len() as u32)
    }

    fn push_string_pointer(out: &mut Vec<u8>, offset: u32, length: u32) {
        out.extend_from_slice(&offset.to_le_bytes());
        out.extend_from_slice(&length.to_le_bytes());
    }

    fn push_module_record(out: &mut Vec<u8>, name: (u32, u32), contents: (u32, u32)) {
        push_string_pointer(out, name.0, name.1);
        push_string_pointer(out, contents.0, contents.1);
        for _ in 0..4 {
            push_string_pointer(out, 0, 0);
        }
        out.extend_from_slice(&[0, 0, 0, 0]);
        assert_eq!(out.len() % MODULE_RECORD_SIZE, 0);
    }

    fn build_payload(files: &[(&str, &[u8])], entry_point_id: u32) -> Vec<u8> {
        let mut body = Vec::new();
        let mut modules = Vec::new();

        for (name, contents) in files {
            let name_ptr = push_bytes(&mut body, name.as_bytes());
            let contents_ptr = push_bytes(&mut body, contents);
            push_module_record(&mut modules, name_ptr, contents_ptr);
        }

        let modules_offset = body.len() as u32;
        body.extend_from_slice(&modules);

        let byte_count = body.len() as u64;
        let mut payload = body;
        payload.extend_from_slice(&byte_count.to_le_bytes());
        push_string_pointer(&mut payload, modules_offset, modules.len() as u32);
        payload.extend_from_slice(&entry_point_id.to_le_bytes());
        push_string_pointer(&mut payload, 0, 0);
        payload.extend_from_slice(&0u32.to_le_bytes());
        payload.extend_from_slice(TRAILER);

        assert_eq!(
            payload.len(),
            byte_count as usize + OFFSETS_SIZE_64 + TRAILER.len()
        );
        assert_eq!(STRING_POINTER_SIZE, 8);
        payload
    }

    #[test]
    fn parses_appended_standalone_graph() {
        let payload = build_payload(
            &[
                ("/$bunfs/root/app.js", b"// @bun\nconsole.log('entry');\n"),
                ("B:/~BUN/root/chunk.wasm", b"\0asm\x01\0\0\0"),
            ],
            0,
        );

        let mut exe = vec![0x7f, b'E', b'L', b'F'];
        exe.resize(128, 0);
        let payload_offset = exe.len();
        exe.extend_from_slice(&payload);
        exe.extend_from_slice(&(exe.len() as u64 + 8).to_le_bytes());

        let inspection = inspect_executable(&exe)
            .expect("parser should not fail")
            .expect("parser should find an appended payload");

        assert_eq!(inspection.payload_file_offset, payload_offset);
        assert_eq!(inspection.files.len(), 2);
        assert_eq!(inspection.files[0].virtual_path, "/$bunfs/root/app.js");
        assert_eq!(inspection.files[1].virtual_path, "/$bunfs/root/chunk.wasm");
        assert_eq!(
            inspection.entry_point_path.as_deref(),
            Some("/$bunfs/root/app.js")
        );
        assert_eq!(
            inspection.entry_point_source.as_deref(),
            Some("// @bun\nconsole.log('entry');\n")
        );
    }
}
