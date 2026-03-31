use std::collections::HashMap;

use super::layout::{
    MODULE_RECORD_SIZE_COMPACT, MODULE_RECORD_SIZE_EXTENDED, MODULE_RECORD_SIZE_WITH_MODULE_INFO,
};
use super::{OFFSETS_SIZE_64, ReplacementParts, TRAILER, inspect_executable, repack_executable};

#[derive(Debug, Clone, Copy)]
struct TestModule<'a> {
    name: &'a str,
    contents: &'a [u8],
    sourcemap: &'a [u8],
    bytecode: &'a [u8],
    module_info: &'a [u8],
    bytecode_origin_path: Option<&'a str>,
}

#[derive(Debug, Clone, Copy)]
struct TestModulePointers {
    name: (u32, u32),
    contents: (u32, u32),
    sourcemap: (u32, u32),
    bytecode: (u32, u32),
    module_info: (u32, u32),
    bytecode_origin_path: Option<(u32, u32)>,
}

#[derive(Debug, Clone, Copy)]
enum TestModuleRecordLayout {
    Compact,
    WithModuleInfo,
    Extended,
}

impl TestModuleRecordLayout {
    const fn size(self) -> usize {
        match self {
            Self::Compact => MODULE_RECORD_SIZE_COMPACT,
            Self::WithModuleInfo => MODULE_RECORD_SIZE_WITH_MODULE_INFO,
            Self::Extended => MODULE_RECORD_SIZE_EXTENDED,
        }
    }
}

fn push_bytes(body: &mut Vec<u8>, bytes: &[u8]) -> (u32, u32) {
    let offset = to_u32(body.len());
    body.extend_from_slice(bytes);
    (offset, to_u32(bytes.len()))
}

fn push_string_pointer(out: &mut Vec<u8>, offset: u32, length: u32) {
    out.extend_from_slice(&offset.to_le_bytes());
    out.extend_from_slice(&length.to_le_bytes());
}

fn push_module_record(
    out: &mut Vec<u8>,
    layout: TestModuleRecordLayout,
    pointers: TestModulePointers,
) {
    push_string_pointer(out, pointers.name.0, pointers.name.1);
    push_string_pointer(out, pointers.contents.0, pointers.contents.1);
    push_string_pointer(out, pointers.sourcemap.0, pointers.sourcemap.1);
    push_string_pointer(out, pointers.bytecode.0, pointers.bytecode.1);
    match layout {
        TestModuleRecordLayout::Compact => {}
        TestModuleRecordLayout::WithModuleInfo => {
            push_string_pointer(out, pointers.module_info.0, pointers.module_info.1);
        }
        TestModuleRecordLayout::Extended => {
            push_string_pointer(out, pointers.module_info.0, pointers.module_info.1);
            let origin = pointers.bytecode_origin_path.unwrap_or((0, 0));
            push_string_pointer(out, origin.0, origin.1);
        }
    }
    out.extend_from_slice(&[1, 1, 1, 0]);
    assert_eq!(out.len() % layout.size(), 0);
}

fn to_u32(value: usize) -> u32 {
    u32::try_from(value).expect("test payload exceeded u32")
}

fn to_u64(value: usize) -> u64 {
    u64::try_from(value).expect("test payload exceeded u64")
}

fn build_appended_executable(payload: &[u8]) -> (Vec<u8>, usize) {
    let mut exe = vec![0x7f, b'E', b'L', b'F'];
    exe.resize(128, 0);
    let payload_offset = exe.len();
    exe.extend_from_slice(payload);
    let total_size = to_u64(exe.len())
        .checked_add(8)
        .expect("test executable size overflowed");
    exe.extend_from_slice(&total_size.to_le_bytes());
    (exe, payload_offset)
}

fn build_payload(
    files: &[TestModule<'_>],
    entry_point_id: u32,
    layout: TestModuleRecordLayout,
) -> Vec<u8> {
    let mut body = Vec::new();
    let mut modules = Vec::new();

    for file in files {
        let name_ptr = push_bytes(&mut body, file.name.as_bytes());
        let contents_ptr = push_bytes(&mut body, file.contents);
        let sourcemap_ptr = push_bytes(&mut body, file.sourcemap);
        let bytecode_ptr = push_bytes(&mut body, file.bytecode);
        let module_info_ptr = push_bytes(&mut body, file.module_info);
        let origin_path_ptr = file
            .bytecode_origin_path
            .map(|value| push_bytes(&mut body, value.as_bytes()));
        push_module_record(
            &mut modules,
            layout,
            TestModulePointers {
                name: name_ptr,
                contents: contents_ptr,
                sourcemap: sourcemap_ptr,
                bytecode: bytecode_ptr,
                module_info: module_info_ptr,
                bytecode_origin_path: origin_path_ptr,
            },
        );
    }

    let modules_offset = to_u32(body.len());
    body.extend_from_slice(&modules);

    let byte_count = body.len();
    let mut payload = body;
    payload.extend_from_slice(&to_u64(byte_count).to_le_bytes());
    push_string_pointer(&mut payload, modules_offset, to_u32(modules.len()));
    payload.extend_from_slice(&entry_point_id.to_le_bytes());
    push_string_pointer(&mut payload, 0, 0);
    payload.extend_from_slice(&0u32.to_le_bytes());
    payload.extend_from_slice(TRAILER);

    assert_eq!(payload.len(), byte_count + OFFSETS_SIZE_64 + TRAILER.len());
    payload
}

#[test]
fn parses_appended_standalone_graph_with_extended_records() {
    let payload = build_payload(
        &[
            TestModule {
                name: "/$bunfs/root/app.js",
                contents: b"// @bun\nconsole.log('entry');\n",
                sourcemap: b"SMAP",
                bytecode: b"BYTE",
                module_info: b"META",
                bytecode_origin_path: Some("B:/~BUN/root/app.js"),
            },
            TestModule {
                name: "B:/~BUN/root/chunk.wasm",
                contents: b"\0asm\x01\0\0\0",
                sourcemap: b"",
                bytecode: b"",
                module_info: b"",
                bytecode_origin_path: None,
            },
        ],
        0,
        TestModuleRecordLayout::Extended,
    );

    let (exe, payload_offset) = build_appended_executable(&payload);

    let inspection = inspect_executable(&exe)
        .expect("parser should not fail")
        .expect("parser should find an appended payload");
    let files = inspection.bunfs_modules().collect::<Vec<_>>();
    let [entry, chunk] = files.as_slice() else {
        panic!("expected two bunfs files");
    };

    assert_eq!(inspection.payload_file_offset, payload_offset);
    assert_eq!(inspection.record_layout_label(), "extended");
    assert_eq!(entry.virtual_path, "/$bunfs/root/app.js");
    assert_eq!(chunk.virtual_path, "/$bunfs/root/chunk.wasm");
    assert_eq!(
        inspection.entry_point_path.as_deref(),
        Some("/$bunfs/root/app.js")
    );
    assert_eq!(
        inspection.entry_point_source.as_deref(),
        Some("// @bun\nconsole.log('entry');\n")
    );
    assert_eq!(entry.sourcemap.as_deref(), Some(b"SMAP".as_slice()));
    assert_eq!(entry.bytecode.as_deref(), Some(b"BYTE".as_slice()));
    assert_eq!(entry.module_info.as_deref(), Some(b"META".as_slice()));
    assert_eq!(
        entry.bytecode_origin_path.as_deref(),
        Some("B:/~BUN/root/app.js")
    );
}

#[test]
fn parses_appended_standalone_graph_with_module_info_records() {
    let payload = build_payload(
        &[
            TestModule {
                name: "/$bunfs/root/app.js",
                contents: b"// @bun\nconsole.log('entry');\n",
                sourcemap: b"SMAP",
                bytecode: b"BYTE",
                module_info: b"META",
                bytecode_origin_path: None,
            },
            TestModule {
                name: "B:/~BUN/root/chunk.wasm",
                contents: b"\0asm\x01\0\0\0",
                sourcemap: b"",
                bytecode: b"",
                module_info: b"",
                bytecode_origin_path: None,
            },
        ],
        0,
        TestModuleRecordLayout::WithModuleInfo,
    );

    let (exe, _) = build_appended_executable(&payload);

    let inspection = inspect_executable(&exe)
        .expect("parser should not fail")
        .expect("parser should find an appended payload");
    let files = inspection.bunfs_modules().collect::<Vec<_>>();
    let [entry, ..] = files.as_slice() else {
        panic!("expected at least one bunfs file");
    };

    assert_eq!(inspection.record_layout_label(), "with-module-info");
    assert_eq!(entry.sourcemap.as_deref(), Some(b"SMAP".as_slice()));
    assert_eq!(entry.bytecode.as_deref(), Some(b"BYTE".as_slice()));
    assert_eq!(entry.module_info.as_deref(), Some(b"META".as_slice()));
    assert_eq!(entry.bytecode_origin_path, None);
}

#[test]
fn parses_appended_standalone_graph_with_compact_records() {
    let payload = build_payload(
        &[
            TestModule {
                name: "/$bunfs/root/app.js",
                contents: b"// @bun\nconsole.log('entry');\n",
                sourcemap: b"SMAP",
                bytecode: b"BYTE",
                module_info: b"",
                bytecode_origin_path: None,
            },
            TestModule {
                name: "B:/~BUN/root/chunk.wasm",
                contents: b"\0asm\x01\0\0\0",
                sourcemap: b"",
                bytecode: b"",
                module_info: b"",
                bytecode_origin_path: None,
            },
        ],
        0,
        TestModuleRecordLayout::Compact,
    );

    let (exe, payload_offset) = build_appended_executable(&payload);

    let inspection = inspect_executable(&exe)
        .expect("parser should not fail")
        .expect("parser should find an appended payload");
    let files = inspection.bunfs_modules().collect::<Vec<_>>();
    let [entry, chunk] = files.as_slice() else {
        panic!("expected two bunfs files");
    };

    assert_eq!(inspection.payload_file_offset, payload_offset);
    assert_eq!(inspection.record_layout_label(), "compact");
    assert_eq!(entry.virtual_path, "/$bunfs/root/app.js");
    assert_eq!(chunk.virtual_path, "/$bunfs/root/chunk.wasm");
    assert_eq!(
        inspection.entry_point_path.as_deref(),
        Some("/$bunfs/root/app.js")
    );
    assert_eq!(
        inspection.entry_point_source.as_deref(),
        Some("// @bun\nconsole.log('entry');\n")
    );
    assert_eq!(entry.sourcemap.as_deref(), Some(b"SMAP".as_slice()));
    assert_eq!(entry.bytecode.as_deref(), Some(b"BYTE".as_slice()));
    assert_eq!(entry.module_info, None);
}

#[test]
fn repacks_appended_standalone_graph_with_replacements() {
    let payload = build_payload(
        &[
            TestModule {
                name: "/$bunfs/root/app.js",
                contents: b"// @bun\nconsole.log('entry');\n",
                sourcemap: b"SMAP",
                bytecode: b"BYTE",
                module_info: b"META",
                bytecode_origin_path: Some("B:/~BUN/root/app.js"),
            },
            TestModule {
                name: "B:/~BUN/root/chunk.wasm",
                contents: b"\0asm\x01\0\0\0",
                sourcemap: b"",
                bytecode: b"",
                module_info: b"",
                bytecode_origin_path: None,
            },
        ],
        0,
        TestModuleRecordLayout::Extended,
    );

    let (exe, _) = build_appended_executable(&payload);

    let inspection = inspect_executable(&exe)
        .expect("parser should not fail")
        .expect("parser should find an appended payload");

    let mut replacements = HashMap::new();
    replacements.insert(
        "/$bunfs/root/app.js".to_string(),
        ReplacementParts {
            contents: Some(b"// @bun\nconsole.log('patched');\n".to_vec()),
            sourcemap: Some(b"NEW-SMAP".to_vec()),
            bytecode: None,
            module_info: Some(b"NEW-META".to_vec()),
        },
    );

    let repacked =
        repack_executable(&exe, inspection, &replacements).expect("repack should succeed");
    let patched = inspect_executable(&repacked.bytes)
        .expect("parser should not fail")
        .expect("parser should find the repacked payload");
    let files = patched.bunfs_modules().collect::<Vec<_>>();
    let [entry, ..] = files.as_slice() else {
        panic!("expected at least one bunfs file");
    };

    assert_eq!(repacked.replacement_counts.contents, 1);
    assert_eq!(repacked.replacement_counts.sourcemaps, 1);
    assert_eq!(repacked.replacement_counts.bytecodes, 0);
    assert_eq!(repacked.replacement_counts.module_infos, 1);
    assert_eq!(
        patched.entry_point_source.as_deref(),
        Some("// @bun\nconsole.log('patched');\n")
    );
    assert_eq!(entry.sourcemap.as_deref(), Some(b"NEW-SMAP".as_slice()));
    assert_eq!(entry.bytecode.as_deref(), Some(b"BYTE".as_slice()));
    assert_eq!(entry.module_info.as_deref(), Some(b"NEW-META".as_slice()));
}
