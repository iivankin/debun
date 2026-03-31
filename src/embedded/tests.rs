use super::{EmbeddedKind, structured::structured_embedded_files};
use crate::standalone::StandaloneModule;

#[test]
fn structured_standalone_files_include_sidecars() {
    let module = StandaloneModule {
        original_path: "/$bunfs/root/index.js".to_string(),
        virtual_path: "/$bunfs/root/index.js".to_string(),
        source_offset: 123,
        bytes: b"// @bun\nconsole.log('entry');\n".to_vec(),
        sourcemap: Some(b"SMAP".to_vec()),
        sourcemap_offset: Some(456),
        bytecode: Some(b"BYTE".to_vec()),
        bytecode_offset: Some(789),
        module_info: Some(b"META".to_vec()),
        module_info_offset: Some(999),
        bytecode_origin_path: Some("B:/~BUN/root/index.js".to_string()),
        encoding: 1,
        loader: 1,
        module_format: 1,
        side: 0,
    };
    let files = structured_embedded_files([&module]);
    let [contents, sourcemap, bytecode, module_info] = files.as_slice() else {
        panic!("expected contents plus three standalone sidecars");
    };

    assert_eq!(contents.kind, EmbeddedKind::JsWrapper);
    assert_eq!(contents.standalone_role, Some("contents"));
    assert_eq!(
        contents.standalone_bytecode_origin_path.as_deref(),
        Some("B:/~BUN/root/index.js")
    );
    assert_eq!(sourcemap.kind, EmbeddedKind::StandaloneSourceMap);
    assert_eq!(
        sourcemap.derived_from.as_deref(),
        Some("/$bunfs/root/index.js")
    );
    assert_eq!(sourcemap.source_offset, 456);
    assert_eq!(bytecode.kind, EmbeddedKind::StandaloneBytecode);
    assert_eq!(bytecode.source_offset, 789);
    assert_eq!(module_info.kind, EmbeddedKind::StandaloneModuleInfo);
    assert_eq!(module_info.source_offset, 999);
}
