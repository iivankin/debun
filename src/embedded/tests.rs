use super::{EmbeddedKind, structured::structured_embedded_files};
use crate::standalone::StandaloneFile;

#[test]
fn structured_standalone_files_include_sidecars() {
    let files = structured_embedded_files(&[StandaloneFile {
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
    }]);

    assert_eq!(files.len(), 4);
    assert_eq!(files[0].kind, EmbeddedKind::JsWrapper);
    assert_eq!(files[0].standalone_role, Some("contents"));
    assert_eq!(
        files[0].standalone_bytecode_origin_path.as_deref(),
        Some("B:/~BUN/root/index.js")
    );
    assert_eq!(files[1].kind, EmbeddedKind::StandaloneSourceMap);
    assert_eq!(
        files[1].derived_from.as_deref(),
        Some("/$bunfs/root/index.js")
    );
    assert_eq!(files[1].source_offset, 456);
    assert_eq!(files[2].kind, EmbeddedKind::StandaloneBytecode);
    assert_eq!(files[2].source_offset, 789);
    assert_eq!(files[3].kind, EmbeddedKind::StandaloneModuleInfo);
    assert_eq!(files[3].source_offset, 999);
}
