use super::decode_module_info;

const FLAG_CONTAINS_IMPORT_META: u8 = 1 << 0;

fn push_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

#[test]
fn decodes_module_info_into_structured_json_shape() {
    let mut strings_buf = Vec::new();
    strings_buf.extend_from_slice(b"foo");
    strings_buf.extend_from_slice(b"./dep.js");
    strings_buf.extend_from_slice(b"bar");

    let mut raw = Vec::new();
    push_u32(&mut raw, 3);
    raw.extend_from_slice(&[0, 2, 6]);
    raw.push(0);
    push_u32(&mut raw, strings_buf.len() as u32);
    raw.extend_from_slice(&strings_buf);
    push_u32(&mut raw, 3);
    push_u32(&mut raw, 3);
    push_u32(&mut raw, 8);
    push_u32(&mut raw, 3);
    push_u32(&mut raw, 7);
    push_u32(&mut raw, 0);
    push_u32(&mut raw, 1);
    push_u32(&mut raw, 2);
    push_u32(&mut raw, 0);
    push_u32(&mut raw, 0);
    push_u32(&mut raw, 2);
    push_u32(&mut raw, u32::MAX);
    push_u32(&mut raw, 1);
    push_u32(&mut raw, 1);
    push_u32(&mut raw, u32::MAX - 1);
    raw.push(FLAG_CONTAINS_IMPORT_META);
    raw.extend_from_slice(&[0, 0, 0]);

    let decoded = decode_module_info(&raw).expect("module_info should decode");

    assert!(decoded.contains_import_meta);
    assert!(!decoded.is_typescript);
    assert_eq!(decoded.declared_variables, vec!["foo"]);
    assert_eq!(decoded.lexical_variables.len(), 0);
    assert_eq!(decoded.imports.len(), 1);
    assert_eq!(decoded.imports[0].kind, "single");
    assert_eq!(decoded.imports[0].module, "./dep.js");
    assert_eq!(decoded.imports[0].import_name, "bar");
    assert_eq!(decoded.imports[0].local_name, "foo");
    assert_eq!(decoded.exports.len(), 1);
    assert_eq!(decoded.exports[0].kind, "local");
    assert_eq!(decoded.exports[0].export_name.as_deref(), Some("foo"));
    assert_eq!(decoded.exports[0].local_name.as_deref(), Some("bar"));
    assert_eq!(decoded.requested_modules.len(), 1);
    assert_eq!(decoded.requested_modules[0].module, "./dep.js");
    assert_eq!(decoded.requested_modules[0].attributes_kind, "javascript");

    let rendered = decoded.render_json();
    assert!(rendered.contains("\"contains_import_meta\":true"));
    assert!(rendered.contains("\"declared_variables\":[\"foo\"]"));
    assert!(rendered.contains("\"attributes_kind\":\"javascript\""));
}
