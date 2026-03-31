use super::decode_module_info;

const FLAG_CONTAINS_IMPORT_META: u8 = 1 << 0;

fn push_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn to_u32(value: usize) -> u32 {
    u32::try_from(value).expect("test payload exceeded u32")
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
    push_u32(&mut raw, to_u32(strings_buf.len()));
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
    let [import] = decoded.imports.as_slice() else {
        panic!("expected one decoded import");
    };
    let [export] = decoded.exports.as_slice() else {
        panic!("expected one decoded export");
    };
    let [requested_module] = decoded.requested_modules.as_slice() else {
        panic!("expected one requested module");
    };

    assert!(decoded.contains_import_meta);
    assert!(!decoded.is_typescript);
    assert_eq!(decoded.declared_variables, vec!["foo"]);
    assert!(decoded.lexical_variables.is_empty());
    assert_eq!(import.kind, "single");
    assert_eq!(import.module, "./dep.js");
    assert_eq!(import.import_name, "bar");
    assert_eq!(import.local_name, "foo");
    assert_eq!(export.kind, "local");
    assert_eq!(export.export_name.as_deref(), Some("foo"));
    assert_eq!(export.local_name.as_deref(), Some("bar"));
    assert_eq!(requested_module.module, "./dep.js");
    assert_eq!(requested_module.attributes_kind, "javascript");

    let rendered = decoded.render_json();
    assert!(rendered.contains("\"contains_import_meta\":true"));
    assert!(rendered.contains("\"declared_variables\":[\"foo\"]"));
    assert!(rendered.contains("\"attributes_kind\":\"javascript\""));
}
