use super::{analysis::infer_runtime_helper, analyze_lazy_exports, collect_external_bundle_refs};

#[test]
fn collects_generic_bundle_refs() {
    let refs = collect_external_bundle_refs(
        "bundle_var_1(); bundle_fn_2(); let local_var_3 = 1; local_var_3;",
    )
    .expect("collector should parse");

    assert_eq!(
        refs,
        vec!["bundle_fn_2".to_string(), "bundle_var_1".to_string()]
    );
}

#[test]
fn tracks_ts_wrapped_assignment_targets_in_lazy_export_analysis() {
    let analysis =
        analyze_lazy_exports("", "(bundle_var_1 as any) = 1;").expect("analysis should parse");

    assert_eq!(analysis.exports, vec!["bundle_var_1".to_string()]);
    assert!(analysis.support_bindings.is_empty());
}

#[test]
fn infers_runtime_helper_from_function_body() {
    let helper = infer_runtime_helper(
        "{ const keys = Object.keys(spec); for (const key of keys) Object.defineProperty(target, key, { get: spec[key], enumerable: true }); }",
    );

    assert_eq!(helper, Some("__debun.defineExports"));
}
