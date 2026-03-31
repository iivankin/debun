use crate::{
    args::Config,
    embedded::BinaryInspection,
    extract::ExtractedSource,
    js::TransformArtifacts,
    json::{json_bool, json_field},
};

use super::WrittenOutputs;

pub(super) fn render_summary_json(
    config: &Config,
    extracted_source: &ExtractedSource,
    inspection: Option<&BinaryInspection>,
    artifacts: &TransformArtifacts,
    outputs: &WrittenOutputs,
) -> String {
    let embedded_files = inspection.map_or(0, |value| value.files.len());
    let fields = [
        json_field("input", &config.input.display().to_string()),
        json_field("module_name", &config.module_name),
        json_bool_field("rename_enabled", config.rename_symbols),
        json_bool_field("unbundle_enabled", config.unbundle),
        format!(
            "\"source\":{{\"trimmed_prefix\":{},\"trimmed_suffix\":{},\"had_nul_terminator\":{}}}",
            extracted_source.trimmed_prefix,
            extracted_source.trimmed_suffix,
            json_bool(extracted_source.had_nul_terminator())
        ),
        format!(
            "\"stats\":{{\"renamed_symbols\":{},\"split_modules\":{},\"parse_warnings\":{},\"semantic_warnings\":{},\"embedded_files\":{}}}",
            artifacts.renames.len(),
            artifacts.modules.len(),
            artifacts.parse_errors.len(),
            artifacts.semantic_errors.len(),
            embedded_files
        ),
        format!(
            "\"outputs\":{{\"primary\":{},\"symbols\":{},\"modules_dir\":{},\"modules_index\":{},\"embedded_manifest\":{},\"pack_support\":{},\"warnings\":{}}}",
            option_json_string(outputs.primary_output()),
            option_json_string(outputs.symbols),
            option_json_string(outputs.modules.map(|value| value.directory)),
            option_json_string(outputs.modules.map(|value| value.index)),
            option_json_string(outputs.embedded_manifest),
            option_json_string(outputs.pack_support),
            option_json_string(outputs.warnings)
        ),
    ];

    format!("{{{}}}\n", fields.join(","))
}

fn json_bool_field(name: &str, value: bool) -> String {
    format!("{}:{}", crate::json::json_string(name), json_bool(value))
}

fn option_json_string(value: Option<&str>) -> String {
    value.map_or_else(|| "null".to_string(), crate::json::json_string)
}
