use std::collections::BTreeMap;

use crate::{
    args::Config, embedded::BinaryInspection, extract::ExtractedSource, js::TransformArtifacts,
};

use super::OutputSummary;

pub(super) fn render_summary_json(
    config: &Config,
    extracted: &ExtractedSource,
    inspection: Option<&BinaryInspection>,
    artifacts: &TransformArtifacts,
    outputs: &OutputSummary,
) -> String {
    let embedded_files = inspection.map(|value| value.files.len()).unwrap_or(0);
    let fields = [
        json_field("input", &config.input.display().to_string()),
        json_field("module_name", &config.module_name),
        json_bool_field("rename_enabled", config.rename_symbols),
        json_bool_field("unbundle_enabled", config.unbundle),
        format!(
            "\"source\":{{\"trimmed_prefix\":{},\"trimmed_suffix\":{},\"had_nul_terminator\":{}}}",
            extracted.trimmed_prefix,
            extracted.trimmed_suffix,
            if extracted.had_nul_terminator {
                "true"
            } else {
                "false"
            }
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
            option_json_string(outputs.primary_output.as_deref()),
            option_json_string(outputs.wrote_symbols.then_some("symbols.txt")),
            option_json_string(outputs.wrote_modules.then_some("modules")),
            option_json_string(outputs.wrote_modules.then_some("modules.txt")),
            option_json_string(
                outputs
                    .wrote_embedded_manifest
                    .then_some("embedded/manifest.json")
            ),
            option_json_string(outputs.wrote_pack_support.then_some(".debun")),
            option_json_string(outputs.wrote_warnings.then_some("warnings.txt"))
        ),
    ];

    format!("{{{}}}\n", fields.join(","))
}

pub(super) fn render_embedded_manifest_json(inspection: &BinaryInspection) -> String {
    let extracted = inspection
        .files
        .iter()
        .map(|file| file.virtual_path.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    let missing_paths = inspection
        .bunfs_paths
        .iter()
        .filter(|path| !extracted.contains(path.as_str()))
        .cloned()
        .collect::<Vec<_>>();
    let metadata = inspection
        .metadata
        .iter()
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect::<BTreeMap<_, _>>();

    let files_json = inspection
        .files
        .iter()
        .map(render_embedded_file_json)
        .collect::<Vec<_>>()
        .join(",");

    let metadata_json = metadata
        .iter()
        .map(|(key, value)| format!("{}:{}", json_string(key), json_string(value)))
        .collect::<Vec<_>>()
        .join(",");

    let missing_json = missing_paths
        .iter()
        .map(|path| json_string(path))
        .collect::<Vec<_>>()
        .join(",");

    format!(
        concat!(
            "{{",
            "\"container\":{{",
            "\"name\":{},\"file_offset\":{},\"headerless_offset\":{},\"section_size\":{},",
            "\"graph_file_offset\":{},\"graph_size\":{},\"standalone_layout\":{},",
            "\"standalone_record_size\":{},\"bun_version\":{},\"entry_point\":{}",
            "}},",
            "\"metadata\":{{{}}},",
            "\"files_dir\":\"files\",",
            "\"bunfs_paths\":{},",
            "\"extracted_files\":{},",
            "\"missing_paths\":[{}],",
            "\"files\":[{}]",
            "}}\n"
        ),
        option_json_string(inspection.bun_section_name.as_deref()),
        option_json_usize(inspection.bun_section_file_offset),
        option_json_usize(inspection.bun_section_headerless_offset),
        inspection.bun_section_bytes.len(),
        option_json_usize(inspection.standalone_graph_file_offset),
        option_json_usize(inspection.standalone_graph_bytes.as_ref().map(Vec::len)),
        option_json_string(inspection.standalone_layout),
        option_json_usize(inspection.standalone_record_size),
        option_json_string(inspection.bun_version.as_deref()),
        option_json_string(inspection.entry_point_path.as_deref()),
        metadata_json,
        inspection.bunfs_paths.len(),
        inspection.files.len(),
        missing_json,
        files_json
    )
}

fn render_embedded_file_json(file: &crate::embedded::EmbeddedFile) -> String {
    let mut fields = vec![
        json_field("path", &file.virtual_path),
        json_field("kind", file.kind.label()),
        json_usize_field("size", file.bytes.len()),
        json_usize_field("source_offset", file.source_offset),
    ];

    if let Some(derived_from) = &file.derived_from {
        fields.push(json_field("derived_from", derived_from));
    }
    if let Some(role) = file.standalone_role {
        fields.push(json_field("standalone_role", role));
    }
    if let Some(encoding) = file.standalone_encoding {
        fields.push(json_field("encoding", encoding));
    }
    if let Some(loader_id) = file.standalone_loader_id {
        fields.push(json_usize_field("loader_id", usize::from(loader_id)));
    }
    if let Some(module_format) = file.standalone_module_format {
        fields.push(json_field("module_format", module_format));
    }
    if let Some(side) = file.standalone_side {
        fields.push(json_field("side", side));
    }
    if let Some(origin_path) = &file.standalone_bytecode_origin_path {
        fields.push(json_field("bytecode_origin_path", origin_path));
    }

    format!("{{{}}}", fields.join(","))
}

fn json_field(name: &str, value: &str) -> String {
    format!("{}:{}", json_string(name), json_string(value))
}

fn json_usize_field(name: &str, value: usize) -> String {
    format!("{}:{}", json_string(name), value)
}

fn json_bool_field(name: &str, value: bool) -> String {
    format!(
        "{}:{}",
        json_string(name),
        if value { "true" } else { "false" }
    )
}

fn option_json_string(value: Option<&str>) -> String {
    value.map(json_string).unwrap_or_else(|| "null".to_string())
}

fn option_json_usize(value: Option<usize>) -> String {
    value
        .map(|value| value.to_string())
        .unwrap_or_else(|| "null".to_string())
}

fn json_string(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            ch if ch.is_control() => {
                use std::fmt::Write as _;
                let _ = write!(out, "\\u{:04x}", ch as u32);
            }
            ch => out.push(ch),
        }
    }
    out.push('"');
    out
}
