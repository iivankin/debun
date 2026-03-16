use std::{collections::BTreeMap, error::Error, fs, path::Path};

use super::{
    args::Config,
    embedded::BinaryInspection,
    extract::ExtractedSource,
    js::{TransformArtifacts, symbols_report},
    split::modules_report,
};

pub struct OutputSummary {
    pub primary_output: Option<String>,
    pub wrote_symbols: bool,
    pub wrote_modules: bool,
    pub wrote_embedded_manifest: bool,
    pub wrote_warnings: bool,
}

pub fn write_outputs(
    config: &Config,
    extracted: &ExtractedSource,
    inspection: Option<&BinaryInspection>,
    artifacts: &TransformArtifacts,
) -> Result<OutputSummary, Box<dyn Error>> {
    let wrote_symbols = config.rename_symbols && !artifacts.renames.is_empty();

    remove_if_exists(config.out_dir.join("source.js"))?;
    remove_if_exists(config.out_dir.join("extracted.js"))?;
    remove_if_exists(config.out_dir.join("formatted.js"))?;
    remove_if_exists(config.out_dir.join("renamed.js"))?;
    if wrote_symbols {
        write_file(
            config.out_dir.join("symbols.txt"),
            &symbols_report(&artifacts.renames),
        )?;
    } else {
        remove_if_exists(config.out_dir.join("symbols.txt"))?;
    }
    remove_if_exists(config.out_dir.join("README.txt"))?;

    let wrote_modules = if !artifacts.modules.is_empty() {
        let modules_dir = config.out_dir.join("modules");
        if modules_dir.exists() {
            fs::remove_dir_all(&modules_dir)?;
        }
        fs::create_dir_all(&modules_dir)?;
        write_file(modules_dir.join("_debun_runtime.js"), runtime_source())?;
        for module in &artifacts.modules {
            write_file(modules_dir.join(&module.file_name), &module.source)?;
        }
        write_file(
            config.out_dir.join("modules.txt"),
            &modules_report(&artifacts.modules),
        )?;
        true
    } else {
        let modules_dir = config.out_dir.join("modules");
        if modules_dir.exists() {
            fs::remove_dir_all(modules_dir)?;
        }
        let modules_report_path = config.out_dir.join("modules.txt");
        if modules_report_path.exists() {
            fs::remove_file(modules_report_path)?;
        }
        false
    };

    let wrote_embedded_manifest = write_embedded_outputs(config, inspection)?;

    let wrote_warnings =
        if !artifacts.parse_errors.is_empty() || !artifacts.semantic_errors.is_empty() {
            let mut warnings = String::new();
            if !artifacts.parse_errors.is_empty() {
                warnings.push_str("[parse]\n");
                for warning in &artifacts.parse_errors {
                    warnings.push_str(warning);
                    warnings.push_str("\n\n");
                }
            }
            if !artifacts.semantic_errors.is_empty() {
                warnings.push_str("[semantic]\n");
                for warning in &artifacts.semantic_errors {
                    warnings.push_str(warning);
                    warnings.push_str("\n\n");
                }
            }
            write_file(config.out_dir.join("warnings.txt"), &warnings)?;
            true
        } else {
            remove_if_exists(config.out_dir.join("warnings.txt"))?;
            false
        };
    let primary_output = if wrote_modules {
        Some("modules.txt".to_string())
    } else if wrote_embedded_manifest {
        Some("embedded/manifest.json".to_string())
    } else if wrote_warnings {
        Some("warnings.txt".to_string())
    } else if wrote_symbols {
        Some("symbols.txt".to_string())
    } else {
        None
    };

    write_file(
        config.out_dir.join("summary.json"),
        &render_summary_json(
            config,
            extracted,
            inspection,
            artifacts,
            &OutputSummary {
                primary_output: primary_output.clone(),
                wrote_symbols,
                wrote_modules,
                wrote_embedded_manifest,
                wrote_warnings,
            },
        ),
    )?;

    Ok(OutputSummary {
        primary_output,
        wrote_symbols,
        wrote_modules,
        wrote_embedded_manifest,
        wrote_warnings,
    })
}

fn write_file(path: impl AsRef<Path>, contents: &str) -> Result<(), Box<dyn Error>> {
    fs::write(path, contents)?;
    Ok(())
}

fn remove_if_exists(path: impl AsRef<Path>) -> Result<(), Box<dyn Error>> {
    let path = path.as_ref();
    if path.exists() {
        fs::remove_file(path)?;
    }
    Ok(())
}

fn write_embedded_outputs(
    config: &Config,
    inspection: Option<&BinaryInspection>,
) -> Result<bool, Box<dyn Error>> {
    let embedded_dir = config.out_dir.join("embedded");
    if let Some(inspection) = inspection {
        if embedded_dir.exists() {
            fs::remove_dir_all(&embedded_dir)?;
        }
        fs::create_dir_all(&embedded_dir)?;
        write_file(
            embedded_dir.join("manifest.json"),
            &render_embedded_manifest_json(inspection),
        )?;

        let files_dir = embedded_dir.join("files");
        fs::create_dir_all(&files_dir)?;
        for file in &inspection.files {
            let tree_path = files_dir.join(file.virtual_path.trim_start_matches('/'));
            if let Some(parent) = tree_path.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::write(tree_path, &file.bytes)?;
        }
        Ok(true)
    } else if embedded_dir.exists() {
        fs::remove_dir_all(&embedded_dir)?;
        Ok(false)
    } else {
        Ok(false)
    }
}

fn render_summary_json(
    config: &Config,
    extracted: &ExtractedSource,
    inspection: Option<&BinaryInspection>,
    artifacts: &TransformArtifacts,
    outputs: &OutputSummary,
) -> String {
    let embedded_files = inspection.map(|value| value.files.len()).unwrap_or(0);
    let fields = vec![
        json_field("input", &config.input.display().to_string()),
        json_field("module_name", &config.module_name),
        json_bool_field("rename_enabled", config.rename_symbols),
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
            "\"outputs\":{{\"primary\":{},\"symbols\":{},\"modules_dir\":{},\"modules_index\":{},\"embedded_manifest\":{},\"warnings\":{}}}",
            option_json_string(outputs.primary_output.as_deref()),
            option_json_string(outputs.wrote_symbols.then_some("symbols.txt")),
            option_json_string(outputs.wrote_modules.then_some("modules")),
            option_json_string(outputs.wrote_modules.then_some("modules.txt")),
            option_json_string(
                outputs
                    .wrote_embedded_manifest
                    .then_some("embedded/manifest.json")
            ),
            option_json_string(outputs.wrote_warnings.then_some("warnings.txt"))
        ),
    ];

    format!("{{{}}}\n", fields.join(","))
}

fn render_embedded_manifest_json(inspection: &BinaryInspection) -> String {
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
        .map(|file| {
            format!(
                "{{\"path\":{},\"kind\":{},\"size\":{},\"source_offset\":{}}}",
                json_string(&file.virtual_path),
                json_string(file.kind.label()),
                file.bytes.len(),
                file.source_offset
            )
        })
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
            "\"graph_file_offset\":{},\"graph_size\":{},\"entry_point\":{}",
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
        option_json_string(inspection.entry_point_path.as_deref()),
        metadata_json,
        inspection.bunfs_paths.len(),
        inspection.files.len(),
        missing_json,
        files_json
    )
}

fn json_field(name: &str, value: &str) -> String {
    format!("{}:{}", json_string(name), json_string(value))
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

fn runtime_source() -> &'static str {
    r#"function copyProps(target, source, reexportTarget) {
  const propertyNames = Object.getOwnPropertyNames(source);
  for (const propertyName of propertyNames) {
    if (!Object.prototype.hasOwnProperty.call(target, propertyName) && propertyName !== "default") {
      Object.defineProperty(target, propertyName, {
        get: () => source[propertyName],
        enumerable: true
      });
    }
  }
  if (!reexportTarget) {
    return;
  }
  for (const propertyName of propertyNames) {
    if (!Object.prototype.hasOwnProperty.call(reexportTarget, propertyName) && propertyName !== "default") {
      Object.defineProperty(reexportTarget, propertyName, {
        get: () => source[propertyName],
        enumerable: true
      });
    }
  }
  return reexportTarget;
}

const toESMCache = new WeakMap();
const toESMNodeCache = new WeakMap();

function toESM(value, isNodeMode, target) {
  const isObjectLike = value != null && typeof value === "object";
  if (isObjectLike) {
    const cache = isNodeMode ? toESMNodeCache : toESMCache;
    const cached = cache.get(value);
    if (cached) {
      return cached;
    }
    target = Object.create(Object.getPrototypeOf(value));
    const namespace = isNodeMode || !value || !value.__esModule ? Object.defineProperty(target, "default", {
      value,
      enumerable: true
    }) : target;
    for (const propertyName of Object.getOwnPropertyNames(value)) {
      if (!Object.prototype.hasOwnProperty.call(namespace, propertyName)) {
        Object.defineProperty(namespace, propertyName, {
          get: () => value[propertyName],
          enumerable: true
        });
      }
    }
    cache.set(value, namespace);
    return namespace;
  }
  target = value != null ? Object.create(Object.getPrototypeOf(value)) : {};
  return isNodeMode || !value || !value.__esModule ? Object.defineProperty(target, "default", {
    value,
    enumerable: true
  }) : target;
}

const toCommonJSCache = new WeakMap();

function toCommonJS(value) {
  const cached = toCommonJSCache.get(value);
  if (cached) {
    return cached;
  }
  const namespace = Object.defineProperty({}, "__esModule", { value: true });
  if ((value && typeof value === "object") || typeof value === "function") {
    for (const propertyName of Object.getOwnPropertyNames(value)) {
      if (!Object.prototype.hasOwnProperty.call(namespace, propertyName)) {
        const descriptor = Object.getOwnPropertyDescriptor(value, propertyName);
        Object.defineProperty(namespace, propertyName, {
          get: () => value[propertyName],
          enumerable: !descriptor || descriptor.enumerable
        });
      }
    }
  }
  toCommonJSCache.set(value, namespace);
  return namespace;
}

function defineExports(target, spec) {
  for (const propertyName in spec) {
    Object.defineProperty(target, propertyName, {
      get: spec[propertyName],
      enumerable: true,
      configurable: true,
      set(value) {
        spec[propertyName] = () => value;
      }
    });
  }
}

function createLazyInit(init) {
  let initialized = false;
  let cache;
  return function initOnce() {
    if (initialized) {
      return cache;
    }
    initialized = true;
    cache = init();
    return cache;
  };
}

module.exports = {
  copyProps,
  createLazyInit,
  defineExports,
  toCommonJS,
  toESM
};
"#
}
