use std::{error::Error, fs, path::Path};

use super::{
    args::Config,
    embedded::BinaryInspection,
    extract::ExtractedSource,
    js::{TransformArtifacts, symbols_report},
    split::modules_report,
};

mod json;
mod runtime;

use json::{render_embedded_manifest_json, render_summary_json};
use runtime::runtime_source;

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
