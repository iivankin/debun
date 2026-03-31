use std::{error::Error, fs, io::ErrorKind, path::Path};

use crate::{
    args::Config,
    embedded::BinaryInspection,
    js::{TransformArtifacts, symbols_report},
    pack_support::{base_executable_path, original_path_path, support_dir},
    split::{SplitModule, modules_report},
};

use super::{
    manifest::render_embedded_manifest_json, runtime::runtime_source, state::ModuleOutputs,
};

pub(super) fn remove_legacy_outputs(out_dir: &Path) -> Result<(), Box<dyn Error>> {
    remove_file_if_exists(out_dir.join("source.js"))?;
    remove_file_if_exists(out_dir.join("extracted.js"))?;
    remove_file_if_exists(out_dir.join("formatted.js"))?;
    remove_file_if_exists(out_dir.join("renamed.js"))?;
    remove_file_if_exists(out_dir.join("README.txt"))?;
    Ok(())
}

pub(super) fn write_symbols_output(
    config: &Config,
    artifacts: &TransformArtifacts,
) -> Result<Option<&'static str>, Box<dyn Error>> {
    let path = config.out_dir.join("symbols.txt");
    if config.rename_symbols && !artifacts.renames.is_empty() {
        write_file(path, &symbols_report(&artifacts.renames))?;
        Ok(Some("symbols.txt"))
    } else {
        remove_file_if_exists(path)?;
        Ok(None)
    }
}

pub(super) fn write_modules_output(
    config: &Config,
    modules: &[SplitModule],
) -> Result<Option<ModuleOutputs>, Box<dyn Error>> {
    let modules_dir = config.out_dir.join("modules");
    let modules_index = config.out_dir.join("modules.txt");

    if modules.is_empty() {
        remove_dir_if_exists(&modules_dir)?;
        remove_file_if_exists(modules_index)?;
        return Ok(None);
    }

    remove_dir_if_exists(&modules_dir)?;
    fs::create_dir_all(&modules_dir)?;
    write_file(modules_dir.join("_debun_runtime.js"), runtime_source())?;
    for module in modules {
        write_file(modules_dir.join(&module.file_name), &module.source)?;
    }
    write_file(modules_index, &modules_report(modules))?;

    Ok(Some(ModuleOutputs {
        directory: "modules",
        index: "modules.txt",
    }))
}

pub(super) fn write_warnings_output(
    config: &Config,
    artifacts: &TransformArtifacts,
) -> Result<Option<&'static str>, Box<dyn Error>> {
    let warnings_path = config.out_dir.join("warnings.txt");
    if artifacts.parse_errors.is_empty() && artifacts.semantic_errors.is_empty() {
        remove_file_if_exists(warnings_path)?;
        return Ok(None);
    }

    let mut warnings = String::new();
    append_warning_section(&mut warnings, "parse", &artifacts.parse_errors);
    append_warning_section(&mut warnings, "semantic", &artifacts.semantic_errors);
    write_file(warnings_path, &warnings)?;
    Ok(Some("warnings.txt"))
}

pub(super) fn write_embedded_outputs(
    config: &Config,
    inspection: Option<&BinaryInspection>,
) -> Result<Option<&'static str>, Box<dyn Error>> {
    let embedded_dir = config.out_dir.join("embedded");
    let Some(inspection) = inspection else {
        remove_dir_if_exists(&embedded_dir)?;
        return Ok(None);
    };

    remove_dir_if_exists(&embedded_dir)?;
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

    Ok(Some("embedded/manifest.json"))
}

pub(super) fn write_pack_support(
    config: &Config,
    inspection: Option<&BinaryInspection>,
) -> Result<Option<&'static str>, Box<dyn Error>> {
    let support_root = support_dir(&config.out_dir);
    let supports_repack = inspection
        .and_then(|value| value.standalone_graph_bytes.as_ref())
        .is_some();

    if !supports_repack {
        remove_dir_if_exists(&support_root)?;
        return Ok(None);
    }

    remove_dir_if_exists(&support_root)?;
    fs::create_dir_all(&support_root)?;

    let base_path = base_executable_path(&config.out_dir);
    fs::copy(&config.input, &base_path)?;
    fs::set_permissions(&base_path, fs::metadata(&config.input)?.permissions())?;
    write_file(
        original_path_path(&config.out_dir),
        &format!("{}\n", config.input.display()),
    )?;

    Ok(Some(".debun"))
}

pub(super) fn write_file(path: impl AsRef<Path>, contents: &str) -> Result<(), Box<dyn Error>> {
    fs::write(path, contents)?;
    Ok(())
}

fn append_warning_section(out: &mut String, name: &str, warnings: &[String]) {
    if warnings.is_empty() {
        return;
    }

    out.push('[');
    out.push_str(name);
    out.push_str("]\n");
    for warning in warnings {
        out.push_str(warning);
        out.push_str("\n\n");
    }
}

fn remove_file_if_exists(path: impl AsRef<Path>) -> Result<(), Box<dyn Error>> {
    match fs::remove_file(path.as_ref()) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err.into()),
    }
}

fn remove_dir_if_exists(path: impl AsRef<Path>) -> Result<(), Box<dyn Error>> {
    match fs::remove_dir_all(path.as_ref()) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err.into()),
    }
}
