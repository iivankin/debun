use std::{
    collections::HashSet,
    error::Error,
    ffi::OsString,
    fs::{self, OpenOptions},
    io::{ErrorKind, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use crate::{
    args::Config,
    embedded::BinaryInspection,
    js::{TransformArtifacts, symbols_report},
    pack_support::{BASE_EXECUTABLE_NAME, ORIGINAL_PATH_NAME, support_dir},
    split::{SplitModule, modules_report},
    workspace_path::WorkspacePath,
};

use super::{
    manifest::render_embedded_manifest_json, runtime::runtime_source, state::ModuleOutputs,
};

static TEMP_DIRECTORY_COUNTER: AtomicU64 = AtomicU64::new(0);

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

    let files_dir = embedded_dir.join("files");
    let mut file_outputs = Vec::with_capacity(inspection.files.len());
    let mut output_paths = HashSet::with_capacity(inspection.files.len());
    for file in &inspection.files {
        let path = WorkspacePath::from_virtual(&file.virtual_path)?.join_under(&files_dir);
        if !output_paths.insert(path.clone()) {
            return Err(format!("multiple embedded files mapped to {}", path.display()).into());
        }
        file_outputs.push((path, file));
    }

    remove_dir_if_exists(&embedded_dir)?;
    fs::create_dir_all(&embedded_dir)?;
    write_file(
        embedded_dir.join("manifest.json"),
        &render_embedded_manifest_json(inspection),
    )?;

    fs::create_dir_all(&files_dir)?;
    for (tree_path, file) in file_outputs {
        if let Some(parent) = tree_path.parent() {
            fs::create_dir_all(parent)?;
        }
        write_new_file(&tree_path, &file.bytes)?;
    }

    Ok(Some("embedded/manifest.json"))
}

fn write_new_file(path: &Path, contents: &[u8]) -> Result<(), Box<dyn Error>> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(contents)?;
    Ok(())
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

    replace_pack_support(&config.input, &config.out_dir)?;
    Ok(Some(".debun"))
}

fn replace_pack_support(input: &Path, out_dir: &Path) -> Result<(), Box<dyn Error>> {
    let support_root = support_dir(out_dir);
    let staged_root = create_temporary_sibling_directory(&support_root)?;
    let prepared = (|| -> Result<(), Box<dyn Error>> {
        let staged_base_path = staged_root.join(BASE_EXECUTABLE_NAME);
        let permissions = fs::metadata(input)?.permissions();
        fs::copy(input, &staged_base_path)?;
        fs::set_permissions(&staged_base_path, permissions)?;
        write_file(
            staged_root.join(ORIGINAL_PATH_NAME),
            &format!("{}\n", input.display()),
        )?;
        Ok(())
    })();
    if let Err(error) = prepared {
        let _ = fs::remove_dir_all(&staged_root);
        return Err(error);
    }

    remove_dir_if_exists(&support_root)?;
    if let Err(error) = fs::rename(&staged_root, &support_root) {
        let _ = fs::remove_dir_all(&staged_root);
        return Err(error.into());
    }
    Ok(())
}

fn create_temporary_sibling_directory(path: &Path) -> Result<PathBuf, Box<dyn Error>> {
    let parent = path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .ok_or_else(|| format!("output directory {} had no file name", path.display()))?;

    for _ in 0..32 {
        let id = TEMP_DIRECTORY_COUNTER.fetch_add(1, Ordering::Relaxed);
        let mut temporary_name = OsString::from(".");
        temporary_name.push(file_name);
        temporary_name.push(format!(".debun-tmp-{}-{id}", std::process::id()));
        let temporary_path = parent.join(temporary_name);
        match fs::create_dir(&temporary_path) {
            Ok(()) => return Ok(temporary_path),
            Err(error) if error.kind() == ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error.into()),
        }
    }

    Err(format!(
        "could not create a temporary directory next to {}",
        path.display()
    )
    .into())
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

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    #[test]
    fn preserves_base_executable_when_replacing_its_own_support_directory() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("debun-reunpack-{nonce}"));
        let support = support_dir(&root);
        let input = support.join(BASE_EXECUTABLE_NAME);
        fs::create_dir_all(&support).unwrap();
        fs::write(&input, b"original executable").unwrap();

        replace_pack_support(&input, &root).unwrap();

        assert_eq!(fs::read(&input).unwrap(), b"original executable");
        assert_eq!(
            fs::read_to_string(support.join(ORIGINAL_PATH_NAME)).unwrap(),
            format!("{}\n", input.display())
        );
        fs::remove_dir_all(root).unwrap();
    }
}
