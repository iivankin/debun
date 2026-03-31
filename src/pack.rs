use std::{
    collections::HashMap,
    error::Error,
    fs,
    path::{Path, PathBuf},
};

#[cfg(target_os = "macos")]
use std::process::Command as ProcessCommand;

use crate::{
    args::PackConfig,
    pack_support::base_executable_path,
    standalone::{ReplacementParts, inspect_executable, repack_executable},
};

pub struct PackSummary {
    pub replacements_root: PathBuf,
    pub replaced_contents: usize,
    pub replaced_sourcemaps: usize,
    pub replaced_bytecodes: usize,
    pub replaced_module_infos: usize,
}

pub fn pack_binary(config: &PackConfig) -> Result<PackSummary, Box<dyn Error>> {
    let workspace_root = resolve_pack_workspace(&config.from_dir)?;
    let base_executable = base_executable_path(&workspace_root);
    let original_bytes = fs::read(&base_executable)?;
    let original_permissions = fs::metadata(&base_executable)?.permissions();
    let inspection = inspect_executable(&original_bytes)?
        .ok_or("pack only supports Bun standalone executables")?;
    let replacements_root = resolve_replacements_root(&workspace_root)?;
    let replacements = collect_replacements(&replacements_root, &inspection.files)?;
    let repacked = repack_executable(&original_bytes, inspection, &replacements)?;

    if let Some(parent) = config
        .out_file
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)?;
    }
    fs::write(&config.out_file, repacked.bytes)?;
    fs::set_permissions(&config.out_file, original_permissions)?;
    resign_if_needed(&config.out_file)?;

    Ok(PackSummary {
        replacements_root,
        replaced_contents: repacked.replaced_contents,
        replaced_sourcemaps: repacked.replaced_sourcemaps,
        replaced_bytecodes: repacked.replaced_bytecodes,
        replaced_module_infos: repacked.replaced_module_infos,
    })
}

fn collect_replacements(
    root: &Path,
    files: &[crate::standalone::StandaloneFile],
) -> Result<HashMap<String, ReplacementParts>, Box<dyn Error>> {
    let mut replacements = HashMap::new();

    for file in files {
        let contents = read_if_exists(root, &file.virtual_path)?;
        let sourcemap =
            read_if_exists(root, &format!("{}.debun-sourcemap.bin", file.virtual_path))?;
        let bytecode = read_if_exists(root, &format!("{}.debun-bytecode.bin", file.virtual_path))?;
        let module_info = read_if_exists(
            root,
            &format!("{}.debun-module-info.bin", file.virtual_path),
        )?;

        if contents.is_none() && sourcemap.is_none() && bytecode.is_none() && module_info.is_none()
        {
            continue;
        }

        replacements.insert(
            file.virtual_path.clone(),
            ReplacementParts {
                contents,
                sourcemap,
                bytecode,
                module_info,
            },
        );
    }

    Ok(replacements)
}

fn read_if_exists(root: &Path, virtual_path: &str) -> Result<Option<Vec<u8>>, Box<dyn Error>> {
    let path = root.join(virtual_path.trim_start_matches('/'));
    if !path.is_file() {
        return Ok(None);
    }

    Ok(Some(fs::read(path)?))
}

fn resolve_replacements_root(from_dir: &Path) -> Result<PathBuf, Box<dyn Error>> {
    for candidate in [
        from_dir.join("embedded").join("files"),
        from_dir.join("files"),
        from_dir.to_path_buf(),
    ] {
        if candidate.is_dir() {
            return Ok(candidate);
        }
    }

    Err(format!(
        "replacement root was not found under {}",
        from_dir.display()
    )
    .into())
}

fn resolve_pack_workspace(from_dir: &Path) -> Result<PathBuf, Box<dyn Error>> {
    for candidate in workspace_candidates(from_dir) {
        if base_executable_path(&candidate).is_file() {
            return Ok(candidate);
        }
    }

    Err(format!(
        "repack support was not found under {}. Run debun on the original standalone binary first so it can save .debun/base-executable.",
        from_dir.display()
    )
    .into())
}

fn workspace_candidates(from_dir: &Path) -> impl Iterator<Item = PathBuf> {
    let direct = from_dir.to_path_buf();
    let parent = from_dir.parent().map(Path::to_path_buf);
    let grandparent = from_dir
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf);

    [Some(direct), parent, grandparent].into_iter().flatten()
}

fn resign_if_needed(path: &Path) -> Result<(), Box<dyn Error>> {
    #[cfg(target_os = "macos")]
    {
        // Repacking mutates Mach-O bytes in place, which invalidates the embedded
        // signature from the original app bundle. Re-sign ad-hoc so the output
        // remains directly executable on the local machine.
        let output = ProcessCommand::new("codesign")
            .args([
                "--force",
                "--sign",
                "-",
                "--preserve-metadata=entitlements,requirements,flags,runtime",
            ])
            .arg(path)
            .output()?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
            let details = if !stderr.is_empty() {
                stderr
            } else if !stdout.is_empty() {
                stdout
            } else {
                "codesign returned a non-zero exit status".to_string()
            };

            return Err(format!(
                "failed to re-sign packed binary {}: {}",
                path.display(),
                details
            )
            .into());
        }
    }

    #[cfg(not(target_os = "macos"))]
    {
        let _ = path;
    }

    Ok(())
}
