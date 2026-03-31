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
    pack_support::{base_executable_path, workspace_candidates},
    standalone::{
        ReplacementCounts, ReplacementParts, StandaloneModule, StandaloneSidecarKind,
        inspect_executable, repack_executable,
    },
};

pub(crate) struct PackSummary {
    pub(crate) replacements_root: PathBuf,
    pub(crate) replacement_counts: ReplacementCounts,
}

pub fn pack_binary(config: &PackConfig) -> Result<PackSummary, Box<dyn Error>> {
    let workspace_root = resolve_pack_workspace(&config.from_dir)?;
    let base_executable = base_executable_path(&workspace_root);
    let original_bytes = fs::read(&base_executable)?;
    let original_permissions = fs::metadata(&base_executable)?.permissions();
    let standalone = inspect_executable(&original_bytes)?
        .ok_or("pack only supports Bun standalone executables")?;
    let replacements_root = resolve_replacements_root(&workspace_root)?;
    let replacements = collect_replacements(&replacements_root, standalone.bunfs_modules())?;
    let repacked = repack_executable(&original_bytes, standalone, &replacements)?;

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
        replacement_counts: repacked.replacement_counts,
    })
}

fn collect_replacements<'a>(
    root: &Path,
    modules: impl IntoIterator<Item = &'a StandaloneModule>,
) -> Result<HashMap<String, ReplacementParts>, Box<dyn Error>> {
    let mut replacements = HashMap::new();

    for module in modules {
        let contents = read_if_exists(root, &module.virtual_path)?;
        let sourcemap = read_if_exists(
            root,
            &module.sidecar_path(StandaloneSidecarKind::SourceMapBinary),
        )?;
        let bytecode = read_if_exists(
            root,
            &module.sidecar_path(StandaloneSidecarKind::BytecodeBinary),
        )?;
        let module_info = read_if_exists(
            root,
            &module.sidecar_path(StandaloneSidecarKind::ModuleInfoBinary),
        )?;

        let replacement = ReplacementParts {
            contents,
            sourcemap,
            bytecode,
            module_info,
        };
        if replacement.is_empty() {
            continue;
        }

        replacements.insert(module.virtual_path.clone(), replacement);
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
