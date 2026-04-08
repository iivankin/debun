use std::{
    error::Error,
    fs,
    path::{Path, PathBuf},
};

#[cfg(target_os = "macos")]
use std::process::Command as ProcessCommand;

pub const SUPPORT_DIR_NAME: &str = ".debun";
pub const BASE_EXECUTABLE_NAME: &str = "base-executable";
pub const ORIGINAL_PATH_NAME: &str = "original-path.txt";

pub fn support_dir(root: &Path) -> PathBuf {
    root.join(SUPPORT_DIR_NAME)
}

pub fn base_executable_path(root: &Path) -> PathBuf {
    support_dir(root).join(BASE_EXECUTABLE_NAME)
}

pub fn original_path_path(root: &Path) -> PathBuf {
    support_dir(root).join(ORIGINAL_PATH_NAME)
}

pub fn workspace_candidates(root: &Path) -> impl Iterator<Item = PathBuf> {
    let direct = root.to_path_buf();
    let parent = root.parent().map(Path::to_path_buf);
    let grandparent = root.parent().and_then(Path::parent).map(Path::to_path_buf);

    [Some(direct), parent, grandparent].into_iter().flatten()
}

pub fn read_original_input_path(root: &Path) -> Option<PathBuf> {
    workspace_candidates(root).find_map(|candidate| {
        let contents = fs::read_to_string(original_path_path(&candidate)).ok()?;
        let trimmed = contents.trim();
        (!trimmed.is_empty()).then(|| PathBuf::from(trimmed))
    })
}

pub fn resolve_workspace_root(from_dir: &Path) -> Result<PathBuf, Box<dyn Error>> {
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

pub fn resolve_replacements_root(from_dir: &Path) -> Result<PathBuf, Box<dyn Error>> {
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

pub fn resign_if_needed(path: &Path) -> Result<(), Box<dyn Error>> {
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
