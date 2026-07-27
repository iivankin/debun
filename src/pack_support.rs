use std::{
    error::Error,
    ffi::OsString,
    fs::{self, OpenOptions, Permissions},
    io::Write,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

#[cfg(target_os = "macos")]
use std::{io::Read, process::Command as ProcessCommand};

pub const SUPPORT_DIR_NAME: &str = ".debun";
pub const BASE_EXECUTABLE_NAME: &str = "base-executable";
pub const ORIGINAL_PATH_NAME: &str = "original-path.txt";

static TEMP_FILE_COUNTER: AtomicU64 = AtomicU64::new(0);

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

pub fn write_repacked_executable(
    path: &Path,
    bytes: &[u8],
    permissions: Permissions,
    section_backed_macho: bool,
) -> Result<(), Box<dyn Error>> {
    write_repacked_executable_with(path, bytes, permissions, |temporary_path| {
        resign_if_needed(temporary_path, section_backed_macho)
    })
}

fn write_repacked_executable_with(
    path: &Path,
    bytes: &[u8],
    permissions: Permissions,
    finalize: impl FnOnce(&Path) -> Result<(), Box<dyn Error>>,
) -> Result<(), Box<dyn Error>> {
    write_atomic_file_with(
        path,
        Some(permissions),
        |file| {
            file.write_all(bytes)?;
            Ok(())
        },
        finalize,
    )
}

pub fn write_atomic_file(
    path: &Path,
    write_contents: impl FnOnce(&mut fs::File) -> Result<(), Box<dyn Error>>,
) -> Result<(), Box<dyn Error>> {
    let permissions = match fs::metadata(path) {
        Ok(metadata) => Some(metadata.permissions()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(error.into()),
    };

    write_atomic_file_with(path, permissions, write_contents, |_| Ok(()))
}

fn write_atomic_file_with(
    path: &Path,
    permissions: Option<Permissions>,
    write_contents: impl FnOnce(&mut fs::File) -> Result<(), Box<dyn Error>>,
    finalize: impl FnOnce(&Path) -> Result<(), Box<dyn Error>>,
) -> Result<(), Box<dyn Error>> {
    let parent = path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;

    let (temporary_path, mut temporary_file) = create_temporary_sibling(path)?;
    let prepared = (|| -> Result<(), Box<dyn Error>> {
        write_contents(&mut temporary_file)?;
        if let Some(permissions) = permissions {
            temporary_file.set_permissions(permissions)?;
        }
        temporary_file.sync_all()?;
        Ok(())
    })();
    drop(temporary_file);

    if let Err(error) = prepared {
        let _ = fs::remove_file(&temporary_path);
        return Err(error);
    }
    if let Err(error) = finalize(&temporary_path) {
        let _ = fs::remove_file(&temporary_path);
        return Err(format!("failed to prepare output {}: {error}", path.display()).into());
    }
    if let Err(error) = replace_destination(&temporary_path, path) {
        let _ = fs::remove_file(&temporary_path);
        return Err(format!("failed to replace output {}: {error}", path.display()).into());
    }

    Ok(())
}

fn create_temporary_sibling(path: &Path) -> Result<(PathBuf, fs::File), Box<dyn Error>> {
    let parent = path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .ok_or_else(|| format!("output path {} had no file name", path.display()))?;

    for _ in 0..32 {
        let id = TEMP_FILE_COUNTER.fetch_add(1, Ordering::Relaxed);
        let mut temporary_name = OsString::from(".");
        temporary_name.push(file_name);
        temporary_name.push(format!(".debun-tmp-{}-{id}", std::process::id()));
        let temporary_path = parent.join(temporary_name);
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary_path)
        {
            Ok(file) => return Ok((temporary_path, file)),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error.into()),
        }
    }

    Err(format!(
        "could not create a temporary output next to {}",
        path.display()
    )
    .into())
}

#[cfg(not(target_os = "windows"))]
fn replace_destination(temporary_path: &Path, path: &Path) -> Result<(), Box<dyn Error>> {
    fs::rename(temporary_path, path)?;
    Ok(())
}

#[cfg(target_os = "windows")]
fn replace_destination(temporary_path: &Path, path: &Path) -> Result<(), Box<dyn Error>> {
    if !path.exists() {
        fs::rename(temporary_path, path)?;
        return Ok(());
    }

    windows_replace::replace(path, temporary_path)?;
    Ok(())
}

#[cfg(target_os = "windows")]
mod windows_replace {
    use std::{io, iter, os::windows::ffi::OsStrExt, path::Path, ptr};

    use windows_sys::Win32::Storage::FileSystem::{REPLACEFILE_WRITE_THROUGH, ReplaceFileW};

    pub(super) fn replace(destination: &Path, replacement: &Path) -> io::Result<()> {
        let destination = destination
            .as_os_str()
            .encode_wide()
            .chain(iter::once(0))
            .collect::<Vec<_>>();
        let replacement = replacement
            .as_os_str()
            .encode_wide()
            .chain(iter::once(0))
            .collect::<Vec<_>>();

        // The UTF-16 buffers are NUL-terminated and remain alive for the call.
        // ReplaceFileW atomically swaps files without a crash window where the
        // destination name is absent.
        let replaced = unsafe {
            ReplaceFileW(
                destination.as_ptr(),
                replacement.as_ptr(),
                ptr::null(),
                REPLACEFILE_WRITE_THROUGH,
                ptr::null(),
                ptr::null(),
            )
        };
        if replaced == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

fn resign_if_needed(path: &Path, section_backed_macho: bool) -> Result<(), Box<dyn Error>> {
    #[cfg(target_os = "macos")]
    {
        if !section_backed_macho {
            return Ok(());
        }

        let mut magic = [0; 4];
        fs::File::open(path)?.read_exact(&mut magic)?;
        if !matches!(u32::from_le_bytes(magic), 0xfeed_facf | 0xfeed_face) {
            return Ok(());
        }

        // Repacking mutates Mach-O bytes in place, which invalidates the embedded
        // signature from the original app bundle. Re-sign ad-hoc so the output
        // remains directly executable on the local machine.
        // Do not preserve the original requirements: a Developer ID designated
        // requirement cannot be satisfied by the replacement ad-hoc signature.
        let output = ProcessCommand::new("codesign")
            .args([
                "--force",
                "--sign",
                "-",
                "--preserve-metadata=identifier,entitlements,flags,runtime",
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
                "failed to re-sign temporary packed binary {}: {details}",
                path.display()
            )
            .into());
        }
    }

    #[cfg(not(target_os = "macos"))]
    {
        let _ = (path, section_backed_macho);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    #[test]
    fn replaces_existing_output() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let test_dir = std::env::temp_dir().join(format!("debun-replace-output-{nonce}"));
        let output = test_dir.join("app");
        fs::create_dir_all(&test_dir).unwrap();
        fs::write(&output, b"original").unwrap();
        let permissions = fs::metadata(&output).unwrap().permissions();

        write_repacked_executable_with(&output, b"replacement", permissions, |_| Ok(())).unwrap();

        assert_eq!(fs::read(&output).unwrap(), b"replacement");
        assert_eq!(fs::read_dir(&test_dir).unwrap().count(), 1);
        fs::remove_dir_all(test_dir).unwrap();
    }

    #[test]
    fn keeps_existing_output_when_finalization_fails() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let test_dir = std::env::temp_dir().join(format!("debun-atomic-output-{nonce}"));
        let output = test_dir.join("app");
        fs::create_dir_all(&test_dir).unwrap();
        fs::write(&output, b"original").unwrap();
        let permissions = fs::metadata(&output).unwrap().permissions();

        let result = write_repacked_executable_with(&output, b"replacement", permissions, |_| {
            Err("simulated signing failure".into())
        });

        assert!(result.is_err());
        assert_eq!(fs::read(&output).unwrap(), b"original");
        assert_eq!(fs::read_dir(&test_dir).unwrap().count(), 1);
        fs::remove_dir_all(test_dir).unwrap();
    }

    #[test]
    fn keeps_existing_output_when_atomic_write_fails() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let test_dir = std::env::temp_dir().join(format!("debun-atomic-file-{nonce}"));
        let output = test_dir.join("changes.patch");
        fs::create_dir_all(&test_dir).unwrap();
        fs::write(&output, b"original").unwrap();

        let result = write_atomic_file(&output, |file| {
            file.write_all(b"partial")?;
            Err("simulated write failure".into())
        });

        assert!(result.is_err());
        assert_eq!(fs::read(&output).unwrap(), b"original");
        assert_eq!(fs::read_dir(&test_dir).unwrap().count(), 1);
        fs::remove_dir_all(test_dir).unwrap();
    }
}
