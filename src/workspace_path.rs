use std::{
    error::Error,
    fmt, fs,
    io::ErrorKind,
    path::{Component, Path, PathBuf},
};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct WorkspacePath(PathBuf);

impl WorkspacePath {
    pub(crate) fn from_virtual(path: &str) -> Result<Self, Box<dyn Error>> {
        Self::from_relative(Path::new(path.trim_start_matches('/')))
    }

    pub(crate) fn from_relative(path: &Path) -> Result<Self, Box<dyn Error>> {
        let mut normalized = PathBuf::new();
        for component in path.components() {
            match component {
                Component::Normal(value) => normalized.push(value),
                Component::CurDir => {}
                Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                    return Err(format!("unsafe workspace path {}", path.display()).into());
                }
            }
        }
        if normalized.as_os_str().is_empty() {
            return Err("workspace path was empty".into());
        }
        Ok(Self(normalized))
    }

    pub(crate) fn join_under(&self, root: &Path) -> PathBuf {
        root.join(&self.0)
    }

    pub(crate) fn existing_file_under(
        &self,
        root: &Path,
    ) -> Result<Option<PathBuf>, Box<dyn Error>> {
        Self::ensure_real_directory(root)?;
        let mut path = root.to_path_buf();
        let component_count = self.0.components().count();

        for (index, component) in self.0.components().enumerate() {
            let Component::Normal(value) = component else {
                return Err("normalized workspace path contained an invalid component".into());
            };
            path.push(value);

            let metadata = match fs::symlink_metadata(&path) {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
                Err(error) => return Err(error.into()),
            };
            if metadata.file_type().is_symlink() {
                return Err(format!("workspace path {} contains a symlink", path.display()).into());
            }

            let is_last = index + 1 == component_count;
            if is_last {
                if metadata.is_file() {
                    return Ok(Some(path));
                }
                return Err(
                    format!("workspace path {} is not a regular file", path.display()).into(),
                );
            }
            if !metadata.is_dir() {
                return Ok(None);
            }
        }

        Ok(None)
    }

    pub(crate) fn ensure_real_directory(path: &Path) -> Result<(), Box<dyn Error>> {
        let metadata = fs::symlink_metadata(path)?;
        if metadata.file_type().is_symlink() {
            return Err(format!("workspace root {} is a symlink", path.display()).into());
        }
        if !metadata.is_dir() {
            return Err(format!("workspace root {} is not a directory", path.display()).into());
        }
        Ok(())
    }

    pub(crate) fn to_slash_string(&self) -> String {
        self.0.to_string_lossy().replace('\\', "/")
    }
}

impl fmt::Display for WorkspacePath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.display().fmt(formatter)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_paths_that_escape_the_workspace() {
        assert!(WorkspacePath::from_virtual("/$bunfs/root/../../../outside").is_err());
        assert!(WorkspacePath::from_virtual("../outside").is_err());
        assert!(WorkspacePath::from_relative(Path::new("/absolute")).is_err());
    }

    #[test]
    fn normalizes_safe_virtual_paths() {
        let path = WorkspacePath::from_virtual("/$bunfs/root/./app.js").unwrap();
        assert_eq!(path.to_slash_string(), "$bunfs/root/app.js");
    }

    #[test]
    fn rejects_a_directory_in_place_of_a_file() {
        use std::time::{SystemTime, UNIX_EPOCH};

        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("debun-workspace-directory-{nonce}"));
        fs::create_dir_all(root.join("$bunfs/root/app.js")).unwrap();
        let path = WorkspacePath::from_virtual("/$bunfs/root/app.js").unwrap();

        assert!(path.existing_file_under(&root).is_err());

        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlinks_below_and_at_the_workspace_root() {
        use std::os::unix::fs::symlink;
        use std::time::{SystemTime, UNIX_EPOCH};

        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let test_dir = std::env::temp_dir().join(format!("debun-workspace-path-{nonce}"));
        let root = test_dir.join("root");
        let outside = test_dir.join("outside");
        fs::create_dir_all(&root).unwrap();
        fs::create_dir_all(&outside).unwrap();
        fs::write(outside.join("app.js"), b"outside").unwrap();

        symlink(&outside, root.join("$bunfs")).unwrap();
        let path = WorkspacePath::from_virtual("/$bunfs/app.js").unwrap();
        assert!(path.existing_file_under(&root).is_err());

        let linked_root = test_dir.join("linked-root");
        symlink(&outside, &linked_root).unwrap();
        assert!(path.existing_file_under(&linked_root).is_err());

        fs::remove_dir_all(test_dir).unwrap();
    }
}
