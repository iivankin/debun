use std::path::{Path, PathBuf};

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
