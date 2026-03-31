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
