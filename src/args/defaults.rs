use std::{
    fs,
    path::{Path, PathBuf},
};

use crate::pack_support::{original_path_path, workspace_candidates};

pub(super) fn default_out_dir(input: &Path) -> PathBuf {
    let parent = input.parent().unwrap_or_else(|| Path::new("."));
    let stem = input
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or("bundle");
    parent.join(format!("{stem}.readable"))
}

pub(super) fn default_module_name(input: &Path) -> String {
    input
        .file_stem()
        .and_then(|value| value.to_str())
        .filter(|value| !value.is_empty())
        .unwrap_or("bundle")
        .to_string()
}

pub(super) fn default_pack_out_file(from_dir: &Path) -> PathBuf {
    if let Some(original_input) = read_pack_original_path(from_dir) {
        return default_repacked_path(&original_input);
    }

    let name = from_dir
        .file_name()
        .and_then(|value| value.to_str())
        .filter(|value| !value.is_empty())
        .unwrap_or("packed-binary");
    from_dir.join(format!("{name}.repacked"))
}

fn default_repacked_path(input: &Path) -> PathBuf {
    let parent = input.parent().unwrap_or_else(|| Path::new("."));
    let file_name = input
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("binary");
    let stem = input.file_stem().and_then(|value| value.to_str());
    let extension = input.extension().and_then(|value| value.to_str());

    match (stem, extension) {
        (Some(stem), Some(extension)) if !stem.is_empty() && !extension.is_empty() => {
            parent.join(format!("{stem}.repacked.{extension}"))
        }
        _ => parent.join(format!("{file_name}.repacked")),
    }
}

fn read_pack_original_path(from_dir: &Path) -> Option<PathBuf> {
    workspace_candidates(from_dir).find_map(|candidate| {
        let path = original_path_path(&candidate);
        let contents = fs::read_to_string(path).ok()?;
        let trimmed = contents.trim();
        (!trimmed.is_empty()).then(|| PathBuf::from(trimmed))
    })
}
