use std::path::{Path, PathBuf};

use crate::pack_support::read_original_input_path;

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
    if let Some(original_input) = read_original_input_path(from_dir) {
        return default_repacked_path(&original_input);
    }

    let name = from_dir
        .file_name()
        .and_then(|value| value.to_str())
        .filter(|value| !value.is_empty())
        .unwrap_or("packed-binary");
    from_dir.join(format!("{name}.repacked"))
}

pub(super) fn default_patch_out_file(from_dir: &Path) -> PathBuf {
    if let Some(original_input) = read_original_input_path(from_dir) {
        return default_patch_path(&original_input);
    }

    let name = from_dir
        .file_name()
        .and_then(|value| value.to_str())
        .filter(|value| !value.is_empty())
        .unwrap_or("changes");
    from_dir.join(format!("{name}.patch"))
}

pub(crate) fn default_apply_patch_out_file(input: &Path) -> PathBuf {
    default_variant_path(input, "patched")
}

fn default_repacked_path(input: &Path) -> PathBuf {
    default_variant_path(input, "repacked")
}

fn default_patch_path(input: &Path) -> PathBuf {
    let parent = input.parent().unwrap_or_else(|| Path::new("."));
    let stem = input
        .file_stem()
        .and_then(|value| value.to_str())
        .filter(|value| !value.is_empty())
        .unwrap_or("changes");
    parent.join(format!("{stem}.patch"))
}

fn default_variant_path(input: &Path, suffix: &str) -> PathBuf {
    let parent = input.parent().unwrap_or_else(|| Path::new("."));
    let file_name = input
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("binary");
    let stem = input.file_stem().and_then(|value| value.to_str());
    let extension = input.extension().and_then(|value| value.to_str());

    match (stem, extension) {
        (Some(stem), Some(extension)) if !stem.is_empty() && !extension.is_empty() => {
            parent.join(format!("{stem}.{suffix}.{extension}"))
        }
        _ => parent.join(format!("{file_name}.{suffix}")),
    }
}
