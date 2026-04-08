use std::{
    collections::HashMap,
    error::Error,
    fs,
    path::{Path, PathBuf},
};

use crate::{
    args::PackConfig,
    pack_support::{
        base_executable_path, resign_if_needed, resolve_replacements_root, resolve_workspace_root,
    },
    standalone::{
        OptionalReplacement, ReplacementCounts, ReplacementParts, RequiredReplacement,
        StandaloneModule, StandaloneSidecarKind, inspect_executable, repack_executable,
    },
};

pub(crate) struct PackSummary {
    pub(crate) replacements_root: PathBuf,
    pub(crate) replacement_counts: ReplacementCounts,
}

pub fn pack_binary(config: &PackConfig) -> Result<PackSummary, Box<dyn Error>> {
    let workspace_root = resolve_workspace_root(&config.from_dir)?;
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
            contents: contents.map_or(RequiredReplacement::Keep, RequiredReplacement::Replace),
            sourcemap: sourcemap.map_or(OptionalReplacement::Keep, OptionalReplacement::Replace),
            bytecode: bytecode.map_or(OptionalReplacement::Keep, OptionalReplacement::Replace),
            module_info: module_info
                .map_or(OptionalReplacement::Keep, OptionalReplacement::Replace),
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
