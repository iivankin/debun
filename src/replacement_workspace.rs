use std::{
    borrow::Cow,
    collections::{HashMap, HashSet, hash_map::Entry},
    error::Error,
    fs,
    path::Path,
};

use crate::{
    standalone::{ReplacementCounts, StandaloneModule, StandaloneSidecarKind},
    standalone_decode::{decode_module_info, decode_serialized_sourcemap},
    workspace_path::WorkspacePath,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) enum ModulePart {
    Contents,
    SourceMap,
    Bytecode,
    ModuleInfo,
}

impl ModulePart {
    pub(crate) const ALL: [Self; 4] = [
        Self::Contents,
        Self::SourceMap,
        Self::Bytecode,
        Self::ModuleInfo,
    ];

    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::Contents => "contents",
            Self::SourceMap => "sourcemap",
            Self::Bytecode => "bytecode",
            Self::ModuleInfo => "module-info",
        }
    }

    pub(crate) fn virtual_path<'a>(self, module: &'a StandaloneModule) -> Cow<'a, str> {
        match self {
            Self::Contents => Cow::Borrowed(&module.virtual_path),
            Self::SourceMap => {
                Cow::Owned(module.sidecar_path(StandaloneSidecarKind::SourceMapBinary))
            }
            Self::Bytecode => {
                Cow::Owned(module.sidecar_path(StandaloneSidecarKind::BytecodeBinary))
            }
            Self::ModuleInfo => {
                Cow::Owned(module.sidecar_path(StandaloneSidecarKind::ModuleInfoBinary))
            }
        }
    }

    pub(crate) fn path(self, module: &StandaloneModule) -> Result<WorkspacePath, Box<dyn Error>> {
        WorkspacePath::from_virtual(&self.virtual_path(module))
    }

    pub(crate) fn original_bytes(self, module: &StandaloneModule) -> Option<&[u8]> {
        match self {
            Self::Contents => Some(&module.bytes),
            Self::SourceMap => module.sourcemap.as_deref(),
            Self::Bytecode => module.bytecode.as_deref(),
            Self::ModuleInfo => module.module_info.as_deref(),
        }
    }

    pub(crate) fn count(self, counts: &mut ReplacementCounts) {
        match self {
            Self::Contents => counts.contents += 1,
            Self::SourceMap => counts.sourcemaps += 1,
            Self::Bytecode => counts.bytecodes += 1,
            Self::ModuleInfo => counts.module_infos += 1,
        }
    }
}

pub(crate) fn read_module_part(
    root: &Path,
    module: &StandaloneModule,
    part: ModulePart,
) -> Result<Option<Vec<u8>>, Box<dyn Error>> {
    let relative = part.path(module)?;
    let Some(path) = relative.existing_file_under(root)? else {
        return Ok(None);
    };
    Ok(Some(fs::read(path)?))
}

pub(crate) fn validate_workspace_files<'a>(
    root: &Path,
    modules: impl IntoIterator<Item = &'a StandaloneModule>,
) -> Result<(), Box<dyn Error>> {
    WorkspacePath::ensure_real_directory(root)?;
    let mut packable_paths = HashSet::new();
    let mut helper_files = HashMap::new();

    for module in modules {
        for part in ModulePart::ALL {
            let path = part.path(module)?;
            if !packable_paths.insert(path) {
                return Err(format!(
                    "standalone modules mapped to duplicate workspace path {}",
                    part.virtual_path(module)
                )
                .into());
            }
        }

        if let Some(sourcemap) = &module.sourcemap
            && let Ok(decoded) = decode_serialized_sourcemap(sourcemap, &module.virtual_path)
        {
            insert_helper(
                &mut helper_files,
                WorkspacePath::from_virtual(
                    &module.sidecar_path(StandaloneSidecarKind::SourceMapJson),
                )?,
                decoded.render_json().into_bytes(),
            )?;
        }
        if let Some(module_info) = &module.module_info
            && let Ok(decoded) = decode_module_info(module_info)
        {
            insert_helper(
                &mut helper_files,
                WorkspacePath::from_virtual(
                    &module.sidecar_path(StandaloneSidecarKind::ModuleInfoJson),
                )?,
                decoded.render_json().into_bytes(),
            )?;
        }
    }

    for helper_path in helper_files.keys() {
        if packable_paths.contains(helper_path) {
            return Err(format!(
                "decoded helper path {helper_path} collided with a packable module path"
            )
            .into());
        }
    }

    for relative in collect_workspace_files(root, root)? {
        if packable_paths.contains(&relative) {
            continue;
        }
        if let Some(expected) = helper_files.get(&relative) {
            let actual = fs::read(relative.join_under(root))?;
            if actual == *expected {
                continue;
            }
            return Err(format!(
                "decoded helper file {relative} was modified; edit the corresponding .bin file instead"
            )
            .into());
        }
        return Err(format!(
            "workspace file {relative} is not packable into the standalone binary"
        )
        .into());
    }

    Ok(())
}

fn insert_helper(
    helpers: &mut HashMap<WorkspacePath, Vec<u8>>,
    path: WorkspacePath,
    bytes: Vec<u8>,
) -> Result<(), Box<dyn Error>> {
    match helpers.entry(path) {
        Entry::Vacant(entry) => {
            entry.insert(bytes);
        }
        Entry::Occupied(entry) => {
            return Err(format!(
                "standalone modules produced duplicate helper path {}",
                entry.key()
            )
            .into());
        }
    }
    Ok(())
}

fn collect_workspace_files(
    root: &Path,
    current: &Path,
) -> Result<Vec<WorkspacePath>, Box<dyn Error>> {
    let mut found = Vec::new();
    for entry in fs::read_dir(current)? {
        let entry = entry?;
        let path = entry.path();
        let file_type = entry.file_type()?;
        if file_type.is_symlink() {
            return Err(format!("workspace path {} is a symlink", path.display()).into());
        }
        if file_type.is_dir() {
            found.extend(collect_workspace_files(root, &path)?);
            continue;
        }
        if !file_type.is_file() {
            return Err(format!("workspace path {} is not a regular file", path.display()).into());
        }

        let relative = path
            .strip_prefix(root)
            .map_err(|_| format!("failed to resolve workspace path {}", path.display()))?;
        found.push(WorkspacePath::from_relative(relative)?);
    }

    found.sort_by_key(WorkspacePath::to_slash_string);
    Ok(found)
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    #[test]
    fn rejects_unknown_workspace_files() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("debun-workspace-validation-{nonce}"));
        fs::create_dir_all(root.join("$bunfs/root")).unwrap();
        fs::write(root.join("$bunfs/root/app.js"), b"console.log('app');").unwrap();
        fs::write(root.join("$bunfs/root/typo.js"), b"not packable").unwrap();
        let module = test_module();

        let error = validate_workspace_files(&root, [&module])
            .expect_err("unknown files must not be silently ignored");

        assert!(error.to_string().contains("typo.js"));
        fs::remove_dir_all(root).unwrap();
    }

    fn test_module() -> StandaloneModule {
        StandaloneModule {
            original_path: "/$bunfs/root/app.js".to_string(),
            virtual_path: "/$bunfs/root/app.js".to_string(),
            source_offset: 0,
            bytes: b"console.log('app');".to_vec(),
            sourcemap: None,
            sourcemap_offset: None,
            bytecode: None,
            bytecode_offset: None,
            module_info: None,
            module_info_offset: None,
            bytecode_origin_path: None,
            encoding: 2,
            loader: 1,
            module_format: 1,
            side: 0,
        }
    }
}
