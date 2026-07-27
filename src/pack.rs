use std::{
    collections::HashMap,
    error::Error,
    fs,
    path::{Path, PathBuf},
};

use crate::{
    args::PackConfig,
    pack_support::{
        base_executable_path, resolve_replacements_root, resolve_workspace_root,
        write_repacked_executable,
    },
    replacement_workspace::{ModulePart, read_module_part, validate_workspace_files},
    standalone::{
        OptionalReplacement, ReplacementCounts, ReplacementParts, RequiredReplacement,
        StandaloneModule, inspect_executable, repack_executable,
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
    let section_backed_macho = standalone.container.is_macho_section();
    let replacements_root = resolve_replacements_root(&workspace_root)?;
    validate_workspace_files(&replacements_root, standalone.bunfs_modules())?;
    let replacements = collect_replacements(&replacements_root, standalone.bunfs_modules())?;
    let modified = !replacements.is_empty();
    let (output_bytes, replacement_counts) = if modified {
        let repacked = repack_executable(&original_bytes, standalone, &replacements)?;
        (repacked.bytes, repacked.replacement_counts)
    } else {
        (original_bytes, ReplacementCounts::default())
    };

    write_repacked_executable(
        &config.out_file,
        &output_bytes,
        original_permissions,
        section_backed_macho && modified,
    )?;

    Ok(PackSummary {
        replacements_root,
        replacement_counts,
    })
}

fn collect_replacements<'a>(
    root: &Path,
    modules: impl IntoIterator<Item = &'a StandaloneModule>,
) -> Result<HashMap<String, ReplacementParts>, Box<dyn Error>> {
    let mut replacements = HashMap::new();

    for module in modules {
        let contents = read_module_part(root, module, ModulePart::Contents)?.ok_or_else(|| {
            format!(
                "workspace file {} is missing; pack cannot delete BunFS modules",
                module.virtual_path
            )
        })?;
        let sourcemap = read_module_part(root, module, ModulePart::SourceMap)?;
        let bytecode = read_module_part(root, module, ModulePart::Bytecode)?;
        let module_info = read_module_part(root, module, ModulePart::ModuleInfo)?;

        let replacement = ReplacementParts {
            contents: if contents == module.bytes {
                RequiredReplacement::Keep
            } else {
                RequiredReplacement::Replace(contents)
            },
            sourcemap: optional_replacement(sourcemap, module.sourcemap.as_deref()),
            bytecode: optional_replacement(bytecode, module.bytecode.as_deref()),
            module_info: optional_replacement(module_info, module.module_info.as_deref()),
        };
        if replacement.is_empty() {
            continue;
        }

        replacements.insert(module.virtual_path.clone(), replacement);
    }

    Ok(replacements)
}

fn optional_replacement(
    candidate: Option<Vec<u8>>,
    original: Option<&[u8]>,
) -> OptionalReplacement {
    match (candidate, original) {
        (None, None) => OptionalReplacement::Keep,
        (None, Some(_)) => OptionalReplacement::Remove,
        (Some(bytes), Some(original)) if bytes == original => OptionalReplacement::Keep,
        (Some(bytes), _) => OptionalReplacement::Replace(bytes),
    }
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    struct TestDir(PathBuf);

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn missing_optional_sidecar_removes_original_part() {
        let root = test_dir("remove-sidecar");
        let module = test_module();
        let contents_path = root.0.join("$bunfs/root/app.js");
        fs::create_dir_all(contents_path.parent().unwrap()).unwrap();
        fs::write(contents_path, &module.bytes).unwrap();

        let replacements = collect_replacements(&root.0, [&module]).unwrap();
        let replacement = replacements.get(&module.virtual_path).unwrap();

        assert_eq!(replacement.contents, RequiredReplacement::Keep);
        assert_eq!(replacement.sourcemap, OptionalReplacement::Remove);
    }

    #[test]
    fn missing_module_contents_is_an_error() {
        let root = test_dir("missing-contents");
        let module = test_module();

        let error = collect_replacements(&root.0, [&module])
            .expect_err("pack must not silently retain a missing module");

        assert!(error.to_string().contains("cannot delete BunFS modules"));
    }

    fn test_module() -> StandaloneModule {
        StandaloneModule {
            original_path: "/$bunfs/root/app.js".to_string(),
            virtual_path: "/$bunfs/root/app.js".to_string(),
            source_offset: 0,
            bytes: b"console.log('app');".to_vec(),
            sourcemap: Some(b"SMAP".to_vec()),
            sourcemap_offset: Some(20),
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

    fn test_dir(label: &str) -> TestDir {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("debun-pack-{label}-{nonce}"));
        fs::create_dir_all(&path).unwrap();
        TestDir(path)
    }
}
