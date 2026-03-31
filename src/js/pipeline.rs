use crate::args::Config;

use super::{
    TransformArtifacts, transform::transform_source_best_effort, unbundle::build_split_modules,
};

pub(super) fn transform_source_inner(
    config: &Config,
    source: &str,
    split_modules: bool,
) -> Result<TransformArtifacts, Box<dyn std::error::Error>> {
    let transformed = transform_source_best_effort(config, source)?;

    let modules = if split_modules {
        build_split_modules(
            config,
            if config.rename_symbols {
                &transformed.renamed
            } else {
                &transformed.formatted
            },
        )?
    } else {
        Vec::new()
    };

    Ok(TransformArtifacts {
        formatted: transformed.formatted,
        renamed: transformed.renamed,
        renames: transformed.renames,
        parse_errors: transformed.parse_errors,
        semantic_errors: transformed.semantic_errors,
        modules,
    })
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::transform_source_inner;
    use crate::args::Config;

    fn test_config() -> Config {
        Config {
            input: PathBuf::from("input.js"),
            out_dir: PathBuf::from("out"),
            module_name: "bundle".to_string(),
            rename_symbols: false,
            unbundle: false,
        }
    }

    #[test]
    fn picks_module_goal_for_top_level_await() {
        let artifacts = transform_source_inner(&test_config(), "await boot();", false).unwrap();

        assert!(artifacts.parse_errors.is_empty());
        assert!(artifacts.semantic_errors.is_empty());
    }

    #[test]
    fn picks_module_goal_for_import_meta() {
        let artifacts =
            transform_source_inner(&test_config(), "console.log(import.meta.url);", false).unwrap();

        assert!(artifacts.parse_errors.is_empty());
        assert!(artifacts.semantic_errors.is_empty());
    }

    #[test]
    fn picks_module_goal_for_compact_esm_syntax() {
        let source = r#"var x = 1;import{readFile}from"fs";await readFile("foo");console.log(x);"#;
        let artifacts = transform_source_inner(&test_config(), source, false).unwrap();

        assert!(artifacts.parse_errors.is_empty());
        assert!(artifacts.semantic_errors.is_empty());
    }
}
