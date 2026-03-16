use std::collections::{HashMap, HashSet};

use oxc_allocator::Allocator;
use oxc_codegen::{Codegen, CodegenOptions, IndentChar};
use oxc_parser::{ParseOptions, Parser};
use oxc_semantic::SemanticBuilder;
use oxc_span::SourceType;

use crate::{
    args::Config,
    rewrite::{
        collect_external_bundle_refs, collect_noop_bindings, collect_runtime_helpers,
        rewrite_module_source,
    },
    split::{
        ModuleDescriptor, ModuleKind, SplitModule, build_module_registry, extract_modules,
        preferred_commonjs_names,
    },
};

use super::{TransformArtifacts, rename::rename_symbols};

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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ParseStrategy {
    Unambiguous,
    CommonJs,
}

impl ParseStrategy {
    fn source_type(self) -> SourceType {
        match self {
            Self::Unambiguous => SourceType::unambiguous(),
            Self::CommonJs => SourceType::cjs(),
        }
    }

    fn preference_rank(self) -> usize {
        match self {
            Self::Unambiguous => 0,
            Self::CommonJs => 1,
        }
    }
}

struct CoreTransformArtifacts {
    formatted: String,
    renamed: String,
    renames: Vec<super::SymbolRename>,
    parse_errors: Vec<String>,
    semantic_errors: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct DiagnosticScore {
    parse_errors: usize,
    semantic_errors: usize,
    preference_rank: usize,
}

impl CoreTransformArtifacts {
    fn score(&self, strategy: ParseStrategy) -> DiagnosticScore {
        DiagnosticScore {
            parse_errors: self.parse_errors.len(),
            semantic_errors: self.semantic_errors.len(),
            preference_rank: strategy.preference_rank(),
        }
    }
}

fn transform_source_best_effort(
    config: &Config,
    source: &str,
) -> Result<CoreTransformArtifacts, Box<dyn std::error::Error>> {
    // Bun standalone entrypoints often mix CommonJS wrappers with ESM-only
    // syntax like static imports, `import.meta`, and top-level `await`.
    // Start with Oxc's "unambiguous" mode, then fall back to explicit CJS
    // when it produces fewer diagnostics.
    let mut best: Option<(DiagnosticScore, CoreTransformArtifacts)> = None;
    for strategy in [ParseStrategy::Unambiguous, ParseStrategy::CommonJs] {
        let candidate = transform_source_for_strategy(config, source, strategy)?;
        let score = candidate.score(strategy);
        if best
            .as_ref()
            .map(|(best_score, _)| score < *best_score)
            .unwrap_or(true)
        {
            best = Some((score, candidate));
        }
    }

    best.map(|(_, candidate)| candidate)
        .ok_or_else(|| "no parse strategy candidates were produced".into())
}

fn transform_source_for_strategy(
    config: &Config,
    source: &str,
    strategy: ParseStrategy,
) -> Result<CoreTransformArtifacts, Box<dyn std::error::Error>> {
    let allocator = Allocator::default();
    let parser_return = Parser::new(&allocator, source, strategy.source_type())
        .with_options(ParseOptions {
            allow_return_outside_function: true,
            parse_regular_expression: true,
            ..ParseOptions::default()
        })
        .parse();

    let parse_errors = parser_return
        .errors
        .into_iter()
        .map(|error| format!("{:?}", error.with_source_code(source.to_owned())))
        .collect::<Vec<_>>();

    let program = parser_return.program;
    let formatted = render(&program, source, None);

    let semantic_return = SemanticBuilder::new()
        .with_check_syntax_error(true)
        .build(&program);
    let semantic_errors = semantic_return
        .errors
        .into_iter()
        .map(|error| format!("{:?}", error.with_source_code(source.to_owned())))
        .collect::<Vec<_>>();

    let preferred_names = preferred_commonjs_names(&program);
    let mut scoping = semantic_return.semantic.into_scoping();
    let renames = if config.rename_symbols {
        rename_symbols(&mut scoping, &config.module_name, &preferred_names)
    } else {
        Vec::new()
    };
    let renamed = render(&program, source, Some(scoping));

    Ok(CoreTransformArtifacts {
        formatted,
        renamed,
        renames,
        parse_errors,
        semantic_errors,
    })
}

fn build_split_modules(
    config: &Config,
    source: &str,
) -> Result<Vec<SplitModule>, Box<dyn std::error::Error>> {
    let Ok(mut raw_modules) = extract_modules(source) else {
        return Ok(Vec::new());
    };
    let noop_bindings = collect_noop_bindings(source)?;
    let runtime_helpers = collect_runtime_helpers(source)?;
    let initial_registry = build_module_registry(&raw_modules);

    for raw_module in &mut raw_modules {
        if raw_module.kind != ModuleKind::LazyInit {
            continue;
        }

        let rewritten_support = rewrite_module_source(
            &raw_module.support_source,
            &raw_module.binding_name,
            &initial_registry,
            &noop_bindings,
            &runtime_helpers,
        )?;
        let rewritten_body = rewrite_module_source(
            &raw_module.body_source,
            &raw_module.binding_name,
            &initial_registry,
            &noop_bindings,
            &runtime_helpers,
        )?;
        let implicit_exports =
            collect_external_bundle_refs(&(rewritten_support + "\n" + &rewritten_body))?;
        raw_module.exports.extend(
            implicit_exports
                .into_iter()
                .filter(|name| name != &raw_module.binding_name),
        );
        raw_module.exports.sort();
        raw_module.exports.dedup();
    }

    let registry = build_module_registry(&raw_modules);
    let mut modules = Vec::with_capacity(raw_modules.len());

    for raw_module in raw_modules {
        let mut module_config = config.clone();
        module_config.module_name = raw_module.module_name.clone();
        let used_refs = collect_external_bundle_refs(&format!(
            "{}\n{}",
            raw_module.support_source, raw_module.body_source
        ))?
        .into_iter()
        .collect::<HashSet<_>>();
        let narrowed_registry = narrow_registry_for_module(&registry, &used_refs);
        let rewritten_support = rewrite_module_source(
            &raw_module.support_source,
            &raw_module.binding_name,
            &narrowed_registry,
            &noop_bindings,
            &runtime_helpers,
        )?;
        let rewritten_body = rewrite_module_source(
            &raw_module.body_source,
            &raw_module.binding_name,
            &narrowed_registry,
            &noop_bindings,
            &runtime_helpers,
        )?;
        let module_source = raw_module.render_source(&rewritten_support, &rewritten_body);

        let transformed = transform_source_inner(&module_config, &module_source, false)?;
        let rendered_source = if config.rename_symbols {
            transformed.renamed
        } else {
            transformed.formatted
        };

        modules.push(SplitModule {
            index: raw_module.index,
            file_name: raw_module.file_name,
            module_name: raw_module.module_name,
            binding_name: raw_module.binding_name,
            helper_name: raw_module.helper_name,
            kind: raw_module.kind,
            params: raw_module.params,
            hint: raw_module.hint,
            exports: raw_module.exports,
            source: rendered_source,
            renamed_symbols: transformed.renames.len(),
            parse_warnings: transformed.parse_errors.len(),
            semantic_warnings: transformed.semantic_errors.len(),
        });
    }

    Ok(modules)
}

fn narrow_registry_for_module(
    registry: &HashMap<String, ModuleDescriptor>,
    used_refs: &HashSet<String>,
) -> HashMap<String, ModuleDescriptor> {
    registry
        .iter()
        .map(|(binding, descriptor)| {
            let mut narrowed = descriptor.clone();
            if matches!(narrowed.kind, ModuleKind::LazyInit) {
                narrowed.exports.retain(|name| used_refs.contains(name));
            }
            (binding.clone(), narrowed)
        })
        .collect()
}

fn render(
    program: &oxc_ast::ast::Program<'_>,
    source: &str,
    scoping: Option<oxc_semantic::Scoping>,
) -> String {
    let options = CodegenOptions {
        indent_char: IndentChar::Space,
        indent_width: 2,
        ..CodegenOptions::default()
    };

    Codegen::new()
        .with_options(options)
        .with_source_text(source)
        .with_scoping(scoping)
        .build(program)
        .code
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
