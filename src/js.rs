use std::{
    collections::{HashMap, HashSet},
    fmt::Write as _,
};

use oxc_allocator::Allocator;
use oxc_codegen::{Codegen, CodegenOptions, IndentChar};
use oxc_parser::{ParseOptions, Parser};
use oxc_semantic::SemanticBuilder;
use oxc_span::SourceType;
use oxc_syntax::{
    scope::ScopeId,
    symbol::{SymbolFlags, SymbolId},
};

use super::{
    args::Config,
    rewrite::{
        collect_external_bundle_refs, collect_noop_bindings, collect_runtime_helpers,
        rewrite_module_source,
    },
    split::{SplitModule, build_module_registry, extract_modules, preferred_commonjs_names},
};

#[derive(Debug, Clone)]
pub struct SymbolRename {
    pub old_name: String,
    pub new_name: String,
    pub kind: &'static str,
    pub scope_debug: String,
    pub references: usize,
}

#[derive(Debug, Clone)]
pub struct TransformArtifacts {
    pub formatted: String,
    pub renamed: String,
    pub renames: Vec<SymbolRename>,
    pub parse_errors: Vec<String>,
    pub semantic_errors: Vec<String>,
    pub modules: Vec<SplitModule>,
}

pub fn transform_source(
    config: &Config,
    source: &str,
) -> Result<TransformArtifacts, Box<dyn std::error::Error>> {
    transform_source_inner(config, source, true)
}

fn transform_source_inner(
    config: &Config,
    source: &str,
    split_modules: bool,
) -> Result<TransformArtifacts, Box<dyn std::error::Error>> {
    let allocator = Allocator::default();
    let source_type = detect_source_type(source);

    let parser_return = Parser::new(&allocator, source, source_type)
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

    let modules = if split_modules {
        build_split_modules(
            config,
            if config.rename_symbols {
                &renamed
            } else {
                &formatted
            },
        )?
    } else {
        Vec::new()
    };

    Ok(TransformArtifacts {
        formatted,
        renamed,
        renames,
        parse_errors,
        semantic_errors,
        modules,
    })
}

fn detect_source_type(source: &str) -> SourceType {
    let trimmed = source.trim_start();
    let looks_like_module = trimmed.starts_with("import ")
        || trimmed.starts_with("export ")
        || source.contains("\nimport ")
        || source.contains("\nexport ")
        || source.contains("// @bun\nimport")
        || source.contains("// @bun\r\nimport");

    if looks_like_module {
        SourceType::mjs()
    } else {
        SourceType::cjs()
    }
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
        if raw_module.kind != super::split::ModuleKind::LazyInit {
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
    registry: &HashMap<String, super::split::ModuleDescriptor>,
    used_refs: &HashSet<String>,
) -> HashMap<String, super::split::ModuleDescriptor> {
    registry
        .iter()
        .map(|(binding, descriptor)| {
            let mut narrowed = descriptor.clone();
            if matches!(narrowed.kind, super::split::ModuleKind::LazyInit) {
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

fn rename_symbols(
    scoping: &mut oxc_semantic::Scoping,
    module_name: &str,
    preferred_names: &HashMap<SymbolId, String>,
) -> Vec<SymbolRename> {
    let symbol_ids = scoping.symbol_ids().collect::<Vec<_>>();
    let mut counters = RenameCounters::default();
    let mut renames = Vec::new();

    for symbol_id in symbol_ids {
        let old_name = scoping.symbol_name(symbol_id).to_string();
        let flags = scoping.symbol_flags(symbol_id);
        let scope_id = scoping.symbol_scope_id(symbol_id);

        let new_name = if let Some(preferred_name) = preferred_names.get(&symbol_id) {
            if old_name == *preferred_name {
                continue;
            }
            if local_name_available(scoping, scope_id, symbol_id, preferred_name) {
                preferred_name.clone()
            } else if should_rename(&old_name, flags) {
                let kind = classify(flags);
                next_name(
                    scoping,
                    scope_id,
                    symbol_id,
                    &mut counters,
                    kind.prefix,
                    module_name,
                )
            } else {
                continue;
            }
        } else {
            if !should_rename(&old_name, flags) {
                continue;
            }
            let kind = classify(flags);
            next_name(
                scoping,
                scope_id,
                symbol_id,
                &mut counters,
                kind.prefix,
                module_name,
            )
        };

        if old_name == new_name {
            continue;
        }

        let references = scoping.get_resolved_reference_ids(symbol_id).len();
        scoping.rename_symbol(symbol_id, scope_id, new_name.as_str().into());

        renames.push(SymbolRename {
            old_name,
            new_name,
            kind: classify(flags).label,
            scope_debug: format!("{scope_id:?}"),
            references,
        });
    }

    renames
}

fn should_rename(name: &str, flags: SymbolFlags) -> bool {
    if matches!(
        name,
        "exports" | "require" | "module" | "__filename" | "__dirname" | "arguments"
    ) {
        return false;
    }

    if is_common_short_name(name) {
        return false;
    }

    if flags.contains(SymbolFlags::Import) && name.len() > 4 && !looks_minified(name) {
        return false;
    }

    looks_minified(name) || looks_generated_name(name)
}

fn is_common_short_name(name: &str) -> bool {
    matches!(
        name,
        "err"
            | "len"
            | "idx"
            | "key"
            | "val"
            | "src"
            | "dst"
            | "buf"
            | "end"
            | "pos"
            | "msg"
            | "map"
            | "set"
            | "ast"
            | "api"
            | "url"
            | "env"
            | "ctx"
    )
}

fn looks_minified(name: &str) -> bool {
    if name.len() <= 2 {
        return true;
    }

    let has_digit = name.bytes().any(|byte| byte.is_ascii_digit());
    let has_upper = name.bytes().any(|byte| byte.is_ascii_uppercase());
    let has_lower = name.bytes().any(|byte| byte.is_ascii_lowercase());
    let has_suffix_underscore = name.ends_with('_');

    if name.len() <= 3 {
        return true;
    }

    if has_digit && name.len() <= 8 {
        return true;
    }

    if has_suffix_underscore && name.len() <= 8 {
        return true;
    }

    if name.len() <= 5 && has_upper && has_lower {
        return true;
    }

    let upper_count = name
        .bytes()
        .filter(|byte| byte.is_ascii_uppercase())
        .count();
    upper_count >= 2 && name.len() <= 6
}

fn looks_generated_name(name: &str) -> bool {
    [
        "_var_", "_let_", "_const_", "_fn_", "_class_", "_catch_", "_import_", "_value_",
    ]
    .iter()
    .any(|marker| name.contains(marker))
}

#[derive(Clone, Copy)]
struct KindInfo {
    label: &'static str,
    prefix: &'static str,
}

fn classify(flags: SymbolFlags) -> KindInfo {
    if flags.contains(SymbolFlags::Function) {
        KindInfo {
            label: "function",
            prefix: "fn",
        }
    } else if flags.contains(SymbolFlags::Class) {
        KindInfo {
            label: "class",
            prefix: "class",
        }
    } else if flags.contains(SymbolFlags::Import) {
        KindInfo {
            label: "import",
            prefix: "import",
        }
    } else if flags.contains(SymbolFlags::CatchVariable) {
        KindInfo {
            label: "catch",
            prefix: "catch",
        }
    } else if flags.contains(SymbolFlags::ConstVariable) {
        KindInfo {
            label: "const",
            prefix: "const",
        }
    } else if flags.contains(SymbolFlags::BlockScopedVariable) {
        KindInfo {
            label: "let",
            prefix: "let",
        }
    } else if flags.contains(SymbolFlags::FunctionScopedVariable) {
        KindInfo {
            label: "var",
            prefix: "var",
        }
    } else {
        KindInfo {
            label: "value",
            prefix: "value",
        }
    }
}

#[derive(Default)]
struct RenameCounters {
    function: usize,
    class: usize,
    import: usize,
    catch: usize,
    constant: usize,
    let_like: usize,
    var_like: usize,
    value: usize,
}

impl RenameCounters {
    fn next(&mut self, prefix: &str) -> usize {
        let slot = match prefix {
            "fn" => &mut self.function,
            "class" => &mut self.class,
            "import" => &mut self.import,
            "catch" => &mut self.catch,
            "const" => &mut self.constant,
            "let" => &mut self.let_like,
            "var" => &mut self.var_like,
            _ => &mut self.value,
        };
        *slot += 1;
        *slot
    }
}

fn next_name(
    scoping: &oxc_semantic::Scoping,
    scope_id: ScopeId,
    symbol_id: SymbolId,
    counters: &mut RenameCounters,
    prefix: &str,
    module_name: &str,
) -> String {
    loop {
        let ordinal = counters.next(prefix);
        let candidate = format!("{}_{}_{}", module_name_slug(module_name), prefix, ordinal);
        if local_name_available(scoping, scope_id, symbol_id, &candidate) {
            return candidate;
        }
    }
}

fn local_name_available(
    scoping: &oxc_semantic::Scoping,
    scope_id: ScopeId,
    symbol_id: SymbolId,
    candidate: &str,
) -> bool {
    match scoping.get_binding(scope_id, candidate.into()) {
        None => true,
        Some(existing_symbol_id) => existing_symbol_id == symbol_id,
    }
}

fn module_name_slug(module_name: &str) -> String {
    let mut slug = String::new();
    for ch in module_name.chars() {
        let normalized = if ch.is_ascii_alphanumeric() {
            ch.to_ascii_lowercase()
        } else {
            '_'
        };
        slug.push(normalized);
    }
    if slug.is_empty() {
        "module".to_string()
    } else {
        slug
    }
}

pub fn symbols_report(renames: &[SymbolRename]) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "old_name\tnew_name\tkind\tscope\treferences");
    for rename in renames {
        let _ = writeln!(
            out,
            "{}\t{}\t{}\t{}\t{}",
            rename.old_name, rename.new_name, rename.kind, rename.scope_debug, rename.references
        );
    }
    out
}
