use std::{collections::HashMap, error::Error};

use oxc_allocator::Allocator;
use oxc_ast::ast::Program;
use oxc_parser::{ParseOptions, Parser};
use oxc_span::SourceType;
use oxc_syntax::symbol::SymbolId;

use crate::rewrite::analyze_lazy_exports;

use super::{
    ModuleKind, RawSplitModule,
    candidate::{body_statements, collect_module_candidates},
    naming::{default_module_name, digit_width, infer_hint, slugify, unique_file_name},
    source::{slice_body, slice_statement_range},
};

pub fn preferred_commonjs_names(program: &Program<'_>) -> HashMap<SymbolId, String> {
    let mut preferred = HashMap::new();

    for candidate in collect_module_candidates(program) {
        if candidate.kind != ModuleKind::CommonJs {
            continue;
        }

        if let Some(symbol_id) = candidate.export_symbol_id {
            preferred
                .entry(symbol_id)
                .or_insert_with(|| "exports".to_string());
        }
        if let Some(symbol_id) = candidate.module_symbol_id {
            preferred
                .entry(symbol_id)
                .or_insert_with(|| "module".to_string());
        }
    }

    preferred
}

pub fn extract_modules(source: &str) -> Result<Vec<RawSplitModule>, Box<dyn Error>> {
    let allocator = Allocator::default();
    let parsed = Parser::new(&allocator, source, SourceType::cjs())
        .with_options(ParseOptions {
            allow_return_outside_function: true,
            parse_regular_expression: true,
            ..ParseOptions::default()
        })
        .parse();

    if !parsed.errors.is_empty() {
        return Err(format!(
            "failed to parse rendered source for module splitting: {} diagnostics",
            parsed.errors.len()
        )
        .into());
    }

    let candidates = collect_module_candidates(&parsed.program);
    let statements = body_statements(&parsed.program);
    let index_width = digit_width(candidates.len());
    let mut used_file_names = std::collections::HashSet::new();
    let mut modules = Vec::with_capacity(candidates.len());

    for (index, candidate) in candidates.iter().enumerate() {
        let next_statement_index = candidates
            .get(index + 1)
            .map_or(statements.len(), |next| next.statement_index);
        let support_source = slice_statement_range(
            source,
            statements,
            candidate.statement_index + 1,
            next_statement_index,
        )?;
        let body_source = slice_body(source, candidate.body_span)?;
        let hint = infer_hint(&(support_source.clone() + &body_source));
        let file_slug = slugify(hint.as_deref().unwrap_or(&candidate.binding_name));
        let module_name = hint.as_deref().map_or_else(
            || default_module_name(candidate.kind, index + 1, index_width),
            slugify,
        );
        let file_name = unique_file_name(index + 1, index_width, &file_slug, &mut used_file_names);
        let (support_bindings, exports) = match candidate.kind {
            ModuleKind::CommonJs => (Vec::new(), Vec::new()),
            ModuleKind::LazyInit => {
                let analysis = analyze_lazy_exports(&support_source, &body_source)?;
                (analysis.support_bindings, analysis.exports)
            }
        };

        modules.push(RawSplitModule {
            index: index + 1,
            file_name,
            module_name,
            binding_name: candidate.binding_name.clone(),
            helper_name: candidate.helper_name.clone(),
            kind: candidate.kind,
            params: candidate.params.clone(),
            hint,
            support_source,
            body_source,
            support_bindings,
            exports,
        });
    }

    Ok(modules)
}
