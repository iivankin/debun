use std::{collections::HashMap, error::Error};

use oxc_allocator::Allocator;
use oxc_ast::ast::{Argument, Expression, FormalParameters, FunctionBody, Program, Statement};
use oxc_parser::{ParseOptions, Parser};
use oxc_span::{SourceType, Span};
use oxc_syntax::symbol::SymbolId;

use crate::rewrite::analyze_lazy_exports;

use super::{
    ModuleKind, RawSplitModule,
    naming::{default_module_name, digit_width, infer_hint, slugify, unique_file_name},
    source::{slice_body, slice_statement_range},
};

#[derive(Debug, Clone)]
struct ModuleCandidate {
    statement_index: usize,
    binding_name: String,
    helper_name: String,
    kind: ModuleKind,
    body_span: Span,
    params: Vec<String>,
    export_symbol_id: Option<SymbolId>,
    module_symbol_id: Option<SymbolId>,
}

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
    let parser_return = Parser::new(&allocator, source, SourceType::cjs())
        .with_options(ParseOptions {
            allow_return_outside_function: true,
            parse_regular_expression: true,
            ..ParseOptions::default()
        })
        .parse();

    if !parser_return.errors.is_empty() {
        return Err(format!(
            "failed to parse rendered source for module splitting: {} diagnostics",
            parser_return.errors.len()
        )
        .into());
    }

    let candidates = collect_module_candidates(&parser_return.program);
    let statements = body_statements(&parser_return.program);
    let width = digit_width(candidates.len());
    let mut used_file_names = std::collections::HashSet::new();
    let mut modules = Vec::with_capacity(candidates.len());

    for (index, candidate) in candidates.iter().enumerate() {
        let next_statement_index = candidates
            .get(index + 1)
            .map(|next| next.statement_index)
            .unwrap_or(statements.len());
        let support_source = slice_statement_range(
            source,
            statements,
            candidate.statement_index + 1,
            next_statement_index,
        )?;
        let body_source = slice_body(source, candidate.body_span)?;
        let hint = infer_hint(&(support_source.clone() + &body_source));
        let file_slug = slugify(hint.as_deref().unwrap_or(&candidate.binding_name));
        let module_name = hint
            .as_deref()
            .map(slugify)
            .unwrap_or_else(|| default_module_name(candidate.kind, index + 1, width));
        let file_name = unique_file_name(index + 1, width, &file_slug, &mut used_file_names);
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

fn collect_module_candidates(program: &Program<'_>) -> Vec<ModuleCandidate> {
    let mut raw_candidates = Vec::new();

    for (statement_index, statement) in body_statements(program).iter().enumerate() {
        let Statement::VariableDeclaration(declaration) = statement else {
            continue;
        };

        for declarator in &declaration.declarations {
            let Some(binding_name) = declarator
                .id
                .get_identifier_name()
                .map(|name| name.as_str().to_string())
            else {
                continue;
            };

            let Some(Expression::CallExpression(call_expression)) = declarator.init.as_ref() else {
                continue;
            };
            let Some(Expression::Identifier(helper_ident)) = Some(&call_expression.callee) else {
                continue;
            };

            if call_expression.arguments.len() != 1 {
                continue;
            }

            let Some((params, body)) = extract_factory(&call_expression.arguments[0]) else {
                continue;
            };
            if params.items.len() > 2 || params.rest.is_some() {
                continue;
            }

            let kind = match params.items.len() {
                0 => ModuleKind::LazyInit,
                1 | 2 => ModuleKind::CommonJs,
                _ => continue,
            };

            let param_names = params
                .items
                .iter()
                .filter_map(|item| item.pattern.get_identifier_name())
                .map(|name| name.as_str().to_string())
                .collect::<Vec<_>>();
            if param_names.len() != params.items.len() {
                continue;
            }

            let export_symbol_id = params
                .items
                .first()
                .and_then(|item| item.pattern.get_binding_identifier())
                .and_then(|ident| ident.symbol_id.get());
            let module_symbol_id = params
                .items
                .get(1)
                .and_then(|item| item.pattern.get_binding_identifier())
                .and_then(|ident| ident.symbol_id.get());

            raw_candidates.push(ModuleCandidate {
                statement_index,
                binding_name,
                helper_name: helper_ident.name.as_str().to_string(),
                kind,
                body_span: body.span,
                params: param_names,
                export_symbol_id,
                module_symbol_id,
            });
        }
    }

    let mut helper_counts = HashMap::<(ModuleKind, String), usize>::new();
    for candidate in &raw_candidates {
        *helper_counts
            .entry((candidate.kind, candidate.helper_name.clone()))
            .or_insert(0) += 1;
    }

    raw_candidates
        .into_iter()
        .filter(|candidate| {
            helper_counts
                .get(&(candidate.kind, candidate.helper_name.clone()))
                .copied()
                .unwrap_or(0)
                > 1
        })
        .collect()
}

fn body_statements<'a>(program: &'a Program<'a>) -> &'a [Statement<'a>] {
    if let [Statement::ExpressionStatement(statement)] = program.body.as_slice()
        && let Some(body) = expression_function_body(&statement.expression)
    {
        return body.statements.as_slice();
    }

    program.body.as_slice()
}

fn expression_function_body<'a>(expression: &'a Expression<'a>) -> Option<&'a FunctionBody<'a>> {
    match expression {
        Expression::ParenthesizedExpression(parenthesized) => {
            expression_function_body(&parenthesized.expression)
        }
        Expression::FunctionExpression(function) => function.body.as_deref(),
        Expression::ArrowFunctionExpression(function) => Some(&function.body),
        _ => None,
    }
}

fn extract_factory<'a>(
    argument: &'a Argument<'a>,
) -> Option<(&'a FormalParameters<'a>, &'a FunctionBody<'a>)> {
    match argument {
        Argument::ArrowFunctionExpression(function) => Some((&function.params, &function.body)),
        Argument::FunctionExpression(function) => function
            .body
            .as_ref()
            .map(|body| (function.params.as_ref(), body.as_ref())),
        _ => None,
    }
}
