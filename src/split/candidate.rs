use std::collections::HashMap;

use oxc_ast::ast::{Argument, Expression, FormalParameters, FunctionBody, Program, Statement};
use oxc_span::Span;
use oxc_syntax::symbol::SymbolId;

use super::ModuleKind;

#[derive(Debug, Clone)]
pub(super) struct ModuleCandidate {
    pub(super) statement_index: usize,
    pub(super) binding_name: String,
    pub(super) helper_name: String,
    pub(super) kind: ModuleKind,
    pub(super) body_span: Span,
    pub(super) params: Vec<String>,
    pub(super) export_symbol_id: Option<SymbolId>,
    pub(super) module_symbol_id: Option<SymbolId>,
}

pub(super) fn collect_module_candidates(program: &Program<'_>) -> Vec<ModuleCandidate> {
    let mut candidates = Vec::new();

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
            let Expression::Identifier(helper_ident) = &call_expression.callee else {
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

            candidates.push(ModuleCandidate {
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
    for candidate in &candidates {
        *helper_counts
            .entry((candidate.kind, candidate.helper_name.clone()))
            .or_insert(0) += 1;
    }

    candidates
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

pub(super) fn body_statements<'a>(program: &'a Program<'a>) -> &'a [Statement<'a>] {
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
