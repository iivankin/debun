use std::{
    collections::{HashMap, HashSet},
    error::Error,
};

use oxc_ast::ast::Statement;
use oxc_ast_visit::Visit;

use super::parser::{expression_function_body, with_parsed_program, wrapper_body_statements};

mod collectors;
mod helpers;
mod targets;

use self::collectors::{ExternalReferenceCollector, LazyExportCollector};
use self::helpers::{
    collect_top_level_bindings, is_bundle_symbol, is_empty_function_expression, is_reserved_name,
};

#[derive(Debug, Clone)]
pub struct LazyExportAnalysis {
    pub support_bindings: Vec<String>,
    pub exports: Vec<String>,
}

pub fn analyze_lazy_exports(
    support_source: &str,
    body_source: &str,
) -> Result<LazyExportAnalysis, Box<dyn Error>> {
    let mut support_bindings = collect_top_level_bindings(support_source)?;
    support_bindings.retain(|name| !is_reserved_name(name));
    support_bindings.sort();
    support_bindings.dedup();

    let mut collector = LazyExportCollector::default();
    with_parsed_program(body_source, |program| collector.visit_program(program))?;

    let mut exports = collector
        .assigned
        .into_iter()
        .filter(|name| !collector.locals.contains(name) && !is_reserved_name(name))
        .collect::<Vec<_>>();
    exports.extend(support_bindings.iter().cloned());
    exports.sort();
    exports.dedup();
    Ok(LazyExportAnalysis {
        support_bindings,
        exports,
    })
}

pub fn collect_noop_bindings(source: &str) -> Result<HashSet<String>, Box<dyn Error>> {
    let mut names = HashSet::new();
    with_parsed_program(source, |program| {
        for statement in wrapper_body_statements(program) {
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
                let Some(init) = declarator.init.as_ref() else {
                    continue;
                };
                if is_empty_function_expression(init) {
                    names.insert(binding_name);
                }
            }
        }
    })?;
    Ok(names)
}

pub fn collect_runtime_helpers(source: &str) -> Result<HashMap<String, String>, Box<dyn Error>> {
    let mut helpers = HashMap::new();
    with_parsed_program(source, |program| {
        for statement in wrapper_body_statements(program) {
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
                let Some(init) = declarator.init.as_ref() else {
                    continue;
                };
                let Some(body) = expression_function_body(init) else {
                    continue;
                };
                let start = usize::try_from(body.span.start).ok();
                let end = usize::try_from(body.span.end).ok();
                let Some((start, end)) = start.zip(end) else {
                    continue;
                };
                let Some(body_source) = source.get(start..end) else {
                    continue;
                };
                let runtime_name = infer_runtime_helper(body_source);
                if let Some(runtime_name) = runtime_name {
                    helpers.insert(binding_name, runtime_name.to_string());
                }
            }
        }
    })?;
    Ok(helpers)
}

pub fn collect_external_bundle_refs(source: &str) -> Result<Vec<String>, Box<dyn Error>> {
    let mut collector = ExternalReferenceCollector::default();
    with_parsed_program(source, |program| collector.visit_program(program))?;

    let mut names = collector
        .references
        .into_iter()
        .filter(|name| !collector.locals.contains(name))
        .filter(|name| !is_reserved_name(name))
        .filter(|name| is_bundle_symbol(name))
        .collect::<Vec<_>>();
    names.sort();
    names.dedup();
    Ok(names)
}

pub(crate) use self::helpers::infer_runtime_helper;
