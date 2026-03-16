use std::error::Error;

use oxc_ast::ast::{Expression, Statement};

use super::super::parser::with_parsed_program;

pub(crate) fn infer_runtime_helper(body_source: &str) -> Option<&'static str> {
    let normalized = body_source
        .chars()
        .filter(|ch| !ch.is_whitespace())
        .collect::<String>();

    if normalized.contains("Object.getOwnPropertyNames(")
        && normalized.contains("Object.defineProperty(")
        && normalized.contains("propertyName!==\"default\"")
    {
        return Some("__debun.copyProps");
    }

    if normalized.contains("Object.getPrototypeOf(")
        && normalized.contains("\"default\"")
        && normalized.contains("__esModule")
    {
        return Some("__debun.toESM");
    }

    if normalized.contains("Object.defineProperty(Object.create(null),\"__esModule\"")
        || (normalized.contains("__esModule") && normalized.contains("copyProps("))
    {
        return Some("__debun.toCommonJS");
    }

    if normalized.contains("Object.keys(")
        && normalized.contains("Object.defineProperty(")
        && normalized.contains("enumerable:true")
    {
        return Some("__debun.defineExports");
    }

    None
}

pub(super) fn collect_top_level_bindings(source: &str) -> Result<Vec<String>, Box<dyn Error>> {
    let mut bindings = Vec::new();
    with_parsed_program(source, |program| {
        for statement in program.body.as_slice() {
            collect_top_level_declared_names(statement, &mut bindings);
        }
    })?;
    Ok(bindings)
}

fn collect_top_level_declared_names(statement: &Statement<'_>, bindings: &mut Vec<String>) {
    match statement {
        Statement::VariableDeclaration(declaration) => {
            for declarator in &declaration.declarations {
                if let Some(name) = declarator.id.get_identifier_name() {
                    bindings.push(name.as_str().to_string());
                }
            }
        }
        Statement::FunctionDeclaration(declaration) => {
            if let Some(name) = declaration
                .id
                .as_ref()
                .map(|id| id.name.as_str().to_string())
            {
                bindings.push(name);
            }
        }
        Statement::ClassDeclaration(declaration) => {
            if let Some(name) = declaration
                .id
                .as_ref()
                .map(|id| id.name.as_str().to_string())
            {
                bindings.push(name);
            }
        }
        _ => {}
    }
}

pub(super) fn is_empty_function_expression(expression: &Expression<'_>) -> bool {
    match expression {
        Expression::ArrowFunctionExpression(function) => {
            function.params.items.is_empty()
                && function.params.rest.is_none()
                && function.body.statements.is_empty()
        }
        Expression::FunctionExpression(function) => {
            function.params.items.is_empty()
                && function.params.rest.is_none()
                && function
                    .body
                    .as_ref()
                    .is_some_and(|body| body.statements.is_empty())
        }
        _ => false,
    }
}

pub(super) fn is_reserved_name(name: &str) -> bool {
    matches!(
        name,
        "exports" | "module" | "require" | "__filename" | "__dirname"
    )
}

pub(super) fn is_bundle_symbol(name: &str) -> bool {
    let Some((prefix, suffix)) = name.rsplit_once('_') else {
        return false;
    };
    if suffix.is_empty() || !suffix.chars().all(|ch| ch.is_ascii_digit()) {
        return false;
    }

    matches!(
        prefix.rsplit_once('_').map(|(_, kind)| kind),
        Some("var" | "let" | "const" | "fn" | "class" | "catch" | "import" | "value")
    )
}
