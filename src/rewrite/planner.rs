use std::{
    collections::{HashMap, HashSet},
    error::Error,
};

use oxc_ast::ast::{CallExpression, Expression, ExpressionStatement, SequenceExpression};
use oxc_ast_visit::{Visit, walk};
use oxc_span::{GetSpan, Span};

use crate::split::{ModuleDescriptor, ModuleKind};

use super::parser::with_parsed_program;

pub fn rewrite_module_source(
    source: &str,
    current_binding: &str,
    registry: &HashMap<String, ModuleDescriptor>,
    noop_bindings: &HashSet<String>,
    runtime_helpers: &HashMap<String, String>,
) -> Result<String, Box<dyn Error>> {
    let mut planner = DependencyRewritePlanner {
        source,
        registry,
        current_binding,
        noop_bindings,
        runtime_helpers,
        replacements: Vec::new(),
    };
    with_parsed_program(source, |program| planner.visit_program(program))?;
    apply_replacements(source, &planner.replacements)
}

#[derive(Debug)]
struct Replacement {
    span: Span,
    text: String,
}

struct DependencyRewritePlanner<'a> {
    source: &'a str,
    registry: &'a HashMap<String, ModuleDescriptor>,
    current_binding: &'a str,
    noop_bindings: &'a HashSet<String>,
    runtime_helpers: &'a HashMap<String, String>,
    replacements: Vec<Replacement>,
}

impl<'a> Visit<'a> for DependencyRewritePlanner<'_> {
    fn visit_expression_statement(&mut self, it: &ExpressionStatement<'a>) {
        if let Expression::CallExpression(call_expression) = &it.expression
            && let Some(noop_name) = referenced_noop(call_expression, self.noop_bindings)
        {
            self.replacements.push(Replacement {
                span: it.span,
                text: format!("/* debun: removed noop helper {noop_name} */"),
            });
            return;
        }

        if let Expression::CallExpression(call_expression) = &it.expression
            && let Some(dependency) =
                referenced_dependency(call_expression, self.registry, self.current_binding)
        {
            self.replacements.push(Replacement {
                span: it.span,
                text: dependency.statement_replacement(),
            });
            return;
        }

        walk::walk_expression_statement(self, it);
    }

    fn visit_call_expression(&mut self, it: &CallExpression<'a>) {
        if let Some(dependency) = referenced_dependency(it, self.registry, self.current_binding) {
            self.replacements.push(Replacement {
                span: it.span,
                text: dependency.inline_replacement(),
            });
            return;
        }

        if let Some(replacement) = helper_runtime_replacement(it, self.runtime_helpers) {
            self.replacements.push(replacement);
            walk::walk_call_expression(self, it);
            return;
        }

        walk::walk_call_expression(self, it);
    }

    fn visit_sequence_expression(&mut self, it: &SequenceExpression<'a>) {
        if let Some(replacement) = rewrite_dependency_sequence(
            self.source,
            it,
            self.current_binding,
            self.registry,
            self.noop_bindings,
            self.runtime_helpers,
        ) {
            self.replacements.push(replacement);
            return;
        }

        walk::walk_sequence_expression(self, it);
    }
}

fn referenced_dependency<'a>(
    call_expression: &'a CallExpression<'a>,
    registry: &'a HashMap<String, ModuleDescriptor>,
    current_binding: &str,
) -> Option<&'a ModuleDescriptor> {
    if call_expression.optional || !call_expression.arguments.is_empty() {
        return None;
    }

    let Expression::Identifier(identifier) = &call_expression.callee else {
        return None;
    };

    let binding_name = identifier.name.as_str();
    if binding_name == current_binding {
        return None;
    }

    registry.get(binding_name)
}

fn referenced_noop<'a>(
    call_expression: &'a CallExpression<'a>,
    noop_bindings: &'a HashSet<String>,
) -> Option<&'a str> {
    if call_expression.optional || !call_expression.arguments.is_empty() {
        return None;
    }

    let Expression::Identifier(identifier) = &call_expression.callee else {
        return None;
    };

    let binding_name = identifier.name.as_str();
    noop_bindings.contains(binding_name).then_some(binding_name)
}

fn helper_runtime_replacement(
    call_expression: &CallExpression<'_>,
    runtime_helpers: &HashMap<String, String>,
) -> Option<Replacement> {
    let Expression::Identifier(identifier) = &call_expression.callee else {
        return None;
    };

    let helper_name = runtime_helpers.get(identifier.name.as_str())?;

    Some(Replacement {
        span: identifier.span,
        text: helper_name.clone(),
    })
}

fn rewrite_dependency_sequence(
    source: &str,
    sequence_expression: &SequenceExpression<'_>,
    current_binding: &str,
    registry: &HashMap<String, ModuleDescriptor>,
    noop_bindings: &HashSet<String>,
    runtime_helpers: &HashMap<String, String>,
) -> Option<Replacement> {
    let first = sequence_expression.expressions.first()?;
    let Expression::CallExpression(call_expression) = first else {
        return None;
    };
    let dependency = referenced_dependency(call_expression, registry, current_binding)?;
    if dependency.kind != ModuleKind::LazyInit || dependency.exports.is_empty() {
        return None;
    }

    let second = sequence_expression.expressions.get(1)?;
    let start = usize::try_from(second.span().start).ok()?;
    let end = usize::try_from(sequence_expression.span.end).ok()?;
    let tail_source = source.get(start..end)?;
    let rewritten_tail = rewrite_module_source(
        tail_source,
        current_binding,
        registry,
        noop_bindings,
        runtime_helpers,
    )
    .ok()?;

    Some(Replacement {
        span: sequence_expression.span,
        text: format!(
            "(() => {{ var {{ {} }} = {}; return {}; }})()",
            dependency.exports.join(", "),
            dependency.inline_replacement(),
            rewritten_tail.trim()
        ),
    })
}

impl ModuleDescriptor {
    fn inline_replacement(&self) -> String {
        let require_path = format!("require(\"./{}\")", self.file_name);
        match self.kind {
            ModuleKind::CommonJs => require_path,
            ModuleKind::LazyInit => format!("{require_path}()"),
        }
    }

    fn statement_replacement(&self) -> String {
        match self.kind {
            ModuleKind::CommonJs => format!("{};", self.inline_replacement()),
            ModuleKind::LazyInit if self.exports.is_empty() => {
                format!("{};", self.inline_replacement())
            }
            ModuleKind::LazyInit => format!(
                "var {{ {} }} = {};",
                self.exports.join(", "),
                self.inline_replacement()
            ),
        }
    }
}

fn apply_replacements(
    source: &str,
    replacements: &[Replacement],
) -> Result<String, Box<dyn Error>> {
    if replacements.is_empty() {
        return Ok(source.to_string());
    }

    let mut replacements = replacements.iter().collect::<Vec<_>>();
    replacements.sort_by_key(|replacement| replacement.span.start);

    for window in replacements.windows(2) {
        let current = window[0];
        let next = window[1];
        if current.span.end > next.span.start {
            return Err("dependency rewrite generated overlapping replacements".into());
        }
    }

    let mut output = String::with_capacity(source.len());
    let mut cursor = 0usize;

    for replacement in replacements {
        let start = usize::try_from(replacement.span.start)?;
        let end = usize::try_from(replacement.span.end)?;
        let Some(prefix) = source.get(cursor..start) else {
            return Err("replacement start was out of bounds".into());
        };
        output.push_str(prefix);
        output.push_str(&replacement.text);
        cursor = end;
    }

    let Some(suffix) = source.get(cursor..) else {
        return Err("replacement end was out of bounds".into());
    };
    output.push_str(suffix);
    Ok(output)
}
