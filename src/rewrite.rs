use std::{
    collections::{HashMap, HashSet},
    error::Error,
};

use oxc_allocator::Allocator;
use oxc_ast::ast::{
    AssignmentExpression, AssignmentTarget, AssignmentTargetMaybeDefault, AssignmentTargetProperty,
    CallExpression, Expression, ExpressionStatement, FunctionBody, Program, SequenceExpression,
    SimpleAssignmentTarget, Statement, UpdateExpression,
};
use oxc_ast_visit::{Visit, walk};
use oxc_parser::{ParseOptions, Parser};
use oxc_span::{GetSpan, SourceType, Span};

use crate::split::{ModuleDescriptor, ModuleKind};

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

fn with_parsed_program(
    source: &str,
    mut visit: impl for<'a> FnMut(&oxc_ast::ast::Program<'a>),
) -> Result<(), Box<dyn Error>> {
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
            "failed to parse module body for analysis/rewrite: {} diagnostics",
            parser_return.errors.len()
        )
        .into());
    }

    let program = parser_return.program;
    visit(&program);
    Ok(())
}

fn wrapper_body_statements<'a>(program: &'a Program<'a>) -> &'a [Statement<'a>] {
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

fn collect_top_level_bindings(source: &str) -> Result<Vec<String>, Box<dyn Error>> {
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

fn is_empty_function_expression(expression: &Expression<'_>) -> bool {
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

fn infer_runtime_helper(body_source: &str) -> Option<&'static str> {
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

fn is_reserved_name(name: &str) -> bool {
    matches!(
        name,
        "exports" | "module" | "require" | "__filename" | "__dirname"
    )
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

fn is_bundle_symbol(name: &str) -> bool {
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

#[derive(Default)]
struct LazyExportCollector {
    locals: HashSet<String>,
    assigned: HashSet<String>,
}

#[derive(Default)]
struct ExternalReferenceCollector {
    locals: HashSet<String>,
    references: HashSet<String>,
}

impl<'a> Visit<'a> for LazyExportCollector {
    fn visit_binding_identifier(&mut self, it: &oxc_ast::ast::BindingIdentifier<'a>) {
        self.locals.insert(it.name.as_str().to_string());
        walk::walk_binding_identifier(self, it);
    }

    fn visit_assignment_expression(&mut self, it: &AssignmentExpression<'a>) {
        collect_assignment_target_names(&it.left, &mut self.assigned);
        walk::walk_assignment_expression(self, it);
    }

    fn visit_update_expression(&mut self, it: &UpdateExpression<'a>) {
        collect_simple_assignment_target_names(&it.argument, &mut self.assigned);
        walk::walk_update_expression(self, it);
    }
}

impl<'a> Visit<'a> for ExternalReferenceCollector {
    fn visit_binding_identifier(&mut self, it: &oxc_ast::ast::BindingIdentifier<'a>) {
        self.locals.insert(it.name.as_str().to_string());
        walk::walk_binding_identifier(self, it);
    }

    fn visit_identifier_reference(&mut self, it: &oxc_ast::ast::IdentifierReference<'a>) {
        self.references.insert(it.name.as_str().to_string());
        walk::walk_identifier_reference(self, it);
    }
}

fn collect_assignment_target_names(target: &AssignmentTarget<'_>, names: &mut HashSet<String>) {
    match target {
        AssignmentTarget::AssignmentTargetIdentifier(identifier) => {
            names.insert(identifier.name.as_str().to_string());
        }
        AssignmentTarget::TSAsExpression(expression) => {
            collect_assignment_target_names_from_expression(&expression.expression, names);
        }
        AssignmentTarget::TSSatisfiesExpression(expression) => {
            collect_assignment_target_names_from_expression(&expression.expression, names);
        }
        AssignmentTarget::TSNonNullExpression(expression) => {
            collect_assignment_target_names_from_expression(&expression.expression, names);
        }
        AssignmentTarget::TSTypeAssertion(expression) => {
            collect_assignment_target_names_from_expression(&expression.expression, names);
        }
        AssignmentTarget::ComputedMemberExpression(_)
        | AssignmentTarget::StaticMemberExpression(_)
        | AssignmentTarget::PrivateFieldExpression(_) => {}
        AssignmentTarget::ArrayAssignmentTarget(pattern) => {
            for item in &pattern.elements {
                if let Some(item) = item {
                    collect_assignment_target_maybe_default_names(item, names);
                }
            }
            if let Some(rest) = &pattern.rest {
                collect_assignment_target_names(&rest.target, names);
            }
        }
        AssignmentTarget::ObjectAssignmentTarget(pattern) => {
            for property in &pattern.properties {
                match property {
                    AssignmentTargetProperty::AssignmentTargetPropertyIdentifier(property) => {
                        names.insert(property.binding.name.as_str().to_string());
                    }
                    AssignmentTargetProperty::AssignmentTargetPropertyProperty(property) => {
                        collect_assignment_target_maybe_default_names(&property.binding, names);
                    }
                }
            }
            if let Some(rest) = &pattern.rest {
                collect_assignment_target_names(&rest.target, names);
            }
        }
    }
}

fn collect_assignment_target_maybe_default_names(
    target: &AssignmentTargetMaybeDefault<'_>,
    names: &mut HashSet<String>,
) {
    match target {
        AssignmentTargetMaybeDefault::AssignmentTargetIdentifier(identifier) => {
            names.insert(identifier.name.as_str().to_string());
        }
        AssignmentTargetMaybeDefault::TSAsExpression(expression) => {
            collect_assignment_target_names_from_expression(&expression.expression, names);
        }
        AssignmentTargetMaybeDefault::TSSatisfiesExpression(expression) => {
            collect_assignment_target_names_from_expression(&expression.expression, names);
        }
        AssignmentTargetMaybeDefault::TSNonNullExpression(expression) => {
            collect_assignment_target_names_from_expression(&expression.expression, names);
        }
        AssignmentTargetMaybeDefault::TSTypeAssertion(expression) => {
            collect_assignment_target_names_from_expression(&expression.expression, names);
        }
        AssignmentTargetMaybeDefault::ComputedMemberExpression(_)
        | AssignmentTargetMaybeDefault::StaticMemberExpression(_)
        | AssignmentTargetMaybeDefault::PrivateFieldExpression(_) => {}
        AssignmentTargetMaybeDefault::ArrayAssignmentTarget(pattern) => {
            for item in &pattern.elements {
                if let Some(item) = item {
                    collect_assignment_target_maybe_default_names(item, names);
                }
            }
            if let Some(rest) = &pattern.rest {
                collect_assignment_target_names(&rest.target, names);
            }
        }
        AssignmentTargetMaybeDefault::ObjectAssignmentTarget(pattern) => {
            for property in &pattern.properties {
                match property {
                    AssignmentTargetProperty::AssignmentTargetPropertyIdentifier(property) => {
                        names.insert(property.binding.name.as_str().to_string());
                    }
                    AssignmentTargetProperty::AssignmentTargetPropertyProperty(property) => {
                        collect_assignment_target_maybe_default_names(&property.binding, names);
                    }
                }
            }
            if let Some(rest) = &pattern.rest {
                collect_assignment_target_names(&rest.target, names);
            }
        }
        AssignmentTargetMaybeDefault::AssignmentTargetWithDefault(target) => {
            collect_assignment_target_names(&target.binding, names);
        }
    }
}

fn collect_assignment_target_names_from_expression(
    expression: &Expression<'_>,
    names: &mut HashSet<String>,
) {
    match expression {
        Expression::TSAsExpression(expression) => {
            collect_assignment_target_names_from_expression(&expression.expression, names);
        }
        Expression::TSSatisfiesExpression(expression) => {
            collect_assignment_target_names_from_expression(&expression.expression, names);
        }
        Expression::TSNonNullExpression(expression) => {
            collect_assignment_target_names_from_expression(&expression.expression, names);
        }
        Expression::TSTypeAssertion(expression) => {
            collect_assignment_target_names_from_expression(&expression.expression, names);
        }
        _ => {}
    }
}

fn collect_simple_assignment_target_names(
    target: &SimpleAssignmentTarget<'_>,
    names: &mut HashSet<String>,
) {
    match target {
        SimpleAssignmentTarget::AssignmentTargetIdentifier(identifier) => {
            names.insert(identifier.name.as_str().to_string());
        }
        SimpleAssignmentTarget::TSAsExpression(expression) => {
            collect_assignment_target_names_from_expression(&expression.expression, names);
        }
        SimpleAssignmentTarget::TSSatisfiesExpression(expression) => {
            collect_assignment_target_names_from_expression(&expression.expression, names);
        }
        SimpleAssignmentTarget::TSNonNullExpression(expression) => {
            collect_assignment_target_names_from_expression(&expression.expression, names);
        }
        SimpleAssignmentTarget::TSTypeAssertion(expression) => {
            collect_assignment_target_names_from_expression(&expression.expression, names);
        }
        SimpleAssignmentTarget::ComputedMemberExpression(_)
        | SimpleAssignmentTarget::StaticMemberExpression(_)
        | SimpleAssignmentTarget::PrivateFieldExpression(_) => {}
    }
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

#[cfg(test)]
mod tests {
    use super::{collect_external_bundle_refs, infer_runtime_helper};

    #[test]
    fn collects_generic_bundle_refs() {
        let refs = collect_external_bundle_refs(
            "bundle_var_1(); bundle_fn_2(); let local_var_3 = 1; local_var_3;",
        )
        .expect("collector should parse");

        assert_eq!(
            refs,
            vec!["bundle_fn_2".to_string(), "bundle_var_1".to_string()]
        );
    }

    #[test]
    fn infers_runtime_helper_from_function_body() {
        let helper = infer_runtime_helper(
            "{ const keys = Object.keys(spec); for (const key of keys) Object.defineProperty(target, key, { get: spec[key], enumerable: true }); }",
        );

        assert_eq!(helper, Some("__debun.defineExports"));
    }
}
