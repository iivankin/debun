use std::{collections::HashMap, error::Error, fmt::Write as _};

use oxc_allocator::Allocator;
use oxc_ast::ast::{Argument, Expression, FormalParameters, FunctionBody, Program, Statement};
use oxc_parser::{ParseOptions, Parser};
use oxc_span::{GetSpan, SourceType, Span};
use oxc_syntax::symbol::SymbolId;

use crate::rewrite::analyze_lazy_exports;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ModuleKind {
    CommonJs,
    LazyInit,
}

impl ModuleKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::CommonJs => "commonjs",
            Self::LazyInit => "lazy-init",
        }
    }
}

#[derive(Debug, Clone)]
pub struct ModuleDescriptor {
    pub file_name: String,
    pub kind: ModuleKind,
    pub exports: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct RawSplitModule {
    pub index: usize,
    pub file_name: String,
    pub module_name: String,
    pub binding_name: String,
    pub helper_name: String,
    pub kind: ModuleKind,
    pub params: Vec<String>,
    pub hint: Option<String>,
    pub support_source: String,
    pub body_source: String,
    pub support_bindings: Vec<String>,
    pub exports: Vec<String>,
}

impl RawSplitModule {
    pub fn descriptor(&self) -> ModuleDescriptor {
        ModuleDescriptor {
            file_name: self.file_name.clone(),
            kind: self.kind,
            exports: self.exports.clone(),
        }
    }

    pub fn render_source(&self, support_source: &str, body_source: &str) -> String {
        let mut out = String::new();
        let _ = writeln!(out, "// extracted binding: {}", self.binding_name);
        let _ = writeln!(out, "// wrapper helper: {}", self.helper_name);
        let _ = writeln!(out, "// module kind: {}", self.kind.label());
        if let Some(hint) = &self.hint {
            let _ = writeln!(out, "// inferred hint: {hint}");
        }
        if !self.params.is_empty() {
            let _ = writeln!(out, "// factory params: {}", self.params.join(", "));
        }
        if !self.exports.is_empty() {
            let _ = writeln!(out, "// exported state: {}", self.exports.join(", "));
        }
        out.push('\n');
        out.push_str("const __debun = require(\"./_debun_runtime.js\");\n");
        if !support_source.trim().is_empty() {
            out.push('\n');
            out.push_str(support_source.trim_end());
            out.push('\n');
        }
        out.push('\n');

        match self.kind {
            ModuleKind::CommonJs => {
                out.push_str(body_source.trim_end());
                out.push('\n');
            }
            ModuleKind::LazyInit => {
                for export_name in &self.exports {
                    if !self
                        .support_bindings
                        .iter()
                        .any(|binding| binding == export_name)
                    {
                        let _ = writeln!(out, "let {export_name};");
                    }
                }
                if !self.exports.is_empty() {
                    out.push('\n');
                }
                out.push_str("module.exports = __debun.createLazyInit(function init() {\n");
                out.push_str(&indent_block(body_source, "  "));
                if self.exports.is_empty() {
                    out.push_str("  return {};\n");
                } else {
                    out.push_str("  return {\n");
                    for export_name in &self.exports {
                        let _ = writeln!(out, "    {export_name}: {export_name},");
                    }
                    out.push_str("  };\n");
                }
                out.push_str("});\n");
            }
        }

        out
    }
}

#[derive(Debug, Clone)]
pub struct SplitModule {
    pub index: usize,
    pub file_name: String,
    pub module_name: String,
    pub binding_name: String,
    pub helper_name: String,
    pub kind: ModuleKind,
    pub params: Vec<String>,
    pub hint: Option<String>,
    pub exports: Vec<String>,
    pub source: String,
    pub renamed_symbols: usize,
    pub parse_warnings: usize,
    pub semantic_warnings: usize,
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

pub fn build_module_registry(modules: &[RawSplitModule]) -> HashMap<String, ModuleDescriptor> {
    modules
        .iter()
        .map(|module| (module.binding_name.clone(), module.descriptor()))
        .collect()
}

pub fn modules_report(modules: &[SplitModule]) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "index\tfile\tmodule_name\tbinding\thelper\tkind\tparams\texports\thint\trenamed_symbols\tparse_warnings\tsemantic_warnings"
    );

    for module in modules {
        let _ = writeln!(
            out,
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            module.index,
            module.file_name,
            module.module_name,
            module.binding_name,
            module.helper_name,
            module.kind.label(),
            module.params.join(","),
            module.exports.join(","),
            module.hint.as_deref().unwrap_or(""),
            module.renamed_symbols,
            module.parse_warnings,
            module.semantic_warnings,
        );
    }

    out
}

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

fn slice_body(source: &str, body_span: Span) -> Result<String, Box<dyn Error>> {
    let start = usize::try_from(body_span.start)?;
    let end = usize::try_from(body_span.end)?;
    let Some(block_source) = source.get(start..end) else {
        return Err("module body span was out of bounds".into());
    };

    Ok(unwrap_block(block_source))
}

fn slice_statement_range(
    source: &str,
    statements: &[Statement<'_>],
    start_index: usize,
    end_index: usize,
) -> Result<String, Box<dyn Error>> {
    if start_index >= end_index || start_index >= statements.len() {
        return Ok(String::new());
    }

    let start = usize::try_from(statements[start_index].span().start)?;
    let end = usize::try_from(statements[end_index - 1].span().end)?;
    let Some(snippet) = source.get(start..end) else {
        return Err("module support span was out of bounds".into());
    };

    let mut out = snippet.trim().to_string();
    if !out.is_empty() && !out.ends_with('\n') {
        out.push('\n');
    }
    Ok(out)
}

fn unwrap_block(block_source: &str) -> String {
    let trimmed = block_source.trim();
    if !trimmed.starts_with('{') || !trimmed.ends_with('}') {
        let mut out = trimmed.to_string();
        if !out.ends_with('\n') {
            out.push('\n');
        }
        return out;
    }

    let inner = &trimmed[1..trimmed.len() - 1];
    let inner = inner.strip_prefix('\n').unwrap_or(inner);
    let inner = inner.strip_suffix('\n').unwrap_or(inner);
    let lines = inner.lines().collect::<Vec<_>>();

    let min_indent = lines
        .iter()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            line.chars()
                .take_while(|ch| ch.is_ascii_whitespace())
                .count()
        })
        .min()
        .unwrap_or(0);

    let mut out = String::new();
    for (index, line) in lines.iter().enumerate() {
        let trimmed_line = trim_indent(line, min_indent);
        out.push_str(trimmed_line);
        if index + 1 < lines.len() {
            out.push('\n');
        }
    }

    if !out.ends_with('\n') {
        out.push('\n');
    }

    out
}

fn trim_indent(line: &str, indent: usize) -> &str {
    let mut trimmed = line;
    let mut remaining = indent;

    while remaining > 0 {
        let Some(ch) = trimmed.chars().next() else {
            break;
        };
        if !ch.is_ascii_whitespace() {
            break;
        }
        trimmed = &trimmed[ch.len_utf8()..];
        remaining -= 1;
    }

    trimmed
}

fn indent_block(source: &str, indent: &str) -> String {
    let mut out = String::new();
    for line in source.lines() {
        if line.is_empty() {
            out.push('\n');
        } else {
            out.push_str(indent);
            out.push_str(line);
            out.push('\n');
        }
    }
    out
}

fn infer_hint(body_source: &str) -> Option<String> {
    for needle in [
        "\"/$bunfs/root/",
        "'/$bunfs/root/",
        "\"file:///$bunfs/root/",
        "'file:///$bunfs/root/",
        "\"./",
        "'./",
        "\"../",
        "'../",
    ] {
        if let Some(path) = extract_quoted_path(body_source, needle) {
            return Some(path_hint(&path));
        }
    }

    None
}

fn extract_quoted_path(source: &str, needle: &str) -> Option<String> {
    let start = source.find(needle)?;
    let quote = needle.chars().next()?;
    let path_start = start + quote.len_utf8();
    let rest = source.get(path_start..)?;
    let end = rest.find(quote)?;
    Some(rest[..end].to_string())
}

fn path_hint(path: &str) -> String {
    let trimmed = path.trim_matches('/');
    let basename = trimmed.rsplit('/').next().unwrap_or(trimmed);
    if basename.is_empty() {
        slugify(trimmed)
    } else {
        slugify(basename)
    }
}

fn unique_file_name(
    index: usize,
    width: usize,
    module_name: &str,
    used_file_names: &mut std::collections::HashSet<String>,
) -> String {
    let base_name = if module_name.is_empty() {
        "module".to_string()
    } else {
        module_name.to_string()
    };

    let mut suffix = 0usize;
    loop {
        let stem = if suffix == 0 {
            format!("{index:0width$}__{base_name}", width = width.max(1))
        } else {
            format!(
                "{index:0width$}__{base_name}_{suffix}",
                width = width.max(1)
            )
        };
        let file_name = format!("{stem}.js");
        if used_file_names.insert(file_name.clone()) {
            return file_name;
        }
        suffix += 1;
    }
}

fn digit_width(count: usize) -> usize {
    count.max(1).to_string().len()
}

fn slugify(value: &str) -> String {
    let mut slug = String::new();
    let mut previous_was_separator = false;

    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() {
            slug.push(ch.to_ascii_lowercase());
            previous_was_separator = false;
        } else if !previous_was_separator {
            slug.push('_');
            previous_was_separator = true;
        }
    }

    let slug = slug.trim_matches('_').to_string();
    if slug.is_empty() {
        "module".to_string()
    } else {
        slug
    }
}

fn default_module_name(kind: ModuleKind, index: usize, width: usize) -> String {
    match kind {
        ModuleKind::CommonJs => format!("cjs{:0width$}", index, width = width.max(1)),
        ModuleKind::LazyInit => format!("esm{:0width$}", index, width = width.max(1)),
    }
}
