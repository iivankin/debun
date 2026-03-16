use std::error::Error;

use oxc_ast::ast::Statement;
use oxc_span::{GetSpan, Span};

pub(super) fn slice_body(source: &str, body_span: Span) -> Result<String, Box<dyn Error>> {
    let start = usize::try_from(body_span.start)?;
    let end = usize::try_from(body_span.end)?;
    let Some(block_source) = source.get(start..end) else {
        return Err("module body span was out of bounds".into());
    };

    Ok(unwrap_block(block_source))
}

pub(super) fn slice_statement_range(
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

pub(super) fn indent_block(source: &str, indent: &str) -> String {
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
