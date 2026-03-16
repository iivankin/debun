use std::collections::HashSet;

use super::ModuleKind;

pub(super) fn infer_hint(body_source: &str) -> Option<String> {
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

pub(super) fn unique_file_name(
    index: usize,
    width: usize,
    module_name: &str,
    used_file_names: &mut HashSet<String>,
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

pub(super) fn digit_width(count: usize) -> usize {
    count.max(1).to_string().len()
}

pub(super) fn slugify(value: &str) -> String {
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

pub(super) fn default_module_name(kind: ModuleKind, index: usize, width: usize) -> String {
    match kind {
        ModuleKind::CommonJs => format!("cjs{:0width$}", index, width = width.max(1)),
        ModuleKind::LazyInit => format!("esm{:0width$}", index, width = width.max(1)),
    }
}
