use std::collections::HashMap;

use oxc_semantic::Scoping;
use oxc_syntax::{
    scope::ScopeId,
    symbol::{SymbolFlags, SymbolId},
};

use super::SymbolRename;

pub(super) fn rename_symbols(
    scoping: &mut Scoping,
    module_name: &str,
    preferred_names: &HashMap<SymbolId, String>,
) -> Vec<SymbolRename> {
    let symbol_ids = scoping.symbol_ids().collect::<Vec<_>>();
    let mut counters = RenameCounters::default();
    let mut renames = Vec::new();

    for symbol_id in symbol_ids {
        let old_name = scoping.symbol_name(symbol_id).to_string();
        let flags = scoping.symbol_flags(symbol_id);
        let scope_id = scoping.symbol_scope_id(symbol_id);
        let kind = classify(flags);

        let new_name = if let Some(preferred_name) = preferred_names.get(&symbol_id) {
            if old_name == *preferred_name {
                continue;
            }
            if local_name_available(scoping, scope_id, symbol_id, preferred_name) {
                preferred_name.clone()
            } else if should_rename(&old_name, flags) {
                next_name(
                    scoping,
                    scope_id,
                    symbol_id,
                    &mut counters,
                    kind,
                    module_name,
                )
            } else {
                continue;
            }
        } else {
            if !should_rename(&old_name, flags) {
                continue;
            }
            next_name(
                scoping,
                scope_id,
                symbol_id,
                &mut counters,
                kind,
                module_name,
            )
        };

        if old_name == new_name {
            continue;
        }

        let references = scoping.get_resolved_reference_ids(symbol_id).len();
        scoping.rename_symbol(symbol_id, scope_id, new_name.as_str().into());

        renames.push(SymbolRename {
            old_name,
            new_name,
            kind: kind.label(),
            scope_debug: format!("{scope_id:?}"),
            references,
        });
    }

    renames
}

fn should_rename(name: &str, flags: SymbolFlags) -> bool {
    if matches!(
        name,
        "exports" | "require" | "module" | "__filename" | "__dirname" | "arguments"
    ) {
        return false;
    }

    if is_common_short_name(name) {
        return false;
    }

    if flags.contains(SymbolFlags::Import) && name.len() > 4 && !looks_minified(name) {
        return false;
    }

    looks_minified(name) || looks_generated_name(name)
}

fn is_common_short_name(name: &str) -> bool {
    matches!(
        name,
        "err"
            | "len"
            | "idx"
            | "key"
            | "val"
            | "src"
            | "dst"
            | "buf"
            | "end"
            | "pos"
            | "msg"
            | "map"
            | "set"
            | "ast"
            | "api"
            | "url"
            | "env"
            | "ctx"
    )
}

fn looks_minified(name: &str) -> bool {
    if name.len() <= 2 {
        return true;
    }

    let has_digit = name.bytes().any(|byte| byte.is_ascii_digit());
    let has_upper = name.bytes().any(|byte| byte.is_ascii_uppercase());
    let has_lower = name.bytes().any(|byte| byte.is_ascii_lowercase());
    let has_suffix_underscore = name.ends_with('_');

    if name.len() <= 3 {
        return true;
    }

    if has_digit && name.len() <= 8 {
        return true;
    }

    if has_suffix_underscore && name.len() <= 8 {
        return true;
    }

    if name.len() <= 5 && has_upper && has_lower {
        return true;
    }

    let upper_count = name.bytes().filter(u8::is_ascii_uppercase).count();
    upper_count >= 2 && name.len() <= 6
}

fn looks_generated_name(name: &str) -> bool {
    [
        "_var_", "_let_", "_const_", "_fn_", "_class_", "_catch_", "_import_", "_value_",
    ]
    .iter()
    .any(|marker| name.contains(marker))
}

#[derive(Clone, Copy)]
enum RenameKind {
    Function,
    Class,
    Import,
    Catch,
    Const,
    Let,
    Var,
    Value,
}

impl RenameKind {
    const fn label(self) -> &'static str {
        match self {
            Self::Function => "function",
            Self::Class => "class",
            Self::Import => "import",
            Self::Catch => "catch",
            Self::Const => "const",
            Self::Let => "let",
            Self::Var => "var",
            Self::Value => "value",
        }
    }

    const fn prefix(self) -> &'static str {
        match self {
            Self::Function => "fn",
            Self::Class => "class",
            Self::Import => "import",
            Self::Catch => "catch",
            Self::Const => "const",
            Self::Let => "let",
            Self::Var => "var",
            Self::Value => "value",
        }
    }
}

fn classify(flags: SymbolFlags) -> RenameKind {
    if flags.contains(SymbolFlags::Function) {
        RenameKind::Function
    } else if flags.contains(SymbolFlags::Class) {
        RenameKind::Class
    } else if flags.contains(SymbolFlags::Import) {
        RenameKind::Import
    } else if flags.contains(SymbolFlags::CatchVariable) {
        RenameKind::Catch
    } else if flags.contains(SymbolFlags::ConstVariable) {
        RenameKind::Const
    } else if flags.contains(SymbolFlags::BlockScopedVariable) {
        RenameKind::Let
    } else if flags.contains(SymbolFlags::FunctionScopedVariable) {
        RenameKind::Var
    } else {
        RenameKind::Value
    }
}

#[derive(Default)]
struct RenameCounters {
    function: usize,
    class: usize,
    import: usize,
    catch: usize,
    constant: usize,
    let_like: usize,
    var_like: usize,
    value: usize,
}

impl RenameCounters {
    fn next(&mut self, kind: RenameKind) -> usize {
        let slot = match kind {
            RenameKind::Function => &mut self.function,
            RenameKind::Class => &mut self.class,
            RenameKind::Import => &mut self.import,
            RenameKind::Catch => &mut self.catch,
            RenameKind::Const => &mut self.constant,
            RenameKind::Let => &mut self.let_like,
            RenameKind::Var => &mut self.var_like,
            RenameKind::Value => &mut self.value,
        };
        *slot += 1;
        *slot
    }
}

fn next_name(
    scoping: &Scoping,
    scope_id: ScopeId,
    symbol_id: SymbolId,
    counters: &mut RenameCounters,
    kind: RenameKind,
    module_name: &str,
) -> String {
    loop {
        let ordinal = counters.next(kind);
        let candidate = format!(
            "{}_{}_{}",
            module_name_slug(module_name),
            kind.prefix(),
            ordinal
        );
        if local_name_available(scoping, scope_id, symbol_id, &candidate) {
            return candidate;
        }
    }
}

fn local_name_available(
    scoping: &Scoping,
    scope_id: ScopeId,
    symbol_id: SymbolId,
    candidate: &str,
) -> bool {
    match scoping.get_binding(scope_id, candidate.into()) {
        None => true,
        Some(existing_symbol_id) => existing_symbol_id == symbol_id,
    }
}

fn module_name_slug(module_name: &str) -> String {
    let mut slug = String::new();
    for ch in module_name.chars() {
        let normalized = if ch.is_ascii_alphanumeric() {
            ch.to_ascii_lowercase()
        } else {
            '_'
        };
        slug.push(normalized);
    }
    if slug.is_empty() {
        "module".to_string()
    } else {
        slug
    }
}
