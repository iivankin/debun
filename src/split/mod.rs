use std::{collections::HashMap, fmt::Write as _};

use self::source::indent_block;

mod extract;
mod naming;
mod source;

pub use self::extract::{extract_modules, preferred_commonjs_names};

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
