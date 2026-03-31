use std::collections::HashMap;

mod candidate;
mod extract;
mod naming;
mod render;
mod source;

pub use self::extract::{extract_modules, preferred_commonjs_names};
pub use self::render::modules_report;

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
