use crate::args::Config;

mod pipeline;
mod rename;
mod report;

pub use self::report::symbols_report;

#[derive(Debug, Clone)]
pub struct SymbolRename {
    pub old_name: String,
    pub new_name: String,
    pub kind: &'static str,
    pub scope_debug: String,
    pub references: usize,
}

#[derive(Debug, Clone)]
pub struct TransformArtifacts {
    pub formatted: String,
    pub renamed: String,
    pub renames: Vec<SymbolRename>,
    pub parse_errors: Vec<String>,
    pub semantic_errors: Vec<String>,
    pub modules: Vec<crate::split::SplitModule>,
}

pub fn transform_source(
    config: &Config,
    source: &str,
) -> Result<TransformArtifacts, Box<dyn std::error::Error>> {
    pipeline::transform_source_inner(config, source, true)
}
