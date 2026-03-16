mod analysis;
mod parser;
mod planner;
#[cfg(test)]
mod tests;

pub use analysis::{
    analyze_lazy_exports, collect_external_bundle_refs, collect_noop_bindings,
    collect_runtime_helpers,
};
pub use planner::rewrite_module_source;
