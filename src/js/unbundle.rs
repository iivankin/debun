use std::collections::{HashMap, HashSet};

use crate::{
    args::Config,
    rewrite::{
        collect_external_bundle_refs, collect_noop_bindings, collect_runtime_helpers,
        rewrite_module_source,
    },
    split::{ModuleDescriptor, ModuleKind, SplitModule, build_module_registry, extract_modules},
};

pub(super) fn build_split_modules(
    config: &Config,
    source: &str,
) -> Result<Vec<SplitModule>, Box<dyn std::error::Error>> {
    let Ok(mut candidate_modules) = extract_modules(source) else {
        return Ok(Vec::new());
    };
    let noop_bindings = collect_noop_bindings(source)?;
    let runtime_helpers = collect_runtime_helpers(source)?;
    let initial_registry = build_module_registry(&candidate_modules);

    for raw_module in &mut candidate_modules {
        if raw_module.kind != ModuleKind::LazyInit {
            continue;
        }

        let rewritten_support = rewrite_module_source(
            &raw_module.support_source,
            &raw_module.binding_name,
            &initial_registry,
            &noop_bindings,
            &runtime_helpers,
        )?;
        let rewritten_body = rewrite_module_source(
            &raw_module.body_source,
            &raw_module.binding_name,
            &initial_registry,
            &noop_bindings,
            &runtime_helpers,
        )?;
        let implicit_exports =
            collect_external_bundle_refs(&(rewritten_support + "\n" + &rewritten_body))?;
        raw_module.exports.extend(
            implicit_exports
                .into_iter()
                .filter(|name| name != &raw_module.binding_name),
        );
        raw_module.exports.sort();
        raw_module.exports.dedup();
    }

    let registry = build_module_registry(&candidate_modules);
    let mut modules = Vec::with_capacity(candidate_modules.len());

    for raw_module in candidate_modules {
        let mut module_config = config.clone();
        module_config
            .module_name
            .clone_from(&raw_module.module_name);
        let used_bundle_refs = collect_external_bundle_refs(&format!(
            "{}\n{}",
            raw_module.support_source, raw_module.body_source
        ))?
        .into_iter()
        .collect::<HashSet<_>>();
        let narrowed_registry = narrow_registry_for_module(&registry, &used_bundle_refs);
        let rewritten_support = rewrite_module_source(
            &raw_module.support_source,
            &raw_module.binding_name,
            &narrowed_registry,
            &noop_bindings,
            &runtime_helpers,
        )?;
        let rewritten_body = rewrite_module_source(
            &raw_module.body_source,
            &raw_module.binding_name,
            &narrowed_registry,
            &noop_bindings,
            &runtime_helpers,
        )?;
        let module_source = raw_module.render_source(&rewritten_support, &rewritten_body);

        let transformed =
            super::pipeline::transform_source_inner(&module_config, &module_source, false)?;
        let final_source = if config.rename_symbols {
            transformed.renamed
        } else {
            transformed.formatted
        };

        modules.push(SplitModule {
            index: raw_module.index,
            file_name: raw_module.file_name,
            module_name: raw_module.module_name,
            binding_name: raw_module.binding_name,
            helper_name: raw_module.helper_name,
            kind: raw_module.kind,
            params: raw_module.params,
            hint: raw_module.hint,
            exports: raw_module.exports,
            source: final_source,
            renamed_symbols: transformed.renames.len(),
            parse_warnings: transformed.parse_errors.len(),
            semantic_warnings: transformed.semantic_errors.len(),
        });
    }

    Ok(modules)
}

fn narrow_registry_for_module(
    registry: &HashMap<String, ModuleDescriptor>,
    used_refs: &HashSet<String>,
) -> HashMap<String, ModuleDescriptor> {
    registry
        .iter()
        .map(|(binding, descriptor)| {
            let mut narrowed = descriptor.clone();
            if matches!(narrowed.kind, ModuleKind::LazyInit) {
                narrowed.exports.retain(|name| used_refs.contains(name));
            }
            (binding.clone(), narrowed)
        })
        .collect()
}
