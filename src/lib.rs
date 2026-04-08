pub mod args;
mod binary;
mod embedded;
mod extract;
mod js;
mod json;
mod output;
mod pack;
mod pack_support;
mod patch;
mod rewrite;
mod split;
mod standalone;
mod standalone_decode;

use std::{error::Error, fs};

use args::{ApplyPatchConfig, Command, Config, PackConfig, PatchConfig};
use embedded::inspect_binary;
use extract::ExtractedSource;
use js::transform_source;
use output::write_outputs;
use pack::pack_binary;
use patch::{apply_patch, create_patch};

pub fn run(command: Command) -> Result<(), Box<dyn Error>> {
    match command {
        Command::Unpack(config) => run_unpack(&config),
        Command::Pack(config) => run_pack(&config),
        Command::Patch(config) => run_patch(&config),
        Command::ApplyPatch(config) => run_apply_patch(&config),
    }
}

fn run_unpack(config: &Config) -> Result<(), Box<dyn Error>> {
    print_header(config);

    print_phase(1, 3, "inspect");
    let binary_inspection = inspect_binary(&config.input)?;
    print_inspection_details(binary_inspection.as_ref());

    print_phase(2, 3, "transform");
    let extracted_source = if let Some(source) = binary_inspection
        .as_ref()
        .and_then(|inspection| inspection.entry_point_source.clone())
    {
        ExtractedSource::from_source(source)
    } else {
        ExtractedSource::from_path(&config.input)?
    };
    let transform = transform_source(config, &extracted_source.source)?;

    print_phase(3, 3, "write");
    fs::create_dir_all(&config.out_dir)?;
    let written_outputs = write_outputs(
        config,
        &extracted_source,
        binary_inspection.as_ref(),
        &transform,
    )?;

    println!();
    println!("done");
    if let Some(primary_output) = written_outputs.primary_output() {
        print_detail("primary", primary_output);
    }
    if let Some(symbols) = written_outputs.symbols {
        print_detail("symbols", symbols);
    }
    print_detail("renamed", transform.renames.len());
    if written_outputs.modules.is_some() {
        print_detail("modules", transform.modules.len());
    }
    if let Some(manifest) = written_outputs.embedded_manifest {
        print_detail("manifest", manifest);
    }
    if let Some(pack_support) = written_outputs.pack_support {
        print_detail("pack", pack_support);
    }
    if let Some(inspection) = &binary_inspection {
        print_detail("files", inspection.files.len());
    }

    if !transform.parse_errors.is_empty() {
        print_detail(
            "parse",
            format!("{} warnings", transform.parse_errors.len()),
        );
    }
    if !transform.semantic_errors.is_empty() {
        print_detail(
            "semantic",
            format!("{} warnings", transform.semantic_errors.len()),
        );
    }

    Ok(())
}

fn run_pack(config: &PackConfig) -> Result<(), Box<dyn Error>> {
    println!("debun");
    print_detail("from", config.from_dir.display());
    print_detail("output", config.out_file.display());
    println!();

    print_phase(1, 2, "pack");
    let summary = pack_binary(config)?;

    println!();
    println!("done");
    print_detail("output", config.out_file.display());
    print_detail("root", summary.replacements_root.display());
    print_detail("contents", summary.replacement_counts.contents);
    if summary.replacement_counts.sourcemaps > 0 {
        print_detail("sourcemaps", summary.replacement_counts.sourcemaps);
    }
    if summary.replacement_counts.bytecodes > 0 {
        print_detail("bytecode", summary.replacement_counts.bytecodes);
    }
    if summary.replacement_counts.module_infos > 0 {
        print_detail("module-info", summary.replacement_counts.module_infos);
    }

    Ok(())
}

fn run_patch(config: &PatchConfig) -> Result<(), Box<dyn Error>> {
    println!("debun");
    print_detail("from", config.from_dir.display());
    print_detail("output", config.out_file.display());
    println!();

    print_phase(1, 2, "patch");
    let summary = create_patch(config)?;

    println!();
    println!("done");
    print_detail("output", config.out_file.display());
    print_detail("root", summary.replacements_root.display());
    print_detail("contents", summary.record_counts.contents);
    if summary.record_counts.sourcemaps > 0 {
        print_detail("sourcemaps", summary.record_counts.sourcemaps);
    }
    if summary.record_counts.bytecodes > 0 {
        print_detail("bytecode", summary.record_counts.bytecodes);
    }
    if summary.record_counts.module_infos > 0 {
        print_detail("module-info", summary.record_counts.module_infos);
    }

    Ok(())
}

fn run_apply_patch(config: &ApplyPatchConfig) -> Result<(), Box<dyn Error>> {
    println!("debun");
    print_detail("patch", config.patch_file.display());
    if let Some(input) = &config.input {
        print_detail("input", input.display());
    }
    if let Some(out_file) = &config.out_file {
        print_detail("output", out_file.display());
    }
    println!();

    print_phase(1, 2, "apply-patch");
    let summary = apply_patch(config)?;

    println!();
    println!("done");
    print_detail("input", summary.input_file.display());
    print_detail("output", summary.out_file.display());
    print_detail("contents", summary.record_counts.contents);
    if summary.record_counts.sourcemaps > 0 {
        print_detail("sourcemaps", summary.record_counts.sourcemaps);
    }
    if summary.record_counts.bytecodes > 0 {
        print_detail("bytecode", summary.record_counts.bytecodes);
    }
    if summary.record_counts.module_infos > 0 {
        print_detail("module-info", summary.record_counts.module_infos);
    }

    Ok(())
}

fn print_header(config: &Config) {
    println!("debun");
    print_detail("input", config.input.display());
    print_detail("output", config.out_dir.display());
    println!();
}

fn print_phase(index: usize, total: usize, label: &str) {
    println!("==> [{index}/{total}] {label}");
}

fn print_inspection_details(inspection: Option<&embedded::BinaryInspection>) {
    let Some(inspection) = inspection else {
        return;
    };

    if let Some(version) = inspection.bun_version.as_deref() {
        print_detail("bun", version);
    }
    if let Some(layout) = inspection.standalone_record_layout {
        print_detail(
            "standalone",
            format!("{} ({}-byte record)", layout.label(), layout.size()),
        );
    }
}

fn print_detail(label: &str, value: impl std::fmt::Display) {
    println!("  {label:<10} {value}");
}
