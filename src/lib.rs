pub mod args;
mod embedded;
mod extract;
mod js;
mod output;
mod rewrite;
mod split;
mod standalone;
mod standalone_decode;

use std::{error::Error, fs};

use args::Config;
use embedded::inspect_binary;
use extract::ExtractedSource;
use js::transform_source;
use output::write_outputs;

pub fn run(config: Config) -> Result<(), Box<dyn Error>> {
    print_header(&config);

    print_phase(1, 3, "inspect");
    let inspection = inspect_binary(&config.input)?;
    print_inspection_details(inspection.as_ref());

    print_phase(2, 3, "transform");
    let extracted = if let Some(source) = inspection
        .as_ref()
        .and_then(|inspection| inspection.entry_point_source.clone())
    {
        ExtractedSource::from_source(source)
    } else {
        ExtractedSource::from_path(&config.input)?
    };
    let artifacts = transform_source(&config, &extracted.source)?;

    print_phase(3, 3, "write");
    fs::create_dir_all(&config.out_dir)?;
    let output_summary = write_outputs(&config, &extracted, inspection.as_ref(), &artifacts)?;

    println!();
    println!("done");
    if let Some(primary_output) = &output_summary.primary_output {
        print_detail("primary", primary_output);
    }
    if output_summary.wrote_symbols {
        print_detail("symbols", "symbols.txt");
    }
    print_detail("renamed", artifacts.renames.len());
    if output_summary.wrote_modules {
        print_detail("modules", artifacts.modules.len());
    }
    if output_summary.wrote_embedded_manifest {
        print_detail("manifest", "embedded/manifest.json");
    }
    if let Some(inspection) = &inspection {
        print_detail("files", inspection.files.len());
    }

    if output_summary.wrote_warnings && !artifacts.parse_errors.is_empty() {
        print_detail(
            "parse",
            format!("{} warnings", artifacts.parse_errors.len()),
        );
    }
    if output_summary.wrote_warnings && !artifacts.semantic_errors.is_empty() {
        print_detail(
            "semantic",
            format!("{} warnings", artifacts.semantic_errors.len()),
        );
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
    if let Some(record_size) = inspection.standalone_record_size {
        let layout = inspection.standalone_layout.unwrap_or("unknown");
        print_detail(
            "standalone",
            format!("{layout} ({record_size}-byte record)"),
        );
    }
}

fn print_detail(label: &str, value: impl std::fmt::Display) {
    println!("  {:<10} {}", label, value);
}
