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
    let inspection = inspect_binary(&config.input)?;
    let extracted = if let Some(source) = inspection
        .as_ref()
        .and_then(|inspection| inspection.entry_point_source.clone())
    {
        ExtractedSource::from_source(source)
    } else {
        ExtractedSource::from_path(&config.input)?
    };
    let artifacts = transform_source(&config, &extracted.source)?;

    fs::create_dir_all(&config.out_dir)?;
    let output_summary = write_outputs(&config, &extracted, inspection.as_ref(), &artifacts)?;

    println!("input: {}", config.input.display());
    println!("output: {}", config.out_dir.display());
    if let Some(primary_output) = &output_summary.primary_output {
        println!("primary: {primary_output}");
    }
    if let Some(inspection) = &inspection
        && let Some(record_size) = inspection.standalone_record_size
    {
        if let Some(version_hint) = inspection.bun_version_hint {
            println!("bun version hint: {version_hint} ({record_size}-byte standalone record)");
        } else {
            println!("standalone record size: {record_size}");
        }
    }
    if output_summary.wrote_symbols {
        println!("rename map: symbols.txt");
    }
    println!("renamed symbols: {}", artifacts.renames.len());
    if output_summary.wrote_modules {
        println!("split modules: {}", artifacts.modules.len());
    }
    if output_summary.wrote_embedded_manifest {
        println!("embedded manifest: embedded/manifest.json");
    }
    if let Some(inspection) = &inspection {
        println!("embedded files: {}", inspection.files.len());
    }

    if output_summary.wrote_warnings && !artifacts.parse_errors.is_empty() {
        println!("parse warnings: {}", artifacts.parse_errors.len());
    }
    if output_summary.wrote_warnings && !artifacts.semantic_errors.is_empty() {
        println!("semantic warnings: {}", artifacts.semantic_errors.len());
    }

    Ok(())
}
