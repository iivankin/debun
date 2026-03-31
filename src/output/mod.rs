use std::error::Error;

use super::{
    args::Config, embedded::BinaryInspection, extract::ExtractedSource, js::TransformArtifacts,
};

mod manifest;
mod runtime;
mod state;
mod summary;
mod writer;

pub(crate) use state::WrittenOutputs;
use summary::render_summary_json;

pub fn write_outputs(
    config: &Config,
    extracted: &ExtractedSource,
    inspection: Option<&BinaryInspection>,
    artifacts: &TransformArtifacts,
) -> Result<WrittenOutputs, Box<dyn Error>> {
    writer::remove_legacy_outputs(&config.out_dir)?;

    let outputs = WrittenOutputs {
        symbols: writer::write_symbols_output(config, artifacts)?,
        modules: writer::write_modules_output(config, &artifacts.modules)?,
        embedded_manifest: writer::write_embedded_outputs(config, inspection)?,
        pack_support: writer::write_pack_support(config, inspection)?,
        warnings: writer::write_warnings_output(config, artifacts)?,
    };

    writer::write_file(
        config.out_dir.join("summary.json"),
        &render_summary_json(config, extracted, inspection, artifacts, &outputs),
    )?;

    Ok(outputs)
}
