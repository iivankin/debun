use std::path::PathBuf;

use super::{ApplyPatchConfig, Command, Config, PackConfig, PatchConfig, defaults};

pub(super) fn parse_args<I>(args: I) -> Result<Option<Command>, String>
where
    I: IntoIterator<Item = String>,
{
    let mut args = args.into_iter();
    let binary = args.next().unwrap_or_else(|| "debun".to_string());

    let Some(first) = args.next() else {
        return Err(format!("missing input file\n\n{}", help_text(&binary)));
    };

    match first.as_str() {
        "-h" | "--help" => {
            println!("{}", help_text(&binary));
            Ok(None)
        }
        "pack" => parse_pack_args(&binary, args),
        "patch" => parse_patch_args(&binary, args),
        "apply-patch" => parse_apply_patch_args(&binary, args),
        value => parse_unpack_args(&binary, std::iter::once(value.to_string()).chain(args)),
    }
}

fn parse_unpack_args<I>(binary: &str, args: I) -> Result<Option<Command>, String>
where
    I: IntoIterator<Item = String>,
{
    let mut args = args.into_iter();
    let mut input = None;
    let mut out_dir = None;
    let mut module_name = None;
    let mut rename_symbols = true;
    let mut unbundle = false;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-h" | "--help" => {
                println!("{}", help_text(binary));
                return Ok(None);
            }
            "--out-dir" => {
                out_dir = Some(PathBuf::from(require_value(&mut args, "--out-dir")?));
            }
            "--module-name" => {
                module_name = Some(require_value(&mut args, "--module-name")?);
            }
            "--no-rename" => rename_symbols = false,
            "--unbundle" => unbundle = true,
            value if value.starts_with('-') => {
                return Err(format!("unknown flag: {value}\n\n{}", help_text(binary)));
            }
            value => assign_positional(&mut input, PathBuf::from(value), value, binary)?,
        }
    }

    let input = input.ok_or_else(|| format!("missing input file\n\n{}", help_text(binary)))?;
    let out_dir = out_dir.unwrap_or_else(|| defaults::default_out_dir(&input));
    let module_name = module_name.unwrap_or_else(|| defaults::default_module_name(&input));

    Ok(Some(Command::Unpack(Config {
        input,
        out_dir,
        module_name,
        rename_symbols,
        unbundle,
    })))
}

fn parse_pack_args<I>(binary: &str, args: I) -> Result<Option<Command>, String>
where
    I: IntoIterator<Item = String>,
{
    let mut args = args.into_iter();
    let mut from_dir = None;
    let mut out_file = None;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-h" | "--help" => {
                println!("{}", help_text(binary));
                return Ok(None);
            }
            "--from" => {
                from_dir = Some(PathBuf::from(require_value(&mut args, "--from")?));
            }
            "--out" => {
                out_file = Some(PathBuf::from(require_value(&mut args, "--out")?));
            }
            value if value.starts_with('-') => {
                return Err(format!("unknown flag: {value}\n\n{}", help_text(binary)));
            }
            value => assign_positional(&mut from_dir, PathBuf::from(value), value, binary)?,
        }
    }

    let from_dir = from_dir.unwrap_or_else(|| PathBuf::from("."));
    let out_file = out_file.unwrap_or_else(|| defaults::default_pack_out_file(&from_dir));

    Ok(Some(Command::Pack(PackConfig { from_dir, out_file })))
}

fn parse_patch_args<I>(binary: &str, args: I) -> Result<Option<Command>, String>
where
    I: IntoIterator<Item = String>,
{
    let mut args = args.into_iter();
    let mut from_dir = None;
    let mut out_file = None;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-h" | "--help" => {
                println!("{}", help_text(binary));
                return Ok(None);
            }
            "--from" => {
                from_dir = Some(PathBuf::from(require_value(&mut args, "--from")?));
            }
            "--out" => {
                out_file = Some(PathBuf::from(require_value(&mut args, "--out")?));
            }
            value if value.starts_with('-') => {
                return Err(format!("unknown flag: {value}\n\n{}", help_text(binary)));
            }
            value => assign_positional(&mut from_dir, PathBuf::from(value), value, binary)?,
        }
    }

    let from_dir = from_dir.unwrap_or_else(|| PathBuf::from("."));
    let out_file = out_file.unwrap_or_else(|| defaults::default_patch_out_file(&from_dir));

    Ok(Some(Command::Patch(PatchConfig { from_dir, out_file })))
}

fn parse_apply_patch_args<I>(binary: &str, args: I) -> Result<Option<Command>, String>
where
    I: IntoIterator<Item = String>,
{
    let mut args = args.into_iter();
    let mut patch_file = None;
    let mut input = None;
    let mut out_file = None;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-h" | "--help" => {
                println!("{}", help_text(binary));
                return Ok(None);
            }
            "--input" => {
                input = Some(PathBuf::from(require_value(&mut args, "--input")?));
            }
            "--out" => {
                out_file = Some(PathBuf::from(require_value(&mut args, "--out")?));
            }
            value if value.starts_with('-') => {
                return Err(format!("unknown flag: {value}\n\n{}", help_text(binary)));
            }
            value if patch_file.is_none() => {
                patch_file = Some(PathBuf::from(value));
            }
            value => assign_positional(&mut input, PathBuf::from(value), value, binary)?,
        }
    }

    let patch_file =
        patch_file.ok_or_else(|| format!("missing patch file\n\n{}", help_text(binary)))?;

    Ok(Some(Command::ApplyPatch(ApplyPatchConfig {
        patch_file,
        input,
        out_file,
    })))
}

fn assign_positional<T>(
    slot: &mut Option<T>,
    value: T,
    display: &str,
    binary: &str,
) -> Result<(), String> {
    if slot.is_some() {
        return Err(format!(
            "unexpected extra positional argument: {display}\n\n{}",
            help_text(binary)
        ));
    }

    *slot = Some(value);
    Ok(())
}

fn require_value<I>(args: &mut I, flag: &str) -> Result<String, String>
where
    I: Iterator<Item = String>,
{
    args.next()
        .ok_or_else(|| format!("{flag} requires a value"))
}

fn help_text(binary: &str) -> String {
    format!(
        "\
Turn compressed Bun/JS bundle output into a more readable set of files.

Usage:
  {binary} <input> [--out-dir <dir>] [--module-name <name>] [--no-rename] [--unbundle]
  {binary} pack [<dir>] [--out <file>]
  {binary} patch [<dir>] [--out <file>]
  {binary} apply-patch <patch-file> [<input-binary>] [--out <file>]

Output files:
  summary.json   machine-friendly output inventory and stats
  symbols.txt    old -> new symbol mapping report
  modules/       split CommonJS and lazy-init module bodies + shared runtime (--unbundle only)
  modules.txt    split module index (--unbundle only)
  embedded/      raw __BUN data, bunfs paths, metadata, and extracted embedded files
  warnings.txt   parser/semantic diagnostics, if any

Pack command:
  Reads replacement files and the saved base executable from <dir>. The unpack
  output stores repack support under .debun automatically for Bun standalone binaries.

Patch commands:
  patch generates a debun .patch bundle from edited embedded/files content.
  apply-patch validates and applies that bundle to a Bun standalone binary.
"
    )
}
