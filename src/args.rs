use std::{
    env, fs,
    path::{Path, PathBuf},
};

use crate::pack_support::original_path_path;

#[derive(Debug, Clone)]
pub struct Config {
    pub input: PathBuf,
    pub out_dir: PathBuf,
    pub module_name: String,
    pub rename_symbols: bool,
    pub unbundle: bool,
}

#[derive(Debug, Clone)]
pub struct PackConfig {
    pub from_dir: PathBuf,
    pub out_file: PathBuf,
}

#[derive(Debug, Clone)]
pub enum Command {
    Unpack(Config),
    Pack(PackConfig),
}

impl Command {
    pub fn parse_env() -> Result<Option<Self>, String> {
        parse_args(env::args())
    }
}

fn parse_args<I>(args: I) -> Result<Option<Command>, String>
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
                let Some(value) = args.next() else {
                    return Err("--out-dir requires a value".to_string());
                };
                out_dir = Some(PathBuf::from(value));
            }
            "--module-name" => {
                let Some(value) = args.next() else {
                    return Err("--module-name requires a value".to_string());
                };
                module_name = Some(value);
            }
            "--no-rename" => {
                rename_symbols = false;
            }
            "--unbundle" => {
                unbundle = true;
            }
            value if value.starts_with('-') => {
                return Err(format!("unknown flag: {value}\n\n{}", help_text(binary)));
            }
            value => {
                if input.is_some() {
                    return Err(format!(
                        "unexpected extra positional argument: {value}\n\n{}",
                        help_text(binary)
                    ));
                }
                input = Some(PathBuf::from(value));
            }
        }
    }

    let input = input.ok_or_else(|| format!("missing input file\n\n{}", help_text(binary)))?;
    let out_dir = out_dir.unwrap_or_else(|| default_out_dir(&input));
    let module_name = module_name.unwrap_or_else(|| default_module_name(&input));

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
                let Some(value) = args.next() else {
                    return Err("--from requires a value".to_string());
                };
                from_dir = Some(PathBuf::from(value));
            }
            "--out" => {
                let Some(value) = args.next() else {
                    return Err("--out requires a value".to_string());
                };
                out_file = Some(PathBuf::from(value));
            }
            value if value.starts_with('-') => {
                return Err(format!("unknown flag: {value}\n\n{}", help_text(binary)));
            }
            value => {
                if from_dir.is_some() {
                    return Err(format!(
                        "unexpected extra positional argument: {value}\n\n{}",
                        help_text(binary)
                    ));
                }
                from_dir = Some(PathBuf::from(value));
            }
        }
    }

    let from_dir = from_dir.unwrap_or_else(|| PathBuf::from("."));
    let out_file = out_file.unwrap_or_else(|| default_pack_out_file(&from_dir));

    Ok(Some(Command::Pack(PackConfig { from_dir, out_file })))
}

fn default_out_dir(input: &Path) -> PathBuf {
    let parent = input.parent().unwrap_or_else(|| Path::new("."));
    let stem = input
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or("bundle");
    parent.join(format!("{stem}.readable"))
}

fn default_module_name(input: &Path) -> String {
    input
        .file_stem()
        .and_then(|value| value.to_str())
        .filter(|value| !value.is_empty())
        .unwrap_or("bundle")
        .to_string()
}

fn default_repacked_path(input: &Path) -> PathBuf {
    let parent = input.parent().unwrap_or_else(|| Path::new("."));
    let file_name = input
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("binary");
    let stem = input.file_stem().and_then(|value| value.to_str());
    let extension = input.extension().and_then(|value| value.to_str());

    match (stem, extension) {
        (Some(stem), Some(extension)) if !stem.is_empty() && !extension.is_empty() => {
            parent.join(format!("{stem}.repacked.{extension}"))
        }
        _ => parent.join(format!("{file_name}.repacked")),
    }
}

fn default_pack_out_file(from_dir: &Path) -> PathBuf {
    if let Some(original_input) = read_pack_original_path(from_dir) {
        return default_repacked_path(&original_input);
    }

    let name = from_dir
        .file_name()
        .and_then(|value| value.to_str())
        .filter(|value| !value.is_empty())
        .unwrap_or("packed-binary");
    from_dir.join(format!("{name}.repacked"))
}

fn read_pack_original_path(from_dir: &Path) -> Option<PathBuf> {
    pack_workspace_candidates(from_dir).find_map(|candidate| {
        let path = original_path_path(&candidate);
        let contents = fs::read_to_string(path).ok()?;
        let trimmed = contents.trim();
        (!trimmed.is_empty()).then(|| PathBuf::from(trimmed))
    })
}

fn pack_workspace_candidates(from_dir: &Path) -> impl Iterator<Item = PathBuf> {
    let direct = from_dir.to_path_buf();
    let parent = from_dir.parent().map(Path::to_path_buf);
    let grandparent = from_dir
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf);

    [Some(direct), parent, grandparent].into_iter().flatten()
}

fn help_text(binary: &str) -> String {
    format!(
        "\
Turn compressed Bun/JS bundle output into a more readable set of files.

Usage:
  {binary} <input> [--out-dir <dir>] [--module-name <name>] [--no-rename] [--unbundle]
  {binary} pack [<dir>] [--out <file>]

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
"
    )
}

#[cfg(test)]
mod tests {
    use super::{Command, parse_args};

    fn parse(args: &[&str]) -> Result<Option<Command>, String> {
        parse_args(
            args.iter()
                .map(|value| value.to_string())
                .collect::<Vec<_>>(),
        )
    }

    #[test]
    fn unpack_defaults_to_no_unbundle() {
        let command = parse(&["debun", "./app-binary"]).unwrap().unwrap();
        let Command::Unpack(config) = command else {
            panic!("expected unpack command");
        };

        assert!(!config.unbundle);
        assert!(config.rename_symbols);
    }

    #[test]
    fn unpack_enables_unbundle_explicitly() {
        let command = parse(&["debun", "./app-binary", "--unbundle"])
            .unwrap()
            .unwrap();
        let Command::Unpack(config) = command else {
            panic!("expected unpack command");
        };

        assert!(config.unbundle);
    }

    #[test]
    fn pack_command_uses_unpack_defaults() {
        let command = parse(&["debun", "pack", "./app.readable"])
            .unwrap()
            .unwrap();
        let Command::Pack(config) = command else {
            panic!("expected pack command");
        };

        assert!(config.from_dir.ends_with("app.readable"));
        assert!(config.out_file.ends_with("app.readable.repacked"));
    }
}
