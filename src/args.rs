use std::{
    env,
    path::{Path, PathBuf},
};

#[derive(Debug, Clone)]
pub struct Config {
    pub input: PathBuf,
    pub out_dir: PathBuf,
    pub module_name: String,
    pub rename_symbols: bool,
}

impl Config {
    pub fn parse_env() -> Result<Option<Self>, String> {
        let mut args = env::args().skip(1);
        let binary = env::args()
            .next()
            .unwrap_or_else(|| "bundle_reflow".to_string());

        let mut input = None;
        let mut out_dir = None;
        let mut module_name = None;
        let mut rename_symbols = true;

        while let Some(arg) = args.next() {
            match arg.as_str() {
                "-h" | "--help" => {
                    println!("{}", help_text(&binary));
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
                value if value.starts_with('-') => {
                    return Err(format!("unknown flag: {value}\n\n{}", help_text(&binary)));
                }
                value => {
                    if input.is_some() {
                        return Err(format!(
                            "unexpected extra positional argument: {value}\n\n{}",
                            help_text(&binary)
                        ));
                    }
                    input = Some(PathBuf::from(value));
                }
            }
        }

        let input = input.ok_or_else(|| format!("missing input file\n\n{}", help_text(&binary)))?;
        let out_dir = out_dir.unwrap_or_else(|| default_out_dir(&input));
        let module_name = module_name.unwrap_or_else(|| default_module_name(&input));

        Ok(Some(Self {
            input,
            out_dir,
            module_name,
            rename_symbols,
        }))
    }
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

fn help_text(binary: &str) -> String {
    format!(
        "\
Turn compressed Bun/JS bundle output into a more readable set of files.

Usage:
  {binary} <input> [--out-dir <dir>] [--module-name <name>] [--no-rename]

Output files:
  summary.json   machine-friendly output inventory and stats
  symbols.txt    old -> new symbol mapping report
  modules/       split CommonJS and lazy-init module bodies + shared runtime
  modules.txt    split module index
  embedded/      raw __BUN data, bunfs paths, metadata, and extracted embedded files
  warnings.txt   parser/semantic diagnostics, if any
"
    )
}
