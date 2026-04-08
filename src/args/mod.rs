use std::{env, path::PathBuf};

pub(crate) mod defaults;
mod parse;

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
pub struct PatchConfig {
    pub from_dir: PathBuf,
    pub out_file: PathBuf,
}

#[derive(Debug, Clone)]
pub struct ApplyPatchConfig {
    pub patch_file: PathBuf,
    pub input: Option<PathBuf>,
    pub out_file: Option<PathBuf>,
}

#[derive(Debug, Clone)]
pub enum Command {
    Unpack(Config),
    Pack(PackConfig),
    Patch(PatchConfig),
    ApplyPatch(ApplyPatchConfig),
}

impl Command {
    pub fn parse_env() -> Result<Option<Self>, String> {
        parse::parse_args(env::args())
    }
}

#[cfg(test)]
mod tests {
    use super::{Command, parse::parse_args};

    fn parse(args: &[&str]) -> Result<Option<Command>, String> {
        parse_args(
            args.iter()
                .map(std::string::ToString::to_string)
                .collect::<Vec<_>>(),
        )
    }

    #[test]
    fn unpack_infers_output_dir_module_name_and_flags() {
        let command = parse(&["debun", "./app-binary"]).unwrap().unwrap();
        let Command::Unpack(config) = command else {
            panic!("expected unpack command");
        };

        assert!(config.out_dir.ends_with("app-binary.readable"));
        assert_eq!(config.module_name, "app-binary");
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
    fn pack_defaults_output_path_from_input_directory() {
        let command = parse(&["debun", "pack", "./app.readable"])
            .unwrap()
            .unwrap();
        let Command::Pack(config) = command else {
            panic!("expected pack command");
        };

        assert!(config.from_dir.ends_with("app.readable"));
        assert!(config.out_file.ends_with("app.readable.repacked"));
    }

    #[test]
    fn patch_defaults_output_path_from_input_directory() {
        let command = parse(&["debun", "patch", "./app.readable"])
            .unwrap()
            .unwrap();
        let Command::Patch(config) = command else {
            panic!("expected patch command");
        };

        assert!(config.from_dir.ends_with("app.readable"));
        assert!(config.out_file.ends_with("app.readable.patch"));
    }

    #[test]
    fn apply_patch_accepts_positional_binary_input() {
        let command = parse(&["debun", "apply-patch", "./changes.patch", "./app-binary"])
            .unwrap()
            .unwrap();
        let Command::ApplyPatch(config) = command else {
            panic!("expected apply-patch command");
        };

        assert!(config.patch_file.ends_with("changes.patch"));
        assert!(config.input.unwrap().ends_with("app-binary"));
        assert!(config.out_file.is_none());
    }
}
