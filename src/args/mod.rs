use std::{env, path::PathBuf};

mod defaults;
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
pub enum Command {
    Unpack(Config),
    Pack(PackConfig),
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
}
