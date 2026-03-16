use std::process;

use debun::{args::Config, run};

fn main() {
    let config = match Config::parse_env() {
        Ok(Some(config)) => config,
        Ok(None) => return,
        Err(err) => {
            eprintln!("{err}");
            process::exit(2);
        }
    };

    if let Err(err) = run(config) {
        eprintln!("debun: {err}");
        process::exit(1);
    }
}
