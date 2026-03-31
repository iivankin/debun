use std::process;

use debun::{args::Command, run};

fn main() {
    let command = match Command::parse_env() {
        Ok(Some(command)) => command,
        Ok(None) => return,
        Err(err) => {
            eprintln!("{err}");
            process::exit(2);
        }
    };

    if let Err(err) = run(command) {
        eprintln!("debun: {err}");
        process::exit(1);
    }
}
