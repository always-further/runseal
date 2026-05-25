mod config;
mod profile;
mod runner;
mod secrets;

use anyhow::{bail, Context, Result};
use config::RunConfig;
use std::env;

fn main() {
    if let Err(err) = real_main() {
        eprintln!("::error::{err:#}");
        std::process::exit(1);
    }
}

fn real_main() -> Result<()> {
    let mut args = env::args().skip(1);
    match args.next().as_deref() {
        Some("run") => run(),
        Some("--version") | Some("version") => {
            println!("runseal {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        Some(cmd) => bail!("unknown command '{cmd}', expected 'run'"),
        None => bail!("missing command, expected 'run'"),
    }
}

fn run() -> Result<()> {
    let config = RunConfig::from_action_env().context("failed to read action inputs")?;
    let sealed = secrets::seal_credentials(&config).context("failed to seal credentials")?;
    let profile =
        profile::build_profile(&config, &sealed).context("failed to build nono profile")?;
    let profile_path = sealed.dir.path().join("profile.json");
    profile::write_profile(&profile_path, &profile).context("failed to write nono profile")?;

    runner::run_nono(&config, &sealed, &profile_path).context("nono run failed")
}
