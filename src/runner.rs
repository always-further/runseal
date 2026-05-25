use crate::config::{NetworkPolicy, RunConfig};
use crate::secrets::SealedCredentials;
use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};
use std::process::Command;

pub fn run_nono(config: &RunConfig, sealed: &SealedCredentials, profile_path: &Path) -> Result<()> {
    println!("::group::runseal sandbox configuration");
    println!(
        "  filesystem read:  {}",
        display_list(&config.fs_read, "<workspace>")
    );
    println!(
        "  filesystem write: {}",
        display_list(&config.fs_write, "<none>")
    );
    let fs_args = fs_args(config)?;
    println!("  nono fs args:     {}", display_fs_args(&fs_args));
    println!("  direct network:   {}", display_network(&config.network));
    println!(
        "  credential proxy: {}",
        display_credential_proxy(sealed.access.len())
    );
    println!("  access grants:    {} configured", sealed.access.len());
    println!("  nono profile:     {}", profile_path.display());
    println!("::endgroup::");

    let mut command = Command::new("nono");
    command
        .arg("run")
        .arg("--no-rollback")
        .arg("--no-diagnostics")
        .arg("--profile")
        .arg(profile_path);

    for (flag, path) in &fs_args {
        command.arg(flag).arg(path);
    }

    command.arg("--").arg("bash").arg("-c").arg(&config.command);
    command.env_clear().envs(&sealed.sanitized_env);

    let status = command.status().context("failed to spawn nono")?;
    if !status.success() {
        bail!("nono exited with status {status}");
    }
    Ok(())
}

fn fs_args(config: &RunConfig) -> Result<Vec<(&'static str, String)>> {
    let mut args = Vec::new();
    for path in &config.fs_read {
        args.push((fs_flag(path, FsAccess::Read)?, path.clone()));
    }
    for path in &config.fs_write {
        args.push((fs_flag(path, FsAccess::Write)?, path.clone()));
    }
    Ok(args)
}

#[derive(Debug, Clone, Copy)]
enum FsAccess {
    Read,
    Write,
}

fn fs_flag(path: &str, access: FsAccess) -> Result<&'static str> {
    let path = PathBuf::from(path);
    if path.exists() {
        if path.is_dir() {
            return Ok(match access {
                FsAccess::Read => "--read",
                FsAccess::Write => "--write",
            });
        }
        if path.is_file() {
            return Ok(match access {
                FsAccess::Read => "--read-file",
                FsAccess::Write => "--write-file",
            });
        }
        bail!(
            "filesystem policy path '{}' exists but is neither a regular file nor directory",
            path.display()
        );
    }

    match access {
        FsAccess::Read => bail!(
            "filesystem read path '{}' does not exist; create it first or allow an existing parent directory",
            path.display()
        ),
        FsAccess::Write => Ok("--write"),
    }
}

fn display_list(values: &[String], empty: &str) -> String {
    if values.is_empty() {
        empty.to_string()
    } else {
        values.join(", ")
    }
}

fn display_fs_args(args: &[(&'static str, String)]) -> String {
    if args.is_empty() {
        return "<none>".to_string();
    }

    args.iter()
        .map(|(flag, path)| format!("{flag} {path}"))
        .collect::<Vec<_>>()
        .join(", ")
}

fn display_network(network: &NetworkPolicy) -> String {
    match network {
        NetworkPolicy::Blocked => "blocked".to_string(),
        NetworkPolicy::AllowDomains(domains) => domains.join(", "),
    }
}

fn display_credential_proxy(credential_count: usize) -> &'static str {
    if credential_count == 0 {
        "disabled"
    } else {
        "enabled for sealed credential routes"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn read_directory_uses_read_flag() {
        let dir = tempfile::tempdir().expect("tempdir");
        assert_eq!(
            fs_flag(path_str(dir.path()), FsAccess::Read).unwrap(),
            "--read"
        );
    }

    #[test]
    fn read_file_uses_read_file_flag() {
        let dir = tempfile::tempdir().expect("tempdir");
        let file = dir.path().join("allowed.txt");
        fs::write(&file, "allowed").expect("write file");

        assert_eq!(
            fs_flag(path_str(&file), FsAccess::Read).unwrap(),
            "--read-file"
        );
    }

    #[test]
    fn write_directory_uses_write_flag() {
        let dir = tempfile::tempdir().expect("tempdir");
        assert_eq!(
            fs_flag(path_str(dir.path()), FsAccess::Write).unwrap(),
            "--write"
        );
    }

    #[test]
    fn write_file_uses_write_file_flag() {
        let dir = tempfile::tempdir().expect("tempdir");
        let file = dir.path().join("result.txt");
        fs::write(&file, "old").expect("write file");

        assert_eq!(
            fs_flag(path_str(&file), FsAccess::Write).unwrap(),
            "--write-file"
        );
    }

    #[test]
    fn missing_read_path_fails_closed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let missing = dir.path().join("missing.txt");

        let err = fs_flag(path_str(&missing), FsAccess::Read).unwrap_err();
        assert!(err.to_string().contains("does not exist"));
    }

    fn path_str(path: &Path) -> &str {
        path.to_str().expect("test path utf-8")
    }
}
