use crate::config::RunConfig;
use anyhow::{bail, Context, Result};
use std::collections::{BTreeMap, HashSet};
use std::env;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use tempfile::TempDir;

#[derive(Debug)]
pub struct SealedCredentials {
    pub dir: TempDir,
    pub access: Vec<SealedCredential>,
    pub sanitized_env: BTreeMap<String, String>,
}

#[derive(Debug)]
pub struct SealedCredential {
    pub name: String,
    pub upstream: String,
    pub tls_ca: Option<String>,
    pub inject_mode: String,
    pub credential_file: std::path::PathBuf,
    pub endpoint_rules: Vec<crate::config::EndpointRule>,
}

pub fn seal_credentials(config: &RunConfig) -> Result<SealedCredentials> {
    let dir = tempfile::Builder::new()
        .prefix("runseal-creds.")
        .tempdir()?;
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700))?;

    let secret_names: HashSet<&str> = config.access.iter().map(|c| c.secret.as_str()).collect();
    let sanitized_env: BTreeMap<String, String> = env::vars()
        .filter(|(key, _)| !secret_names.contains(key.as_str()))
        .filter(|(key, _)| !key.starts_with("RUNSEAL_"))
        .filter(|(key, _)| !key.starts_with("NONO_ACTION_"))
        .collect();

    let mut sealed = Vec::new();
    for grant in &config.access {
        let secret = env::var(&grant.secret)
            .with_context(|| format!("access secret env var '{}' is not set", grant.secret))?;
        if secret.is_empty() {
            bail!("access secret env var '{}' is empty", grant.secret);
        }
        println!("::add-mask::{secret}");

        let name = grant.name.clone();
        let path = dir.path().join(&name);
        fs::write(&path, secret.as_bytes())?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;

        sealed.push(SealedCredential {
            name,
            upstream: grant.upstream.clone(),
            tls_ca: grant.tls_ca.clone(),
            inject_mode: grant.inject_mode.clone(),
            credential_file: path,
            endpoint_rules: grant.endpoint_rules.clone(),
        });
    }

    Ok(SealedCredentials {
        dir,
        access: sealed,
        sanitized_env,
    })
}
