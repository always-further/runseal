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
    pub credentials: Vec<SealedCredential>,
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

    let secret_names: HashSet<&str> = config
        .credentials
        .iter()
        .map(|c| c.secret_env.as_str())
        .collect();
    let sanitized_env: BTreeMap<String, String> = env::vars()
        .filter(|(key, _)| !secret_names.contains(key.as_str()))
        .filter(|(key, _)| !key.starts_with("RUNSEAL_"))
        .filter(|(key, _)| !key.starts_with("NONO_ACTION_"))
        .collect();

    let mut sealed = Vec::new();
    for (idx, credential) in config.credentials.iter().enumerate() {
        let secret = env::var(&credential.secret_env).with_context(|| {
            format!("credential env var '{}' is not set", credential.secret_env)
        })?;
        if secret.is_empty() {
            bail!("credential env var '{}' is empty", credential.secret_env);
        }
        println!("::add-mask::{secret}");

        let name = format!("cred_{idx}");
        let path = dir.path().join(&name);
        fs::write(&path, secret.as_bytes())?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;

        sealed.push(SealedCredential {
            name,
            upstream: credential.upstream.clone(),
            tls_ca: credential.tls_ca.clone(),
            inject_mode: credential.inject_mode.clone(),
            credential_file: path,
            endpoint_rules: credential.endpoint_rules.clone(),
        });
    }

    Ok(SealedCredentials {
        dir,
        credentials: sealed,
        sanitized_env,
    })
}
