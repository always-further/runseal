use anyhow::{bail, Context, Result};
use serde::Deserialize;
use std::env;

#[derive(Debug, Clone)]
pub struct RunConfig {
    pub command: String,
    pub fs_read: Vec<String>,
    pub fs_write: Vec<String>,
    pub network: NetworkPolicy,
    pub credentials: Vec<CredentialConfig>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetworkPolicy {
    Blocked,
    AllowDomains(Vec<String>),
}

#[derive(Debug, Clone)]
pub struct CredentialConfig {
    pub secret_env: String,
    pub upstream: String,
    pub tls_ca: Option<String>,
    pub inject_mode: String,
    pub endpoint_rules: Vec<EndpointRule>,
}

#[derive(Debug, Clone, Deserialize, serde::Serialize)]
pub struct EndpointRule {
    pub method: String,
    pub path: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyInput {
    fs: Option<FsInput>,
    network: Option<NetworkInput>,
    credentials: Option<std::collections::BTreeMap<String, CredentialInput>>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FsInput {
    #[serde(default)]
    read: Vec<String>,
    #[serde(default)]
    write: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct NetworkInput {
    #[serde(default = "default_blocked")]
    default: String,
    #[serde(default)]
    allow: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CredentialInput {
    host: String,
    #[serde(default = "default_https_scheme")]
    scheme: String,
    #[serde(default)]
    tls_ca: Option<String>,
    #[serde(default)]
    inject: InjectInput,
    #[serde(default)]
    endpoints: Vec<EndpointRule>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct InjectInput {
    #[serde(default = "default_header_mode")]
    mode: String,
}

impl Default for InjectInput {
    fn default() -> Self {
        Self {
            mode: default_header_mode(),
        }
    }
}

fn default_blocked() -> String {
    "blocked".to_string()
}
fn default_header_mode() -> String {
    "header".to_string()
}
fn default_https_scheme() -> String {
    "https".to_string()
}

impl RunConfig {
    pub fn from_action_env() -> Result<Self> {
        let command = env_value("RUNSEAL_RUN")
            .or_else(|| env_value("NONO_ACTION_COMMAND"))
            .context("RUNSEAL_RUN is required")?;

        if let Some(policy_yaml) = env_value("RUNSEAL_POLICY") {
            let policy: PolicyInput = serde_yaml::from_str(&policy_yaml)
                .context("RUNSEAL_POLICY is not valid runseal policy YAML")?;
            return Self::from_policy(command, policy);
        }

        let fs_read = split_csv(
            env_value("RUNSEAL_FS_READ")
                .or_else(|| env_value("NONO_ACTION_FS_READ"))
                .as_deref(),
        );
        let fs_write = split_csv(
            env_value("RUNSEAL_FS_WRITE")
                .or_else(|| env_value("NONO_ACTION_FS_WRITE"))
                .as_deref(),
        );
        let network = parse_network(
            env_value("RUNSEAL_NETWORK")
                .or_else(|| env_value("NONO_ACTION_NETWORK"))
                .as_deref(),
        );
        let credentials = parse_legacy_credentials(
            env_value("RUNSEAL_CREDENTIALS")
                .or_else(|| env_value("NONO_ACTION_CREDENTIALS"))
                .as_deref(),
            env_value("RUNSEAL_ENDPOINT_RULES")
                .or_else(|| env_value("NONO_ACTION_ENDPOINT_RULES"))
                .as_deref(),
        )?;

        Ok(Self {
            command,
            fs_read,
            fs_write,
            network,
            credentials,
        })
    }

    fn from_policy(command: String, policy: PolicyInput) -> Result<Self> {
        let (fs_read, fs_write) = policy.fs.map(|fs| (fs.read, fs.write)).unwrap_or_default();
        let network = match policy.network {
            Some(network) if network.default == "blocked" && network.allow.is_empty() => {
                NetworkPolicy::Blocked
            }
            Some(network) if network.default == "blocked" => {
                NetworkPolicy::AllowDomains(network.allow)
            }
            Some(network) => bail!(
                "unsupported network.default '{}'; only 'blocked' is supported",
                network.default
            ),
            None => NetworkPolicy::Blocked,
        };
        let mut credentials = Vec::new();
        for (secret_env, cred) in policy.credentials.unwrap_or_default() {
            credentials.push(CredentialConfig {
                secret_env,
                upstream: credential_upstream(&cred.scheme, &cred.host)?,
                tls_ca: cred.tls_ca,
                inject_mode: cred.inject.mode,
                endpoint_rules: cred.endpoints,
            });
        }
        Ok(Self {
            command,
            fs_read,
            fs_write,
            network,
            credentials,
        })
    }
}

fn env_value(name: &str) -> Option<String> {
    env::var(name).ok().filter(|v| !v.trim().is_empty())
}

fn split_csv(value: Option<&str>) -> Vec<String> {
    value
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

fn parse_network(value: Option<&str>) -> NetworkPolicy {
    let raw = value.unwrap_or("blocked").trim();
    if raw.is_empty() || raw == "blocked" {
        NetworkPolicy::Blocked
    } else {
        NetworkPolicy::AllowDomains(split_csv(Some(raw)))
    }
}

fn parse_legacy_credentials(
    credentials: Option<&str>,
    endpoint_rules: Option<&str>,
) -> Result<Vec<CredentialConfig>> {
    let mut result = Vec::new();
    for line in credentials
        .unwrap_or_default()
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
    {
        let mut parts = line.splitn(3, ':');
        let secret_env = parts.next().unwrap_or_default().trim();
        let host = parts.next().unwrap_or_default().trim();
        let inject_mode = parts.next().unwrap_or("header").trim();
        if secret_env.is_empty() || host.is_empty() {
            bail!("credential mapping '{line}' must be SECRET_NAME:host[:inject_mode]");
        }
        let rules = parse_rules_for_secret(secret_env, endpoint_rules)?;
        result.push(CredentialConfig {
            secret_env: secret_env.to_string(),
            upstream: credential_upstream("https", host)?,
            tls_ca: None,
            inject_mode: inject_mode.to_string(),
            endpoint_rules: rules,
        });
    }
    Ok(result)
}

fn credential_upstream(scheme: &str, host: &str) -> Result<String> {
    if host.starts_with("http://") || host.starts_with("https://") {
        return Ok(host.to_string());
    }

    match scheme {
        "http" | "https" => Ok(format!("{scheme}://{host}")),
        _ => bail!("unsupported credential scheme '{scheme}'; expected 'https' or 'http'"),
    }
}

fn parse_rules_for_secret(
    secret_env: &str,
    endpoint_rules: Option<&str>,
) -> Result<Vec<EndpointRule>> {
    let mut rules = Vec::new();
    for line in endpoint_rules
        .unwrap_or_default()
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
    {
        let mut parts = line.splitn(3, ':');
        let rule_secret = parts.next().unwrap_or_default().trim();
        let method = parts.next().unwrap_or_default().trim();
        let path = parts.next().unwrap_or_default().trim();
        if rule_secret != secret_env {
            continue;
        }
        if method.is_empty() || path.is_empty() {
            bail!("endpoint rule '{line}' must be SECRET_NAME:METHOD:path_glob");
        }
        rules.push(EndpointRule {
            method: method.to_string(),
            path: path.to_string(),
        });
    }
    Ok(rules)
}
