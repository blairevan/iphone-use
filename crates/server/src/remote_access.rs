//! Explicit HTTPS activation with an authenticated daemon-identity probe and
//! transactional profile rollback. TLS is terminated by an existing trusted
//! HTTPS service, not by disabling certificate validation in the clients.

use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use clap::Subcommand;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub version: u32,
    pub enabled: bool,
    pub public_url: Option<String>,
    pub relay_url: Option<String>,
    pub trusted_proxy_ips: Vec<String>,
}

#[derive(Subcommand)]
pub enum Action {
    /// Show the selected instance's remote profile, never its credentials.
    Status {
        #[arg(long)]
        instance: Option<String>,
    },
    /// Enable an existing HTTPS entry point, verify it reaches this daemon,
    /// migrate QR/callback addresses and restart; roll back on any failure.
    Enable {
        #[arg(long)]
        url: String,
        #[arg(long)]
        relay: Option<String>,
        #[arg(long)]
        instance: Option<String>,
        #[arg(long)]
        confirm: bool,
    },
    /// Close configured remote routes, keep local service, revoke old sessions.
    Disable {
        #[arg(long)]
        instance: Option<String>,
        #[arg(long)]
        confirm: bool,
    },
}

/// Require a normalized HTTPS base URL, no userinfo, query, fragment or encoded
/// path separators. This value is used in QR codes, redirects and callbacks.
pub fn https_url(raw: &str) -> Result<reqwest::Url> {
    if raw.len() > 2048 || raw.chars().any(char::is_control) || raw.trim() != raw {
        bail!("invalid HTTPS entry point length or characters");
    }
    let url = reqwest::Url::parse(raw).context("invalid HTTPS entry point")?;
    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.host_str().is_none()
        || url.path().contains('%')
        || url.path().contains("//")
    {
        bail!("remote entry point must be an HTTPS base URL without credentials or query");
    }
    Ok(url)
}

/// Validate operator settings before they enter routing or launchd.
pub fn validate(profile: &Profile) -> Result<()> {
    if profile.version != 1 {
        bail!("unsupported remote profile version");
    }
    if !profile.enabled {
        if profile.public_url.is_some()
            || profile.relay_url.is_some()
            || !profile.trusted_proxy_ips.is_empty()
        {
            bail!("disabled remote profile must not carry active ingress settings");
        }
        return Ok(());
    }
    https_url(
        profile
            .public_url
            .as_deref()
            .context("remote profile needs HTTPS URL")?,
    )?;
    if let Some(relay) = &profile.relay_url {
        https_url(relay)?;
    }
    for ip in &profile.trusted_proxy_ips {
        if !ip
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
        {
            bail!("HTTP TLS terminators must connect over loopback; remote plaintext proxy hops are not allowed");
        }
    }
    Ok(())
}

/// An explicit persisted profile overrides legacy environment settings, so
/// disabling cannot be undone by a leftover RELAY_URL in an old plist.
pub fn apply(cfg: &mut crate::config::Config, state: &Path) -> Result<()> {
    let path = state.join("remote.json");
    if !path.try_exists()? {
        return Ok(());
    }
    let profile: Profile = serde_json::from_slice(&crate::secure_store::read(&path, 16 * 1024)?)?;
    validate(&profile)?;
    cfg.host = "127.0.0.1".into();
    cfg.remote_enabled = profile.enabled;
    cfg.public_url = profile.public_url;
    cfg.relay_url = profile.relay_url;
    cfg.trusted_proxy_ips = profile.trusted_proxy_ips;
    cfg.base_path = cfg
        .public_url
        .as_deref()
        .map(https_url)
        .transpose()?
        .map(|u| u.path().trim_end_matches('/').to_string())
        .unwrap_or_default();
    Ok(())
}

/// Install a profile only if restarting and checking its actual transport
/// succeeds. Restoring the original bytes also restores a legacy environment.
fn transaction(path: &Path, next: &[u8], mut activate: impl FnMut() -> Result<()>) -> Result<()> {
    let before = if path.symlink_metadata().is_ok() {
        Some(crate::secure_store::read(path, 16 * 1024)?)
    } else {
        None
    };
    crate::secure_store::write(path, next)?;
    if let Err(error) = activate() {
        if let Some(before) = before {
            crate::secure_store::write(path, &before)?;
        } else {
            std::fs::remove_file(path)?;
        }
        if activate().is_err() {
            bail!("remote configuration failed; previous profile restored but service recovery also failed: {error}");
        }
        bail!("remote configuration failed; previous profile and service restored: {error}");
    }
    Ok(())
}

/// Restart only the exact product job. Never invoke setup or drive a phone.
fn restart(instance: &crate::instance::Instance) -> Result<()> {
    // SAFETY: geteuid only reads process identity.
    let label = format!(
        "gui/{}/{}",
        unsafe { libc::geteuid() },
        instance.daemon_label
    );
    if !std::process::Command::new("/bin/launchctl")
        .args(["kickstart", "-k", &label])
        .status()?
        .success()
    {
        bail!("launchd could not restart the selected instance");
    }
    Ok(())
}

/// Obtain a nonce proof without sending a password, session or device token.
/// System TLS validation and no-redirect policy are always in effect.
async fn proof(client: &reqwest::Client, base: &str, nonce: &str, target: &str) -> Result<String> {
    let response = client
        .get(format!("{}/pair/probe", base.trim_end_matches('/')))
        .query(&[("n", nonce), ("u", target)])
        .send()
        .await
        .map_err(|_| anyhow::anyhow!("identity probe transport failed"))?;
    if !response.status().is_success() {
        bail!("identity probe was refused");
    }
    if response.content_length().is_some_and(|n| n > 4096) {
        bail!("identity probe body too large");
    }
    let mut response = response;
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if body.len() + chunk.len() > 4096 {
            bail!("identity probe body too large");
        }
        body.extend_from_slice(&chunk);
    }
    let value: serde_json::Value = serde_json::from_slice(&body)?;
    let proof = value["proof"].as_str().context("identity proof missing")?;
    if !URL_SAFE_NO_PAD.decode(proof).is_ok_and(|v| v.len() == 32) {
        bail!("invalid identity proof");
    }
    Ok(proof.into())
}

/// Verify that the TLS endpoint reaches the selected local instance. A valid
/// certificate for an unrelated server is not proof of daemon identity.
pub async fn verify_channel(local: &str, public: &str) -> Result<()> {
    https_url(public)?;
    let mut random = [0u8; 24];
    getrandom::fill(&mut random).map_err(|_| anyhow::anyhow!("secure entropy unavailable"))?;
    let nonce = URL_SAFE_NO_PAD.encode(random);
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(8))
        .no_proxy()
        .build()?;
    let expected = proof(&client, local, &nonce, public).await?;
    let actual = proof(&client, public, &nonce, public).await?;
    if !core::auth::verify_password(&actual, &expected) {
        bail!("HTTPS endpoint belongs to a different daemon");
    }
    Ok(())
}

/// Read persisted settings without printing or putting credentials in argv.
fn plist_env(
    instance: &crate::instance::Instance,
) -> Result<std::collections::BTreeMap<String, String>> {
    let path = instance
        .home
        .join("Library/LaunchAgents")
        .join(format!("{}.plist", instance.daemon_label));
    let value = plist::Value::from_reader(std::io::Cursor::new(crate::secure_store::read(
        &path,
        1024 * 1024,
    )?))?;
    let env = value
        .as_dictionary()
        .and_then(|v| v.get("EnvironmentVariables"))
        .and_then(plist::Value::as_dictionary)
        .context("installed daemon has no environment")?;
    Ok(env
        .iter()
        .filter_map(|(k, v)| v.as_string().map(|s| (k.clone(), s.to_owned())))
        .collect())
}

/// Run explicit instance-scoped configuration. TLS certificate provisioning
/// and renewal remain with the chosen HTTPS terminator; no new cloud service,
/// certificate authority, firewall rule or public listener is silently created.
pub fn run(action: Action) -> Result<()> {
    let name = match &action {
        Action::Status { instance }
        | Action::Enable { instance, .. }
        | Action::Disable { instance, .. } => instance.clone(),
    }
    .unwrap_or_else(|| std::env::var("IPHONE_USE_INSTANCE").unwrap_or_else(|_| "default".into()));
    let home = PathBuf::from(std::env::var_os("HOME").context("HOME is not set")?);
    let instance =
        crate::instance::Instance::derive(&name, home, None).map_err(anyhow::Error::msg)?;
    instance.verify_on_disk().map_err(anyhow::Error::msg)?;
    let path = instance.state_dir.join("remote.json");
    if matches!(action, Action::Status { .. }) {
        if path.try_exists()? {
            let profile: Profile =
                serde_json::from_slice(&crate::secure_store::read(&path, 16 * 1024)?)?;
            validate(&profile)?;
            println!("{}", serde_json::to_string_pretty(&profile)?);
        } else {
            println!("No remote profile. Legacy environment settings, if any, are not changed.");
        }
        return Ok(());
    }
    let (profile, confirm) = match action {
        Action::Enable {
            url,
            relay,
            confirm,
            ..
        } => (
            Profile {
                version: 1,
                enabled: true,
                public_url: Some(https_url(&url)?.to_string().trim_end_matches('/').into()),
                relay_url: relay,
                trusted_proxy_ips: vec!["127.0.0.1".into(), "::1".into()],
            },
            confirm,
        ),
        Action::Disable { confirm, .. } => (
            Profile {
                version: 1,
                enabled: false,
                public_url: None,
                relay_url: None,
                trusted_proxy_ips: Vec::new(),
            },
            confirm,
        ),
        Action::Status { .. } => return Ok(()),
    };
    if !confirm {
        bail!("remote configuration requires --confirm; the service may briefly restart");
    }
    validate(&profile)?;
    let env = plist_env(&instance)?;
    let cfg = crate::config::Config::from_map(|key| env.get(key).cloned());
    if profile.enabled {
        crate::security::validate_remote_credentials(&cfg).map_err(anyhow::Error::msg)?;
    }
    let _lock = crate::secure_store::lock(&instance.state_dir.join("remote-config"))?;
    let rt = tokio::runtime::Runtime::new()?;
    transaction(&path, &serde_json::to_vec(&profile)?, || {
        restart(&instance)?;
        let mut live = cfg.clone();
        apply(&mut live, &instance.state_dir)?;
        let local = format!("http://127.0.0.1:{}", live.port);
        let mut last_error = None;
        for _ in 0..15 {
            let result = rt.block_on(async {
                let client = reqwest::Client::builder()
                    .no_proxy()
                    .redirect(reqwest::redirect::Policy::none())
                    .timeout(std::time::Duration::from_secs(2))
                    .build()?;
                let mut request = client.get(format!("{local}/agent/status"));
                if let Some(token) = live.agent_token.as_ref().or(live.password.as_ref()) {
                    request = request.bearer_auth(token);
                }
                if !request.send().await?.status().is_success() {
                    bail!("local health check failed");
                }
                if live.remote_enabled {
                    verify_channel(
                        &local,
                        live.public_url.as_deref().context("missing public URL")?,
                    )
                    .await?;
                }
                Ok(())
            });
            match result {
                Ok(()) => return Ok(()),
                Err(error) => last_error = Some(error),
            }
            std::thread::sleep(std::time::Duration::from_secs(1));
        }
        Err(last_error.unwrap_or_else(|| anyhow::anyhow!("service verification failed")))
    })?;
    if !profile.enabled {
        rt.block_on(async {
            let password = cfg
                .password
                .as_ref()
                .context("password required to revoke remote sessions")?;
            let token = cfg
                .agent_token
                .as_ref()
                .or(cfg.password.as_ref())
                .context("agent credential required")?;
            let client = reqwest::Client::builder()
                .no_proxy()
                .timeout(std::time::Duration::from_secs(5))
                .build()?;
            let response = client
                .post(format!(
                    "http://127.0.0.1:{}/agent/security/credentials",
                    cfg.port
                ))
                .bearer_auth(token)
                .header("x-phone-control", "1")
                .json(&serde_json::json!({"action":"revoke_devices","admin_password":password}))
                .send()
                .await?;
            if !response.status().is_success() {
                bail!(
                    "remote routes are off, but session revocation failed; use /security locally"
                );
            }
            Ok(())
        })?;
    }
    println!(
        "{}",
        serde_json::json!({"ok":true,"remote_enabled":profile.enabled,"public_url":profile.public_url,"instance":name})
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn profile_validation_and_failed_activation_restore_exact_previous_bytes() {
        for raw in [
            "http://control.example",
            "https://user:pass@control.example",
            "https://control.example?a=b",
            "https://control.example/a%2fb",
        ] {
            assert!(https_url(raw).is_err());
        }
        assert!(https_url("https://control.example/phone-one").is_ok());
        let temp = tempfile::tempdir().unwrap();
        let dir = std::fs::canonicalize(temp.path()).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = dir.join("remote.json");
        crate::secure_store::write(&path, b"previous").unwrap();
        let mut count = 0;
        assert!(transaction(&path, b"next", || {
            count += 1;
            if count == 1 {
                bail!("fixture failure");
            }
            Ok(())
        })
        .is_err());
        assert_eq!(count, 2);
        assert_eq!(std::fs::read(&path).unwrap(), b"previous");
        std::fs::remove_file(&path).unwrap();
        count = 0;
        assert!(transaction(&path, b"next", || {
            count += 1;
            if count == 1 {
                bail!("fixture failure");
            }
            Ok(())
        })
        .is_err());
        assert!(!path.exists());
    }
}
