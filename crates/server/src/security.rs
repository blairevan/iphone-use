//! Shared fail-closed network policy for desktop and embedded daemons.

use crate::config::Config;
use std::net::{IpAddr, SocketAddr};

/// Correlate operational events without persisting caller-chosen identifiers.
/// The key exists only for this process; low-entropy labels cannot be recovered
/// with an offline dictionary, and restarts intentionally break correlation.
pub fn log_identifier(value: &str) -> String {
    static KEY: std::sync::OnceLock<Option<[u8; 32]>> = std::sync::OnceLock::new();
    match KEY.get_or_init(|| {
        let mut key = [0u8; 32];
        getrandom::fill(&mut key).ok().map(|()| key)
    }) {
        Some(key) => core::auth::sign(key, value),
        None => "redacted".to_string(),
    }
}

/// Only literal loopback addresses (and the specially bound localhost name)
/// are local. Hostnames, wildcard addresses and private LAN IPs are not.
pub fn is_loopback_host(host: &str) -> bool {
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    let host = host
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(host);
    host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

/// Remote routes require both human authentication and a distinct machine
/// credential. This also applies to an outbound relay on a loopback listener.
pub fn validate_remote_credentials(cfg: &Config) -> Result<(), String> {
    let password = cfg.password.as_deref().filter(|s| !s.trim().is_empty());
    let token = cfg.agent_token.as_deref().filter(|s| !s.trim().is_empty());
    match (password, token) {
        (Some(password), Some(token)) if password != token => Ok(()),
        _ => Err("remote access requires a non-empty IPHONE_USE_PASSWORD and a different IPHONE_USE_AGENT_TOKEN; configure credentials and migrate clients before restarting".into()),
    }
}

/// Check before touching devices or binding ports. Never silently convert a
/// legacy listener: an operator must explicitly approve the remote exposure.
pub fn validate_startup(cfg: &Config, remote_enabled: bool, has_relay: bool) -> Result<(), String> {
    if cfg
        .trusted_proxy_ips
        .iter()
        .any(|ip| !ip.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback()))
    {
        return Err("IPHONE_USE_TRUSTED_PROXY_IPS must contain only loopback IP addresses; remote plaintext proxy hops are forbidden".into());
    }
    if let Some(url) = &cfg.public_url {
        crate::remote_access::https_url(url).map_err(|e| e.to_string())?;
    }
    if let Some(relay) = &cfg.relay_url {
        if relay_base(relay)?.scheme() != "https" {
            return Err("production remote relay must use HTTPS/WSS".into());
        }
    }
    if !is_loopback_host(&cfg.host) || has_relay || cfg.public_url.is_some() {
        if !remote_enabled {
            return Err("remote access is disabled; use loopback, or explicitly configure authenticated HTTPS and IPHONE_USE_REMOTE_ACCESS=1 before migration".into());
        }
        validate_remote_credentials(cfg)?;
        if cfg.public_url.is_none() && !has_relay {
            return Err("remote access requires a configured HTTPS entry point or secure relay; credentials alone do not encrypt HTTP".into());
        }
    }
    Ok(())
}

/// Check the actual bound address as well; DNS must not turn localhost into
/// a network listener. No request has been accepted when this check runs.
pub fn validate_bound_address(cfg: &Config, address: SocketAddr) -> Result<(), String> {
    if is_loopback_host(&cfg.host) && !address.ip().is_loopback() {
        return Err("a loopback configuration resolved to a non-loopback listener".into());
    }
    Ok(())
}

/// Parse and normalize a relay base URL before reading keys or connecting.
/// Plain transport is permitted only to literal loopback addresses; DNS names
/// cannot opt into this exception. A WSS input has an HTTPS public counterpart.
pub fn relay_base(raw: &str) -> Result<reqwest::Url, String> {
    let mut url = reqwest::Url::parse(raw).map_err(|_| "invalid relay URL")?;
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err("relay URL must not contain credentials, query or fragment".into());
    }
    let local = url.host_str().is_some_and(|host| {
        host.trim_start_matches('[')
            .trim_end_matches(']')
            .parse::<IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
    });
    let scheme = match url.scheme() {
        "https" | "wss" => "https",
        "http" | "ws" if local => "http",
        _ => {
            return Err(
                "non-loopback relay requires HTTPS/WSS with certificate verification".into(),
            )
        }
    };
    url.set_scheme(scheme).map_err(|_| "invalid relay scheme")?;
    Ok(url)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn log_identifiers_do_not_persist_free_form_names() {
        let value = "fixture-screen-and-password";
        let pseudonym = log_identifier(value);
        assert!(!pseudonym.contains(value));
        assert_eq!(pseudonym, log_identifier(value));
        assert_ne!(pseudonym, log_identifier("different-fixture"));
    }

    fn config(host: &str, password: Option<&str>, token: Option<&str>) -> Config {
        Config::from_map(|key| match key {
            "IPHONE_USE_HOST" => Some(host.into()),
            "IPHONE_USE_PASSWORD" => password.map(str::to_string),
            "IPHONE_USE_AGENT_TOKEN" => token.map(str::to_string),
            _ => None,
        })
    }

    #[test]
    fn literal_loopback_policy_covers_ipv4_ipv6_and_rejects_lan() {
        for host in ["127.0.0.1", "127.1.2.3", "::1", "[::1]", "localhost"] {
            assert!(is_loopback_host(host), "{host}");
        }
        for host in [
            "0.0.0.0",
            "::",
            "192.168.1.2",
            "localhost.example",
            "127.0.0.1.example",
            "",
        ] {
            assert!(!is_loopback_host(host), "{host}");
        }
    }

    #[test]
    fn every_remote_route_needs_explicit_enablement_and_separate_credentials() {
        for host in ["0.0.0.0", "::", "192.168.1.2"] {
            let mut cfg = config(host, Some("fixture-password"), Some("fixture-agent"));
            assert!(validate_startup(&cfg, true, false).is_err());
            cfg.public_url = Some("https://control.example".into());
            assert!(validate_startup(&cfg, false, false).is_err());
            assert!(validate_startup(&cfg, true, false).is_ok());
            for (password, token) in [
                (None, None),
                (Some("p"), None),
                (None, Some("t")),
                (Some("same"), Some("same")),
            ] {
                assert!(validate_startup(&config(host, password, token), true, false).is_err());
            }
        }
        let local = config("127.0.0.1", None, None);
        assert!(validate_startup(&local, false, false).is_ok());
        assert!(validate_startup(&local, true, true).is_err());
    }

    #[test]
    fn relay_rejects_plain_remote_and_credential_bearing_urls() {
        for url in [
            "http://relay.example",
            "ws://relay.example",
            "http://localhost",
            "http://127.0.0.1.example",
            "ftp://relay.example",
            "https://user:secret@relay.example",
            "https://relay.example?key=x",
            "https://relay.example#x",
        ] {
            assert!(relay_base(url).is_err(), "{url}");
        }
        for url in [
            "https://relay.example",
            "wss://relay.example",
            "http://127.0.0.1:8080",
            "ws://[::1]:8080",
        ] {
            assert!(relay_base(url).is_ok(), "{url}");
        }
    }
}
