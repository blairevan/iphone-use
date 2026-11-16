//! Stable physical-LAN identities, independent of VPN routes and DHCP host addresses.

use super::discovery::{self, Endpoint, Network};
use anyhow::{bail, Result};
use sha2::{Digest, Sha256};
use std::{net::Ipv4Addr, time::Duration};

/// An active physical interface and its privacy-preserving network identity.
#[derive(Clone)]
pub struct Scope {
    pub network: Network,
    pub key: Option<String>,
}

impl Scope {
    /// Rebind remembered addresses to this interface only when they remain local.
    pub fn endpoint(&self, endpoint: &Endpoint) -> Option<Endpoint> {
        self.network.contains(endpoint.ip).then(|| Endpoint {
            interface: self.network.interface.clone(),
            ..endpoint.clone()
        })
    }
}

/// Run read-only network tools with a deadline; their raw output is never logged.
fn output(program: &str, args: &[&str]) -> Option<String> {
    let (text, success) = crate::setup::sys::run_bounded(program, args, Duration::from_secs(2));
    success.then_some(text)
}

/// Extract one scalar from macOS diagnostic output without retaining the whole report.
fn scalar<'a>(text: &'a str, name: &str) -> Option<&'a str> {
    text.lines().find_map(|line| {
        let (key, value) = line.trim().split_once(':')?;
        (key.trim() == name).then_some(value.trim())
    })
}

/// Normalize a complete unicast gateway MAC; incomplete and special addresses are rejected.
fn mac(value: &str) -> Option<[u8; 6]> {
    let parts = value.split(':').collect::<Vec<_>>();
    if parts.len() != 6 {
        return None;
    }
    let mut bytes = [0; 6];
    for (byte, part) in bytes.iter_mut().zip(parts) {
        if part.is_empty() || part.len() > 2 {
            return None;
        }
        *byte = u8::from_str_radix(part, 16).ok()?;
    }
    (bytes != [0; 6] && bytes[0] & 1 == 0).then_some(bytes)
}

/// Match the default router's complete ARP entry on the selected physical interface.
fn router_mac(table: &str, router: Ipv4Addr, interface: &str) -> Option<[u8; 6]> {
    table.lines().find_map(|line| {
        let (_, rest) = line.split_once('(')?;
        let (address, _) = rest.split_once(')')?;
        if address.parse::<Ipv4Addr>().ok()? != router {
            return None;
        }
        let words = line.split_whitespace().collect::<Vec<_>>();
        if !words.windows(2).any(|pair| pair == ["on", interface]) {
            return None;
        }
        mac(words.windows(2).find(|pair| pair[0] == "at")?[1])
    })
}

/// Hash stable LAN properties, excluding the client IP, BSSID and connection counter.
fn fingerprint(network: &Network, route: &str, summary: &str, table: &str) -> Option<String> {
    if scalar(route, "interface")? != network.interface {
        return None;
    }
    let router = scalar(route, "gateway")?.parse::<Ipv4Addr>().ok()?;
    if !network.contains(router) {
        return None;
    }
    let gateway_mac = router_mac(table, router, &network.interface)?;
    let mut hash = Sha256::new();
    hash.update(b"iphone-use-lan-v1\0");
    hash.update((u32::from(network.ip) & u32::from(network.mask)).to_be_bytes());
    hash.update(network.mask.octets());
    hash.update(router.octets());
    hash.update(gateway_mac);
    if let Some(ssid) = scalar(summary, "SSID").filter(|s| !s.is_empty() && !s.contains('<')) {
        hash.update(b"\0ssid\0");
        hash.update(ssid.as_bytes());
    }
    Some(format!("{:x}", hash.finalize()))
}

/// Observe only scoped physical routes; a VPN's default route cannot select a profile.
pub fn current() -> Result<(Vec<Scope>, String)> {
    let networks = discovery::networks()?;
    let table = output("/usr/sbin/arp", &["-an"]);
    let Some(table) = table else {
        bail!("could not read the local neighbor table");
    };
    let scopes = networks
        .into_iter()
        .map(|network| {
            let route = output(
                "/sbin/route",
                &["-n", "get", "-ifscope", &network.interface, "default"],
            );
            let summary = output("/usr/sbin/ipconfig", &["getsummary", &network.interface]);
            let key = route.as_deref().and_then(|route| {
                fingerprint(&network, route, summary.as_deref().unwrap_or(""), &table)
            });
            Scope { network, key }
        })
        .collect();
    Ok((scopes, table))
}

/// Do not save a successful handshake under a network that changed while it was running.
pub fn unchanged(scope: &Scope) -> bool {
    let Some(key) = &scope.key else {
        return false;
    };
    current().is_ok_and(|(scopes, _)| {
        scopes.iter().any(|current| {
            current.key.as_ref() == Some(key)
                && current.network.interface == scope.network.interface
                && current.network.ip == scope.network.ip
                && current.network.mask == scope.network.mask
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Make a synthetic physical LAN, with no real network identity in fixtures.
    fn network(ip: &str) -> Result<Network> {
        Ok(Network {
            interface: "en0".into(),
            ip: ip.parse()?,
            mask: "255.255.255.0".parse()?,
        })
    }

    const ROUTE: &str = "gateway: 192.168.1.1\ninterface: en0\n";
    const ARP: &str = "? (192.168.1.1) at 02:00:00:00:00:01 on en0 ifscope";

    /// Roaming APs and DHCP host-address changes keep the same network profile.
    #[test]
    fn roaming_and_dhcp_do_not_change_identity() -> Result<()> {
        let first = fingerprint(
            &network("192.168.1.10")?,
            ROUTE,
            "SSID : Example\nBSSID : ap-one\nConnectionID : 1",
            ARP,
        );
        let second = fingerprint(
            &network("192.168.1.20")?,
            ROUTE,
            "SSID : Example\nBSSID : ap-two\nConnectionID : 2",
            ARP,
        );
        assert!(first.is_some());
        assert_eq!(first, second);
        Ok(())
    }

    /// Overlapping home/office subnets remain separate when their gateways or SSIDs differ.
    #[test]
    fn overlapping_subnets_are_separated_without_raw_ssids() -> Result<()> {
        let net = network("192.168.1.10")?;
        let home = fingerprint(&net, ROUTE, "SSID : <redacted>", ARP);
        let office = fingerprint(&net, ROUTE, "SSID : <redacted>", &ARP.replace(":01", ":02"));
        assert_ne!(home, office);
        assert_ne!(
            fingerprint(&net, ROUTE, "SSID : Example-A", ARP),
            fingerprint(&net, ROUTE, "SSID : Example-B", ARP)
        );
        assert_eq!(home.as_ref().map(String::len), Some(64));
        assert_eq!(home, fingerprint(&net, ROUTE, "", ARP));
        Ok(())
    }

    /// Missing or wrong-interface gateway evidence must never produce a shared default key.
    #[test]
    fn ambiguous_and_vpn_routes_disable_memory() -> Result<()> {
        let net = network("192.168.1.10")?;
        for (route, table) in [
            (ROUTE, ""),
            (ROUTE, "? (192.168.1.1) at (incomplete) on en0"),
            ("gateway: 192.168.1.1\ninterface: utun4", ARP),
            (ROUTE, "? (192.168.1.1) at 01:00:00:00:00:01 on en0"),
        ] {
            assert!(fingerprint(&net, route, "SSID : <redacted>", table).is_none());
        }
        Ok(())
    }
}
