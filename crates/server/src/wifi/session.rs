//! Verified endpoint selection, native encrypted tunnel, and local Runner relays.

use super::{
    cache,
    discovery::{self, Endpoint},
    network, normalized_udid, pairing,
};
use anyhow::{bail, Context, Result};
use idevice::{
    remote_pairing::{
        connect_tls_psk_tunnel_native, PeerDevice, RemotePairingClient, RpPairingSocket,
    },
    services::rsd::RsdHandshake,
    tcp::{adapter::Adapter, handle::AdapterHandle},
};
use std::{path::Path, time::Duration};
use tokio::{
    io::AsyncWriteExt,
    net::{TcpListener, TcpStream},
    task::JoinSet,
};

/// The pair control channel and software stack must outlive every service connection.
pub struct Session {
    pub handle: AdapterHandle,
    pub rsd: RsdHandshake,
    _control: RemotePairingClient<RpPairingSocket<TcpStream>>,
}

impl Session {
    /// Pair-verify only: no PIN, trust prompts or new pairing for a network candidate.
    async fn open(profile: &mut pairing::Profile, endpoint: &Endpoint) -> Result<Self> {
        let stream = discovery::connect(endpoint, endpoint.port).await?;
        stream.set_nodelay(true)?;
        let mut control = RemotePairingClient::new(RpPairingSocket::new(stream), &profile.host);
        control.attempt_pair_verify().await?;
        control.validate_pairing(&mut profile.pair).await?;
        eprintln!("wifi-auto: pair verification succeeded");
        let port = control.create_tcp_listener().await?;
        let transport = discovery::connect(endpoint, port).await?;
        transport.set_nodelay(true)?;
        let tunnel = connect_tls_psk_tunnel_native(transport, control.encryption_key()).await?;
        eprintln!("wifi-auto: encrypted tunnel established");
        let info = tunnel.info.clone();
        let mut adapter = Adapter::new(
            Box::new(tunnel.into_inner()),
            info.client_address.parse()?,
            info.server_address.parse()?,
        );
        adapter.set_mss(usize::from(info.mtu).saturating_sub(60).min(1380));
        let mut handle = adapter.to_async_handle();
        let rsd = RsdHandshake::new(handle.connect(info.server_rsd_port).await?).await?;
        let observed = rsd
            .properties
            .get("UniqueDeviceID")
            .and_then(plist::Value::as_string);
        if !same_device(observed, &profile.udid) {
            handle.close().await?;
            bail!("wireless RSD identity differs from the paired target");
        }
        Ok(Self {
            handle,
            rsd,
            _control: control,
        })
    }
}

/// A reachable endpoint is usable only when RSD names the configured physical device.
fn same_device(observed: Option<&str>, expected: &str) -> bool {
    let Some(expected) = normalized_udid(expected) else {
        return false;
    };
    observed.and_then(normalized_udid).as_deref() == Some(expected.as_str())
}

/// Prefer a stale cached host for port refresh, then deduplicated bounded neighbors.
fn candidate_order(
    preferred: impl IntoIterator<Item = Endpoint>,
    neighbors: Vec<Endpoint>,
) -> Vec<Endpoint> {
    let mut seen = std::collections::BTreeSet::new();
    preferred
        .into_iter()
        .chain(neighbors)
        .filter(|endpoint| seen.insert((endpoint.ip, endpoint.interface.clone())))
        .take(discovery::MAX_CANDIDATES)
        .collect()
}

/// Discover this paired target, preferring a still-local cached endpoint before neighbors.
pub async fn locate(state: &Path, udid: &str) -> Result<Session> {
    let mut profile = pairing::load(state, udid)?;
    let (scopes, arp) = network::current()?;
    let selected = cache::select(state, udid, &scopes);
    let networks: Vec<_> = scopes.iter().map(|scope| scope.network.clone()).collect();
    for endpoint in &selected.verified {
        if let Ok(Ok(session)) = tokio::time::timeout(
            Duration::from_secs(5),
            Session::open(&mut profile, endpoint),
        )
        .await
        {
            if let Some(scope) = scopes
                .iter()
                .find(|scope| scope.network.interface == endpoint.interface)
            {
                cache::remember_verified(state, udid, endpoint, scope);
            }
            eprintln!(
                "wifi-auto: authenticated network-cached endpoint {}",
                endpoint.ip
            );
            return Ok(session);
        }
    }
    let hints = candidate_order(selected.hints, discovery::neighbors(&arp, &networks));
    let candidates = candidate_order(selected.verified, hints);
    let alt_irk = profile
        .pair
        .alt_irk
        .clone()
        .context("missing paired identity")?;
    eprintln!(
        "wifi-auto: checking {} current LAN neighbors",
        candidates.len()
    );
    for batch in candidates.chunks(4) {
        let mut probes = JoinSet::new();
        for candidate in batch {
            let endpoint = candidate.clone();
            let Some(network) = networks
                .iter()
                .find(|n| n.interface == endpoint.interface && n.contains(endpoint.ip))
                .cloned()
            else {
                continue;
            };
            probes.spawn(async move {
                let answer = discovery::query(&endpoint, &network).await;
                (endpoint, answer)
            });
        }
        while let Some(result) = probes.join_next().await {
            let Ok((mut endpoint, Ok(answer))) = result else {
                continue;
            };
            if !PeerDevice::validate_auth_tag(&alt_irk, &answer.identifier, &answer.auth_tag) {
                continue;
            }
            endpoint.port = answer.port;
            if let Ok(Ok(session)) = tokio::time::timeout(
                Duration::from_secs(12),
                Session::open(&mut profile, &endpoint),
            )
            .await
            {
                if let Some(scope) = scopes
                    .iter()
                    .find(|scope| scope.network.interface == endpoint.interface)
                {
                    cache::remember_verified(state, udid, &endpoint, scope);
                }
                eprintln!("wifi-auto: authenticated neighbor endpoint {}", endpoint.ip);
                return Ok(session);
            }
        }
    }
    bail!("paired iPhone was not authenticated at its cached address or current LAN neighbors; keep it unlocked on this network, or reconnect USB")
}

/// Forward one local connection into the authenticated point-to-point tunnel.
async fn forward(mut local: TcpStream, mut handle: AdapterHandle, port: u16) -> Result<()> {
    let mut remote = tokio::time::timeout(Duration::from_secs(5), handle.connect(port)).await??;
    tokio::io::copy_bidirectional(&mut local, &mut remote).await?;
    local.shutdown().await?;
    Ok(())
}

/// Open a loopback-only relay, keeping all device traffic inside the encrypted tunnel.
async fn relay(listener: TcpListener, handle: AdapterHandle, port: u16) -> Result<()> {
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (client, _) = accepted?;
                let handle = handle.clone();
                connections.spawn(async move { let _ = forward(client, handle, port).await; });
            }
            _ = connections.join_next(), if !connections.is_empty() => {}
        }
    }
}

/// Start the installed Runner and hold both relays until disconnect or explicit shutdown.
pub async fn serve(
    state: &Path,
    udid: &str,
    runner_port: u16,
    mjpeg_port: u16,
    bundle: &str,
) -> Result<()> {
    let mut session = locate(state, udid).await?;
    let control = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, runner_port)).await?;
    let video = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, mjpeg_port)).await?;
    let token = crate::runner_token::read(state).context("missing Runner signing token")?;
    let control_handle = session.handle.clone();
    let video_handle = session.handle.clone();
    let outcome = tokio::select! {
        outcome = super::xctest::run(&mut session.handle, &session.rsd, bundle, &token) => outcome,
        outcome = relay(control, control_handle, 8100) => outcome,
        outcome = relay(video, video_handle, 9100) => outcome,
        _ = tokio::signal::ctrl_c() => Ok(()),
        _ = async { if let Ok(mut signal) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) { signal.recv().await; } } => Ok(()),
    };
    let _ = session.handle.close().await;
    outcome
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RSD identity checks tolerate spelling only; wrong, absent and malformed IDs fail.
    #[test]
    fn rsd_identity_is_target_scoped() {
        let expected = "00000000-000000000000000A";
        assert!(same_device(Some("00000000000000000000000a"), expected));
        for observed in [None, Some("00000000000000000000000b"), Some("invalid")] {
            assert!(!same_device(observed, expected));
        }
        assert!(!same_device(None, "invalid"));
    }

    /// Stale service ports are refreshed from the cached host before other neighbors.
    #[test]
    fn stale_cache_deduplicates_without_expanding_probe_budget() -> Result<()> {
        let cached = Endpoint {
            ip: "192.168.1.200".parse()?,
            port: 49152,
            interface: "en0".into(),
        };
        let mut neighbors: Vec<_> = (3..80)
            .map(|n| Endpoint {
                ip: std::net::Ipv4Addr::new(192, 168, 1, n),
                port: 0,
                interface: "en0".into(),
            })
            .collect();
        neighbors.push(cached.clone());
        let selected = candidate_order(Some(cached.clone()), neighbors);
        assert_eq!(selected.len(), discovery::MAX_CANDIDATES);
        assert_eq!(selected.first(), Some(&cached));
        assert_eq!(
            selected
                .iter()
                .filter(|value| value.ip == cached.ip)
                .count(),
            1
        );
        Ok(())
    }
}
