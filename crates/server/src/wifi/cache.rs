//! Private per-device, per-network address memory with advisory legacy migration.

use super::{
    discovery::Endpoint,
    network::{self, Scope},
    normalized_udid, pairing,
};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::Path,
    time::{Duration, Instant},
};

const MAX_NETWORKS: usize = 32;
const FILE: &str = "networks.json";

/// Trusted endpoints and USB hints stay distinct within each network.
#[derive(Default, Serialize, Deserialize)]
struct Entry {
    verified: Option<Endpoint>,
    hint: Option<Endpoint>,
    used: u64,
}

/// Network keys are hashes; SSIDs and gateway MACs are never stored.
#[derive(Serialize, Deserialize)]
struct Store {
    schema: u32,
    udid: String,
    networks: BTreeMap<String, Entry>,
}

/// Old unscoped records can supply hints, never trusted network-specific cache hits.
#[derive(Deserialize)]
struct Legacy {
    schema: u32,
    udid: String,
    endpoint: Endpoint,
}

/// Only active network profiles are selected; all results still require authentication.
#[derive(Default)]
pub struct Selection {
    pub verified: Vec<Endpoint>,
    pub hints: Vec<Endpoint>,
}

/// Reject arbitrary profile names and path-like keys even in private corrupted JSON.
fn valid_key(key: &str) -> bool {
    key.len() == 64 && key.bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// Read a bounded private store without creating any directories or files.
fn read(state: &Path, udid: &str) -> Result<Option<Store>> {
    let result: Result<Store> = (|| {
        let dir = pairing::checked_directory(state, udid, false)?;
        let store: Store = serde_json::from_slice(&pairing::read_private(&dir.join(FILE))?)?;
        if store.schema != 2
            || normalized_udid(&store.udid) != normalized_udid(udid)
            || store.networks.len() > MAX_NETWORKS
            || store.networks.keys().any(|key| !valid_key(key))
        {
            bail!("invalid network address cache");
        }
        Ok(store)
    })();
    match result {
        Ok(store) => Ok(Some(store)),
        Err(error)
            if error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound) =>
        {
            Ok(None)
        }
        Err(error) => Err(error),
    }
}

/// Read legacy metadata in place; its files remain available for rollback.
fn legacy(state: &Path, udid: &str, filename: &str) -> Option<Endpoint> {
    let dir = pairing::checked_directory(state, udid, false).ok()?;
    let record: Legacy =
        serde_json::from_slice(&pairing::read_private(&dir.join(filename)).ok()?).ok()?;
    (record.schema == 1 && normalized_udid(&record.udid) == normalized_udid(udid))
        .then_some(record.endpoint)
}

/// Select the corresponding profile even when two Wi-Fi networks use the same subnet.
pub fn select(state: &Path, udid: &str, scopes: &[Scope]) -> Selection {
    let store = match read(state, udid) {
        Ok(store) => store,
        Err(_) => {
            eprintln!(
                "wifi-auto: network address cache unavailable; using unicast discovery hints"
            );
            None
        }
    };
    let mut selected = Selection::default();
    for scope in scopes {
        let entry = scope
            .key
            .as_ref()
            .and_then(|key| store.as_ref()?.networks.get(key));
        if let Some(entry) = entry {
            selected.verified.extend(
                entry
                    .verified
                    .as_ref()
                    .filter(|e| e.port > 0)
                    .and_then(|e| scope.endpoint(e)),
            );
            selected
                .hints
                .extend(entry.hint.as_ref().and_then(|e| scope.endpoint(e)));
        } else {
            for filename in ["address.json", "hint.json"] {
                selected
                    .hints
                    .extend(legacy(state, udid, filename).and_then(|e| scope.endpoint(&e)));
            }
        }
    }
    selected
}

/// Serialize read-modify-write so USB metadata cannot erase another network's update.
fn lock(dir: &Path) -> Result<std::fs::File> {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(dir.join("networks.lock"))?;
    let metadata = file.metadata()?;
    // SAFETY: geteuid has no pointer arguments or side effects.
    if !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o077 != 0
    {
        bail!("unsafe network address cache lock");
    }
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        // SAFETY: flock operates only on the live file descriptor owned here.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
            return Ok(file);
        }
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::WouldBlock || Instant::now() >= deadline {
            return Err(error.into());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// Update one network without replacing others; retain the 32 most recently used profiles.
fn save(state: &Path, udid: &str, key: &str, endpoint: &Endpoint, verified: bool) -> Result<()> {
    if !valid_key(key) || (verified && endpoint.port == 0) {
        bail!("invalid network address record");
    }
    let dir = pairing::directory(state, udid)?;
    let _lock = lock(&dir)?;
    let mut store = read(state, udid)?.unwrap_or(Store {
        schema: 2,
        udid: normalized_udid(udid).context("invalid target")?,
        networks: BTreeMap::new(),
    });
    let used = store
        .networks
        .values()
        .map(|entry| entry.used)
        .max()
        .unwrap_or(0)
        .checked_add(1)
        .context("network cache sequence exhausted")?;
    let entry = store.networks.entry(key.to_owned()).or_default();
    entry.used = used;
    if verified {
        entry.verified = Some(endpoint.clone());
    } else {
        entry.hint = Some(endpoint.clone());
    }
    while store.networks.len() > MAX_NETWORKS {
        let oldest = store
            .networks
            .iter()
            .min_by_key(|(_, entry)| entry.used)
            .map(|(key, _)| key.clone())
            .context("missing oldest network")?;
        store.networks.remove(&oldest);
    }
    pairing::write_private(&dir.join(FILE), &serde_json::to_vec(&store)?)
}

/// Match only literal Runner addresses on an active physical local network.
fn url_hint<'a>(url: &str, scopes: &'a [Scope]) -> Option<(Endpoint, &'a Scope)> {
    let url = reqwest::Url::parse(url).ok()?;
    if url.scheme() != "http" {
        return None;
    }
    let ip = url.host_str()?.parse().ok()?;
    let scope = scopes.iter().find(|scope| scope.network.contains(ip))?;
    Some((
        Endpoint {
            ip,
            port: 0,
            interface: scope.network.interface.clone(),
        },
        scope,
    ))
}

/// Save USB-reported metadata under the currently observed network, without promoting trust.
pub fn remember_url(state: &Path, udid: &str, url: &str) -> Result<()> {
    if !pairing::is_paired(state, udid) {
        bail!("missing paired identity for USB address hint");
    }
    let (scopes, _) = network::current()?;
    let (endpoint, scope) =
        url_hint(url, &scopes).context("Runner did not report a local IPv4 address")?;
    let key = scope
        .key
        .as_deref()
        .context("physical network identity is unavailable")?;
    if !network::unchanged(scope) {
        bail!("network changed while remembering USB address");
    }
    save(state, udid, key, &endpoint, false)
}

/// Remember an authenticated endpoint only if its captured network identity is still current.
pub fn remember_verified(state: &Path, udid: &str, endpoint: &Endpoint, scope: &Scope) {
    if let Some(key) = scope.key.as_deref().filter(|_| network::unchanged(scope)) {
        if save(state, udid, key, endpoint, true).is_err() {
            eprintln!("wifi-auto: network address could not be saved; authenticated connection remains usable");
        }
    } else {
        eprintln!(
            "wifi-auto: physical network identity unavailable or changed; address was not cached"
        );
    }
}

#[cfg(test)]
#[path = "cache_tests.rs"]
mod tests;
