//! Persistent revocation for paired devices, browser sessions and individually
//! issued agents. The store never contains passwords, cookies or bearer tokens.

use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

const MAX_RECORDS: usize = 4096;
const MAX_BYTES: u64 = 4 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Scope {
    Read,
    Control,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Record {
    pub id: String,
    pub kind: String,
    pub name: String,
    pub scope: Scope,
    pub created_at: u64,
    pub last_seen: u64,
    pub revoked: bool,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Data {
    version: u32,
    allow_legacy: bool,
    records: BTreeMap<String, Record>,
}

/// The file lock prevents two daemons from mutating one authorization store.
/// An in-memory store is also used by isolated router tests.
pub struct Store {
    path: Option<PathBuf>,
    _lock: Option<std::fs::File>,
    data: Data,
    revoked: tokio::sync::watch::Sender<u64>,
}

impl Default for Store {
    fn default() -> Self {
        Self {
            path: None,
            _lock: None,
            data: Data {
                version: 1,
                allow_legacy: true,
                records: BTreeMap::new(),
            },
            revoked: tokio::sync::watch::channel(0).0,
        }
    }
}

impl Store {
    /// Open only private, well-formed persisted state; corruption blocks boot.
    pub fn open(state: &Path) -> Result<Self> {
        let dir = state.join("access");
        let lock = crate::secure_store::lock(&dir)?;
        let path = dir.join("credentials.json");
        let mut store = Self {
            path: Some(path.clone()),
            _lock: Some(lock),
            ..Self::default()
        };
        if path.symlink_metadata().is_ok() {
            store.data = serde_json::from_slice(&crate::secure_store::read(&path, MAX_BYTES)?)
                .context("invalid credential revocation store")?;
            if store.data.version != 1
                || store.data.records.len() > MAX_RECORDS
                || store
                    .data
                    .records
                    .iter()
                    .any(|(id, record)| id != &record.id)
            {
                bail!("invalid credential store version or records");
            }
        } else {
            store.persist(&store.data)?;
        }
        Ok(store)
    }

    /// Write before publishing an authorization change in memory.
    fn persist(&self, data: &Data) -> Result<()> {
        if let Some(path) = &self.path {
            crate::secure_store::write(path, &serde_json::to_vec(data)?)?;
        }
        Ok(())
    }

    /// Stable opaque identity, distinct even for similar subjects in different
    /// namespaces. The HMAC key never leaves the daemon.
    pub fn id(secret: &[u8], kind: &str, subject: &str) -> String {
        core::auth::sign(secret, &format!("credential-v1:{kind}:{subject}"))
    }

    /// Register a freshly issued or authenticated legacy identity. Explicitly
    /// revoked identities are never resurrected by renewal.
    pub fn register(
        &mut self,
        secret: &[u8],
        kind: &str,
        subject: &str,
        name: &str,
        scope: Scope,
        now: u64,
    ) -> Result<Record> {
        let id = Self::id(secret, kind, subject);
        if let Some(record) = self.data.records.get_mut(&id) {
            if record.revoked {
                bail!("credential revoked");
            }
            record.last_seen = now;
            return Ok(record.clone());
        }
        if self.data.records.len() >= MAX_RECORDS {
            bail!("credential registry is full; administrator action required");
        }
        if name.len() > 80 || name.chars().any(char::is_control) {
            bail!("invalid credential display name");
        }
        let record = Record {
            id: id.clone(),
            kind: kind.into(),
            name: name.into(),
            scope,
            created_at: now,
            last_seen: now,
            revoked: false,
        };
        let mut next = self.data.clone();
        next.records.insert(id, record.clone());
        self.persist(&next)?;
        self.data = next;
        Ok(record)
    }

    /// Verify revocation after cryptographic authentication, never before it.
    /// First-use legacy sessions migrate without changing a paired address.
    pub fn authorize(
        &mut self,
        secret: &[u8],
        kind: &str,
        subject: &str,
        now: u64,
    ) -> Option<Record> {
        let id = Self::id(secret, kind, subject);
        if let Some(record) = self.data.records.get_mut(&id) {
            if record.revoked {
                return None;
            }
            record.last_seen = now;
            return Some(record.clone());
        }
        if !self.data.allow_legacy || kind == "agent" {
            return None;
        }
        self.register(
            secret,
            kind,
            subject,
            "Migrated credential",
            Scope::Control,
            now,
        )
        .ok()
    }

    /// Issue a high-entropy per-agent bearer once. Only the keyed digest and
    /// metadata are persisted; the caller must store the returned token safely.
    pub fn issue_agent(
        &mut self,
        secret: &[u8],
        name: &str,
        scope: Scope,
        now: u64,
    ) -> Result<(Record, String)> {
        let mut random = [0u8; 32];
        getrandom::fill(&mut random).map_err(|_| anyhow::anyhow!("secure entropy unavailable"))?;
        let token = format!("ipu_agent_{}", URL_SAFE_NO_PAD.encode(random));
        let record = self.register(secret, "agent", &token, name, scope, now)?;
        Ok((record, token))
    }

    /// Apply a one-way revocation atomically; a new credential gets a new id.
    pub fn revoke(&mut self, id: &str) -> Result<()> {
        let mut next = self.data.clone();
        next.records
            .get_mut(id)
            .context("credential not found")?
            .revoked = true;
        self.persist(&next)?;
        self.data = next;
        self.revoked.send_modify(|n| *n = n.wrapping_add(1));
        Ok(())
    }

    /// Explicit emergency recovery also denies unknown pre-upgrade tokens.
    /// Password login can mint a fresh registered browser identity afterward.
    pub fn revoke_all(&mut self) -> Result<()> {
        let mut next = self.data.clone();
        next.allow_legacy = false;
        for record in next.records.values_mut() {
            record.revoked = true;
        }
        self.persist(&next)?;
        self.data = next;
        self.revoked.send_modify(|n| *n = n.wrapping_add(1));
        Ok(())
    }

    /// Closing remote access revokes paired-device and browser sessions while
    /// preserving local automation credentials. Ingress closure, not source-IP
    /// guesses about a bearer, is what prevents further remote use.
    pub fn revoke_devices(&mut self) -> Result<Vec<String>> {
        let mut next = self.data.clone();
        let mut revoked = Vec::new();
        for record in next.records.values_mut() {
            if matches!(record.kind.as_str(), "device" | "session") {
                record.revoked = true;
                revoked.push(record.id.clone());
            }
        }
        // Unknown pre-migration cookies must not survive an explicit closure.
        next.allow_legacy = false;
        self.persist(&next)?;
        self.data = next;
        self.revoked.send_modify(|n| *n = n.wrapping_add(1));
        Ok(revoked)
    }

    /// Long-lived viewers subscribe before a response starts streaming.
    pub fn subscribe(&self) -> tokio::sync::watch::Receiver<u64> {
        self.revoked.subscribe()
    }

    /// Recheck a previously authenticated identity without minting anything.
    pub fn active(&self, id: &str) -> bool {
        self.data
            .records
            .get(id)
            .is_some_and(|record| !record.revoked)
    }

    /// Public metadata only. Most recent activity is in-memory until a mutation
    /// persists it; no claim is made that it is a complete access log.
    pub fn list(&self) -> Vec<Record> {
        self.data.records.values().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn device_renewal_keeps_identity_and_revocation_survives_restart() {
        let temp = tempfile::tempdir().unwrap();
        let dir = std::fs::canonicalize(temp.path()).unwrap();
        let mut store = Store::open(&dir).unwrap();
        let a = store
            .authorize(b"fixture", "device", "device-a", 1)
            .unwrap();
        let b = store
            .authorize(b"fixture", "device", "device-b", 1)
            .unwrap();
        assert_ne!(a.id, b.id);
        assert_eq!(
            store
                .authorize(b"fixture", "device", "device-a", 2)
                .unwrap()
                .id,
            a.id
        );
        store.revoke(&a.id).unwrap();
        drop(store);
        let mut store = Store::open(&dir).unwrap();
        assert!(store
            .authorize(b"fixture", "device", "device-a", 3)
            .is_none());
        assert!(store
            .authorize(b"fixture", "device", "device-b", 3)
            .is_some());
        assert!(store
            .register(b"fixture", "device", "device-a", "", Scope::Control, 4)
            .is_err());
        store.revoke_all().unwrap();
        assert!(store
            .authorize(b"fixture", "session", "unknown-old", 5)
            .is_none());
        assert!(store
            .register(b"fixture", "session", "new-login", "", Scope::Control, 5)
            .is_ok());
    }

    #[test]
    fn agent_credentials_are_independent_and_never_persist_plaintext() {
        let temp = tempfile::tempdir().unwrap();
        let dir = std::fs::canonicalize(temp.path()).unwrap();
        let mut store = Store::open(&dir).unwrap();
        let (a, token_a) = store
            .issue_agent(b"fixture", "reader", Scope::Read, 1)
            .unwrap();
        let (b, token_b) = store
            .issue_agent(b"fixture", "controller", Scope::Control, 1)
            .unwrap();
        assert_ne!(token_a, token_b);
        assert_ne!(a.id, b.id);
        let text = std::fs::read_to_string(dir.join("access/credentials.json")).unwrap();
        assert!(!text.contains(&token_a));
        assert!(!text.contains(&token_b));
        store.revoke(&a.id).unwrap();
        assert!(store.authorize(b"fixture", "agent", &token_a, 2).is_none());
        assert_eq!(
            store
                .authorize(b"fixture", "agent", &token_b, 2)
                .unwrap()
                .scope,
            Scope::Control
        );
        assert!(store.authorize(b"fixture", "agent", "unknown", 2).is_none());
    }
}
