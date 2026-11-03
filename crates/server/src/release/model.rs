//! Exact-byte, domain-separated Ed25519 metadata. This intentionally small
//! offline bundle format is not an implementation of the complete TUF protocol.

use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

pub const DOMAIN: &[u8] = b"iphone-use-release-metadata-v1\0";
pub const MAX_METADATA: u64 = 2 * 1024 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Envelope {
    pub payload: String,
    pub signatures: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Keys {
    pub threshold: usize,
    /// Key id is the SHA-256 of its raw 32-byte Ed25519 public key.
    pub keys: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Root {
    pub kind: String,
    pub version: u64,
    pub expires: u64,
    pub root: Keys,
    pub releases: Keys,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Asset {
    pub sha256: String,
    pub size: u64,
    pub executable: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub kind: String,
    pub version: String,
    pub sequence: u64,
    pub commit: String,
    pub expires: u64,
    pub platform: String,
    pub files: BTreeMap<String, Asset>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Floor {
    pub sequence: u64,
    pub version: String,
    pub manifest_sha256: String,
    pub last_seen: u64,
    pub installed_sequence: u64,
}

/// SHA-256 identifies immutable bytes; authenticity is checked separately.
pub fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

/// Decode bounded exact signed bytes, never a reserialized JSON object.
pub fn payload(envelope: &Envelope) -> Result<Vec<u8>> {
    if envelope.payload.len() as u64 > MAX_METADATA * 2 {
        bail!("metadata too large");
    }
    let bytes = STANDARD
        .decode(&envelope.payload)
        .context("invalid metadata encoding")?;
    if bytes.len() as u64 > MAX_METADATA {
        bail!("metadata too large");
    }
    Ok(bytes)
}

/// Reject ambiguous or unusable trust policies before any verification.
pub fn validate_keys(keys: &Keys) -> Result<()> {
    if keys.threshold == 0 || keys.threshold > keys.keys.len() || keys.keys.len() > 32 {
        bail!("invalid signature threshold");
    }
    for (id, encoded) in &keys.keys {
        let key = STANDARD
            .decode(encoded)
            .context("invalid public key encoding")?;
        if key.len() != 32 || digest(&key) != *id {
            bail!("public key id mismatch");
        }
    }
    Ok(())
}

/// Verify distinct authorized signatures; unknown or duplicate keys never add
/// votes. Domain separation prevents a signature from another protocol working.
pub fn verify(envelope: &Envelope, keys: &Keys) -> Result<Vec<u8>> {
    validate_keys(keys)?;
    if envelope.signatures.len() > 64 {
        bail!("too many signatures");
    }
    let bytes = payload(envelope)?;
    let message = [DOMAIN, bytes.as_slice()].concat();
    let mut valid = BTreeSet::new();
    for (id, signature) in &envelope.signatures {
        let Some(public) = keys.keys.get(id) else {
            continue;
        };
        let public = STANDARD.decode(public)?;
        let Ok(signature) = STANDARD.decode(signature) else {
            continue;
        };
        if ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, public)
            .verify(&message, &signature)
            .is_ok()
        {
            valid.insert(id);
        }
    }
    if valid.len() < keys.threshold {
        bail!("trusted signature threshold not met");
    }
    Ok(bytes)
}

/// Validate the locally provisioned root and expiry. An expired old root may
/// authenticate its immediate replacement, but cannot authorize an install.
pub fn validate_root(root: &Root) -> Result<()> {
    if root.kind != "iphone-use-root-v1" || root.version == 0 {
        bail!("invalid trust root");
    }
    validate_keys(&root.root)?;
    validate_keys(&root.releases)
}

/// Release versions are deliberately strict stable triples, not lexicographic
/// strings or mutable tags. Prereleases need an explicit future format version.
pub fn version(value: &str) -> Result<(u64, u64, u64)> {
    let parts: Vec<_> = value.split('.').collect();
    if parts.len() != 3
        || parts.iter().any(|p| {
            p.is_empty()
                || !p.bytes().all(|b| b.is_ascii_digit())
                || (p.len() > 1 && p.starts_with('0'))
        })
    {
        bail!("release version must be a stable numeric triple");
    }
    Ok((parts[0].parse()?, parts[1].parse()?, parts[2].parse()?))
}

/// Apply expiry, installed-version, clock and rollback constraints before
/// touching the installed app. A failed install may retry the exact same bytes.
pub fn check_manifest(
    manifest: &Manifest,
    bytes: &[u8],
    floor: &Floor,
    current: &str,
    now: u64,
) -> Result<()> {
    if manifest.kind != "iphone-use-release-v1"
        || manifest.sequence == 0
        || manifest.expires <= now
        || now.saturating_add(300) < floor.last_seen
    {
        bail!("invalid, expired, or clock-rollback release metadata");
    }
    let expected_platform = format!("{}-apple-darwin", std::env::consts::ARCH);
    if manifest.platform != expected_platform {
        bail!("release is for a different platform");
    }
    if manifest.commit.len() != 40
        || !manifest
            .commit
            .bytes()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
    {
        bail!("release must name an exact source commit");
    }
    if version(&manifest.version)? < version(current)?
        || (!floor.version.is_empty() && version(&manifest.version)? < version(&floor.version)?)
        || manifest.sequence < floor.sequence
    {
        bail!("release rollback refused");
    }
    if manifest.sequence == floor.sequence && floor.manifest_sha256 != digest(bytes) {
        bail!("same release sequence has different content");
    }
    Ok(())
}
