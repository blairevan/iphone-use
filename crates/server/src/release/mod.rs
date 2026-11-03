//! Explicit, signed offline release installation. Network checks can announce a
//! version but can never provision trust or execute the downloaded publisher.

mod bundle;
mod model;
#[cfg(test)]
mod tests;

use anyhow::{bail, Context, Result};
use clap::Subcommand;
use model::{Envelope, Floor, Manifest, Root, MAX_METADATA};
use std::path::{Path, PathBuf};

#[derive(Subcommand)]
pub enum Action {
    /// Import an independently verified root. Never fetch a root from a release.
    Trust {
        root: PathBuf,
        /// SHA-256 of the exact root payload, obtained through another channel.
        #[arg(long)]
        fingerprint: String,
    },
    /// Verify an entire offline release bundle without installing anything.
    Verify { bundle: PathBuf },
    /// Verify and install a fixed offline bundle. No remote scripts are fetched.
    Install {
        bundle: PathBuf,
        #[arg(long)]
        confirm: bool,
        #[arg(long)]
        instance: Option<String>,
    },
}

/// Metadata can be public but cannot be a link, FIFO, unbounded file or a
/// mutable stream. Trust-state files use stronger private-file checks.
fn metadata(path: &Path) -> Result<Vec<u8>> {
    use std::io::Read;
    use std::os::unix::fs::OpenOptionsExt;
    crate::secure_store::no_symlink_components(path)?;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let meta = file.metadata()?;
    if !meta.is_file() || meta.len() > MAX_METADATA {
        bail!("invalid metadata file");
    }
    let mut bytes = Vec::new();
    file.take(MAX_METADATA + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_METADATA {
        bail!("metadata grew beyond its limit");
    }
    Ok(bytes)
}

/// Persist each authenticated root before attempting the next one or loading a
/// release. An incomplete bundle must not undo a learned signer revocation.
fn rotate_with(
    mut root: Root,
    bundle: &Path,
    now: u64,
    mut accept: impl FnMut(&Root) -> Result<()>,
) -> Result<Root> {
    model::validate_root(&root)?;
    for _ in 0..64 {
        let next = root
            .version
            .checked_add(1)
            .context("root version overflow")?;
        let path = bundle.join(format!("roots/{next}.json"));
        if !path.try_exists()? {
            break;
        }
        let envelope: Envelope = serde_json::from_slice(&metadata(&path)?)?;
        let bytes = model::verify(&envelope, &root.root)?;
        let candidate: Root = serde_json::from_slice(&bytes)?;
        model::validate_root(&candidate)?;
        if candidate.version != next {
            bail!("root rotation must advance by exactly one version");
        }
        model::verify(&envelope, &candidate.root)?;
        accept(&candidate)?;
        root = candidate;
    }
    let next = root
        .version
        .checked_add(1)
        .context("root version overflow")?;
    if bundle.join(format!("roots/{next}.json")).try_exists()? {
        bail!("too many consecutive trust-root rotations in one operation");
    }
    if root.expires <= now {
        bail!("trusted root is expired");
    }
    Ok(root)
}

/// Pure rotation helper for isolated signature-policy tests.
#[cfg(test)]
fn rotate(root: Root, bundle: &Path, now: u64) -> Result<Root> {
    rotate_with(root, bundle, now, |_| Ok(()))
}

/// Keep rollback floor and root in one atomic state record to prevent a crash
/// between two files from authorizing a previously revoked signer.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct TrustState {
    root: Root,
    floor: Floor,
}

/// Validate and snapshot a release while a caller holds the trust-state lock.
fn prepare(
    dir: &Path,
    source: &Path,
    now: u64,
) -> Result<(TrustState, Manifest, tempfile::TempDir)> {
    let mut state: TrustState = serde_json::from_slice(&crate::secure_store::read(
        &dir.join("trust.json"),
        MAX_METADATA,
    )?)
    .context("no valid locally provisioned release trust root")?;
    if now.saturating_add(300) < state.floor.last_seen {
        bail!("local clock rollback refused");
    }
    let root = rotate_with(state.root.clone(), source, now, |root| {
        state.root = root.clone();
        state.floor.last_seen = now.max(state.floor.last_seen);
        crate::secure_store::write(&dir.join("trust.json"), &serde_json::to_vec(&state)?)
    })?;
    let envelope: Envelope = serde_json::from_slice(&metadata(&source.join("manifest.json"))?)?;
    let bytes = model::verify(&envelope, &root.releases)?;
    let manifest: Manifest = serde_json::from_slice(&bytes)?;
    model::check_manifest(
        &manifest,
        &bytes,
        &state.floor,
        env!("CARGO_PKG_VERSION"),
        now,
    )?;
    let floor = Floor {
        sequence: manifest.sequence,
        version: manifest.version.clone(),
        manifest_sha256: model::digest(&bytes),
        last_seen: now.max(state.floor.last_seen),
        installed_sequence: state.floor.installed_sequence,
    };
    let state = TrustState { root, floor };
    // A valid signed manifest establishes a high-water mark even if a mirror
    // withholds a payload. Verification may update trust metadata, never apps.
    crate::secure_store::write(&dir.join("trust.json"), &serde_json::to_vec(&state)?)?;
    let staged = bundle::stage(source, &manifest)?;
    Ok((state, manifest, staged))
}

/// Execute only a completely verified private snapshot. The old installation
/// transaction owns app/plist/skill/runner rollback and health verification.
fn install(staged: &Path, instance: Option<&str>) -> Result<()> {
    let home = std::env::var_os("HOME").context("HOME is not set")?;
    if let Some(name) = instance {
        crate::instance::Instance::derive(name, PathBuf::from(&home), None)
            .map_err(anyhow::Error::msg)?;
    }
    let mut command = std::process::Command::new("/bin/bash");
    command
        .env_clear()
        .env("HOME", &home)
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin")
        .env("IPHONE_USE_NO_SETUP", "1")
        .env("IPHONE_USE_AUTO_UPDATE", "0")
        .arg(staged.join("install.sh"))
        .arg(staged.join("iPhoneUse.app"))
        .arg("--no-setup")
        .arg("--no-auto-update")
        .stdin(std::process::Stdio::null());
    if let Some(name) = instance {
        command.args(["--instance", name]);
    }
    let status = command.status().context("start verified local installer")?;
    if !status.success() {
        bail!("verified installer failed; its transaction restores the previous installation");
    }
    Ok(())
}

/// Dispatch the explicit local trust/verification/install CLI; no branch can
/// fetch, self-sign or silently enable remote code execution.
pub fn run(action: Action) -> Result<()> {
    let home = PathBuf::from(std::env::var_os("HOME").context("HOME is not set")?);
    let dir = home.join(".iphone-use/release-trust");
    let _lock = crate::secure_store::lock(&dir)?;
    let now = crate::update::unix_now();
    match action {
        Action::Trust { root, fingerprint } => {
            if dir.join("trust.json").symlink_metadata().is_ok() {
                bail!("trust already provisioned; use a cross-signed root rotation");
            }
            let bytes = metadata(&std::fs::canonicalize(root)?)?;
            if model::digest(&bytes) != fingerprint {
                bail!("independent trust-root fingerprint mismatch");
            }
            let root: Root = serde_json::from_slice(&bytes)?;
            model::validate_root(&root)?;
            if root.expires <= now {
                bail!("cannot trust an expired root");
            }
            let state = TrustState {
                root,
                floor: Floor::default(),
            };
            crate::secure_store::write(&dir.join("trust.json"), &serde_json::to_vec(&state)?)?;
            println!("Release trust root provisioned. No release was installed.");
        }
        Action::Verify { bundle } => {
            let (_, manifest, _staged) = prepare(&dir, &std::fs::canonicalize(bundle)?, now)?;
            println!(
                "{}",
                serde_json::json!({"verified":true,"installed":false,"version":manifest.version,"commit":manifest.commit,"files":manifest.files.len()})
            );
        }
        Action::Install {
            bundle,
            confirm,
            instance,
        } => {
            if !confirm {
                bail!("installation requires --confirm after reviewing the fixed release");
            }
            let (mut state, manifest, staged) =
                prepare(&dir, &std::fs::canonicalize(bundle)?, now)?;
            // Observe the signed high-water mark before execution; a crash or
            // failed install can retry these bytes, never a downgraded release.
            crate::secure_store::write(&dir.join("trust.json"), &serde_json::to_vec(&state)?)?;
            install(staged.path(), instance.as_deref())?;
            state.floor.installed_sequence = manifest.sequence;
            crate::secure_store::write(&dir.join("trust.json"), &serde_json::to_vec(&state)?)?;
            println!(
                "Verified release {} installed; unattended updates remain disabled.",
                manifest.version
            );
        }
    }
    Ok(())
}
