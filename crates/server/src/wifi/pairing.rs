//! Per-instance private identity and last authenticated endpoint storage.

use super::normalized_udid;
use anyhow::{bail, Context, Result};
use idevice::{
    remote_pairing::{RemotePairingLockdownService, RpPairingFile},
    usbmuxd::{UsbmuxdAddr, UsbmuxdConnection},
    IdeviceService,
};
use std::{
    io::Write,
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

/// Private identity metadata, intentionally not Debug to prevent key logging.
pub struct Profile {
    pub udid: String,
    pub host: String,
    pub pair: RpPairingFile,
}

/// Resolve and validate an instance-owned private directory without following symlinks.
pub fn directory(state: &Path, udid: &str) -> Result<PathBuf> {
    checked_directory(state, udid, true)
}

/// Read-only lookups must not create directories or change their permissions.
pub(super) fn checked_directory(state: &Path, udid: &str, create: bool) -> Result<PathBuf> {
    let udid = normalized_udid(udid).context("invalid Wi-Fi target UDID")?;
    let parent = state.join("wifi-paired");
    let dir = parent.join(udid);
    for path in [state, parent.as_path(), dir.as_path()] {
        if create && path != state && std::fs::symlink_metadata(path).is_err() {
            std::fs::create_dir(path)?;
        }
        let metadata = std::fs::symlink_metadata(path)?;
        // SAFETY: geteuid has no pointer arguments or side effects.
        if !metadata.is_dir() || metadata.uid() != unsafe { libc::geteuid() } {
            bail!("unsafe Wi-Fi state directory");
        }
        if create && path != state {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
        } else if metadata.mode() & 0o077 != 0 {
            bail!("Wi-Fi state directory must be private");
        }
    }
    Ok(dir)
}

/// Atomically replace one private file in the already checked directory.
pub(super) fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    let dir = path.parent().context("missing Wi-Fi state directory")?;
    let mut temp = tempfile::NamedTempFile::new_in(dir)?;
    temp.as_file()
        .set_permissions(std::fs::Permissions::from_mode(0o600))?;
    temp.write_all(bytes)?;
    temp.as_file().sync_all()?;
    temp.persist(path).map_err(|error| error.error)?;
    Ok(())
}

/// Read only regular private files owned by the current user, without symlink traversal.
pub(super) fn read_private(path: &Path) -> Result<Vec<u8>> {
    use std::io::Read;
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let metadata = file.metadata()?;
    // SAFETY: geteuid reads the process identity only.
    if !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o077 != 0
        || metadata.len() > 64 * 1024
    {
        bail!("unsafe Wi-Fi state file");
    }
    let mut data = Vec::new();
    file.read_to_end(&mut data)?;
    Ok(data)
}

/// A usable independent RemotePairing identity has already been bootstrapped over USB.
pub fn is_paired(state: &Path, udid: &str) -> bool {
    load(state, udid).is_ok()
}

/// Load only this device's identity; never borrow another instance's key material.
pub fn load(state: &Path, udid: &str) -> Result<Profile> {
    let dir = checked_directory(state, udid, false)?;
    let host = String::from_utf8(read_private(&dir.join("host"))?)?;
    // The pinned decoder logs its input at debug level, including private keys.
    let quiet = tracing::subscriber::set_default(tracing::subscriber::NoSubscriber::default());
    let pair = RpPairingFile::from_bytes(&read_private(&dir.join("pair.plist"))?)?;
    drop(quiet);
    if pair.alt_irk.as_ref().map(Vec::len) != Some(16) {
        bail!("Wi-Fi pairing lacks device identity");
    }
    Ok(Profile {
        udid: normalized_udid(udid).context("invalid target")?,
        host,
        pair,
    })
}

/// Bootstrap trust over existing paired USB only; wireless discovery never calls pair-setup.
pub async fn remember(state: &Path, udid: &str) -> Result<()> {
    if is_paired(state, udid) {
        return Ok(());
    }
    let mut mux = UsbmuxdConnection::default().await?;
    let target = normalized_udid(udid).context("invalid target")?;
    let device = mux
        .get_devices()
        .await?
        .into_iter()
        .find(|device| {
            device.connection_type == idevice::usbmuxd::Connection::Usb
                && normalized_udid(&device.udid).as_deref() == Some(target.as_str())
        })
        .context("the paired target must be connected over USB to remember Wi-Fi trust")?;
    let provider = device.to_provider(
        UsbmuxdAddr::from_env_var().unwrap_or_default(),
        "iphone-use-wifi",
    );
    let dir = directory(state, udid)?;
    let host = format!("iphone-use-{}", uuid::Uuid::new_v4());
    let mut pair = RpPairingFile::generate(&host);
    let service = RemotePairingLockdownService::connect(&provider).await?;
    eprintln!("wifi-auto: trusted USB pairing service connected");
    let mut client = service.into_client(&host)?;
    client.attempt_pair_verify().await?;
    eprintln!("wifi-auto: USB pairing handshake completed");
    // A new host must finish the failed verify exchange before asking for consent.
    // Skipping it leaves remotepairingdeviced waiting in the verify state.
    match client.validate_pairing(&mut pair).await {
        Err(idevice::IdeviceError::RemotePairing(
            idevice::remote_pairing::errors::RemotePairingError::PairVerifyFailed,
        )) => {}
        Err(error) => return Err(error.into()),
        Ok(()) => bail!("a fresh pairing identity unexpectedly already exists on the device"),
    }
    eprintln!("wifi-auto: requesting independent USB pairing consent");
    client
        .pair(&mut pair, || async { "000000".to_owned() })
        .await?;
    if normalized_udid(&client.paired_peer_device()?.remotepairing_udid) != normalized_udid(udid) {
        bail!("USB pairing target mismatch");
    }
    write_private(&dir.join("host"), host.as_bytes())?;
    write_private(&dir.join("pair.plist"), &pair.to_bytes())?;
    eprintln!("wifi-auto: independent paired-device identity saved");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    const U: &str = "000000000000000000000001";

    /// A symlink must never redirect credential reads or directory permission changes.
    #[test]
    fn symlink_state_is_rejected() -> Result<()> {
        let state = tempfile::tempdir()?;
        let outside = tempfile::tempdir()?;
        std::os::unix::fs::symlink(outside.path(), state.path().join("wifi-paired"))?;
        assert!(directory(state.path(), U).is_err());
        assert!(!outside.path().join(U).exists());
        Ok(())
    }

    /// Merely checking trust must leave an unpaired instance untouched.
    #[test]
    fn unpaired_lookup_is_read_only() -> Result<()> {
        let state = tempfile::tempdir()?;
        assert!(!is_paired(state.path(), U));
        assert!(!state.path().join("wifi-paired").exists());
        Ok(())
    }
}
