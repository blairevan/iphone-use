//! Small private-file primitives shared by local security state. Existing
//! corrupt or insecure files are errors, never silently replaced by defaults.

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;

use anyhow::{bail, Context, Result};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::os::unix::io::AsRawFd;

/// Validate every existing path component. A symlinked parent must not move
/// credentials or release state outside the intended namespace.
pub fn no_symlink_components(path: &Path) -> Result<()> {
    if !path.is_absolute() {
        bail!("security state path must be absolute");
    }
    let mut current = std::path::PathBuf::new();
    for part in path.components() {
        if matches!(
            part,
            std::path::Component::ParentDir | std::path::Component::CurDir
        ) {
            bail!("security state path must be canonical");
        }
        current.push(part);
        match std::fs::symlink_metadata(&current) {
            Ok(meta) if meta.file_type().is_symlink() => {
                let system_alias = meta.uid() == 0
                    && match current.to_str() {
                        Some("/var") => std::fs::canonicalize(&current)
                            .is_ok_and(|p| p == Path::new("/private/var")),
                        Some("/tmp") => std::fs::canonicalize(&current)
                            .is_ok_and(|p| p == Path::new("/private/tmp")),
                        _ => false,
                    };
                if !system_alias {
                    bail!("symlink in security state path");
                }
            }
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => break,
            Err(e) => return Err(e).context("inspect security state path"),
        }
    }
    Ok(())
}

/// Create a private directory without changing permissions on existing user
/// data. macOS's /var and /tmp aliases are resolved by callers, not trusted here.
pub fn directory(path: &Path) -> Result<()> {
    no_symlink_components(path)?;
    for parent in path.ancestors().skip(1) {
        if let Ok(meta) = std::fs::metadata(parent) {
            if meta.mode() & 0o022 != 0 && !(meta.uid() == 0 && meta.mode() & 0o1000 != 0) {
                bail!("security state has a writable unprotected ancestor");
            }
        }
    }
    if !path.exists() {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(path)?;
    }
    let meta = std::fs::symlink_metadata(path)?;
    // SAFETY: geteuid has no pointer arguments or mutation.
    if !meta.is_dir() || meta.uid() != unsafe { libc::geteuid() } || meta.mode() & 0o077 != 0 {
        bail!("security directory must be owned by the current user and private (0700)");
    }
    Ok(())
}

/// Read a bounded, private regular file through an O_NOFOLLOW descriptor.
pub fn read(path: &Path, limit: u64) -> Result<Vec<u8>> {
    no_symlink_components(path)?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let meta = file.metadata()?;
    // SAFETY: geteuid reads the current effective user id.
    if !meta.is_file()
        || meta.uid() != unsafe { libc::geteuid() }
        || meta.mode() & 0o077 != 0
        || meta.len() > limit
    {
        bail!("security file must be a bounded private regular file");
    }
    let mut bytes = Vec::new();
    file.take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        bail!("security file grew beyond its limit");
    }
    Ok(bytes)
}

/// Atomically replace local metadata. Validation precedes staging, and fsync
/// precedes publication so a crash cannot publish a partial authorization.
pub fn write(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().context("security file has no parent")?;
    directory(parent)?;
    if path.symlink_metadata().is_ok() {
        read(path, 8 * 1024 * 1024)?;
    }
    let mut staged = tempfile::NamedTempFile::new_in(parent)?;
    staged.write_all(bytes)?;
    staged.as_file().sync_all()?;
    staged.persist(path)?;
    File::open(parent)?.sync_all()?;
    Ok(())
}

/// Hold a process-wide security transaction lock until this descriptor drops.
/// Never delete the lock pathname: doing so could create two lock domains.
pub fn lock(dir: &Path) -> Result<File> {
    directory(dir)?;
    let path = dir.join(".lock");
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(&path)?;
    read(&path, 4096)?;
    // SAFETY: the descriptor remains live throughout this call and ownership.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        bail!("another security transaction already holds this state directory");
    }
    Ok(file)
}
