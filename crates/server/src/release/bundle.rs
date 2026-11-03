//! Verify every file before making any executable available to the installer.

use super::model::Manifest;
use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path};

const MAX_FILES: usize = 20_000;
const MAX_TOTAL: u64 = 4 * 1024 * 1024 * 1024;
const MAX_DEPTH: usize = 64;
const REQUIRED: &[&str] = &[
    "install.sh",
    "uninstall.sh",
    "scripts/setup-runner.sh",
    "skills/iphone-use/SKILL.md",
    "iPhoneUse.app/Contents/Info.plist",
    "iPhoneUse.app/Contents/MacOS/iphone-use",
    "iPhoneUse.app/Contents/MacOS/iphone-use-mcp",
    "runner/IPhoneUseRunner/IPhoneUseRunner.xcodeproj/project.pbxproj",
];

/// Restrict signed paths as well as unsigned ones. No alternate separators,
/// shell control characters, hidden helpers or ambiguous path components.
pub fn safe_path(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= 1024
        && !path.starts_with('/')
        && path
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"/_-. ".contains(&b))
        && path
            .split('/')
            .all(|p| !p.is_empty() && p != "." && p != "..")
        && Path::new(path)
            .components()
            .all(|c| matches!(c, Component::Normal(_)))
        && path != "manifest.json"
        && !path.starts_with("roots/")
}

/// Enumerate without following links. Every regular file (including helper
/// scripts and app resources) must have a signed entry in the manifest.
fn inventory(
    root: &Path,
    dir: &Path,
    paths: &mut BTreeSet<String>,
    nodes: &mut usize,
    depth: usize,
) -> Result<()> {
    if depth > MAX_DEPTH {
        bail!("release directory nesting limit exceeded");
    }
    for entry in std::fs::read_dir(dir)? {
        *nodes += 1;
        if *nodes > MAX_FILES * 2 {
            bail!("too many release filesystem entries");
        }
        let entry = entry?;
        let path = entry.path();
        let relative = path
            .strip_prefix(root)?
            .to_str()
            .context("non-UTF8 bundle path")?
            .to_string();
        let meta = std::fs::symlink_metadata(&path)?;
        if meta.file_type().is_symlink() {
            bail!("bundle contains a symbolic link");
        }
        if relative == "manifest.json" && meta.is_file() {
            continue;
        }
        if relative == "roots" && meta.is_dir() {
            continue;
        }
        if !safe_path(&relative) {
            bail!("unsafe bundle path");
        }
        if meta.is_dir() {
            inventory(root, &path, paths, nodes, depth + 1)?;
        } else if meta.is_file() {
            paths.insert(relative);
        } else {
            bail!("bundle contains a non-regular file");
        }
        if paths.len() > MAX_FILES {
            bail!("too many release files");
        }
    }
    Ok(())
}

/// Copy while hashing the same open descriptors that supply the staged bytes.
/// The installer only ever sees the resulting private, verified snapshot.
pub fn stage(root: &Path, manifest: &Manifest) -> Result<tempfile::TempDir> {
    crate::secure_store::no_symlink_components(root)?;
    let total = manifest
        .files
        .values()
        .try_fold(0u64, |sum, f| sum.checked_add(f.size))
        .context("release length overflow")?;
    if total > MAX_TOTAL || manifest.files.len() > MAX_FILES {
        bail!("release size limit exceeded");
    }
    if REQUIRED
        .iter()
        .any(|path| !manifest.files.contains_key(*path))
    {
        bail!("release bundle is incomplete");
    }
    for path in REQUIRED
        .iter()
        .filter(|p| p.ends_with(".sh") || p.contains("/MacOS/"))
    {
        if !manifest.files[*path].executable {
            bail!("required executable is not executable");
        }
    }
    let mut paths = BTreeSet::new();
    let mut nodes = 0;
    inventory(root, root, &mut paths, &mut nodes, 0)?;
    if paths != manifest.files.keys().cloned().collect() {
        bail!("unsigned or missing release files");
    }
    let staged = tempfile::Builder::new()
        .prefix("iphone-use-verified-")
        .tempdir()?;
    std::fs::set_permissions(staged.path(), std::fs::Permissions::from_mode(0o700))?;
    for (path, asset) in &manifest.files {
        if !safe_path(path) {
            bail!("unsafe signed asset path");
        }
        let source = root.join(path);
        crate::secure_store::no_symlink_components(&source)?;
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(&source)?;
        let meta = file.metadata()?;
        if !meta.is_file() || meta.len() != asset.size {
            bail!("release asset size/type mismatch");
        }
        let destination = staged.path().join(path);
        std::fs::create_dir_all(destination.parent().context("asset has no parent")?)?;
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&destination)?;
        let mut hash = Sha256::new();
        let mut count = 0u64;
        let mut buffer = [0u8; 64 * 1024];
        loop {
            let n = file.read(&mut buffer)?;
            if n == 0 {
                break;
            }
            count = count.checked_add(n as u64).context("asset overflow")?;
            if count > asset.size {
                bail!("release asset changed while copying");
            }
            hash.update(&buffer[..n]);
            output.write_all(&buffer[..n])?;
        }
        if count != asset.size || format!("{:x}", hash.finalize()) != asset.sha256 {
            bail!("release asset digest mismatch");
        }
        output.sync_all()?;
        std::fs::set_permissions(
            destination,
            std::fs::Permissions::from_mode(if asset.executable { 0o700 } else { 0o600 }),
        )?;
    }
    let info = crate::secure_store::read(
        &staged.path().join("iPhoneUse.app/Contents/Info.plist"),
        2 * 1024 * 1024,
    )?;
    let info = plist::Value::from_reader(std::io::Cursor::new(info))
        .context("invalid app version metadata")?;
    if info
        .as_dictionary()
        .and_then(|dict| dict.get("CFBundleShortVersionString"))
        .and_then(plist::Value::as_string)
        != Some(manifest.version.as_str())
    {
        bail!("signed release version does not match the staged application");
    }
    Ok(staged)
}
