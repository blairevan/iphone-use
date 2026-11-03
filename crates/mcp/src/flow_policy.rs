//! Local operator approvals, deliberately stored outside the downloaded flow
//! registry. A publisher's risk label or checksum never grants permission.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

use crate::flow::{FlowRisk, ValidatedFlow};

/// The approved invocation includes the exact downloaded bytes AND supplied
/// input values. A changed registry file, target, input or default invalidates
/// approval. Inputs are hashed and are never written to the policy store.
pub fn invocation_digest(
    flow: &ValidatedFlow,
    inputs: &BTreeMap<String, String>,
) -> Result<String> {
    let payload =
        serde_json::to_vec(&("iphone-use-flow-approval-v1", &flow.content_sha256, inputs))?;
    Ok(crate::registry::sha256_hex(&payload))
}

/// Local-only policy location. The registry fetcher never reads or writes it.
fn approval_dir() -> Result<PathBuf> {
    let dir = match std::env::var_os("IPHONE_USE_FLOW_APPROVALS_DIR") {
        Some(dir) => PathBuf::from(dir),
        None => PathBuf::from(std::env::var_os("HOME").context("HOME is not configured")?)
            .join(".iphone-use/flow-approvals"),
    };
    if !dir.is_absolute() {
        bail!("flow approval directory must be absolute");
    }
    Ok(dir)
}

/// Validate a private, real policy directory instead of following a registry
/// supplied link or accepting group-writable authorization metadata.
fn check_directory(dir: &Path) -> Result<()> {
    let metadata = std::fs::symlink_metadata(dir)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        bail!("flow approval directory must be a real directory");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        // SAFETY: geteuid has no pointer arguments or state mutation.
        if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o077 != 0 {
            bail!("flow approval directory must be owned by the current user with mode 0700");
        }
    }
    Ok(())
}

/// Only explicitly reviewed low-risk invocations may become one-click flows.
/// Unknown risk and real-world side effects always require per-run approval.
fn may_cache_approval(flow: &ValidatedFlow) -> bool {
    matches!(
        flow.meta.risk,
        Some(FlowRisk::ReadOnly | FlowRisk::Navigation)
    )
}

/// Read a local approval fail-closed. This is a user decision, NOT a claim that
/// JSON can prove UI clicks harmless. An operator can revoke it by deleting
/// the corresponding digest file from the private policy directory.
pub fn is_approved(flow: &ValidatedFlow, inputs: &BTreeMap<String, String>) -> Result<bool> {
    if !may_cache_approval(flow) {
        return Ok(false);
    }
    is_approved_in(&approval_dir()?, &invocation_digest(flow, inputs)?)
}

/// Pure path-oriented reader used by regression tests without global env edits.
fn is_approved_in(dir: &Path, digest: &str) -> Result<bool> {
    match std::fs::symlink_metadata(dir) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        _ => check_directory(dir)?,
    }
    let path = dir.join(digest);
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = match options.open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error).context("read local flow approval"),
    };
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > 256 {
        bail!("invalid flow approval file");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        // SAFETY: geteuid only returns the current process's effective uid.
        if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o077 != 0 {
            bail!("flow approval must be private and owned by the current user");
        }
    }
    let mut text = String::new();
    file.take(257).read_to_string(&mut text)?;
    Ok(text == format!("iphone-use-flow-approval-v1\n{digest}\n"))
}

/// Record approval only through the local CLI. No HTTP/MCP route grants trust;
/// downloaded metadata cannot add itself to this separate policy namespace.
pub fn approve(target: &str, assignments: &[String]) -> Result<String> {
    let path = crate::registry::resolve_target(target)?;
    let flow = crate::flow::load_flow(&path)?;
    if !may_cache_approval(&flow) {
        bail!("only reviewed read_only/navigation flows can receive persistent approval; unknown/side_effect flows require confirmation for every run");
    }
    let inputs = crate::flow::parse_input_assignments(assignments, &flow.inputs)?;
    // Validate required values before recording an approval for an invocation.
    crate::flow::materialized_request(&flow, &inputs)?;
    let digest = invocation_digest(&flow, &inputs)?;
    write_approval(&approval_dir()?, &digest)?;
    Ok(digest)
}

/// Private staging plus atomic replacement never exposes a partially written
/// authorization. Reapproval of the same digest is idempotent.
fn write_approval(dir: &Path, digest: &str) -> Result<()> {
    if !dir.exists() {
        let mut builder = std::fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(dir)?;
    }
    check_directory(dir)?;
    let mut staged = tempfile::NamedTempFile::new_in(dir)?;
    write!(staged, "iphone-use-flow-approval-v1\n{digest}\n")?;
    staged.as_file().sync_all()?;
    staged.persist(dir.join(digest))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn private_dir() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        dir
    }

    fn flow(risk: Option<&str>, name: &str) -> ValidatedFlow {
        let mut value =
            serde_json::json!({"version":1,"name":name,"steps":[{"kind":"pause","ms":1}]});
        if let Some(risk) = risk {
            value["risk"] = risk.into();
        }
        crate::flow::parse_flow(&serde_json::to_vec(&value).unwrap(), "fixture").unwrap()
    }

    #[test]
    fn downloaded_risk_labels_cannot_grant_approval() {
        let dir = private_dir();
        for risk in [
            None,
            Some("read_only"),
            Some("navigation"),
            Some("side_effect"),
        ] {
            let flow = flow(risk, "fixture");
            let digest = invocation_digest(&flow, &BTreeMap::new()).unwrap();
            assert!(!is_approved_in(dir.path(), &digest).unwrap());
            assert_eq!(
                may_cache_approval(&flow),
                matches!(risk, Some("read_only" | "navigation"))
            );
        }
    }

    #[test]
    fn approval_is_bound_to_exact_content_and_inputs() {
        let dir = private_dir();
        let inputs = BTreeMap::from([("recipient".into(), "fixture-a".into())]);
        let flow = flow(Some("read_only"), "first");
        let digest = invocation_digest(&flow, &inputs).unwrap();
        write_approval(dir.path(), &digest).unwrap();
        assert!(is_approved_in(dir.path(), &digest).unwrap());
        let changed_inputs = BTreeMap::from([("recipient".into(), "fixture-b".into())]);
        assert!(!is_approved_in(
            dir.path(),
            &invocation_digest(&flow, &changed_inputs).unwrap()
        )
        .unwrap());
        let mut changed = flow;
        changed.content_sha256 = crate::registry::sha256_hex(b"changed bytes");
        assert!(
            !is_approved_in(dir.path(), &invocation_digest(&changed, &inputs).unwrap()).unwrap()
        );
        assert!(!std::fs::read_to_string(dir.path().join(digest))
            .unwrap()
            .contains("fixture-a"));
    }

    #[cfg(unix)]
    #[test]
    fn symlink_and_insecure_permissions_cannot_authorize_a_flow() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let dir = private_dir();
        let digest = "a".repeat(64);
        write_approval(dir.path(), &digest).unwrap();
        let linked = "b".repeat(64);
        symlink(dir.path().join(&digest), dir.path().join(&linked)).unwrap();
        assert!(is_approved_in(dir.path(), &linked).is_err());
        std::fs::set_permissions(
            dir.path().join(&digest),
            std::fs::Permissions::from_mode(0o666),
        )
        .unwrap();
        assert!(is_approved_in(dir.path(), &digest).is_err());
    }
}
