//! Regression coverage for network switching, migration and private cache storage.

use super::super::discovery::Network;
use super::*;
use std::os::unix::fs::PermissionsExt;

const U: &str = "000000000000000000000001";

/// Create private synthetic instance state without touching real pairing material.
fn state() -> Result<tempfile::TempDir> {
    let state = tempfile::tempdir()?;
    std::fs::set_permissions(state.path(), std::fs::Permissions::from_mode(0o700))?;
    Ok(state)
}

/// Use opaque deterministic network identities with an intentionally overlapping subnet.
fn scope(id: u64) -> Result<Scope> {
    Ok(Scope {
        key: Some(format!("{id:064x}")),
        network: Network {
            interface: "en0".into(),
            ip: "192.168.1.2".parse()?,
            mask: "255.255.255.0".parse()?,
        },
    })
}

/// A service endpoint is not authenticated by these storage fixtures alone.
fn endpoint(tail: u8) -> Endpoint {
    Endpoint {
        ip: std::net::Ipv4Addr::new(192, 168, 1, tail),
        port: 49152,
        interface: "en0".into(),
    }
}

/// Returning home selects its own address after the office record was updated.
#[test]
fn home_office_home_preserves_independent_addresses() -> Result<()> {
    let state = state()?;
    let home = scope(1)?;
    let office = scope(2)?;
    save(
        state.path(),
        U,
        home.key.as_deref().context("home key")?,
        &endpoint(10),
        true,
    )?;
    save(
        state.path(),
        U,
        office.key.as_deref().context("office key")?,
        &endpoint(20),
        true,
    )?;
    assert_eq!(
        select(state.path(), U, std::slice::from_ref(&home)).verified,
        vec![endpoint(10)]
    );
    assert_eq!(
        select(state.path(), U, std::slice::from_ref(&office)).verified,
        vec![endpoint(20)]
    );
    save(
        state.path(),
        U,
        office.key.as_deref().context("office key")?,
        &endpoint(21),
        true,
    )?;
    assert_eq!(
        select(state.path(), U, &[office]).verified,
        vec![endpoint(21)]
    );
    assert_eq!(
        select(state.path(), U, &[home]).verified,
        vec![endpoint(10)]
    );
    assert!(select(state.path(), U, &[scope(3)?]).verified.is_empty());
    Ok(())
}

/// USB hints remain untrusted and cannot overwrite verified addresses or other profiles.
#[test]
fn usb_hints_are_separate_and_local() -> Result<()> {
    let state = state()?;
    let home = scope(1)?;
    let key = home.key.as_deref().context("home key")?;
    let (hint, _) =
        url_hint("http://192.168.1.11:8100", std::slice::from_ref(&home)).context("USB hint")?;
    save(state.path(), U, key, &hint, false)?;
    assert!(select(state.path(), U, std::slice::from_ref(&home))
        .verified
        .is_empty());
    assert_eq!(
        select(state.path(), U, std::slice::from_ref(&home)).hints,
        vec![hint.clone()]
    );
    save(state.path(), U, key, &endpoint(10), true)?;
    let selected = select(state.path(), U, std::slice::from_ref(&home));
    assert_eq!(selected.verified, vec![endpoint(10)]);
    assert_eq!(selected.hints, vec![hint]);
    assert!(select(state.path(), U, &[scope(2)?]).hints.is_empty());
    for url in [
        "http://127.0.0.1:8100",
        "http://192.168.2.3:8100",
        "http://phone.local:8100",
        "http://192.168.1.255:8100",
        "https://192.168.1.3:8100",
    ] {
        assert!(url_hint(url, std::slice::from_ref(&home)).is_none());
    }
    Ok(())
}

/// Legacy files are queried as hints and remain untouched until authentication writes v2.
#[test]
fn legacy_cache_is_advisory_and_preserved() -> Result<()> {
    let state = state()?;
    let dir = pairing::directory(state.path(), U)?;
    let bytes =
        serde_json::to_vec(&serde_json::json!({"schema":1,"udid":U,"endpoint":endpoint(10)}))?;
    pairing::write_private(&dir.join("address.json"), &bytes)?;
    let home = scope(1)?;
    let selected = select(state.path(), U, std::slice::from_ref(&home));
    assert!(selected.verified.is_empty());
    assert_eq!(selected.hints, vec![endpoint(10)]);
    assert!(!dir.join(FILE).exists());
    save(
        state.path(),
        U,
        home.key.as_deref().context("home key")?,
        &endpoint(10),
        true,
    )?;
    assert_eq!(
        select(state.path(), U, &[home]).verified,
        vec![endpoint(10)]
    );
    assert_eq!(std::fs::read(dir.join("address.json"))?, bytes);
    Ok(())
}

/// Missing network evidence never borrows an arbitrary known profile, even on the same subnet.
#[test]
fn unknown_network_cannot_reuse_another_profile() -> Result<()> {
    let state = state()?;
    let mut home = scope(1)?;
    save(
        state.path(),
        U,
        home.key.as_deref().context("home key")?,
        &endpoint(10),
        true,
    )?;
    home.key = None;
    assert!(select(state.path(), U, &[home]).verified.is_empty());
    assert!(
        select(state.path(), "000000000000000000000002", &[scope(1)?])
            .verified
            .is_empty()
    );
    Ok(())
}

/// Interface names may change, but endpoints must still be local on the active interface.
#[test]
fn remembered_addresses_are_bound_to_the_current_lan() -> Result<()> {
    let state = state()?;
    let mut home = scope(1)?;
    save(
        state.path(),
        U,
        home.key.as_deref().context("home key")?,
        &endpoint(10),
        true,
    )?;
    home.network.interface = "en1".into();
    let selected = select(state.path(), U, std::slice::from_ref(&home));
    assert_eq!(
        selected.verified.first().map(|e| e.interface.as_str()),
        Some("en1")
    );
    home.network.ip = "192.168.2.2".parse()?;
    assert!(select(state.path(), U, &[home]).verified.is_empty());
    Ok(())
}

/// Per-network hints and endpoint files retain the existing owner/mode/no-symlink rules.
#[test]
fn store_is_private_and_symlinks_cannot_redirect_it() -> Result<()> {
    let state = state()?;
    let home = scope(1)?;
    let key = home.key.as_deref().context("home key")?;
    save(state.path(), U, key, &endpoint(10), true)?;
    let path = pairing::directory(state.path(), U)?.join(FILE);
    assert_eq!(std::fs::metadata(&path)?.mode() & 0o077, 0);
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))?;
    assert!(select(state.path(), U, std::slice::from_ref(&home))
        .verified
        .is_empty());
    assert!(save(state.path(), U, key, &endpoint(20), true).is_err());
    std::fs::remove_file(&path)?;
    let outside = tempfile::NamedTempFile::new()?;
    std::os::unix::fs::symlink(outside.path(), &path)?;
    assert!(save(state.path(), U, key, &endpoint(20), true).is_err());
    assert_eq!(std::fs::metadata(outside.path())?.len(), 0);
    Ok(())
}

/// Corrupt cache content is recoverable via discovery but is never silently overwritten.
#[test]
fn corrupt_store_is_preserved_and_reads_do_not_create_state() -> Result<()> {
    let state = state()?;
    let home = scope(1)?;
    assert!(select(state.path(), U, std::slice::from_ref(&home))
        .verified
        .is_empty());
    assert!(!state.path().join("wifi-paired").exists());
    let path = pairing::directory(state.path(), U)?.join(FILE);
    pairing::write_private(&path, b"invalid-json")?;
    assert!(select(state.path(), U, std::slice::from_ref(&home))
        .verified
        .is_empty());
    assert!(save(
        state.path(),
        U,
        home.key.as_deref().context("home key")?,
        &endpoint(20),
        true
    )
    .is_err());
    assert_eq!(std::fs::read(path)?, b"invalid-json");
    Ok(())
}

/// A copied store from another device, unsupported schema or malformed key never yields trust.
#[test]
fn store_metadata_is_checked_before_selecting_addresses() -> Result<()> {
    let state = state()?;
    let home = scope(1)?;
    let key = home.key.as_deref().context("home key")?;
    save(state.path(), U, key, &endpoint(10), true)?;
    let file = pairing::directory(state.path(), U)?.join(FILE);
    let original: serde_json::Value = serde_json::from_slice(&std::fs::read(&file)?)?;
    let mut invalid = original.clone();
    invalid["udid"] = serde_json::Value::String("000000000000000000000002".into());
    pairing::write_private(&file, &serde_json::to_vec(&invalid)?)?;
    assert!(select(state.path(), U, std::slice::from_ref(&home))
        .verified
        .is_empty());
    invalid = original.clone();
    invalid["schema"] = serde_json::Value::from(3);
    pairing::write_private(&file, &serde_json::to_vec(&invalid)?)?;
    assert!(read(state.path(), U).is_err());
    invalid = original;
    invalid["networks"]["../other-network"] = invalid["networks"][key].clone();
    pairing::write_private(&file, &serde_json::to_vec(&invalid)?)?;
    assert!(read(state.path(), U).is_err());
    Ok(())
}

/// Lock files cannot be redirected outside private device state.
#[test]
fn symlink_lock_cannot_modify_an_external_file() -> Result<()> {
    let state = state()?;
    let dir = pairing::directory(state.path(), U)?;
    let outside = tempfile::NamedTempFile::new()?;
    std::os::unix::fs::symlink(outside.path(), dir.join("networks.lock"))?;
    assert!(save(state.path(), U, &format!("{:064x}", 1), &endpoint(10), true).is_err());
    assert!(!dir.join(FILE).exists());
    assert_eq!(std::fs::metadata(outside.path())?.len(), 0);
    Ok(())
}

/// Repeated use retains a profile while the bounded store evicts genuinely older networks.
#[test]
fn network_retention_is_bounded_and_tracks_use() -> Result<()> {
    let state = state()?;
    for id in 1..=MAX_NETWORKS as u64 {
        save(state.path(), U, &format!("{id:064x}"), &endpoint(10), true)?;
    }
    save(state.path(), U, &format!("{:064x}", 1), &endpoint(11), true)?;
    save(
        state.path(),
        U,
        &format!("{:064x}", 100),
        &endpoint(12),
        true,
    )?;
    let store = read(state.path(), U)?.context("network store")?;
    assert_eq!(store.networks.len(), MAX_NETWORKS);
    assert!(store.networks.contains_key(&format!("{:064x}", 1)));
    assert!(!store.networks.contains_key(&format!("{:064x}", 2)));
    Ok(())
}

/// Concurrent writes to different network profiles cannot lose one another's addresses.
#[test]
fn concurrent_profile_updates_do_not_erase_each_other() -> Result<()> {
    let state = state()?;
    pairing::directory(state.path(), U)?;
    std::thread::scope(|scope| -> Result<()> {
        let mut tasks = Vec::new();
        for id in 1..=8u64 {
            let path = state.path();
            tasks.push(
                scope.spawn(move || save(path, U, &format!("{id:064x}"), &endpoint(10), true)),
            );
        }
        for task in tasks {
            task.join()
                .map_err(|_| anyhow::anyhow!("cache writer panicked"))??;
        }
        Ok(())
    })?;
    assert_eq!(
        read(state.path(), U)?
            .context("network store")?
            .networks
            .len(),
        8
    );
    Ok(())
}
