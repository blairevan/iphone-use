//! All private signing keys here are ephemeral synthetic test fixtures.
use super::model::{Asset, Keys};
use super::*;
use base64::{engine::general_purpose::STANDARD, Engine};
use ring::signature::{Ed25519KeyPair, KeyPair};
use std::collections::BTreeMap;
use std::os::unix::fs::{symlink, PermissionsExt};

fn signer() -> Ed25519KeyPair {
    let bytes = Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new()).unwrap();
    Ed25519KeyPair::from_pkcs8(bytes.as_ref()).unwrap()
}
fn keys(signers: &[&Ed25519KeyPair], threshold: usize) -> Keys {
    Keys {
        threshold,
        keys: signers
            .iter()
            .map(|s| {
                (
                    model::digest(s.public_key().as_ref()),
                    STANDARD.encode(s.public_key().as_ref()),
                )
            })
            .collect(),
    }
}
fn signed<T: serde::Serialize>(payload: &T, signers: &[&Ed25519KeyPair]) -> Envelope {
    let bytes = serde_json::to_vec(payload).unwrap();
    let message = [model::DOMAIN, bytes.as_slice()].concat();
    Envelope {
        payload: STANDARD.encode(bytes),
        signatures: signers
            .iter()
            .map(|s| {
                (
                    model::digest(s.public_key().as_ref()),
                    STANDARD.encode(s.sign(&message).as_ref()),
                )
            })
            .collect(),
    }
}
fn root(signer: &Ed25519KeyPair, version: u64) -> Root {
    Root {
        kind: "iphone-use-root-v1".into(),
        version,
        expires: 5000,
        root: keys(&[signer], 1),
        releases: keys(&[signer], 1),
    }
}
fn temp() -> (tempfile::TempDir, PathBuf) {
    let temp = tempfile::tempdir().unwrap();
    let path = std::fs::canonicalize(temp.path()).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
    (temp, path)
}
fn manifest() -> Manifest {
    Manifest {
        kind: "iphone-use-release-v1".into(),
        version: env!("CARGO_PKG_VERSION").into(),
        sequence: 10,
        commit: "a".repeat(40),
        expires: 2000,
        platform: format!("{}-apple-darwin", std::env::consts::ARCH),
        files: BTreeMap::new(),
    }
}

#[test]
fn signature_threshold_domain_and_publisher_are_independent_of_download() {
    let a = signer();
    let b = signer();
    let stranger = signer();
    let policy = keys(&[&a, &b], 2);
    assert!(model::verify(&signed(&manifest(), &[&a]), &policy).is_err());
    assert!(model::verify(&signed(&manifest(), &[&a, &stranger]), &policy).is_err());
    let envelope = signed(&manifest(), &[&a, &b]);
    assert!(model::verify(&envelope, &policy).is_ok());
    let mut changed = envelope.clone();
    changed.payload = STANDARD.encode(b"{}");
    assert!(model::verify(&changed, &policy).is_err());
    let mut wrong_domain = envelope;
    wrong_domain.signatures.insert(
        model::digest(a.public_key().as_ref()),
        STANDARD.encode(a.sign(&model::payload(&wrong_domain).unwrap()).as_ref()),
    );
    assert!(model::verify(&wrong_domain, &policy).is_err());
    assert!(model::validate_keys(&keys(&[&a], 0)).is_err());
}

#[test]
fn rotation_requires_both_roots_exact_version_and_revokes_old_release_key() {
    let (_tmp, dir) = temp();
    std::fs::create_dir(dir.join("roots")).unwrap();
    let old = signer();
    let new = signer();
    let next = root(&new, 2);
    let path = dir.join("roots/2.json");
    std::fs::write(&path, serde_json::to_vec(&signed(&next, &[&new])).unwrap()).unwrap();
    assert!(rotate(root(&old, 1), &dir, 1000).is_err());
    std::fs::write(&path, serde_json::to_vec(&signed(&next, &[&old])).unwrap()).unwrap();
    assert!(rotate(root(&old, 1), &dir, 1000).is_err());
    std::fs::write(
        &path,
        serde_json::to_vec(&signed(&next, &[&old, &new])).unwrap(),
    )
    .unwrap();
    let rotated = rotate(root(&old, 1), &dir, 1000).unwrap();
    assert!(model::verify(&signed(&manifest(), &[&old]), &rotated.releases).is_err());
    assert!(model::verify(&signed(&manifest(), &[&new]), &rotated.releases).is_ok());
    assert!(rotate(root(&old, 1), &dir, 5001).is_err());
    std::fs::write(
        &path,
        serde_json::to_vec(&signed(&root(&new, 3), &[&old, &new])).unwrap(),
    )
    .unwrap();
    assert!(rotate(root(&old, 1), &dir, 1000).is_err());
}

#[test]
fn expired_rollback_changed_sequence_and_clock_replay_fail_closed() {
    let mut manifest = manifest();
    let bytes = serde_json::to_vec(&manifest).unwrap();
    let floor = Floor {
        sequence: 10,
        version: manifest.version.clone(),
        manifest_sha256: model::digest(&bytes),
        last_seen: 1000,
        installed_sequence: 9,
    };
    assert!(
        model::check_manifest(&manifest, &bytes, &floor, env!("CARGO_PKG_VERSION"), 1000).is_ok()
    );
    assert!(model::check_manifest(
        &manifest,
        b"different",
        &floor,
        env!("CARGO_PKG_VERSION"),
        1000
    )
    .is_err());
    assert!(
        model::check_manifest(&manifest, &bytes, &floor, env!("CARGO_PKG_VERSION"), 2000).is_err()
    );
    assert!(
        model::check_manifest(&manifest, &bytes, &floor, env!("CARGO_PKG_VERSION"), 600).is_err()
    );
    manifest.sequence = 9;
    assert!(
        model::check_manifest(&manifest, &bytes, &floor, env!("CARGO_PKG_VERSION"), 1000).is_err()
    );
    manifest.sequence = 11;
    manifest.version = "0.1.0".into();
    assert!(
        model::check_manifest(&manifest, &bytes, &floor, env!("CARGO_PKG_VERSION"), 1000).is_err()
    );
    assert!(model::version("1.01.0").is_err());
    assert!(model::version("1.2.3-main").is_err());
}

#[test]
fn full_bundle_snapshot_rejects_missing_tampered_extra_and_linked_assets() {
    let (_tmp, dir) = temp();
    let mut manifest = manifest();
    let paths = [
        "install.sh",
        "uninstall.sh",
        "scripts/setup-runner.sh",
        "skills/iphone-use/SKILL.md",
        "iPhoneUse.app/Contents/Info.plist",
        "iPhoneUse.app/Contents/MacOS/iphone-use",
        "iPhoneUse.app/Contents/MacOS/iphone-use-mcp",
        "runner/IPhoneUseRunner/IPhoneUseRunner.xcodeproj/project.pbxproj",
    ];
    for path in paths {
        let file = dir.join(path);
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        let bytes = if path.ends_with("Info.plist") {
            format!("<?xml version=\"1.0\"?><plist version=\"1.0\"><dict><key>CFBundleShortVersionString</key><string>{}</string></dict></plist>", manifest.version).into_bytes()
        } else {
            b"fixture".to_vec()
        };
        std::fs::write(&file, &bytes).unwrap();
        manifest.files.insert(
            path.into(),
            Asset {
                sha256: model::digest(&bytes),
                size: bytes.len() as u64,
                executable: !path.ends_with("Info.plist"),
            },
        );
    }
    let snapshot = bundle::stage(&dir, &manifest).unwrap();
    assert_eq!(
        std::fs::read(snapshot.path().join("install.sh")).unwrap(),
        b"fixture"
    );
    let mut mislabeled = manifest.clone();
    mislabeled.version = "999.0.0".into();
    assert!(
        bundle::stage(&dir, &mislabeled).is_err(),
        "a new signed version must not label an older app"
    );
    std::fs::write(dir.join("install.sh"), b"changed").unwrap();
    assert!(bundle::stage(&dir, &manifest).is_err());
    std::fs::write(dir.join("install.sh"), b"fixture").unwrap();
    std::fs::write(dir.join("extra.sh"), b"untrusted").unwrap();
    assert!(bundle::stage(&dir, &manifest).is_err());
    std::fs::remove_file(dir.join("extra.sh")).unwrap();
    std::fs::remove_file(dir.join("install.sh")).unwrap();
    assert!(bundle::stage(&dir, &manifest).is_err());
    symlink(dir.join("uninstall.sh"), dir.join("install.sh")).unwrap();
    assert!(bundle::stage(&dir, &manifest).is_err());
    for path in [
        "../escape",
        "/tmp/file",
        "a//b",
        "a/./b",
        "a/../b",
        "a\nb",
        "roots/2.json",
    ] {
        assert!(!bundle::safe_path(path));
    }
}

#[test]
fn private_state_refuses_corruption_permissions_symlinks_and_concurrent_writers() {
    let (_tmp, dir) = temp();
    let file = dir.join("state.json");
    crate::secure_store::write(&file, b"{}").unwrap();
    assert_eq!(crate::secure_store::read(&file, 32).unwrap(), b"{}");
    let _guard = crate::secure_store::lock(&dir).unwrap();
    assert!(crate::secure_store::lock(&dir).is_err());
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(crate::secure_store::read(&file, 32).is_err());
    assert!(crate::secure_store::write(&file, b"replacement").is_err());
    let link = dir.join("linked");
    symlink(&file, &link).unwrap();
    assert!(crate::secure_store::read(&link, 32).is_err());
}

#[test]
fn root_revocation_and_manifest_floor_survive_missing_release_payloads() {
    let (_tmp, dir) = temp();
    let state_dir = dir.join("trust");
    crate::secure_store::directory(&state_dir).unwrap();
    let source = dir.join("bundle");
    std::fs::create_dir_all(source.join("roots")).unwrap();
    let old = signer();
    let new = signer();
    let initial = TrustState {
        root: root(&old, 1),
        floor: Floor::default(),
    };
    crate::secure_store::write(
        &state_dir.join("trust.json"),
        &serde_json::to_vec(&initial).unwrap(),
    )
    .unwrap();
    std::fs::write(
        source.join("roots/2.json"),
        serde_json::to_vec(&signed(&root(&new, 2), &[&old, &new])).unwrap(),
    )
    .unwrap();
    // No manifest exists: learning a valid key revocation still persists it.
    assert!(prepare(&state_dir, &source, 1000).is_err());
    let read_state = || -> TrustState {
        serde_json::from_slice(
            &crate::secure_store::read(&state_dir.join("trust.json"), MAX_METADATA).unwrap(),
        )
        .unwrap()
    };
    assert_eq!(read_state().root.version, 2);
    assert!(model::verify(&signed(&manifest(), &[&old]), &read_state().root.releases).is_err());
    std::fs::write(
        source.join("manifest.json"),
        serde_json::to_vec(&signed(&manifest(), &[&new])).unwrap(),
    )
    .unwrap();
    // Payload files are absent, but the correctly signed manifest is known.
    assert!(prepare(&state_dir, &source, 1000).is_err());
    assert_eq!(read_state().floor.sequence, 10);
    let mut older = manifest();
    older.sequence = 9;
    std::fs::write(
        source.join("manifest.json"),
        serde_json::to_vec(&signed(&older, &[&new])).unwrap(),
    )
    .unwrap();
    assert!(prepare(&state_dir, &source, 1001).is_err());
    assert_eq!(read_state().floor.sequence, 10);
}
