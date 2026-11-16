//! Optional primary-phone selection after renaming the legacy default instance.

#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
use std::path::Path;

/// Validate the private marker's single instance name; reject ambiguous input.
pub fn parse_name(text: &str) -> Result<String, String> {
    let name = text.strip_suffix('\n').unwrap_or(text);
    let first = name.as_bytes().first().copied();
    let reserved = [
        "default",
        "runner",
        "wda",
        "autoupdate",
        "daily-maintenance",
        "flow-reverify",
    ];
    if !first.is_some_and(|value| value.is_ascii_lowercase())
        || name.len() > 32
        || !name
            .bytes()
            .all(|value| value.is_ascii_lowercase() || value.is_ascii_digit() || value == b'-')
        || reserved.contains(&name)
    {
        return Err("invalid ~/.iphone-use/primary-instance; expected a named instance".into());
    }
    Ok(name.to_owned())
}

/// Read a user-owned private marker, failing closed on unsafe or corrupt files.
#[cfg(unix)]
pub fn read_at(home: &Path) -> Result<Option<String>, String> {
    let path = home.join(".iphone-use/primary-instance");
    let meta = match std::fs::symlink_metadata(&path) {
        Ok(meta) => meta,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("read primary instance: {error}")),
    };
    let owner = std::fs::metadata(home)
        .map_err(|error| error.to_string())?
        .uid();
    let canonical_home = home.canonicalize().map_err(|error| error.to_string())?;
    let canonical = path.canonicalize().map_err(|error| error.to_string())?;
    if !meta.is_file()
        || meta.file_type().is_symlink()
        || meta.uid() != owner
        || meta.mode() & 0o077 != 0
        || meta.len() > 33
        || canonical != canonical_home.join(".iphone-use/primary-instance")
    {
        return Err(
            "primary instance must be a private owned regular file without symlinks".into(),
        );
    }
    let text = std::fs::read_to_string(path).map_err(|error| error.to_string())?;
    parse_name(&text).map(Some)
}

/// A remote MCP client on non-Unix hosts has no local macOS primary selection.
#[cfg(not(unix))]
pub fn read_at(_home: &Path) -> Result<Option<String>, String> {
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Named selections are accepted with one optional terminal newline.
    #[test]
    fn accepts_named_primary() -> Result<(), String> {
        assert_eq!(parse_name("i16\n")?, "i16");
        assert_eq!(parse_name("office-phone")?, "office-phone");
        Ok(())
    }

    /// Unsafe marker contents must never silently select the legacy default.
    #[test]
    fn rejects_ambiguous_names() {
        for name in [
            "", "default", "runner", "../i16", " i16", "i16\n\n", "i16\r\n", "I16", "i/16",
        ] {
            assert!(parse_name(name).is_err(), "accepted {name:?}");
        }
    }

    /// Read only owned private regular files, including through parent paths.
    #[cfg(unix)]
    #[test]
    fn rejects_unsafe_marker_files() -> Result<(), String> {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let suffix = getrandom::u64().map_err(|error| error.to_string())?;
        let root =
            std::env::temp_dir().join(format!("iphone-primary-{}-{suffix}", std::process::id()));
        let execute = || -> Result<(), String> {
            std::fs::create_dir_all(root.join(".iphone-use")).map_err(|error| error.to_string())?;
            assert_eq!(read_at(&root)?, None);
            let path = root.join(".iphone-use/primary-instance");
            std::fs::write(&path, "i16\n").map_err(|error| error.to_string())?;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
                .map_err(|error| error.to_string())?;
            assert_eq!(read_at(&root)?, Some("i16".into()));
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))
                .map_err(|error| error.to_string())?;
            assert!(read_at(&root).is_err());
            std::fs::remove_file(&path).map_err(|error| error.to_string())?;
            symlink("../other", &path).map_err(|error| error.to_string())?;
            assert!(read_at(&root).is_err());
            Ok(())
        };
        let result = execute();
        std::fs::remove_dir_all(&root).map_err(|error| error.to_string())?;
        result
    }
}
