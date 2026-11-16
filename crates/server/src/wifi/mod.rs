//! Authenticated discovery and control when native Bonjour discovery is unavailable.

/// Construct a typed plist dictionary without an additional macro dependency.
#[cfg(target_os = "macos")]
macro_rules! dict {
    (dict { $($key:literal : $value:expr),* $(,)? }) => {{
        let mut values = plist::Dictionary::new();
        $(values.insert($key.into(), plist::Value::from($value));)*
        values
    }};
}
#[cfg(target_os = "macos")]
pub(super) use dict;

#[cfg(target_os = "macos")]
mod cache;
#[cfg(target_os = "macos")]
mod cli;
#[cfg(target_os = "macos")]
mod discovery;
#[cfg(target_os = "macos")]
mod dtx;
#[cfg(target_os = "macos")]
mod network;
#[cfg(target_os = "macos")]
mod pairing;
#[cfg(target_os = "macos")]
mod session;
#[cfg(target_os = "macos")]
mod xctest;

#[cfg(target_os = "macos")]
pub use cache::remember_url;
#[cfg(target_os = "macos")]
pub use cli::Options;
#[cfg(target_os = "macos")]
pub use pairing::{is_paired, remember};
#[cfg(target_os = "macos")]
pub use session::serve;

/// Pairing recovery runs on the Mac, never inside the daemon hosted on iOS.
#[cfg(not(target_os = "macos"))]
pub fn is_paired(_state: &std::path::Path, _udid: &str) -> bool {
    false
}

/// Normalize only valid physical device identifiers; never accept arbitrary cache paths.
pub fn normalized_udid(value: &str) -> Option<String> {
    let normalized: String = value.chars().filter(|c| *c != '-').collect();
    (normalized.len() >= 16
        && normalized.len() <= 40
        && normalized.bytes().all(|c| c.is_ascii_hexdigit()))
    .then(|| normalized.to_ascii_lowercase())
}
