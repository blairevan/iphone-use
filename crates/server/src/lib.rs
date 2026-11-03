pub mod activity;
pub mod advice;
pub mod afc;
pub mod app_lookup;
pub mod apps;
pub mod boot;
pub mod browser_boundary;
pub mod collect;
pub mod config;
pub mod crash;
pub mod credentials;
pub mod device_identity;
pub mod flows;
pub mod focus;
pub mod guard;
pub mod h264sps;
pub mod home_layout;
pub mod http;
pub mod input_continuation;
pub mod instance;
pub mod keep_awake;
pub mod keep_runner;
pub mod locale;
pub mod location;
pub mod lock_readiness;
pub mod lockdown;
pub mod logcap;
pub mod login;
pub mod metrics;
pub mod mp4;
pub mod ocr;
pub mod pairing;
pub mod phone_daemon;
pub mod phone_exit;
pub mod prewarm;
pub mod protocol;
pub mod recording;
pub mod redaction;
pub mod relay_client;
pub mod release;
pub mod remote_access;
pub mod runner;
pub mod runner_token;
pub mod runtime_dir;
pub mod schedules;
pub mod scope;
pub mod scroll_progress;
pub mod secure_store;
pub mod security;
pub mod security_http;
pub mod setup;
pub mod simulator;
pub mod syslog;
pub mod telemetry;
pub mod text_input;
pub mod timing;
pub mod tunnel;
pub mod update;
pub mod usbmux;
pub mod video;

/// Re-export of the `core` crate under a non-`core` name.
///
/// Downstream integration-test crates that depend on `server` need the core
/// types but must NOT bring a dependency literally named `core` into their
/// extern prelude — doing so shadows the std `core` crate and breaks any
/// `core::`-emitting macro (e.g. `#[tokio::test]`). Reaching the core types
/// through this alias avoids that footgun.
pub use ::core as core_crate;
pub use iphone_use_mcp::safe_log;
pub mod observation;
