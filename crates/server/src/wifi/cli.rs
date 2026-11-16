//! Internal worker CLI shared by setup and local transport diagnostics.

use anyhow::{bail, Result};
use std::path::PathBuf;

/// A fixed operation prevents the worker from accepting arbitrary remote commands.
#[derive(Clone, clap::ValueEnum)]
enum Action {
    Remember,
    Serve,
}

/// The worker deliberately has no user-supplied IP: trust determines the endpoint.
#[derive(clap::Args)]
pub struct Options {
    /// Bootstrap USB trust or serve an already paired device over Wi-Fi.
    action: Action,
    /// The configured physical target, with or without its dash.
    #[arg(long)]
    udid: String,
    /// Private per-instance identity and token storage.
    #[arg(long)]
    state_dir: PathBuf,
    /// Mac loopback control port.
    #[arg(long, default_value_t = 8100)]
    runner_port: u16,
    /// Mac loopback video port.
    #[arg(long, default_value_t = 9100)]
    mjpeg_port: u16,
    /// An installed XCTest host, never an app supplied by discovery.
    #[arg(long, default_value = "")]
    bundle_id: String,
}

impl Options {
    /// Run protocol work on one thread with all dependency protocol logging suppressed.
    pub fn run(self) -> Result<()> {
        if super::normalized_udid(&self.udid).is_none() || !self.state_dir.is_absolute() {
            bail!("Wi-Fi recovery requires a valid target UDID and an absolute private state directory");
        }
        if matches!(self.action, Action::Serve)
            && (self.runner_port == 0
                || self.mjpeg_port == 0
                || self.runner_port == self.mjpeg_port
                || !self.bundle_id.ends_with(".xctrunner"))
        {
            bail!("Wi-Fi serving requires distinct nonzero loopback ports and an installed .xctrunner bundle");
        }
        if crate::phone_exit::parked(&self.state_dir) {
            bail!("the phone is parked; resume before wireless recovery");
        }
        let _quiet = tracing::subscriber::set_default(tracing::subscriber::NoSubscriber::default());
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        runtime.block_on(async {
            match self.action {
                Action::Remember => super::remember(&self.state_dir, &self.udid).await,
                Action::Serve => {
                    super::serve(
                        &self.state_dir,
                        &self.udid,
                        self.runner_port,
                        self.mjpeg_port,
                        &self.bundle_id,
                    )
                    .await
                }
            }
        })
    }
}
