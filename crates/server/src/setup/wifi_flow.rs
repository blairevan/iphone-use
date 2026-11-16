//! Native Wi-Fi worker lifecycle within the existing setup supervisor.

use super::*;

/// Recognize only the worker's fixed finish marker, never a generic transport error.
pub(super) fn explicitly_finished(path: &std::path::Path) -> bool {
    std::fs::read_to_string(path).is_ok_and(|text| {
        text.lines()
            .any(|line| line == "wireless XCTest ended: _XCT_didFinishExecutingTestPlan")
    })
}

impl Setup {
    /// Preserve the Runner's local address in its network profile after ARP expiry.
    pub(super) fn remember_wifi_address(&self, url: &str) {
        #[cfg(target_os = "macos")]
        if self.paired_wifi_available()
            && crate::wifi::remember_url(self.ctx.state_dir(), &self.ctx.udid, url).is_err()
        {
            warn("could not remember the Runner's local address for this network");
        }
        #[cfg(not(target_os = "macos"))]
        let _ = url;
    }

    /// USB-only policy always wins over stored wireless trust.
    pub(super) fn paired_wifi_available(&self) -> bool {
        self.ctx.wifi_tunnel_allowed()
            && crate::wifi::is_paired(self.ctx.state_dir(), &self.ctx.udid)
    }

    /// Create independent wireless trust on USB without affecting normal setup success.
    pub(super) fn remember_wifi(&self) {
        if !cfg!(target_os = "macos")
            || !self.ctx.wifi_tunnel_allowed()
            || self.paired_wifi_available()
        {
            return;
        }
        let Ok(program) = std::env::current_exe() else {
            return;
        };
        let state = self.ctx.state_dir().to_string_lossy().into_owned();
        let (_, success) = sys::run_bounded(
            &program.to_string_lossy(),
            &[
                "wifi-native",
                "remember",
                "--udid",
                &self.ctx.udid,
                "--state-dir",
                &state,
            ],
            Duration::from_secs(30),
        );
        if success {
            ok("paired Wi-Fi recovery identity saved");
        } else {
            warn("Wi-Fi recovery pairing was unavailable; USB setup continues");
        }
    }

    /// Stop only the PID- and argv-verified transport processes owned by this instance.
    pub(super) fn stop_transport(&self) -> Step {
        for (file, legacy, role) in [
            (
                &self.ctx.mjpeg_relay_pid_file,
                &self.legacy.mjpeg,
                Role::Mjpeg,
            ),
            (&self.ctx.relay_pid_file, &self.legacy.relay, Role::Relay),
            (&self.ctx.runner_pid_file, &self.legacy.runner, Role::Runner),
        ] {
            if !pid::stop(&self.ctx, file, legacy, role) {
                return die("cannot safely identify the previous transport process");
            }
        }
        Ok(())
    }

    /// Recover an installed Runner, waiting for signed readiness before publishing success.
    pub(super) fn start_direct_wifi(&mut self) -> Step {
        if crate::phone_exit::parked(self.ctx.state_dir()) {
            return die("the phone is parked; resume it before Wi-Fi recovery");
        }
        self.legacy = Legacy::new(&self.ctx, &self.ctx.team_id, &self.ctx.bundle_id);
        let target = format!("http://127.0.0.1:{}", self.ctx.runner_port);
        let key = runner::recorded_key(&self.ctx);
        if !self.ctx.keepalive {
            let Some(key) = key else {
                return die("wireless recovery needs a previously installed runner; complete USB setup once");
            };
            if !self.stage_supervisor() {
                return die("could not stage the Wi-Fi recovery supervisor");
            }
            let daemon = self.configure_daemon(&target)?;
            self.handoff(&target, &key)?;
            self.verify_product(&daemon)?;
            self.commit_setup();
            return Ok(());
        }
        let live = pid::validate(
            &self.ctx,
            &self.ctx.runner_pid_file,
            &self.legacy.runner,
            Role::Runner,
            false,
        )
        .is_some();
        if live && !owner::overridden(&self.ctx) {
            if let Some(lease) =
                owner::foreign(owner::current(&self.ctx), owner::caller().as_deref())
            {
                self.failure_kind = Kind::Owned;
                return die(owner::refusal(&lease, &self.ctx));
            }
        }
        self.stop_transport()?;
        let program = std::env::current_exe().map_err(|_| Exit(1))?;
        let args = vec![
            "wifi-native".into(),
            "serve".into(),
            "--udid".into(),
            self.ctx.udid.clone(),
            "--state-dir".into(),
            self.ctx.state_dir().to_string_lossy().into_owned(),
            "--runner-port".into(),
            self.ctx.runner_port.clone(),
            "--mjpeg-port".into(),
            self.ctx.mjpeg_port.clone(),
            "--bundle-id".into(),
            legacy_ios::runner_bundle(&self.ctx.bundle_id),
        ];
        if program.to_string_lossy().chars().any(char::is_whitespace)
            || args.iter().any(|a| a.chars().any(char::is_whitespace))
        {
            return die("Wi-Fi worker paths cannot contain whitespace");
        }
        crate::runner_token::rotate(self.ctx.state_dir()).map_err(|_| Exit(1))?;
        self.phase(
            "launching",
            "",
            "locating the paired iPhone over encrypted Wi-Fi",
        );
        self.runner_log_mark = 0;
        let mut env = self.phone_daemon_env("")?;
        env.push(self.ctx.exit_notice_env(""));
        let env: Vec<_> = env
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str()))
            .collect();
        let child = proc::spawn_detached_env(&program, &args, None, &self.ctx.run_log, None, &env)
            .map_err(|_| Exit(1))?;
        let signature = format!("{} {}", program.display(), args.join(" "));
        for (file, role, prefix) in [
            (&self.ctx.runner_pid_file, Role::Runner, "runner"),
            (&self.ctx.relay_pid_file, Role::Relay, "relay"),
            (&self.ctx.mjpeg_relay_pid_file, Role::Mjpeg, "mjpeg"),
        ] {
            if pid::write(
                &self.ctx,
                file,
                child,
                &format!("{prefix}:{signature}"),
                role,
            )
            .is_none()
            {
                // This is our freshly spawned child, not a PID read from disk.
                let _ = std::process::Command::new("/bin/kill")
                    .args(["-TERM", &child.to_string()])
                    .status();
                return die("could not record the native Wi-Fi worker identity");
            }
        }
        self.started_runner = true;
        self.started_control = true;
        self.started_mjpeg = true;
        self.failure_kind = Kind::NotConnected;
        let deadline = Instant::now() + Duration::from_secs(100);
        loop {
            proc::check()?;
            if crate::phone_exit::parked(self.ctx.state_dir()) {
                self.stop_transport()?;
                return die("phone was parked during Wi-Fi recovery");
            }
            if explicitly_finished(&self.ctx.run_log)
                || (runner::log_shows_automation_revoked(&self.ctx.run_log, 0)
                    && !self.endpoint_locked())
            {
                return self.park_on_phone(crate::phone_exit::Reason::Exited);
            }
            if !sys::pid_exists(child) {
                return die("native Wi-Fi recovery failed; inspect runner log or reconnect USB");
            }
            if let Some((200, body)) = sys::runner_get(
                &format!("{target}/status"),
                Duration::from_secs(2),
                &self.ctx.runner_auth(),
            ) {
                let ready = serde_json::from_slice::<serde_json::Value>(&body)
                    .ok()
                    .and_then(|data| {
                        data.pointer("/value/ready")
                            .and_then(serde_json::Value::as_bool)
                    });
                if ready == Some(true) {
                    break;
                }
            }
            if Instant::now() >= deadline {
                return die("paired Wi-Fi recovery timed out; keep the iPhone unlocked on this LAN or reconnect USB");
            }
            proc::sleep(Duration::from_millis(300))?;
        }
        self.verify_supervision(&target)?;
        self.phone_url = target.clone();
        let daemon = self.configure_daemon(&target)?;
        self.verify_product(&daemon)?;
        if let (Some(run), Some(key)) = (&self.run, key) {
            run.product_key(&key);
        }
        self.commit_setup();
        self.phase(
            "ready",
            "",
            "paired Wi-Fi Runner and signed readiness verified",
        );
        ok("paired iPhone automatically connected over encrypted Wi-Fi");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Transport/bootstrap failures remain retryable; explicit test completion does not.
    #[test]
    fn only_explicit_wireless_finish_parks() -> anyhow::Result<()> {
        let log = tempfile::NamedTempFile::new()?;
        for text in [
            "DTX reader closed\n",
            "wireless XCTest ended: _XCT_didFailToBootstrapWithError:\n",
            "previous: wireless XCTest ended: _XCT_didFinishExecutingTestPlan\n",
        ] {
            std::fs::write(log.path(), text)?;
            assert!(!explicitly_finished(log.path()));
        }
        std::fs::write(
            log.path(),
            "wireless XCTest ended: _XCT_didFinishExecutingTestPlan\n",
        )?;
        assert!(explicitly_finished(log.path()));
        Ok(())
    }
}
