#!/usr/bin/env python3
"""Notification-only updater regression tests; all credentials and services are fixtures."""
import http.server, json, os, plistlib, subprocess, sys, tempfile, threading, time
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent / "auto-update.sh"

class StatusServer:
    """Serves `payload`; once `marker` exists (the stub installer ran for this
    instance) it reports `after_version`, like a restarted daemon would. With
    `bearer` set, any other Authorization is refused."""
    def __init__(self, payload, marker=None, after_version=None, bearer=None):
        self.payload, self.marker, self.after_version, self.bearer = payload, marker, after_version, bearer
        handler = self._handler()
        self.httpd = http.server.HTTPServer(("127.0.0.1", 0), handler)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
    def _handler(s):
        class H(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                if s.bearer is not None and self.headers.get("Authorization") != f"Bearer {s.bearer}":
                    self.send_response(401); self.send_header("Content-Length", "0"); self.end_headers(); return
                payload = dict(s.payload)
                if s.marker is not None and s.after_version and Path(s.marker).exists():
                    payload["version"] = s.after_version
                body = json.dumps(payload).encode()
                self.send_response(200); self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
            def log_message(self, *a): pass
        return H
    @property
    def port(self): return self.httpd.server_port
    @property
    def url(self): return f"http://127.0.0.1:{self.port}/agent/status"
    def close(self): self.httpd.shutdown()

def write_plist(home, label, port, credential=("IPHONE_USE_AGENT_TOKEN", "t")):
    agents = Path(home) / "Library" / "LaunchAgents"
    agents.mkdir(parents=True, exist_ok=True)
    with open(agents / f"{label}.plist", "wb") as f:
        plistlib.dump({"Label": label, "EnvironmentVariables": {
            "IPHONE_USE_PORT": str(port), credential[0]: credential[1], "IPHONE_USE_HOST": "127.0.0.1"}}, f)

def run(latest, *args, home, installed_log, extra_env=None, status_url=None):
    env = dict(os.environ, HOME=home, IPHONE_USE_STATE_DIR=str(Path(home) / "state"),
               AUTO_UPDATE_LATEST_TAG=latest, AUTO_UPDATE_SETTLE_SECS="0",
               AUTO_UPDATE_INSTALLER_CMD=f"echo \"$AUTO_UPDATE_INSTANCE $IPHONE_USE_AUTO_UPDATE_JOB\" >> '{installed_log}'"
                                         f" && touch '{installed_log}.'\"$AUTO_UPDATE_INSTANCE\"",
               AUTO_UPDATE_SELF_URL=f"file://{Path(home) / 'nonexistent.sh'}",
               AUTO_UPDATE_PREBUILD_CMD=f"echo \"$AUTO_UPDATE_INSTANCE\" >> '{installed_log}.prebuilt'")
    if status_url:
        env.update(AUTO_UPDATE_STATUS_URL=status_url, AUTO_UPDATE_TOKEN="t")
    env.update(extra_env or {})
    p = subprocess.run(["bash", str(SCRIPT), "run", *args], env=env, capture_output=True, text=True, timeout=60)
    return p.returncode, p.stderr

def installed_instances(log):
    return [line.split()[0] for line in Path(log).read_text().splitlines()] if Path(log).exists() else []

def outcome(home):
    p = Path(home) / "state" / "auto-update-last.json"
    return json.loads(p.read_text()) if p.exists() else None

base = {"ok": True, "version": "0.5.4", "owner": None, "owner_lease_remaining_secs": 0,
        "hold_remaining_secs": 0, "releasing": False, "reconnecting": False, "device_state": "released",
        "viewer_count": 0, "mjpeg_viewer_count": 0, "idle_secs": 7200}
failures = 0
total = 0
def report(name, ok, detail):
    global failures, total
    total += 1
    print(("ok  " if ok else "FAIL"), name, "" if ok else detail)
    failures += not ok

def case(name, status_payload, latest, *args, expect_install, expect_decision, extra_env=None, expect_rc=0):
    with tempfile.TemporaryDirectory() as home:
        log = Path(home) / "installed"
        srv = StatusServer(status_payload, marker=f"{log}.default", after_version=latest.lstrip("v"))
        write_plist(home, "com.leeguoo.iphone-use", srv.port)
        try:
            rc, err = run(latest, *args, home=home, installed_log=log, extra_env=extra_env, status_url=srv.url)
        finally:
            srv.close()
        installed = bool(installed_instances(log))
        ok = (installed == expect_install) and (expect_decision in err) and rc == expect_rc
        report(name, ok, f"rc={rc} installed={installed} err={err.strip()[-200:]}")

case("up to date → skip", base, "v0.5.4", expect_install=False, expect_decision="skip:up_to_date")
for flags in [(), ("--force",), ("--reinstall",), ("--dry-run",)]:
    case(f"{flags or 'scheduled run'} only reports updates", base, "v0.6.0", *flags,
         expect_install=False, expect_decision="notification-only")
case("busy phone remains untouched", {**base, "owner": "fixture-agent"}, "v0.6.0",
     expect_install=False, expect_decision="skip:phone_owned")
case("older release never installs", base, "v0.5.3", expect_install=False, expect_decision="skip:up_to_date")
case("broken daemon remains untouched", {**base, "ok": False}, "v0.6.0",
     expect_install=False, expect_decision="skip:daemon_not_ok")

# Legacy command/URL hooks and expired signing records cannot trigger code,
# self-refresh, runner rebuilds or re-signing during a notification-only check.
with tempfile.TemporaryDirectory() as home:
    state = Path(home) / "state"; state.mkdir()
    installed = state / "auto-update.sh"; installed.write_text("#!/bin/bash\n# reviewed local copy\n")
    malicious = Path(home) / "remote.sh"; malicious.write_text("#!/bin/bash\nexit 99\n")
    (state / "app-signing.json").write_text(json.dumps({"expires_at": 1}))
    log = Path(home) / "installed"
    fakebin = Path(home) / "bin"; fakebin.mkdir()
    for name in ["iphone-use", "git"]:
        stub = fakebin / name
        stub.write_text(f"#!/bin/sh\ntouch '{home}/unexpected-{name}'\nexit 90\n")
        stub.chmod(0o755)
    servers = {n: StatusServer(base, bearer="t") for n in ["default", "ix"]}
    for name, srv in servers.items():
        label = "com.leeguoo.iphone-use" + ("" if name == "default" else f".{name}")
        write_plist(home, label, srv.port)
    try:
        rc, err = run("v0.6.0", "--force", home=home, installed_log=log, extra_env={
            "PATH": f"{fakebin}:{os.environ['PATH']}",
            "AUTO_UPDATE_INSTALLER_URL": f"file://{malicious}",
            "AUTO_UPDATE_SELF_URL": f"file://{malicious}",
        })
    finally:
        for srv in servers.values(): srv.close()
    report("all instances get notices without executing any update hook",
           rc == 0 and "update available [default]" in err and "update available [ix]" in err
           and not log.exists() and not Path(f"{log}.prebuilt").exists()
           and not (Path(home) / "unexpected-iphone-use").exists()
           and not (Path(home) / "unexpected-git").exists(), err)
    report("the updater cannot replace itself", installed.read_text() == "#!/bin/bash\n# reviewed local copy\n", installed.read_text())
    report("a check does not fabricate an installation outcome", outcome(home) is None, outcome(home))

with tempfile.TemporaryDirectory() as home:
    log = Path(home) / "installed"
    state = Path(home) / "state"; state.mkdir()
    (state / "auto-update.disabled").touch()
    srv = StatusServer(base, bearer="t")
    write_plist(home, "com.leeguoo.iphone-use", srv.port)
    try:
        rc, err = run("v0.6.0", home=home, installed_log=log)
        report("persistent opt-out stops scheduled checks", rc == 0 and "skip: disabled" in err, err)
        rc, err = run("v0.6.0", "--force", home=home, installed_log=log)
        report("--force never overrides execution safety", rc == 0 and "notification-only" in err and not log.exists(), err)
    finally: srv.close()

# A curl wrapper records argv only, while forwarding stdin to the real curl.
# Synthetic bearer values containing curl-config metacharacters must survive
# quoting yet never appear in argv. No user's credentials are read.
with tempfile.TemporaryDirectory() as home:
    import shutil
    curl = shutil.which("curl")
    fakebin = Path(home) / "bin"; fakebin.mkdir()
    argsfile = Path(home) / "curl-argv"
    wrapper = fakebin / "curl"
    wrapper.write_text(f"#!/bin/bash\nprintf '%s\\n' \"$@\" >> '{argsfile}'\nexec '{curl}' \"$@\"\n".replace('\"', '"'))
    wrapper.chmod(0o755)
    token = 'fixture-credential with spaces-"quoted"-\\tail'
    srv = StatusServer(base, bearer=token)
    write_plist(home, "com.leeguoo.iphone-use", srv.port, ("IPHONE_USE_AGENT_TOKEN", token))
    try:
        rc, err = run("v0.6.0", home=home, installed_log=Path(home)/"installed", extra_env={"PATH": f"{fakebin}:{os.environ['PATH']}"})
    finally: srv.close()
    args = argsfile.read_text() if argsfile.exists() else ""
    report("curl receives working credentials on stdin, not argv", rc == 0 and "notification-only" in err and "fixture-credential" not in args, f"rc={rc} err={err} argv={args}")

# Mock launchctl: never interact with the actual user's service manager.
for stuck in [False, True]:
    with tempfile.TemporaryDirectory() as home:
        fakebin=Path(home)/"bin"; fakebin.mkdir()
        launch=fakebin/"launchctl"
        launch.write_text("#!/bin/sh\ncase \"$1\" in print) exit " + ("0" if stuck else "1") + ";; *) exit 0;; esac\n")
        launch.chmod(0o755)
        job=Path(home)/"Library/LaunchAgents/com.leeguoo.iphone-use.autoupdate.plist"
        job.parent.mkdir(parents=True); job.write_text("fixture")
        env=dict(os.environ, HOME=home, IPHONE_USE_STATE_DIR=str(Path(home)/"state"), PATH=f"{fakebin}:{os.environ['PATH']}")
        p=subprocess.run(["bash", str(SCRIPT), "disable"], env=env, capture_output=True, text=True, timeout=10)
        marker=Path(home)/"state/auto-update.disabled"
        report(f"disable confirms job stop (stuck={stuck})",
               (p.returncode != 0) == stuck and job.exists() == stuck and marker.exists()
               and marker.stat().st_mode & 0o777 == 0o600, p.stderr)

text=SCRIPT.read_text()
report("no remote executable / main fallback remains", all(x not in text for x in ["bash -c", "| sh", "/main/install.sh", "refresh_self()", "resign_app()", "run_installer()"]), "unsafe updater code survived")
print("FAILED" if failures else "OK", f"({total-failures}/{total})")
sys.exit(1 if failures else 0)
