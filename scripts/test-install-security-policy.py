#!/usr/bin/env python3
"""Exercise installer migration preflight with isolated plists; no system writes."""
from pathlib import Path
import json
import os
import plistlib
import subprocess
import tempfile


def main() -> None:
    """Keep old services untouched when new network policy cannot be satisfied."""
    source = (Path(__file__).resolve().parents[1] / "install.sh").read_text()
    start = source.index("preflight_remote_migration() {\n")
    end = source.index("\n}\n", start) + 3
    function = source[start:end]
    credentials = {"IPHONE_USE_PASSWORD": "fixture human password", "IPHONE_USE_AGENT_TOKEN": "fixture-agent"}
    cases = [
        ("new install is local", {}, None, True),
        ("IPv6 loopback remains local", {"IPHONE_USE_HOST": "::1"}, None, True),
        ("old wildcard cannot silently remain exposed", {**credentials, "IPHONE_USE_HOST": "0.0.0.0"}, None, False),
        ("remote opt-in alone does not provide TLS", {**credentials, "IPHONE_USE_HOST": "0.0.0.0", "IPHONE_USE_REMOTE_ACCESS": "1"}, None, False),
        ("HTTP public entry is refused", {**credentials, "IPHONE_USE_REMOTE_ACCESS": "1", "IPHONE_USE_PUBLIC_URL": "http://control.example"}, None, False),
        ("reviewed HTTPS configuration passes", {**credentials, "IPHONE_USE_REMOTE_ACCESS": "1", "IPHONE_USE_PUBLIC_URL": "https://control.example/one"}, None, True),
        ("plaintext proxy hops are refused", {**credentials, "IPHONE_USE_REMOTE_ACCESS": "1", "IPHONE_USE_PUBLIC_URL": "https://control.example", "IPHONE_USE_TRUSTED_PROXY_IPS": "192.0.2.2"}, None, False),
        ("identical human and agent credentials are refused", {"IPHONE_USE_PASSWORD": "same", "IPHONE_USE_AGENT_TOKEN": "same", "IPHONE_USE_REMOTE_ACCESS": "1", "IPHONE_USE_RELAY_URL": "https://relay.example"}, None, False),
        ("disabled profile overrides legacy exposure", {"IPHONE_USE_HOST": "0.0.0.0"}, {"version": 1, "enabled": False, "public_url": None, "relay_url": None, "trusted_proxy_ips": []}, True),
        ("saved verified profile survives reinstall", credentials, {"version": 1, "enabled": True, "public_url": "https://control.example/one", "relay_url": None, "trusted_proxy_ips": ["127.0.0.1"]}, True),
        ("disabled profile cannot carry an active relay", credentials, {"version": 1, "enabled": False, "public_url": None, "relay_url": "https://relay.example", "trusted_proxy_ips": []}, False),
    ]
    for name, settings, profile, expected in cases:
        with tempfile.TemporaryDirectory(prefix="iphone-migration-policy-") as temporary:
            home = Path(temporary).resolve()
            old = home / "old.plist"
            old.write_bytes(plistlib.dumps({"EnvironmentVariables": settings}))
            if profile is not None:
                state = home / ".iphone-use"
                state.mkdir(mode=0o700)
                path = state / "remote.json"
                path.write_text(json.dumps(profile))
                path.chmod(0o600)
            before = old.read_bytes()
            env = {"HOME": str(home), "PATH": os.environ["PATH"], "INSTANCE_NAME": "default"}
            result = subprocess.run(["/bin/bash", "-c", function + '\npreflight_remote_migration "$1"',
                                     "fixture", str(old)], env=env, capture_output=True, text=True, timeout=10)
            assert (result.returncode == 0) == expected, name
            assert old.read_bytes() == before, "preflight changed the old installation"
            assert not (home / ".iphone-use/auto-update.disabled").exists()
            print("PASS: " + name)


if __name__ == "__main__":
    main()
