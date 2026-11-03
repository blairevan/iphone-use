#!/usr/bin/env python3
"""Release metadata CLI tests using public/synthetic bytes, never a private key."""
import base64
import hashlib
import json
from pathlib import Path
import plistlib
import subprocess
import sys
import tempfile

TOOL = Path(__file__).resolve().with_name("release-bundle.py")


def invoke(*args, success=True):
    """Assert the CLI outcome without writing outside the test directory."""
    result = subprocess.run([sys.executable, "-I", str(TOOL), *map(str, args)],
                            capture_output=True, text=True, timeout=10)
    assert (result.returncode == 0) == success, result.stderr


def main():
    """Check exact signing bytes, distinct-key policy, inventory and safe writes."""
    with tempfile.TemporaryDirectory(prefix="iphone-release-metadata-") as temporary:
        root = Path(temporary)
        public = root / "public.raw"
        public.write_bytes(bytes(range(32)))
        key_id = hashlib.sha256(public.read_bytes()).hexdigest()
        payload = root / "root.json"
        options = ["root", "--root-key", public, "--release-key", public,
                   "--version", "1", "--expires", "2000000000", "--output", payload]
        invoke(*options)
        data = json.loads(payload.read_bytes())
        assert data["root"]["keys"] == {key_id: base64.b64encode(public.read_bytes()).decode()}
        print("PASS: public keys are identified by content, not filenames")
        before = payload.read_bytes()
        invoke(*options, success=False)
        assert payload.read_bytes() == before
        print("PASS: existing metadata cannot be overwritten")
        invoke("root", "--root-key", public, "--root-key", public, "--release-key", public,
               "--root-threshold", "2", "--version", "1", "--expires", "2000000000",
               "--output", root / "duplicate.json", success=False)
        assert not (root / "duplicate.json").exists()
        print("PASS: repeated public keys cannot satisfy a multisignature threshold")
        signing_input = root / "to-sign"
        invoke("signing-input", payload, "--output", signing_input)
        assert signing_input.read_bytes() == b"iphone-use-release-metadata-v1\0" + before
        print("PASS: signing input is domain-separated exact payload bytes")
        signature = root / "signature.raw"
        signature.write_bytes(b"synthetic-not-a-valid-signature".ljust(64, b"-"))
        envelope = root / "envelope.json"
        invoke("envelope", payload, "--signature", f"{public}:{signature}", "--output", envelope)
        wrapped = json.loads(envelope.read_bytes())
        assert base64.b64decode(wrapped["payload"]) == before
        assert base64.b64decode(wrapped["signatures"][key_id]) == signature.read_bytes()
        signature.write_bytes(b"invalid-length")
        invoke("envelope", payload, "--signature", f"{public}:{signature}", "--output", root / "bad.json", success=False)
        print("PASS: envelope preserves signatures without pretending to verify or sign them")
        bundle = root / "bundle"
        info = bundle / "iPhoneUse.app/Contents/Info.plist"
        info.parent.mkdir(parents=True)
        info.write_bytes(plistlib.dumps({"CFBundleShortVersionString": "1.2.3"}))
        installer = bundle / "install.sh"
        installer.write_text("#!/bin/sh\nexit 0\n")
        installer.chmod(0o700)
        args = ["manifest", bundle, "--version", "1.2.3", "--sequence", "1",
                "--commit", "1" * 40, "--expires", "2000000000", "--platform", "aarch64-apple-darwin"]
        manifest = root / "manifest-payload.json"
        invoke(*args, "--output", manifest)
        inventory = json.loads(manifest.read_bytes())["files"]
        assert inventory["install.sh"]["sha256"] == hashlib.sha256(installer.read_bytes()).hexdigest()
        assert inventory["install.sh"]["executable"] is True
        print("PASS: manifest binds file bytes and executable intent to the app version")
        (bundle / "linked.sh").symlink_to(installer)
        invoke(*args, "--output", root / "linked.json", success=False)
        (bundle / "linked.sh").unlink()
        info.write_bytes(plistlib.dumps({"CFBundleShortVersionString": "1.2.2"}))
        invoke(*args, "--output", root / "mismatch.json", success=False)
        print("PASS: links and relabeled application versions are rejected")


if __name__ == "__main__":
    main()
