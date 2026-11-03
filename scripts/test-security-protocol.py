#!/usr/bin/env python3
"""Exercise the real daemon through loopback HTTP and a verified TLS terminator.

Uses isolated HOME/state, synthetic credentials and a temporary test CA trusted
only by this Python client. No phone, launchd job, system trust or user Keychain
is touched. This is a protocol integration test, not physical-device evidence.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import http.client
import http.server
import json
import os
from pathlib import Path
import secrets
import signal
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import base64


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """Expose login status and cookies rather than silently following 303."""

    def redirect_request(self, request, fp, code, message, headers, new_url):
        return None


class Proxy(http.server.BaseHTTPRequestHandler):
    """Synthetic TLS terminator that overwrites, never trusts, forwarding data."""

    backend_port: int
    protocol_version = "HTTP/1.1"

    def log_message(self, *_):
        pass

    def forward(self):
        length = int(self.headers.get("Content-Length", "0"))
        if length > 1 << 20:
            self.send_error(413)
            return
        body = self.rfile.read(length) if length else None
        headers = {key: value for key, value in self.headers.items()
                   if key.lower() not in {"connection", "content-length", "forwarded", "x-real-ip"}
                   and not key.lower().startswith(("x-forwarded-", "x-iphone-use-"))}
        headers["X-Forwarded-Proto"] = "https"
        headers["X-Real-IP"] = self.client_address[0]
        connection = http.client.HTTPConnection("127.0.0.1", self.backend_port, timeout=10)
        try:
            connection.request(self.command, self.path, body=body, headers=headers)
            response = connection.getresponse()
            data = response.read()
            self.send_response(response.status)
            for key, value in response.getheaders():
                if key.lower() not in {"connection", "transfer-encoding", "content-length"}:
                    self.send_header(key, value)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        finally:
            connection.close()

    do_GET = forward
    do_POST = forward


def free_port() -> int:
    """Reserve a currently unused loopback port for a short-lived test daemon."""
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def stop(process: subprocess.Popen | None) -> None:
    """Always reap the owned test process group, including on failed assertions."""
    if process is None or process.poll() is not None:
        return
    os.killpg(process.pid, signal.SIGTERM)
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        process.wait(timeout=5)


def run(binary: Path) -> list[str]:
    """Run all protocol assertions without publishing any synthetic credential."""
    passed: list[str] = []
    with tempfile.TemporaryDirectory(prefix="iphone-security-protocol-") as temporary:
        root = Path(temporary).resolve()
        home = root / "home"
        home.mkdir(mode=0o700)
        (home / "state").mkdir(mode=0o700)
        certificate = root / "test-cert.pem"
        key = root / "test-key.pem"
        config = root / "test-cert.cnf"
        config.write_text("[req]\nprompt=no\ndistinguished_name=dn\nx509_extensions=v3\n"
                          "[dn]\nCN=localhost\n[v3]\nsubjectAltName=DNS:localhost\n"
                          "basicConstraints=critical,CA:TRUE\nkeyUsage=critical,digitalSignature,keyEncipherment,keyCertSign\n")
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                        "-config", str(config), "-keyout", str(key), "-out", str(certificate)],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        key.chmod(0o600)
        port = free_port()
        Proxy.backend_port = port
        proxy = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Proxy)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certificate, key)
        proxy.socket = context.wrap_socket(proxy.socket, server_side=True)
        thread = threading.Thread(target=proxy.serve_forever, daemon=True)
        thread.start()
        public = f"https://localhost:{proxy.server_port}/fixture"
        local = f"http://127.0.0.1:{port}"
        trusted_context = ssl.create_default_context(cafile=str(certificate))
        client = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(),
                                            urllib.request.HTTPSHandler(context=trusted_context))
        password, token = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        # Do not inherit provider API keys, proxy secrets or other project
        # configuration into the isolated fixture daemon.
        env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LANG": "en_US.UTF-8"}
        env.update(HOME=str(home), TMPDIR=str(home / "state"), CI="1", TOKIO_WORKER_THREADS="2", IPHONE_USE_INSTANCE="security-protocol",
                   IPHONE_USE_STATE_DIR=str(home / "state"), IPHONE_USE_HOST="127.0.0.1",
                   IPHONE_USE_PORT=str(port), IPHONE_USE_PASSWORD=password, IPHONE_USE_AGENT_TOKEN=token,
                   IPHONE_USE_RUNNER_MANAGED="false", IPHONE_USE_RUNNER_URL="http://127.0.0.1:1",
                   IPHONE_USE_RUNNER_MJPEG_URL="http://127.0.0.1:1", IPHONE_USE_REMOTE_ACCESS="1",
                   IPHONE_USE_PUBLIC_URL=public, IPHONE_USE_BASE_PATH="/fixture", IPHONE_USE_TRUSTED_PROXY_IPS="127.0.0.1",
                   IPHONE_USE_FLOWS_NO_AUTO_UPDATE="1", RUST_LOG="trace")
        process = None
        log = root / "daemon.log"

        def call(path, *, secure=True, body=None, headers=None, raw=None):
            """Return non-2xx responses as data, preserving authentication headers."""
            values = dict(headers or {})
            if body is not None:
                raw = json.dumps(body).encode()
                values["Content-Type"] = "application/json"
            request = urllib.request.Request((public if secure else local) + path,
                                             data=raw, headers=values)
            try:
                response = client.open(request, timeout=10)
            except urllib.error.HTTPError as error:
                response = error
            with response:
                data = response.read()
                try:
                    payload = json.loads(data)
                except (ValueError, UnicodeDecodeError):
                    payload = None
                return response.status, response.headers, payload

        def start():
            """Start a real binary and require an authenticated readiness response."""
            with log.open("ab") as output:
                child = subprocess.Popen([str(binary), "serve"], env=env, stdout=output,
                                         stderr=subprocess.STDOUT, start_new_session=True)
            try:
                for _ in range(100):
                    if child.poll() is not None:
                        raise AssertionError("test daemon exited before readiness")
                    try:
                        if call("/agent/status", secure=False, headers={"Authorization": "Bearer " + token})[0] == 200:
                            return child
                    except OSError:
                        pass
                    time.sleep(0.1)
                raise AssertionError("test daemon did not become ready")
            except BaseException:
                stop(child)
                raise

        try:
            process = start()
            passed.append("authenticated real loopback daemon starts without a phone")
            try:
                untrusted = urllib.request.build_opener(urllib.request.ProxyHandler({}))
                untrusted.open(public + "/login", timeout=3)
                raise AssertionError("untrusted certificate was accepted")
            except urllib.error.URLError:
                pass
            passed.append("untrusted TLS identity is rejected without insecure client flags")
            status, headers, _ = call("/login", raw=urllib.parse.urlencode({"password": password}).encode(),
                                      headers={"Content-Type": "application/x-www-form-urlencoded"})
            assert status == 303, "TLS login failed"
            cookie = headers["Set-Cookie"].split(";", 1)[0]
            assert "Secure" in headers["Set-Cookie"] and "HttpOnly" in headers["Set-Cookie"]
            auth = {"Cookie": cookie, "X-Phone-Control": "1"}
            passed.append("HTTPS login preserves secure HttpOnly session cookies and base paths")
            assert call("/pair/new", body={}, headers={**auth, "Origin": "https://unrelated.invalid"})[0] == 403
            passed.append("cross-origin requests cannot reuse a valid session")
            status, _, pair = call("/pair/new", body={}, headers=auth)
            assert status == 200 and pair["url"].startswith(public + "/pair?c=")
            code = urllib.parse.parse_qs(urllib.parse.urlsplit(pair["url"]).query)["c"][0]
            status, paired_headers, paired = call("/pair", body={"code": code})
            assert status == 200
            device_cookie = paired_headers["Set-Cookie"].split(";", 1)[0]
            assert call("/pair", body={"code": code})[0] == 401
            passed.append("HTTPS QR pairing codes redeem exactly once")
            nonce = secrets.token_urlsafe(24)
            query = urllib.parse.urlencode({"n": nonce, "u": public})
            status, _, proof = call("/pair/probe?" + query)
            proof_key = base64.urlsafe_b64decode(paired["lan_key"] + "==")
            expected = base64.urlsafe_b64encode(hmac.new(proof_key,
                f"iphone-use-route-v2\n{nonce}\n{public}".encode(), hashlib.sha256).digest()).decode().rstrip("=")
            assert status == 200 and hmac.compare_digest(proof["proof"], expected)
            other = urllib.parse.urlencode({"n": nonce, "u": "https://unrelated.invalid"})
            assert call("/pair/probe?" + other)[0] == 403
            passed.append("identity proof binds the exact configured HTTPS origin and path")
            for _ in range(8):
                call("/pair", body={"code": "invalid"})
            assert call("/agent/status", headers={"Authorization": "Bearer " + token})[0] == 200
            assert call("/pair", body={"device_token": paired["device_token"]})[0] == 200
            passed.append("anonymous pairing failures do not block valid agents or renewal")
            status, _, issued = call("/agent/security/credentials", headers=auth,
                body={"action": "create_agent", "admin_password": password, "name": "fixture-readonly", "scope": "read"})
            assert status == 200
            read_token = issued["token"]
            reader = {"Authorization": "Bearer " + read_token, "X-Phone-Control": "1"}
            assert call("/agent/status", headers=reader)[0] == 200
            assert call("/agent/input", headers=reader, body={"type": "tap", "x": 0.5, "y": 0.5})[0] == 403
            passed.append("issued read-only agents cannot mutate the phone")
            status, _, identity = call("/agent/security/session", headers={"Cookie": device_cookie})
            assert status == 200
            device_id = identity["credential"]["id"]
            assert call("/agent/security/credentials", headers=auth, body={"action": "revoke",
                "admin_password": password, "id": device_id})[0] == 200
            assert call("/agent/status", headers={"Cookie": device_cookie})[0] == 401
            assert call("/pair", body={"device_token": paired["device_token"]})[0] in (401, 429)
            assert call("/agent/status", headers=reader)[0] == 200
            passed.append("device revocation rejects both existing sessions and renewal without revoking another agent")
            stop(process)
            process = start()
            assert call("/agent/status", headers={"Cookie": device_cookie})[0] == 401
            assert call("/agent/status", headers=reader)[0] == 200
            passed.append("revocation and per-agent credentials survive a daemon restart")
            stop(process)
            process = None
            log_bytes = log.read_bytes()
            for secret in (password, token, read_token, cookie, paired["device_token"]):
                assert secret.encode() not in log_bytes, "credential reached operational logs"
            passed.append("trace-level operational logs do not contain credentials")
        finally:
            stop(process)
            proxy.shutdown()
            proxy.server_close()
            thread.join(timeout=5)
    return passed


def main() -> None:
    """Save a machine-readable test receipt without secrets or ephemeral paths."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--daemon", type=Path, required=True)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    passed = run(args.daemon.resolve(strict=True))
    for name in passed:
        print("PASS: " + name)
    if args.report:
        args.report.write_text(json.dumps({"passed": len(passed), "checks": passed,
            "boundary": "real loopback HTTP/TLS; no physical phone or production trust configuration"}, indent=2) + "\n")


if __name__ == "__main__":
    main()
