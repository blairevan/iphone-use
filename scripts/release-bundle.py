#!/usr/bin/env python3
"""Prepare exact-byte release metadata for an independently managed offline signer.

This tool neither creates private keys nor downloads, signs or installs software.
Sign the emitted signing-input with Ed25519 in the release signing environment,
then combine the raw 64-byte signatures with their raw 32-byte public keys.
"""

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import stat
import sys

DOMAIN = b"iphone-use-release-metadata-v1\0"
MAX_METADATA = 2 * 1024 * 1024


def read_regular(path: Path, limit: int) -> bytes:
    """Read a bounded regular descriptor without following its final symlink."""
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as source:
        meta = os.fstat(source.fileno())
        if not stat.S_ISREG(meta.st_mode) or meta.st_size > limit:
            raise ValueError("expected a bounded regular file")
        data = source.read(limit + 1)
        if len(data) > limit:
            raise ValueError("file grew beyond its size limit")
        return data


def output(path: Path, data: bytes) -> None:
    """Create metadata without overwriting existing files or emitting key bytes."""
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), "wb") as target:
        target.write(data)
        target.flush()
        os.fsync(target.fileno())


def json_bytes(value: object) -> bytes:
    """Serialize once; the signer and verifier use these exact bytes."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def key_policy(paths: list[Path], threshold: int) -> dict:
    """Identify distinct public keys by SHA-256; no filenames are identities."""
    keys = {}
    for path in paths:
        public = read_regular(path, 32)
        if len(public) != 32:
            raise ValueError("Ed25519 public keys must contain exactly 32 raw bytes")
        keys[hashlib.sha256(public).hexdigest()] = base64.b64encode(public).decode()
    if not 1 <= threshold <= len(keys) <= 32:
        raise ValueError("invalid distinct-key threshold")
    return {"threshold": threshold, "keys": keys}


def manifest(args: argparse.Namespace) -> bytes:
    """Inventory all payloads, including installers, skills, app and runner files."""
    root = args.bundle.resolve(strict=True)
    if root in args.output.resolve().parents:
        raise ValueError("write the unsigned payload outside the bundle to avoid self-reference")
    if not re.fullmatch(r"(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)", args.version):
        raise ValueError("version must be a stable numeric triple")
    if not re.fullmatch(r"[0-9a-f]{40}", args.commit) or args.sequence < 1:
        raise ValueError("an exact commit and positive release sequence are required")
    files = {}
    total = 0
    for directory, dirs, names in os.walk(root, followlinks=False):
        base = Path(directory)
        for name in dirs + names:
            path = base / name
            if path.is_symlink():
                raise ValueError("release bundles cannot contain symlinks")
        if base == root:
            dirs[:] = [name for name in dirs if name != "roots"]
        for name in names:
            path = base / name
            relative = path.relative_to(root).as_posix()
            if relative == "manifest.json":
                continue
            if not re.fullmatch(r"[A-Za-z0-9/_. -]+", relative) or any(part in ("", ".", "..") for part in relative.split("/")):
                raise ValueError("unsafe release path")
            meta = path.stat(follow_symlinks=False)
            if not stat.S_ISREG(meta.st_mode):
                raise ValueError("release payload must contain only regular files")
            total += meta.st_size
            if total > 4 * 1024**3 or len(files) >= 20_000:
                raise ValueError("release inventory exceeds its limit")
            digest = hashlib.sha256()
            with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), "rb") as source:
                for chunk in iter(lambda: source.read(1024 * 1024), b""):
                    digest.update(chunk)
            files[relative] = {"sha256": digest.hexdigest(), "size": meta.st_size,
                               "executable": bool(meta.st_mode & 0o111)}
    info = plistlib.loads(read_regular(root / "iPhoneUse.app/Contents/Info.plist", MAX_METADATA))
    if info.get("CFBundleShortVersionString") != args.version:
        raise ValueError("app version does not match the release manifest")
    value = {"kind": "iphone-use-release-v1", "version": args.version, "sequence": args.sequence,
             "commit": args.commit, "expires": args.expires, "platform": args.platform, "files": files}
    result = json_bytes(value)
    if len(result) > MAX_METADATA:
        raise ValueError("manifest exceeds its metadata limit")
    return result


def main() -> None:
    """Build raw payloads, domain-separated signing inputs, or signature envelopes."""
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    make = commands.add_parser("manifest")
    make.add_argument("bundle", type=Path)
    make.add_argument("--version", required=True)
    make.add_argument("--sequence", required=True, type=int)
    make.add_argument("--commit", required=True)
    make.add_argument("--expires", required=True, type=int, help="expiry as Unix seconds")
    make.add_argument("--platform", choices=["aarch64-apple-darwin", "x86_64-apple-darwin"], required=True)
    make.add_argument("--output", required=True, type=Path)
    root = commands.add_parser("root")
    root.add_argument("--root-key", required=True, action="append", type=Path)
    root.add_argument("--release-key", required=True, action="append", type=Path)
    root.add_argument("--root-threshold", type=int, default=1)
    root.add_argument("--release-threshold", type=int, default=1)
    root.add_argument("--version", type=int, required=True)
    root.add_argument("--expires", type=int, required=True)
    root.add_argument("--output", required=True, type=Path)
    for name in ["signing-input", "envelope"]:
        command = commands.add_parser(name)
        command.add_argument("payload", type=Path)
        command.add_argument("--output", required=True, type=Path)
        if name == "envelope":
            command.add_argument("--signature", required=True, action="append", metavar="PUBLIC_RAW:SIGNATURE_RAW")
    args = parser.parse_args()
    if args.command == "manifest":
        result = manifest(args)
    elif args.command == "root":
        if args.version < 1 or args.expires < 1:
            raise ValueError("invalid root version or expiration")
        result = json_bytes({"kind": "iphone-use-root-v1", "version": args.version, "expires": args.expires,
                             "root": key_policy(args.root_key, args.root_threshold),
                             "releases": key_policy(args.release_key, args.release_threshold)})
    else:
        payload = read_regular(args.payload, MAX_METADATA)
        json.loads(payload)
        if args.command == "signing-input":
            result = DOMAIN + payload
        else:
            signatures = {}
            for item in args.signature:
                public_path, signature_path = item.split(":", 1)
                policy = key_policy([Path(public_path)], 1)
                key_id = next(iter(policy["keys"]))
                signature = read_regular(Path(signature_path), 64)
                if len(signature) != 64 or key_id in signatures:
                    raise ValueError("signatures must be 64 bytes from distinct keys")
                signatures[key_id] = base64.b64encode(signature).decode()
            result = json_bytes({"payload": base64.b64encode(payload).decode(), "signatures": signatures})
    output(args.output, result)
    print("Metadata written; verify it with the independently provisioned release verifier before installing.")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(f"Release metadata refused: {error}", file=sys.stderr)
        raise SystemExit(2)
