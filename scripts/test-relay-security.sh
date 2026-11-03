#!/usr/bin/env bash
# Compile the real relay with locked project tooling; run fixtures on Node 18+.
# No Cloudflare account, credentials or deployment is involved.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/iphone-relay-security.XXXXXX")"
trap 'rm -rf -- "$TMP"' EXIT
"$ROOT/relay/node_modules/.bin/tsc" -p "$ROOT/relay/tsconfig.json" --noEmit false --outDir "$TMP"
printf '%s\n' '{"type":"module"}' > "$TMP/package.json"
RELAY_TEST_MODULE="$TMP/index.js" node "$ROOT/scripts/test-relay-security.mjs"
