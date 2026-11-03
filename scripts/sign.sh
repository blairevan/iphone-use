#!/usr/bin/env bash
# Sign a locally built app. Production identities require explicit selection.
# Usage: SIGN_IDENTITY="Developer ID Application: ..." bash scripts/sign.sh APP
# Without SIGN_IDENTITY, use keychain-free ad-hoc signing. The direct daemon
# does not need a stable legacy Mirroring/TCC signing identity. This script
# never discovers, creates, exports or unlocks a private key or changes the
# user's keychain search list. Existing local identities are left untouched.
set -eu
umask 077
APP="${1:-"$(pwd)/iPhoneUse.app"}"
BUNDLE_ID="com.leeguoo.iphone-use"
IDENTITY="${SIGN_IDENTITY:--}"
if [ "$IDENTITY" = - ]; then
    echo "Signing locally with an ad-hoc identity; no private key is accessed."
else
    echo "Signing with the explicitly selected identity."
fi

# ── Verify the .app exists ────────────────────────────────────────────────────
if [ ! -d "$APP" ]; then
    echo "ERROR: app bundle not found: $APP" >&2
    echo "       Run scripts/make-app.sh first." >&2
    exit 1
fi

DAEMON_BINARY="$APP/Contents/MacOS/iphone-use"
MCP_BINARY="$APP/Contents/MacOS/iphone-use-mcp"
for binary in "$DAEMON_BINARY" "$MCP_BINARY"; do
    if [ ! -f "$binary" ]; then
        echo "ERROR: binary missing inside bundle: $binary" >&2
        exit 1
    fi
done

# ── Signing flags ─────────────────────────────────────────────────────────────
# Notarization rejects a Developer ID signature without the hardened runtime
# and a secure timestamp ("The executable does not have the hardened runtime
# enabled" / "The signature does not include a secure timestamp"). The
# self-signed local identity is never notarized, and a timestamp request
# needs network access it may not have, so it keeps the offline flags.
case "$IDENTITY" in
    *"Developer ID Application"*)
        SIGN_FLAGS=(--options runtime --timestamp)
        echo "Developer ID identity: signing with hardened runtime + secure timestamp"
        ;;
    *)
        SIGN_FLAGS=(--timestamp=none)
        ;;
esac

# ── Sign nested binaries first, then the outer bundle ─────────────────────────
# $MCP_BINARY leads deliberately. $DAEMON_BINARY is the bundle's main
# executable, so codesign folds bundle validation into signing it and rejects
# the still-unsigned nested helper ("code object is not signed at all / In
# subcomponent: .../iphone-use-mcp"). The comment above was always right; the
# order underneath it was not.
# The iOS 15/16 launcher is nested code too, so it also goes before the main
# executable.
LEGACY_LAUNCH_BINARY="$APP/Contents/MacOS/iphone-use-legacy-launch"
[ -f "$LEGACY_LAUNCH_BINARY" ] || LEGACY_LAUNCH_BINARY=""
for binary in "$MCP_BINARY" ${LEGACY_LAUNCH_BINARY:+"$LEGACY_LAUNCH_BINARY"} "$DAEMON_BINARY"; do
    echo "Signing binary: $binary ..."
    codesign \
        --force \
        --sign "$IDENTITY" \
        "${SIGN_FLAGS[@]}" \
        "$binary"
done

echo "Signing bundle: $APP ..."
codesign \
    --force \
    --sign "$IDENTITY" \
    "${SIGN_FLAGS[@]}" \
    "$APP"

# ── Verify ────────────────────────────────────────────────────────────────────
echo "Verifying signature ..."
codesign --verify --verbose=2 "$APP"

SIGNED_BUNDLE_ID="$(codesign --display --verbose=4 "$APP" 2>&1 \
                    | grep 'Identifier=' | head -1 \
                    | sed 's/.*Identifier=\(.*\)/\1/' || true)"

if [ "$SIGNED_BUNDLE_ID" != "$BUNDLE_ID" ]; then
    echo "WARNING: signed bundle-id '$SIGNED_BUNDLE_ID' != expected '$BUNDLE_ID'" >&2
    echo "         TCC grants may not persist.  Check deploy/Info.plist." >&2
else
    echo "Bundle id confirmed: $BUNDLE_ID"
fi

echo "Signing complete."
