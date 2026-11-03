#!/usr/bin/env bash
# The installer always retires unattended upgrades without fetching a script.
# Existing user settings are still carried forward. All launchctl calls are mocked.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/iphone-use-install-auto-update.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

pass=0
ok_t() { pass=$((pass + 1)); printf 'ok %d - %s\n' "$pass" "$1"; }
bad()  { printf 'not ok - %s\n' "$1" >&2; exit 1; }

FUNCS="$(sed -n '/^plist_env_get_from() {$/,/^}$/p;/^legacy_env_names() {$/,/^}$/p;/^plist_own_env_keys() {$/,/^}$/p;/^setup_auto_update() {$/,/^}$/p' "$ROOT/install.sh")"
[ -n "$FUNCS" ] || bad "setup_auto_update / plist_own_env_keys not found in install.sh"

mkdir -p "$TMP/bin" "$TMP/home/.iphone-use"
cat > "$TMP/bin/launchctl" <<'MOCK'
#!/bin/bash
printf '%s\n' "$*" >> "$CALLS"
case "$1" in
    print) [ "${STUCK_JOB:-0}" = 1 ] ;;
    disable|bootout) exit 0 ;;
    *) exit 99 ;;
esac
MOCK
chmod +x "$TMP/bin/launchctl"
setup() {
    rm -f "$TMP/calls"
    env -i HOME="$TMP/home" PATH="$TMP/bin:/usr/bin:/bin" CALLS="$TMP/calls" "$@" bash -c "
info() { :; }; ok() { :; }; warn() { :; }
$FUNCS
setup_auto_update"
}
setup || bad "plain install failed"
[ -f "$TMP/home/.iphone-use/auto-update.disabled" ] || bad "no persistent opt-out"
[ "$(stat -f %Lp "$TMP/home/.iphone-use/auto-update.disabled")" = 600 ] || bad "opt-out permissions"
grep -q '^disable ' "$TMP/calls" || bad "launchd not disabled"
! grep -Eq '^(enable|bootstrap)' "$TMP/calls" || bad "scheduled an automatic updater"
ok_t "new installation persistently disables unattended updates"
for setting in IPHONE_USE_STATE_DIR=/elsewhere IPHONE_USE_AUTO_UPDATE=1 IPHONE_USE_AUTO_UPDATE=0 IPHONE_USE_NO_UPDATE_CHECK=1 USE_NO_UPDATE_CHECK=1; do
    setup "$setting" || bad "$setting failed"
    grep -q '^disable ' "$TMP/calls" || bad "$setting bypassed disable"
done
ok_t "legacy flags and custom instance state do not enable the global updater"
setup IPHONE_USE_AUTO_UPDATE_JOB=1 || bad "active transaction handling failed"
grep -q '^disable ' "$TMP/calls" || bad "active job not disabled for next launch"
! grep -q '^bootout ' "$TMP/calls" || bad "killed the installer executing this release"
ok_t "an active upgrade may finish but cannot schedule another one"
setup CI=1 || bad "CI opt-out failed"
[ ! -e "$TMP/calls" ] || bad "CI touched launchd"
ok_t "CI persists opt-out without touching launchd"
mkdir -p "$TMP/home/Library/LaunchAgents"
job="$TMP/home/Library/LaunchAgents/com.leeguoo.iphone-use.autoupdate.plist"
touch "$job"
if setup STUCK_JOB=1; then bad "reported success with updater still loaded"; fi
[ -f "$job" ] || bad "removed live job plist"
ok_t "failed stop keeps the plist and reports failure"
setup || bad "stop failed"
[ ! -e "$job" ] || bad "stopped job plist survived"
ok_t "confirmed stop removes the scheduled job"

cat > "$TMP/old.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict><key>EnvironmentVariables</key><dict>
<key>IPHONE_USE_PORT</key><string>45432</string>
<key>IPHONE_USE_BASE_PATH</key><string>/ix</string>
<key>IPHONE_USE_TELEMETRY</key><string>0</string>
<key>IPU_RUNNER_TRANSPORT</key><string>wifi</string>
<key>DEVELOPER_DIR</key><string>/Applications/Xcode Beta &amp; QA.app/Contents/Developer</string>
<key>IPHONE_USE_BACKEND</key><string>mirror</string>
<key>IPHONE_USE_WDA_URL</key><string>http://127.0.0.1:8100</string>
<key>IPHONE_USE_INTERNAL_TEST_X</key><string>1</string>
<key>IPU_RUNNER_ASC_KEY_ID</key><string>half-a-set</string>
<key>RUST_LOG</key><string>info</string>
<key>PATH</key><string>/usr/bin</string>
</dict></dict></plist>
PLIST
got="$(bash -c "$FUNCS
plist_own_env_keys '$TMP/old.plist'" | sort | tr '\n' ' ')"
[ "$got" = "DEVELOPER_DIR IPHONE_USE_BASE_PATH IPHONE_USE_PORT IPHONE_USE_TELEMETRY IPU_RUNNER_TRANSPORT " ] \
    || bad "carried-forward keys were '$got'"
ok_t "an upgrade carries our settings forward, minus the mirror backend, old runner names, ASC keys and test hooks"

# Native setup writes the direct marker and the phone-specific Xcode into the
# daemon plist. Losing either makes the next setup rewrite/restart that daemon.
# Both default and named installers consume this same production key selector.
/usr/libexec/PlistBuddy -c 'Set :EnvironmentVariables:IPHONE_USE_BACKEND direct' "$TMP/old.plist"
for format in xml1 binary1; do
    /usr/bin/plutil -convert "$format" "$TMP/old.plist"
    got="$(bash -c "$FUNCS
plist_own_env_keys '$TMP/old.plist'" | sort | tr '\n' ' ')"
    [ "$got" = "DEVELOPER_DIR IPHONE_USE_BACKEND IPHONE_USE_BASE_PATH IPHONE_USE_PORT IPHONE_USE_TELEMETRY IPU_RUNNER_TRANSPORT " ] \
        || bad "native $format keys were '$got'"
    # Read the values through the same getter used when serializing the upgrade.
    kept="$(bash -c "$FUNCS
for key in \$(plist_own_env_keys '$TMP/old.plist'); do
    printf '%s=%s\n' \"\$key\" \"\$(plist_env_get_from '$TMP/old.plist' \"\$key\")\"
done")"
    printf '%s\n' "$kept" | grep -Fx 'DEVELOPER_DIR=/Applications/Xcode Beta & QA.app/Contents/Developer' >/dev/null \
        || bad "$format lost the exact per-phone Xcode path"
    printf '%s\n' "$kept" | grep -Fx 'IPHONE_USE_BACKEND=direct' >/dev/null \
        || bad "$format lost the native backend marker"
done
ok_t "XML and binary native plists retain direct and the exact per-phone Xcode path"
/usr/libexec/PlistBuddy -c 'Set :EnvironmentVariables:IPHONE_USE_BACKEND legacy-mirror' "$TMP/old.plist"
got="$(bash -c "$FUNCS
plist_own_env_keys '$TMP/old.plist'")"
! printf '%s\n' "$got" | grep -Fx IPHONE_USE_BACKEND >/dev/null \
    || bad "the obsolete legacy-mirror backend was carried forward"
ok_t "obsolete legacy-mirror remains excluded"

# Exercise the actual default serialization loop with a legacy fallback.
# Native setup's Xcode choice may live only in the pre-rename daemon plist.
/usr/libexec/PlistBuddy -c 'Set :EnvironmentVariables:IPHONE_USE_BACKEND direct' "$TMP/old.plist"
cp "$TMP/old.plist" "$TMP/legacy.plist"
cat > "$TMP/current.plist" <<'PLIST'
<plist version="1.0"><dict><key>EnvironmentVariables</key><dict>
<key>IPHONE_USE_PORT</key><string>45555</string>
</dict></dict></plist>
PLIST
DEFAULT_FUNCS="$(sed -n '/^plist_env_get() {$/,/^}$/p;/^xml_escape() {$/,/^}$/p;/^append_plist_env() {$/,/^}$/p' "$ROOT/install.sh")"
CARRY_LOOP="$(sed -n '/^# The rest of our settings in the previous plist, as they were\.$/,/^done$/p' "$ROOT/install.sh")"
carry_default() {
    bash -c "$FUNCS
$DEFAULT_FUNCS
PLIST_DST='$TMP/current.plist'; OLD_PLIST='$TMP/legacy.plist'
PLIST_ENV_BLOCK=''; PLIST_ENV_HANDLED=' '
$CARRY_LOOP
printf '<plist version=\"1.0\"><dict><key>EnvironmentVariables</key><dict>%s</dict></dict></plist>\n' \"\$PLIST_ENV_BLOCK\"" > "$TMP/carried.plist"
}
carry_default
[ "$(/usr/libexec/PlistBuddy -c 'Print :EnvironmentVariables:DEVELOPER_DIR' "$TMP/carried.plist")" = '/Applications/Xcode Beta & QA.app/Contents/Developer' ] \
    || bad "the default upgrade lost the legacy Xcode choice"
[ "$(/usr/libexec/PlistBuddy -c 'Print :EnvironmentVariables:IPHONE_USE_BACKEND' "$TMP/carried.plist")" = direct ] \
    || bad "the default upgrade lost legacy direct"
[ "$(/usr/libexec/PlistBuddy -c 'Print :EnvironmentVariables:IPHONE_USE_PORT' "$TMP/carried.plist")" = 45555 ] \
    || bad "legacy settings overwrote the current plist"
ok_t "the default serializer preserves legacy-only settings and gives current values precedence"
/usr/libexec/PlistBuddy -c 'Add :EnvironmentVariables:DEVELOPER_DIR string /Applications/Current.app/Contents/Developer' "$TMP/current.plist"
/usr/libexec/PlistBuddy -c 'Add :EnvironmentVariables:IPHONE_USE_BACKEND string mirror' "$TMP/current.plist"
carry_default
[ "$(/usr/libexec/PlistBuddy -c 'Print :EnvironmentVariables:DEVELOPER_DIR' "$TMP/carried.plist")" = /Applications/Current.app/Contents/Developer ] \
    || bad "legacy Xcode overwrote the current phone choice"
! /usr/libexec/PlistBuddy -c 'Print :EnvironmentVariables:IPHONE_USE_BACKEND' "$TMP/carried.plist" >/dev/null 2>&1 \
    || bad "legacy direct resurrected the current mirror backend"
ok_t "current Xcode wins and obsolete current backend cannot be revived from legacy direct"
rm "$TMP/current.plist"
carry_default
[ "$(/usr/libexec/PlistBuddy -c 'Print :EnvironmentVariables:IPHONE_USE_BACKEND' "$TMP/carried.plist")" = direct ] \
    || bad "a legacy-only install lost direct"
ok_t "a legacy-only install retains native settings without a current plist"
/usr/libexec/PlistBuddy -c 'Delete :EnvironmentVariables:IPHONE_USE_BACKEND' "$TMP/legacy.plist"
/usr/libexec/PlistBuddy -c 'Add :EnvironmentVariables:PHONE_REMOTE_BACKEND string direct' "$TMP/legacy.plist"
/usr/libexec/PlistBuddy -c 'Add :EnvironmentVariables:PHONE_REMOTE_TELEMETRY string 1' "$TMP/legacy.plist"
carry_default
[ "$(/usr/libexec/PlistBuddy -c 'Print :EnvironmentVariables:IPHONE_USE_BACKEND' "$TMP/carried.plist")" = direct ] \
    || bad "the legacy spelling of direct was dropped instead of canonicalized"
[ "$(/usr/libexec/PlistBuddy -c 'Print :EnvironmentVariables:IPHONE_USE_TELEMETRY' "$TMP/carried.plist")" = 0 ] \
    || bad "the canonical setting did not win over the legacy spelling in the same plist"
! /usr/libexec/PlistBuddy -c 'Print :EnvironmentVariables:PHONE_REMOTE_BACKEND' "$TMP/carried.plist" >/dev/null 2>&1 \
    || bad "the obsolete key spelling was written to the new plist"
ok_t "supported legacy spellings become canonical keys without overriding canonical values"
grep -q '^    IPHONE_USE_BASE_PATH \\$' "$ROOT/install.sh" || bad "IPHONE_USE_BASE_PATH is not on the default instance's list"
ok_t "the default instance keeps IPHONE_USE_BASE_PATH"

printf '1..%d\n' "$pass"
