#!/bin/bash
# Notification-only release checks. No installation, self-refresh, re-signing
# or runner rebuild is permitted in this job. Legacy run flags only affect
# which version notices are reported, never authorize executable downloads.
#
# auto-update.sh enable       explicitly schedule version checks at 04:30
# auto-update.sh disable      persistently disable and verify job removal
# auto-update.sh status       report schedule and historical upgrade outcome
# auto-update.sh run          check versions; never install
# auto-update.sh run --force  check even when disabled; never install
# auto-update.sh run --instance NAME  check only that instance
set -euo pipefail

# Installs made before the rename set PHONE_REMOTE_*; read them as IPHONE_USE_*
# (the new name wins). Names are [A-Z0-9_], so the eval is safe.
for _legacy in $(env | sed -n 's/^PHONE_REMOTE_\([A-Z0-9_][A-Z0-9_]*\)=.*/\1/p'); do
    eval "[ -n \"\${IPHONE_USE_${_legacy}+x}\" ] || export IPHONE_USE_${_legacy}=\"\$PHONE_REMOTE_${_legacy}\""
done
unset _legacy

REPO="${IPHONE_USE_REPO:-leeguooooo/iphone-use}"
STATE_DIR="${IPHONE_USE_STATE_DIR:-$HOME/.iphone-use}"
LABEL_PREFIX="com.leeguoo.iphone-use"
LABEL="$LABEL_PREFIX.autoupdate"
AGENTS_DIR="$HOME/Library/LaunchAgents"
DAEMON_PLIST="$AGENTS_DIR/$LABEL_PREFIX.plist"
JOB_PLIST="$AGENTS_DIR/$LABEL.plist"
# Names under the label prefix that are not daemons (instance.rs RESERVED_NAMES).
RESERVED_NAMES="runner wda autoupdate daily-maintenance flow-reverify"
LOG_DIR="$HOME/Library/Logs/iPhoneUse"
LOG="$LOG_DIR/auto-update.log"
INSTALLED_SELF="$STATE_DIR/auto-update.sh"
DISABLED_MARKER="$STATE_DIR/auto-update.disabled"
OUTCOME="$STATE_DIR/auto-update-last.json"
HOUR="${AUTO_UPDATE_HOUR:-4}"
MINUTE="${AUTO_UPDATE_MINUTE:-30}"
IDLE_SECS="${AUTO_UPDATE_IDLE_SECS:-900}"
case "$IDLE_SECS" in ''|*[!0-9]*) IDLE_SECS=900 ;; esac

# Under launchd stderr already is $LOG; teeing there too wrote every line twice.
# (`-ef` cannot tell: /dev/fd/2 stats on its own device, so compare inodes.)
stderr_is_log() {
    local fd file
    fd="$(stat -L -f %i /dev/fd/3 3>&2 2>/dev/null)" || return 1
    file="$(stat -f %i "$LOG" 2>/dev/null)" || return 1
    [ -n "$fd" ] && [ "$fd" = "$file" ]
}
log() {
    mkdir -p "$LOG_DIR"
    local line; line="$(date '+%Y-%m-%dT%H:%M:%S%z') $*"
    if stderr_is_log; then
        printf '%s\n' "$line" >&2
    else
        printf '%s\n' "$line" | tee -a "$LOG" >&2
    fi
}
die() { log "ERROR: $*"; exit 1; }

# --- daemon access ----------------------------------------------------------
# One line per daemon on this Mac, "<instance> <plist>", the default instance first.
instances() {
    if [ -f "$DAEMON_PLIST" ]; then printf 'default %s\n' "$DAEMON_PLIST"; fi
    local plist name reserved
    for plist in "$AGENTS_DIR/$LABEL_PREFIX".*.plist; do
        [ -f "$plist" ] || continue
        name="${plist##*/}"; name="${name#"$LABEL_PREFIX".}"; name="${name%.plist}"
        # runner supervisors (.runner, .runner.NAME) and other dotted labels are not daemons
        [[ "$name" =~ ^[a-z][a-z0-9-]{0,31}$ ]] || continue
        for reserved in $RESERVED_NAMES; do [ "$name" != "$reserved" ] || continue 2; done
        printf '%s %s\n' "$name" "$plist"
    done
}

daemon_env() {  # print port, token and host on separate lines; preserve spaces
    [ -f "$1" ] || return 1
    python3 - "$1" <<'PY'
import plistlib, sys
env = plistlib.load(open(sys.argv[1], 'rb')).get('EnvironmentVariables', {})
get = lambda name, default: env.get('IPHONE_USE_' + name, env.get('PHONE_REMOTE_' + name, default))  # older plists
# Without an agent token the daemon takes its password as the bearer; a default
# install has only the password.
values = [str(get('PORT', '44321')), get('AGENT_TOKEN', '') or get('PASSWORD', '') or '-', get('HOST', '127.0.0.1')]
if any('\n' in value or '\r' in value for value in values): sys.exit(1)
print('\n'.join(values))
PY
}

status_json() {  # status_json <instance> <plist>
    if [ "$1" = default ] && [ -n "${AUTO_UPDATE_STATUS_URL:-}" ]; then
        auth_status_curl "${AUTO_UPDATE_TOKEN:-}" "$AUTO_UPDATE_STATUS_URL"
        return
    fi
    local port token host
    { IFS= read -r port && IFS= read -r token && IFS= read -r host; } < <(daemon_env "$2") || return 1
    [ "$token" != "-" ] || token=""
    # These are local instances. Never send their credential to a saved LAN
    # hostname over plaintext merely to report an available version.
    case "$host" in ::1|\[::1\]) host='[::1]' ;; *) host=127.0.0.1 ;; esac
    auth_status_curl "$token" "http://$host:$port/agent/status"
}

# Feed credentials through stdin, not argv or diagnostic output. Quoted curl
# config strings must not admit a second option through a newline or quote.
auth_status_curl() {
    local token="$1" url="$2"
    case "$token" in *$'\n'*|*$'\r'*) return 1 ;; esac
    token="${token//\\/\\\\}"
    token="${token//\"/\\\"}"
    printf 'header = "Authorization: Bearer %s"\n' "$token" \
        | curl -fsS --noproxy '*' -m 10 -K - "$url"
}

status_version() {  # the version a daemon reports, or nothing
    status_json "$1" "$2" 2>/dev/null \
        | python3 -c 'import sys,json; print(json.load(sys.stdin).get("version",""))' 2>/dev/null || true
}

latest_tag() {
    if [ -n "${AUTO_UPDATE_LATEST_TAG:-}" ]; then printf '%s\n' "$AUTO_UPDATE_LATEST_TAG"; return; fi
    # The releases/latest redirect needs no API token and is not rate-limited
    # like api.github.com; the tag is the last path segment of the target URL.
    local url
    url="$(curl -fsSIL --proto =https --proto-redir =https -m 15 -o /dev/null -w '%{url_effective}' "https://github.com/$REPO/releases/latest")" || return 1
    case "$url" in
        */releases/tag/v[0-9]*) printf '%s\n' "${url##*/}" ;;
        *) return 1 ;;
    esac
}

# --- the decision -----------------------------------------------------------
# Prints one of: upgrade | skip:<reason> ; exit 0 either way, 2 on a probe failure.
decide() {  # decide <force> <reinstall> <latest tag> <instance> <plist>
    local force="$1" reinstall="$2" latest="$3" status
    status="$(status_json "$4" "$5")" || { printf 'skip:daemon_unreachable\n'; return 2; }
    STATUS_JSON="$status" LATEST="$latest" FORCE="$force" REINSTALL="$reinstall" IDLE_SECS="$IDLE_SECS" python3 - <<'PY'
import json, os, sys
s = json.loads(os.environ['STATUS_JSON'])
latest = os.environ['LATEST'].lstrip('v')
current = str(s.get('version') or '').lstrip('v')
force = os.environ['FORCE'] == '1'
reinstall = os.environ['REINSTALL'] == '1'
def ver(v):
    try: return tuple(int(x) for x in v.split('-')[0].split('.'))
    except ValueError: return ()
if not s.get('ok'):
    print('skip:daemon_not_ok'); sys.exit(0)
if not reinstall and (not current or ver(latest) <= ver(current)):
    print(f'skip:up_to_date current={current} latest={latest}'); sys.exit(0)
if not force:
    if s.get('owner'):
        print(f"skip:phone_owned owner={s['owner']} lease={s.get('owner_lease_remaining_secs')}s"); sys.exit(0)
    if (s.get('hold_remaining_secs') or 0) > 0:
        print(f"skip:held {s['hold_remaining_secs']}s"); sys.exit(0)
    if s.get('releasing') or s.get('reconnecting'):
        print('skip:transitioning'); sys.exit(0)
    # The hand-off lives in the daemon's memory: a restart would forget the
    # phone is a person's, and the next agent request would start runner under them.
    if s.get('human_handoff'):
        print('skip:handed_to_person'); sys.exit(0)
    viewers = (s.get('viewer_count') or 0) + (s.get('mjpeg_viewer_count') or 0)
    if viewers > 0:
        print(f'skip:watched viewers={viewers}'); sys.exit(0)
    idle = s.get('idle_secs')
    need = int(os.environ['IDLE_SECS'])
    if isinstance(idle, (int, float)) and idle < need:
        print(f'skip:in_use idle_secs={int(idle)} (<{need})'); sys.exit(0)
print(f'upgrade current={current} latest={latest}')
PY
}

cmd_run() {
    local force=0 reinstall=0 only=""
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --force) force=1 ;;
            --reinstall) reinstall=1; force=1 ;;
            --dry-run) : ;;
            --instance) [ "$#" -ge 2 ] || die "--instance needs a name"; only="$2"; shift ;;
            *) die "unknown option for run: $1" ;;
        esac
        shift
    done
    mkdir -p "$STATE_DIR"
    if [ -f "$DISABLED_MARKER" ] && [ "$force" = 0 ]; then
        log "skip: disabled ($DISABLED_MARKER; 'auto-update.sh enable' turns it back on)"; return 0
    fi
    local lock="$STATE_DIR/auto-update.lock"
    if ! mkdir "$lock" 2>/dev/null; then
        log "skip: another auto-update is running (lock $lock)"; return 0
    fi
    # shellcheck disable=SC2064  # expand now: the local is gone by EXIT time
    trap "rmdir '$lock' 2>/dev/null" EXIT
    local latest list
    latest="$(latest_tag)" || { log "decision: skip:latest_unresolved"; return 2; }
    list="$(instances)"
    [ -z "$only" ] || list="$(printf '%s\n' "$list" | awk -v want="$only" '$1 == want')"
    [ -n "$list" ] || { log "decision: skip:not_installed (no daemon LaunchAgent${only:+ for $only})"; return 0; }
    local rc=0 instance plist decision drc
    while read -r instance plist; do
        drc=0
        decision="$(decide "$force" "$reinstall" "$latest" "$instance" "$plist")" || drc=$?
        log "decision[$instance]: $decision"
        case "$decision" in
            upgrade*) log "update available [$instance]: $latest; notification-only, installation requires explicit review" ;;
            *) [ "$drc" = 0 ] || rc=$drc ;;
        esac
    done <<<"$list"
    return "$rc"
}

# --- the schedule -----------------------------------------------------------
write_job_plist() {
    mkdir -p "$(dirname "$JOB_PLIST")" "$LOG_DIR"
    local tmp; tmp="$(mktemp "$JOB_PLIST.XXXXXX")"
    cat > "$tmp" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
    <key>Label</key><string>$LABEL</string>
    <key>ProgramArguments</key>
    <array><string>/bin/bash</string><string>$INSTALLED_SELF</string><string>run</string></array>
    <key>EnvironmentVariables</key>
    <dict><key>PATH</key><string>/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin</string></dict>
    <key>StartCalendarInterval</key>
    <dict><key>Hour</key><integer>$HOUR</integer><key>Minute</key><integer>$MINUTE</integer></dict>
    <key>RunAtLoad</key><false/>
    <key>StandardOutPath</key><string>$LOG</string>
    <key>StandardErrorPath</key><string>$LOG</string>
</dict></plist>
PLIST
    plutil -lint "$tmp" >/dev/null || { rm -f "$tmp"; die "generated $JOB_PLIST is not a valid plist"; }
    mv -f "$tmp" "$JOB_PLIST"
}

job_running() {  # is a run of the job in progress (perhaps the one that called us)?
    launchctl print "gui/$(id -u)/$LABEL" 2>/dev/null | grep -q 'state = running'
}

cmd_enable() {
    # Check before replacing the file a running bash may still be reading.
    if job_running; then
        die "refusing to replace a running updater; verify the active transaction first"
    fi
    [ ! -L "$STATE_DIR" ] && [ ! -L "$INSTALLED_SELF" ] && [ ! -L "$DISABLED_MARKER" ] \
        || die "refusing a symlinked updater namespace"
    mkdir -p "$STATE_DIR"
    local self tmp
    self="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")"
    if [ "$self" != "$INSTALLED_SELF" ]; then
        tmp="$(mktemp "$STATE_DIR/auto-update.sh.XXXXXX")"
        cp "$self" "$tmp" && chmod 0755 "$tmp" && mv -f "$tmp" "$INSTALLED_SELF"
    fi
    chmod 0755 "$INSTALLED_SELF"
    rm -f "$DISABLED_MARKER"
    write_job_plist
    launchctl bootout "gui/$(id -u)/$LABEL" 2>/dev/null || true
    launchctl enable "gui/$(id -u)/$LABEL"
    launchctl bootstrap "gui/$(id -u)" "$JOB_PLIST"
    log "enabled: notification-only checks at $(printf '%02d:%02d' "$HOUR" "$MINUTE"); no automatic installation"
}

cmd_disable() {
    [ ! -L "$STATE_DIR" ] && [ ! -L "$DISABLED_MARKER" ] || die "refusing a symlinked opt-out path"
    mkdir -p "$STATE_DIR"
    (umask 077; : > "$DISABLED_MARKER")
    chmod 600 "$DISABLED_MARKER"
    launchctl disable "gui/$(id -u)/$LABEL"
    launchctl bootout "gui/$(id -u)/$LABEL" 2>/dev/null || true
    if launchctl print "gui/$(id -u)/$LABEL" >/dev/null 2>&1; then
        die "updater is still loaded; keeping its plist and disabled marker for recovery"
    fi
    rm -f "$JOB_PLIST"
    log "disabled: $LABEL stopped; future installs preserve opt-out"
}

cmd_status() {
    if [ -f "$JOB_PLIST" ] && launchctl print "gui/$(id -u)/$LABEL" >/dev/null 2>&1; then
        echo "auto-update: checks-only ($JOB_PLIST, daily $(printf '%02d:%02d' "$HOUR" "$MINUTE"))"
    elif [ -f "$DISABLED_MARKER" ]; then
        echo "auto-update: disabled ($DISABLED_MARKER)"
    else
        echo "auto-update: disabled"
    fi
    local latest instance plist
    latest="$(latest_tag 2>/dev/null || true)"
    while read -r instance plist; do
        [ -n "$instance" ] || continue
        echo "decision now [$instance]: $(decide 0 0 "$latest" "$instance" "$plist" 2>/dev/null || true)"
    done <<<"$(instances)"
    if [ -f "$OUTCOME" ]; then echo "last upgrade:"; cat "$OUTCOME"; fi
    if [ -f "$LOG" ]; then echo "last log lines:"; tail -n 5 "$LOG"; fi
}

case "${1:-}" in
    enable) cmd_enable ;;
    disable) cmd_disable ;;
    status) cmd_status ;;
    run) shift; cmd_run "$@" ;;
    *) sed -n '2,13p' "$0" | sed 's/^# \{0,1\}//'; exit 2 ;;
esac
