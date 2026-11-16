# Paired Wi-Fi recovery

The macOS setup supervisor keeps USB and native CoreDevice as the preferred paths.
When discovery cannot find the configured target, a saved independent RemotePairing
identity enables recovery without an IP argument. The installed Runner must support
signed requests and the phone must have usable developer services.

## Trust and address selection

- A normal USB setup bootstraps trust once, scoped to the instance and normalized
  target UDID. Network candidates never trigger pair-setup or a new trust prompt.
- `wifi-paired/<normalized-udid>/` under the instance state directory contains
  `host`, `pair.plist`, and schema-2 address memory in `networks.json`. Each network
  has a separate verified endpoint and untrusted Runner address hint. Directories
  are private; files are written atomically with mode `0600`. Symlinks and
  foreign-owned state are rejected. Read-only lookups do not create state.
- Network keys hash the physical LAN prefix/mask, scoped default gateway and its
  complete ARP MAC, plus SSID when macOS exposes it. Client DHCP address, AP BSSID,
  connection counter and VPN default routes do not select profiles. Raw SSIDs and
  gateway MACs are not persisted. Home and office can share an IP range and still
  retain separate addresses. AP roaming within the same LAN retains its profile.
- Normal USB or CoreDevice setup remembers the literal local address reported by
  its Runner. Recovery selects only current network profiles. A stale endpoint or
  port falls back to that network's hint and complete local neighbors, queried with
  unicast DNS-SD. Candidates are deduplicated and capped at 32; no subnet scan runs.
- Schema-1 `address.json` / `hint.json` records remain unchanged for rollback. On a
  network with no profile, they are advisory local candidates, never trusted cache
  hits. Only successful pairing and RSD verification can populate a verified v2
  record. A network change during authentication prevents saving to the old profile.
- Updates lock the private store and preserve other networks; it retains the 32
  most recently updated profiles. Corrupt or unsafe stores are not overwritten;
  authenticated connections can remain usable when remembering an address fails.
- Discovery checks the service authentication tag against the paired identity.
  Pair verification and the encrypted tunnel's RSD target ID must succeed before an
  address is remembered. Reachability alone is insufficient.
- Pairing, tunnel control and application traffic stay on the selected physical
  interface. VPNs remain enabled. No multicast responder, route modification,
  privileged packet interface or Python helper is used.

## Process lifecycle

The `wifi-native` internal worker hosts one encrypted tunnel, a wireless XCTest
session and two loopback relays. The supervisor validates the worker's full argv,
UID and start time, and validates each port's listener. A fresh per-launch token
must authenticate `/status` with `value.ready=true` before readiness is published.
The daemon must also report the Runner reachable through its existing product
verification/handoff path. This clears state from a previous Runner when needed;
the worker is reported as `wifi-tunnel` by `/agent/status`.
Only the fixed runner token and existing daemon environment allowlist reach XCTest;
protocol logs, app logs and launch dictionaries are not emitted.

Cable loss can switch the supervisor to this worker. A failed wireless transport is
retried through existing supervision instead of waiting indefinitely for CoreDevice
discovery. USB regains priority when plugged in and the phone has no foreign owner.
Existing ownership and parked-phone rules apply. Explicit XCTest termination and UI
automation revocation park the phone. Signals cancel the worker and close its tunnel.

The fallback is built only for macOS, so the on-phone embedded daemon does not gain
host-side pairing/XCTest dependencies. It reuses the pinned idevice revision and
the explicitly approved `remote_pairing` crypto dependencies; no additional runtime
or helper executable is installed.

## Validation commands

Use the repository's `heavy-cargo` wrapper when installed. This validation machine
does not have it; its configured legacy TUNA git index stalled, so the following
commands used a command-local sparse mirror override and two build jobs. Global
Cargo settings were not changed.

```sh
rustfmt --edition 2021 --check crates/server/src/wifi/*.rs crates/server/src/setup/wifi_flow.rs
git diff --check
CARGO_BUILD_JOBS=2 cargo --config 'source.tuna.registry="sparse+https://rsproxy.cn/index/"' clippy -p server --all-targets
CARGO_BUILD_JOBS=2 cargo --config 'source.tuna.registry="sparse+https://rsproxy.cn/index/"' test -p server --lib
CARGO_BUILD_JOBS=2 cargo --config 'source.tuna.registry="sparse+https://rsproxy.cn/index/"' test -p server --lib wifi::cache
CARGO_BUILD_JOBS=2 cargo --config 'source.tuna.registry="sparse+https://rsproxy.cn/index/"' build -p server --bin iphone-use
```

Unit tests cover neighbor scope/budget, DNS record matching and malformed messages,
target identity, cache permissions/symlink rejection, stale-cache fallback order,
strict PID signatures, and DTX callback handling during a pending request.

Hardware acceptance must separately prove USB bootstrap, automatic cable-loss
recovery without an IP, cached restart, stale-cache relocation, signed readiness,
no USB attachment, and a still-connected Mac VPN. Compilation and unit tests alone
do not establish those outcomes. Local hardware evidence is kept separately from
this document so device identifiers and pairing material are not committed.

## Recorded acceptance (2026-11-16)

The macOS/iOS hardware run verified:

- Native Rust USB pairing and signed USB Runner readiness.
- Unplugged encrypted tunnel, RSD target identity, wireless XCTest and signed
  `200` / `value.ready=true`; control and video listeners bound only to loopback.
- Supervisor restart while unplugged, authenticating the remembered endpoint.
- Replacing the cache with an invalid address, then relocating the paired target
  from LAN neighbors and replacing the invalid cache after authentication.
- Automatic return to USB when the cable was inserted, including creation of a
  private USB address hint. With the verified cache backed up and removed, another
  cable unplug automatically established Wi-Fi and regenerated the verified cache.
- Mac Shadowrocket remained connected during these checks. No screenshot or
  accessibility payload was collected as acceptance evidence.
- Seven signed probes over more than one minute confirmed the same wireless worker
  remained ready with no USB attachment and the VPN connected. The daemon's
  `/agent/status` was separately verified with `runner=true`, `drivable=true` and
  `transport=wifi-tunnel` after loading the final development binary.

The first unplug exposed a missing USB address hint after the phone's ARP entry
expired. The supervisor now saves that hint during USB bring-up; the final unplug
test above used this corrected implementation. Hints never substitute for pairing
or RSD identity verification.

The server library suite passed **1067 tests**, with **1 ignored** and no failures.
The new Wi-Fi modules passed rustfmt, and the patch passed `git diff --check`; all-target clippy and the
debug executable build completed. Clippy still reports pre-existing warnings in
other files. Repository-wide formatting has existing drift and was not rewritten.
An iOS dependency-tree check excluded host-side idevice from that target; an iOS
cross-compilation was not performed.

The tested daemon LaunchAgent runs the isolated worktree's `target/debug/iphone-use`.
Both daemon and runner LaunchAgents select that setup engine through
`IPHONE_USE_SETUP_BIN`. Their previous plists were backed up privately before the
development deployment. Keep the worktree and binary available while using this
deployment. No commit or push was performed. The on-phone Runner source and desktop
application bundle were not changed by this feature.

Recovery is bounded to a saved local hint and at most 32 complete local IPv4
neighbors. If an address changes and the phone is absent from those candidates,
USB bring-up is needed to refresh the hint. No full-subnet scan is performed.

## Network switching boundaries

macOS currently redacts SSID/BSSID/NetworkID on the validation machine. The gateway
fingerprint allows network selection without requesting Location permission. If
SSID is hidden and two LANs have identical prefix/mask, gateway IP and gateway MAC,
they cannot be distinguished from those observations. Pair verification and RSD
identity still protect against connecting to a different device. Changing router
identity or SSID visibility can cause a one-time rediscovery/new profile.

If a complete physical gateway identity is unavailable, verified profile reuse and
new cache writes are skipped; bounded unicast discovery remains available. Cache
identity never replaces the device's cryptographic identity.

The network-aware implementation was validated on 2026-11-16:

- Unit fixtures switch home → office → home, including identical IP prefixes with
  distinct gateways/SSIDs, and preserve each network's verified address and hint.
  They cover AP roaming, DHCP host-address changes, unknown/VPN-only identity,
  network-local interface rebinding, concurrent updates, retention, private-file
  checks and schema-1 advisory migration.
- On the office Wi-Fi with USB absent, the Rust worker authenticated the target
  from legacy/neighbor hints, created one private schema-2 profile, then reused it
  on restart (`authenticated network-cached endpoint`). Legacy files were unchanged.
- An invalid address injected into that current profile was recovered through
  neighbor/unicast authentication and replaced under the same network key.
- The daemon was restarted with the built executable; signed Runner readiness and
  daemon `drivable=true` / `transport=wifi-tunnel` are checked independently. Mac
  Shadowrocket remains connected throughout validation.

Home/office switching is covered by deterministic unit fixtures; a physical trip
between both Wi-Fi sites was not performed. On-device operations for acceptance
remain limited to readiness and service health, with no business-page action.
