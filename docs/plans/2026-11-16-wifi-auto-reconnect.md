# Paired-device Wi-Fi fallback

The user requests automatic reconnection without entering an IP, including real cable-unplug validation, while keeping Mac Shadowrocket connected. Work is isolated on `codex/wifi-auto-reconnect`; the original checkout's RunnerTests.swift is untouched.

## Design

Preserve USB priority and native CoreDevice. Add a Rust-only fallback using the already pinned idevice revision. The user explicitly approved enabling remote_pairing and its cryptographic dependencies after rejecting a Python production dependency. No root, VPN changes, pairing reset, or plaintext device LAN listener.

USB bootstrap creates a separate per-instance RemotePairing identity. Cache only addresses authenticated as the configured UDID. On Wi-Fi, try cached endpoints first, then bounded candidates from active local interface neighbor tables. Unicast DNS-SD obtains the current service port; service authTag and cryptographic pair verification precede cache updates. Never pair an unknown wireless candidate. A missing neighbor entry cannot prove device absence; report a bounded failure and retry or request USB bootstrap.

USB setup also preserves the Runner's reported local address as an untrusted hint.
This allows the first wireless connection after an idle interval has expired the
phone's ARP entry. Hints are restricted to active physical LANs and must pass the
same service tag, pair verification and RSD identity checks before becoming cache.

The native fallback maintains an authenticated TLS-PSK userspace tunnel, starts the installed Runner through RSD/XCTest, and relays control/video only to loopback. The existing setup supervisor owns startup, owner checks, PID verification, status, cancellation, and retries. A pulled cable must transition the supervisor rather than remain indefinitely in the native-discovery waiting state. Credentials remain private per-instance files and process environment, never command-line arguments or logs.

## Implementation and verification

1. Unit-test bounded neighbor parsing, DNS compression/truncation handling, cache validation, identity mismatch rejection, and stale-address fallback order.
2. Implement private pairing/cache storage, USB bootstrap, unicast discovery, encrypted tunnel, and native wireless XCTest launch.
3. Integrate supervisor fallback and lifetime/PID handling; preserve USB-only policy and foreign owner/private-hold behavior.
4. Run targeted format/lint and heavy-cargo tests/build. Test real USB bootstrap, unplugged discovery from neighbors, reconnect from cache, forced stale-cache recovery, target identity, and signed Runner readiness. Check Shadowrocket Connected throughout.

Self-review: address discovery alone is insufficient because USB-hosted XCTest exits after unplug. The fallback therefore owns the wireless XCTest session as well as the relay. Successful probes update cache only after RSD confirms the expected UDID. Package support is optional by transport; normal USB/native paths stay available. No commit, PR, or shared-branch edits are authorized by this task.

## Completed evidence

- [x] Private Rust USB pairing, USB address hint and verified endpoint cache.
- [x] Bounded unicast discovery, paired identity validation, encrypted userspace
  tunnel and native wireless XCTest.
- [x] Automatic unplug recovery without an IP and automatic return to USB.
- [x] Cache-only restart and forced-invalid-cache relocation from neighbors.
- [x] First wireless connection after removing the verified cache, using the
  USB-reported hint and cryptographic authentication.
- [x] More than one minute of signed wireless readiness probes with USB absent
  and Mac Shadowrocket connected.
- [x] Product handoff verification and daemon `runner=true`, `drivable=true`,
  `transport=wifi-tunnel` on the final binary.
- [x] Targeted formatting, patch whitespace, all-target clippy, 1055 passing
  server library tests (1 ignored), and executable build.

See [validation details and commands](../wifi-auto-reconnect.md) for acceptance
boundaries and the current isolated development deployment.

## Network-scoped address memory follow-up

The user requested separate home/office address memory and automatic selection on
Wi-Fi changes, with stale addresses recovered by neighbors and unicast, and Mac
Shadowrocket left enabled. This is a bounded extension of the existing flow. The
short design was presented in chat before implementation; no additional dependency
or architecture change was needed.

- [x] Hash physical LAN prefix/mask, scoped gateway/MAC and available SSID; exclude
  VPN routes, DHCP client IP, AP BSSID and connection counters.
- [x] Keep private schema-2 network profiles with independent verified addresses
  and hints; preserve legacy files as advisory migration data only.
- [x] Select current profiles, revalidate identity, and update only the corresponding
  network; reject cache writes when the observed network changed.
- [x] Serialize updates and bound retention to 32 recent network profiles.
- [x] Cover home/office/home, overlapping subnets, roaming, DHCP, missing network
  evidence, migration, corruption and concurrent writes in unit tests.
- [x] Verify real office migration, scoped-cache restart and stale-profile recovery
  without USB, while preserving the Mac VPN and legacy files.
- [x] Run formatting/patch checks, clippy, 1067 passing server tests (1 ignored),
  executable build and local service readiness checks.

Live cross-site roaming remains untested; see the validation document for that
boundary and for the gateway-fingerprint fallback when macOS hides SSID.
