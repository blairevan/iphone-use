#!/bin/bash
# Native checks of the actual iOS transport/model sources, without a phone,
# simulator, real network requests or the user's Keychain.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
check_dir="$(mktemp -d "${TMPDIR:-/tmp}/iphone-connection-check.XXXXXX")"
trap 'rm -rf "$check_dir"' EXIT
python3 - "$root" "$check_dir" <<'PY'
from pathlib import Path
import sys
root, out = map(Path, sys.argv[1:])
# Pairing.swift also contains UIKit camera views; compile its real, pure QR
# model here rather than requiring an iOS simulator just for HTTP tests.
s = (root/'apps/ios/IPhoneUseRemote/Sources/Pairing.swift').read_text()
model = s[s.index('struct PairLink:'):s.index('/// Full-screen camera')]
(out/'PairLink.swift').write_text('import Foundation\n'+model)
# Browser-only errors are not exercised by these connection checks.
(out/'BrowserError.swift').write_text('enum BrowserToolError: Error { case actionFailed(String), invalidResult }\n')
device = (root/'apps/ios/IPhoneUseRemote/Sources/DeviceSession.swift').read_text()
keychain = device[device.index('enum Keychain {'):]
for name in ['CopyMatching', 'Update', 'Add', 'Delete']:
    keychain = keychain.replace('SecItem'+name+'(', 'FixtureSecItem'+name+'(')
start = device.index('    @discardableResult\n    static func moveCredentials')
# Extract only the static helper. Other instance methods may be added between
# it and savePassword and must not accidentally become fixture enum members.
end = device.index('\n    }\n', start) + len('\n    }\n')
move = device[start:end]
move = move.replace('UserDefaults.standard', 'ConnectionCheckDefaults')
helpers = '''
enum CredentialMover {
    static func deviceAccount(_ s: String) -> String { "device:" + s }
    static func lanKeyAccount(_ s: String) -> String { "lan:" + s }
    static func pairAccount(_ s: String) -> String { "pair:" + s }
    static func lanURLsKey(_ s: String) -> String { "lanURLs:" + s }
'''
# Execute the production write/migration logic with synthetic Security API
# functions. It must never open the login Keychain on the developer's Mac.
(out/'Keychain.swift').write_text('import Foundation\nimport Security\n'+keychain+'\n'+helpers+move+'}\n')
PY
sources="$root/apps/ios/IPhoneUseRemote/Sources"
xcrun swiftc -parse-as-library -swift-version 6 -target "$(uname -m)-apple-macosx13.0" \
  "$sources/ConcurrencyCompatibility.swift" "$sources/Devices.swift" \
  "$sources/LockReadiness.swift" "$sources/Connection.swift" "$sources/AppLanguage.swift" \
  "$sources/DaemonClient.swift" "$check_dir/PairLink.swift" \
  "$check_dir/BrowserError.swift" "$check_dir/Keychain.swift" \
  "$root/scripts/remote-connection-check.swift" \
  -o "$check_dir/check"
"$check_dir/check"
