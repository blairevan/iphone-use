import Foundation
import CryptoKit
import Security

private struct KeyState {
    var values: [String: Data] = [:]
    var deniedWrites: Set<String> = []
    var deniedReads: Set<String> = []
    var deleted: [String] = []
}
private let keys = LockedState(initialState: KeyState())
final class ConnectionDefaults: @unchecked Sendable {
    private let values = LockedState<[String: [String]]>(initialState: [:])
    func stringArray(forKey key: String) -> [String]? { values.withLock { $0[key] } }
    func set(_ value: [String], forKey key: String) { values.withLock { $0[key] = value } }
    func removeObject(forKey key: String) { values.withLock { _ = $0.removeValue(forKey: key) } }
}
let ConnectionCheckDefaults = ConnectionDefaults()
private func account(_ query: CFDictionary) -> String {
    (query as NSDictionary)[kSecAttrAccount as String] as! String
}
func FixtureSecItemCopyMatching(_ query: CFDictionary, _ result: UnsafeMutablePointer<CFTypeRef?>?) -> OSStatus {
    keys.withLock { state in
        let key = account(query)
        if state.deniedReads.contains(key) { return errSecInteractionNotAllowed }
        guard let value = state.values[key] else { return errSecItemNotFound }
        result?.pointee = value as NSData
        return errSecSuccess
    }
}
func FixtureSecItemUpdate(_ query: CFDictionary, _ attributes: CFDictionary) -> OSStatus {
    keys.withLock { state in
        let key = account(query)
        if state.deniedWrites.contains(key) { return errSecInteractionNotAllowed }
        guard state.values[key] != nil else { return errSecItemNotFound }
        state.values[key] = (attributes as NSDictionary)[kSecValueData as String] as? Data
        return errSecSuccess
    }
}
func FixtureSecItemAdd(_ query: CFDictionary, _ result: UnsafeMutablePointer<CFTypeRef?>?) -> OSStatus {
    keys.withLock { state in
        let key = account(query)
        if state.deniedWrites.contains(key) { return errSecInteractionNotAllowed }
        if state.values[key] != nil { return errSecDuplicateItem }
        state.values[key] = (query as NSDictionary)[kSecValueData as String] as? Data
        return errSecSuccess
    }
}
func FixtureSecItemDelete(_ query: CFDictionary) -> OSStatus {
    keys.withLock { state in
        let key = account(query)
        state.deleted.append(key);state.values.removeValue(forKey: key)
        return errSecSuccess
    }
}

private enum Reply: Sendable {
    case http(Int, String, [String: String] = [:])
    case failure(URLError.Code)
}

private final class FixtureProtocol: URLProtocol, @unchecked Sendable {
    static let handler = LockedState<(@Sendable (URLRequest) -> Reply)?>(initialState: nil)
    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
    override func stopLoading() {}
    override func startLoading() {
        guard let handler = Self.handler.withLock({ $0 }) else { fatalError("missing fixture") }
        switch handler(request) {
        case let .failure(code): client?.urlProtocol(self, didFailWithError: URLError(code))
        case let .http(code, text, headers):
            let response = HTTPURLResponse(url: request.url!, statusCode: code,
                                           httpVersion: "HTTP/1.1", headerFields: headers)!
            client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
            client?.urlProtocol(self, didLoad: Data(text.utf8))
            client?.urlProtocolDidFinishLoading(self)
        }
    }
}

@main
private struct Checks {
    static let publicURL = URL(string: "https://expired-tunnel.example")!
    static let lanURL = URL(string: "https://192.0.2.4:44321")!
    static let proofKey = Data(repeating: 0x51, count: 32)
    static let cookie = ["Set-Cookie":"phone_session=synthetic-session; Path=/; Max-Age=28800"]

    static func client(key: Data? = proofKey) -> DaemonClient {
        let normal = URLSessionConfiguration.ephemeral
        normal.protocolClasses = [FixtureProtocol.self]
        let probe = URLSessionConfiguration.ephemeral
        probe.protocolClasses = [FixtureProtocol.self]
        return DaemonClient(base: publicURL, lanCandidates: [lanURL], lanKey: key,
                            configuration: normal, probeConfiguration: probe)
    }

    static func proof(_ request: URLRequest) -> Reply {
        precondition(request.httpMethod == "GET")
        precondition(request.value(forHTTPHeaderField: "Cookie") == nil)
        precondition(request.value(forHTTPHeaderField: "Authorization") == nil)
        precondition(request.httpBody == nil)
        let nonce = URLComponents(url: request.url!, resolvingAgainstBaseURL: false)!
            .queryItems!.first { $0.name == "n" }!.value!
        let base = URLComponents(url: request.url!, resolvingAgainstBaseURL: false)!
            .queryItems!.first { $0.name == "u" }!.value!
        let message = "iphone-use-route-v2\n\(nonce)\n\(base)"
        let signed = HMAC<SHA256>.authenticationCode(for: Data(message.utf8), using: SymmetricKey(data: proofKey))
        return .http(200, "{\"proof\":\"\(Data(signed).base64URL)\"}")
    }

    static func main() async throws {
        let plainLAN = URL(string: "http://192.0.2.4:44321")!
        let secure = client()
        precondition(!secure.use(plainLAN))
        precondition(secure.base == publicURL)
        precondition(!DaemonClient.permitsRedirect(from: publicURL, to: URL(string: "http://expired-tunnel.example")!))
        precondition(!DaemonClient.permitsRedirect(from: publicURL, to: URL(string: "https://unrelated.example")!))
        precondition(DaemonClient.permitsRedirect(from: publicURL, to: publicURL.appendingPathComponent("phone")))
        print("PASS: paired HTTPS cannot downgrade or redirect credentials to another origin")
        let noProbe = URLSessionConfiguration.ephemeral
        noProbe.protocolClasses = [FixtureProtocol.self]
        FixtureProtocol.handler.withLock { $0 = { _ in fatalError("plaintext candidate must not be probed") } }
        let refused = DaemonClient(base: publicURL, lanCandidates: [plainLAN], lanKey: proofKey,
                                   configuration: noProbe, probeConfiguration: noProbe)
        let plaintextCandidate = await refused.probeLAN()
        precondition(plaintextCandidate == nil)
        print("PASS: discovery never selects plaintext LAN even with a pairing proof key")
        FixtureProtocol.handler.withLock { handler in handler = { request in
            let nonce = URLComponents(url: request.url!, resolvingAgainstBaseURL: false)!
                .queryItems!.first { $0.name == "n" }!.value!
            let signed = HMAC<SHA256>.authenticationCode(for: Data(nonce.utf8), using: SymmetricKey(data: proofKey))
            return .http(200, "{\"proof\":\"\(Data(signed).base64URL)\"}")
        } }
        let legacyProof = await client().provesIdentity(at: lanURL, key: proofKey)
        precondition(!legacyProof, "a forwarded nonce-only proof cannot authorize a new origin")
        print("PASS: legacy nonce-only proofs cannot authorize credential migration")
        let revocationStore = UserDefaults(suiteName: "iphone-use-revocation-fixture-\(UUID().uuidString)")!
        let revokedAddress = "https://revoked.example/fixture"
        PairingRevocation.mark(address: revokedAddress, defaults: revocationStore)
        precondition(PairingRevocation.requiresAuthorization(address: revokedAddress, freshCredential: false, defaults: revocationStore))
        precondition(!PairingRevocation.requiresAuthorization(address: revokedAddress, freshCredential: true, defaults: revocationStore))
        // Merely presenting a new credential does not clear the stored latch.
        precondition(PairingRevocation.requiresAuthorization(address: revokedAddress, freshCredential: false, defaults: revocationStore))
        PairingRevocation.authorized(address: revokedAddress, defaults: revocationStore)
        precondition(!PairingRevocation.requiresAuthorization(address: revokedAddress, freshCredential: false, defaults: revocationStore))
        print("PASS: revocation persists until fresh user authorization, not a network retry")
        let events = LockedState<[String]>(initialState: [])
        FixtureProtocol.handler.withLock { handler in handler = { request in
            let url = request.url!
            events.withLock { $0.append("\(request.httpMethod!) \(url.host!)\(url.path)") }
            if url.host == lanURL.host, url.path == "/pair/probe" { return proof(request) }
            guard url.host == lanURL.host else { return .failure(.cannotFindHost) }
            if url.path == "/pair" { return .http(200, "{\"ok\":true}", cookie) }
            precondition(url.path == "/agent/status")
            precondition(request.value(forHTTPHeaderField: "Cookie") == "phone_session=synthetic-session")
            return .http(200, "{\"ok\":true,\"drivable\":true,\"device_state\":\"ready\"}")
        } }
        let saved = client()
        try await saved.renew(deviceToken: "synthetic-device-token")
        let status = try await saved.status()
        precondition(status.drivable && saved.onLAN)
        precondition(events.withLock { $0 } == ["GET 192.0.2.4/pair/probe", "POST 192.0.2.4/pair", "GET 192.0.2.4/agent/status"])
        print("PASS: saved pairing renews over verified LAN while its public URL is gone")

        events.withLock { $0 = [] }
        FixtureProtocol.handler.withLock { handler in handler = { request in
            events.withLock { $0.append("\(request.httpMethod!) \(request.url!.host!)\(request.url!.path)") }
            if request.url!.host == lanURL.host {
                precondition(request.url!.path == "/pair/probe")
                precondition(request.value(forHTTPHeaderField: "Cookie") == nil)
                precondition(request.httpBody == nil)
                return .http(200, "{\"proof\":\"invalid\"}")
            }
            return .failure(.cannotFindHost)
        } }
        do { try await client().renew(deviceToken: "synthetic-device-token"); fatalError("must fail") }
        catch { precondition(!events.withLock { $0.contains("POST 192.0.2.4/pair") }) }
        print("PASS: an unproven LAN endpoint never receives the saved credential")

        FixtureProtocol.handler.withLock { handler in handler = { request in
            precondition(request.url!.host == publicURL.host, "a missing proof key must not use LAN")
            return .http(200, "{\"ok\":true}", cookie)
        } }
        let noProofKey = client(key: nil)
        try await noProofKey.renew(deviceToken: "synthetic-device-token")
        precondition(!noProofKey.onLAN)
        print("PASS: old profiles without a LAN proof key keep their original route")

        for body in ["<html>proxy login</html>", "{\"error\":\"unauthorized\"}"] {
            FixtureProtocol.handler.withLock { handler in handler = { _ in .http(401, body) } }
            do { try await client(key: nil).renew(deviceToken: "synthetic-device-token"); fatalError("must fail") }
            catch DaemonError.notIphoneUse {} // DeviceSession does not delete credentials for this error.
        }
        print("PASS: proxy or unrelated 401 responses are not classified as pairing revocation")

        FixtureProtocol.handler.withLock { handler in handler = { _ in .http(401, "{\"error\":\"device_token_invalid\"}") } }
        do { try await client(key: nil).renew(deviceToken: "synthetic-device-token"); fatalError("must fail") }
        catch DaemonError.pairingRevoked {}
        FixtureProtocol.handler.withLock { handler in handler = { _ in .http(401, "{\"error\":\"pairing_code_invalid\"}") } }
        do { _ = try await client(key: nil).pair(code: "synthetic-code"); fatalError("must fail") }
        catch DaemonError.pairingCodeInvalid {}
        print("PASS: genuine revocation and expired one-time codes still require reauthorization")

        keys.withLock { $0 = KeyState(values: ["old":Data("old-password".utf8)], deniedWrites:["old"]) }
        precondition(!Keychain.save(password: "new-password", for: "old"))
        precondition(Keychain.password(for: "old") == "old-password")
        precondition(keys.withLock { $0.deleted.isEmpty })
        print("PASS: a failed Keychain update keeps the original credential")

        let original = ["old":Data("password".utf8), "device:old":Data("device-token".utf8)]
        keys.withLock { $0 = KeyState(values: original, deniedWrites:["device:new"]) }
        ConnectionCheckDefaults.set(["http://192.0.2.4:44321"], forKey: "lanURLs:old")
        precondition(!CredentialMover.moveCredentials(from: "old", to: "new"))
        precondition(keys.withLock { $0.values["old"] == original["old"] && $0.values["device:old"] == original["device:old"] && $0.deleted.isEmpty })
        precondition(ConnectionCheckDefaults.stringArray(forKey: "lanURLs:old") != nil)
        keys.withLock { $0.deniedWrites = [] }
        precondition(CredentialMover.moveCredentials(from: "old", to: "new"))
        precondition(Keychain.password(for: "new") == "password")
        precondition(Keychain.password(for: "device:new") == "device-token")
        precondition(Keychain.password(for: "old") == nil)
        print("PASS: address migration deletes old credentials only after every copy succeeded")

        keys.withLock { $0 = KeyState(values: original, deniedReads:["old"]) }
        precondition(!CredentialMover.moveCredentials(from: "old", to: "new"))
        precondition(keys.withLock { $0.values == original && $0.deleted.isEmpty })
        precondition(ConnectProblem.noCredentials.resumesWhenCredentialsReturn)
        precondition(ConnectProblem.sessionExpired.resumesWhenCredentialsReturn)
        precondition(!ConnectProblem.pairingRevoked.resumesWhenCredentialsReturn)
        precondition(!ConnectProblem.wrongPassword.resumesWhenCredentialsReturn)
        print("PASS: unreadable credentials survive migration and can retry after unlock")
    }
}
