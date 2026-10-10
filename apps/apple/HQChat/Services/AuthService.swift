import CryptoKit
import Foundation

/// Client of the auth service.
///
///     POST /auth/init     { pk }                            -> { ct }
///     POST /auth/verify   { pk, solution, mqttSigningKey }  -> session + MQTT signing-key id
///     POST /auth/refresh  (Bearer) { mqttSigningKey }      -> a new MQTT signing-key id
///     GET  /auth/transport                                  -> the hqn/1 gateway, when enabled
///
/// `solution` is HKDF(ss, "auth") of the decapsulated KEM challenge, never the
/// secret itself. Every MQTT CONNECT password is a fresh proof signed with an
/// in-memory Ed25519 key whose public half was registered at sign-in or refresh.
actor AuthService {

    struct Session {
        let pk: String
        /// This identity's client id, derived locally from `pk`.
        var id: String { PeerID.from(publicKeyHex: pk) }
        let username: String?
        let sessionToken: String
        var mqttKeyID: String
        /// Expiry of the registered signing key, on the server's clock.
        var mqttKeyExpiresAt: TimeInterval
    }

    enum AuthError: LocalizedError {
        case notAuthenticated
        case badResponse(Int, String)
        case decapsulationFailed
        case malformedChallenge

        var errorDescription: String? {
            switch self {
            case .notAuthenticated: return "Not authenticated"
            case .badResponse(let code, let msg): return "Auth server error \(code): \(msg)"
            case .decapsulationFailed: return "Failed to decapsulate the KEM challenge"
            case .malformedChallenge: return "Malformed challenge from the auth server"
            }
        }
    }

    private var current: Session?
    private var mqttSigner: Curve25519.Signing.PrivateKey?
    /// Server clock minus ours; proofs are judged by the server's clock.
    private var clockOffset: TimeInterval = 0
    /// A key with less than this left is refreshed instead of used.
    private static let keyRefreshMargin: TimeInterval = 120
    private let session: URLSession
    private let pinningDelegate = TLSPinningDelegate()

    init(session: URLSession? = nil) {
        self.session = session
            ?? URLSession(configuration: .default, delegate: pinningDelegate, delegateQueue: nil)
    }

    /// Installs a session without a handshake. Tests only.
    func __setSessionForTesting(_ s: Session?) { current = s }

    func currentSession() -> Session? { current }
    func sessionToken() -> String? { current?.sessionToken }

    func logout() {
        current = nil
        mqttSigner = nil
    }

    /// Proves possession of `secretKey` and opens a session.
    @discardableResult
    func login(publicKeyHex: String, secretKey: Data) async throws -> Session {
        let initResp: InitResponse = try await post(path: "init", body: ["pk": publicKeyHex])
        guard let ct = Data(base64Encoded: initResp.ct) else { throw AuthError.malformedChallenge }
        let ss: Data
        do { ss = try HQCService.decapsulate(secretKey: secretKey, ciphertext: ct) } catch {
            throw AuthError.decapsulationFailed
        }

        let signer = Curve25519.Signing.PrivateKey()
        let verify: VerifyResponse = try await post(
            path: "verify",
            body: [
                "pk": publicKeyHex,
                "solution": AESService.authProof(ss: ss).base64EncodedString(),
                "mqttSigningKey": signer.publicKey.rawRepresentation.base64EncodedString(),
            ])
        guard verify.pk.lowercased() == publicKeyHex.lowercased(),
            PeerID.matches(publicKeyHex: publicKeyHex, id: verify.id)
        else {
            throw AuthError.badResponse(200, "the auth server returned a different identity than the one we signed in with")
        }
        let s = Session(
            pk: verify.pk, username: verify.username, sessionToken: verify.sessionToken,
            mqttKeyID: verify.mqttKeyId, mqttKeyExpiresAt: verify.mqttKeyExpiresAt)
        current = s
        adopt(signer, serverTime: verify.serverTime)
        return s
    }

    /// Registers a fresh MQTT signing key on the existing session.
    func refreshSigningKey() async throws {
        guard let s = current else { throw AuthError.notAuthenticated }
        let signer = Curve25519.Signing.PrivateKey()
        let r: RefreshResponse = try await post(
            path: "refresh", bearer: s.sessionToken,
            body: ["mqttSigningKey": signer.publicKey.rawRepresentation.base64EncodedString()])
        current?.mqttKeyID = r.mqttKeyId
        current?.mqttKeyExpiresAt = r.mqttKeyExpiresAt
        adopt(signer, serverTime: r.serverTime)
    }

    /// The password for the next MQTT CONNECT: a proof signed now, refreshing
    /// the signing key first when it is about to expire.
    func mqttConnectPassword(clientID: String) async throws -> String {
        if let password = try signedPassword(clientID: clientID) { return password }
        try await refreshSigningKey()
        guard let password = try signedPassword(clientID: clientID) else { throw AuthError.notAuthenticated }
        return password
    }

    /// Forces the next CONNECT to refresh the signing key (the broker refused it).
    func invalidateMqttKey() {
        current?.mqttKeyExpiresAt = 0
    }

    private func signedPassword(clientID: String) throws -> String? {
        guard let s = current, let signer = mqttSigner else { return nil }
        let serverNow = Date().timeIntervalSince1970 + clockOffset
        guard s.mqttKeyExpiresAt - serverNow > Self.keyRefreshMargin else { return nil }
        return try MQTTConnectProof.make(
            clientID: clientID, keyID: s.mqttKeyID, key: signer, timestamp: Int64(serverNow.rounded()))
    }

    private func adopt(_ signer: Curve25519.Signing.PrivateKey, serverTime: TimeInterval) {
        mqttSigner = signer
        clockOffset = serverTime - Date().timeIntervalSince1970
    }

    /// Records the home server's hqn/1 gateway (or its absence) in ServerConfig.
    /// A failed request leaves the previous answer in place.
    func refreshTransportDiscovery() async {
        let host = ServerConfig.host
        var req = URLRequest(url: ServerConfig.authBaseURL.appendingPathComponent("transport"))
        req.timeoutInterval = 5
        guard let (data, resp) = try? await session.data(for: req),
            (resp as? HTTPURLResponse)?.statusCode == 200,
            let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
        else { return }
        guard let hqn = obj["hqn"] as? [String: Any] else {
            if obj.keys.contains("hqn") { ServerConfig.setDiscoveredHQN(nil, enabled: false, for: host) }
            return
        }
        ServerConfig.setDiscoveredHQN(HQNEndpoint.parse(hqn), enabled: (hqn["enabled"] as? Bool) ?? false, for: host)
    }

    private func post<T: Decodable>(path: String, bearer: String? = nil, body: [String: String]) async throws -> T {
        var req = URLRequest(url: ServerConfig.authBaseURL.appendingPathComponent(path))
        req.httpMethod = "POST"
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        if let bearer { req.setValue("Bearer \(bearer)", forHTTPHeaderField: "Authorization") }
        req.httpBody = try JSONSerialization.data(withJSONObject: body)

        let (data, resp) = try await session.data(for: req)
        let code = (resp as? HTTPURLResponse)?.statusCode ?? 0
        guard (200..<300).contains(code) else {
            throw AuthError.badResponse(code, String(data: data, encoding: .utf8) ?? "")
        }
        return try JSONDecoder().decode(T.self, from: data)
    }

    private struct InitResponse: Decodable { let ct: String }

    private struct VerifyResponse: Decodable {
        let id: String
        let pk: String
        let username: String?
        let sessionToken: String
        let mqttKeyId: String
        let mqttKeyExpiresAt: TimeInterval
        let serverTime: TimeInterval
    }

    private struct RefreshResponse: Decodable {
        let mqttKeyId: String
        let mqttKeyExpiresAt: TimeInterval
        let serverTime: TimeInterval
    }
}
