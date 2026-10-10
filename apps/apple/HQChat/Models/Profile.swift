import Foundation
import SwiftData

@Model
final class Profile {
    var id: UUID
    /// The username; read it through `username`.
    var name: String
    var createdAt: Date
    var isActive: Bool
    var publicKeyHex: String
    /// Username chosen at creation, cached locally until the first successful
    /// connect — then registered with the server. Cleared once confirmed.
    var desiredUsername: String?
    /// The home server this profile is attached to (full WebSocket URL); nil
    /// means the build's default server. A profile is an
    /// identity + a home server, so each profile can live on a different server.
    var serverURL: String?

    @Relationship(deleteRule: .cascade) var friends: [Friend]?

    init(username: String, publicKeyHex: String, serverURL: String? = nil) {
        self.id = UUID()
        self.name = username
        self.createdAt = Date()
        self.isActive = false
        self.publicKeyHex = publicKeyHex
        self.serverURL = serverURL
        self.friends = []
    }

    /// The handle this identity is known by, locally and on the server.
    var username: String {
        get { name }
        set { name = newValue }
    }

    /// The home server's HOST. A profile is an identity + a home server, and
    /// since the cutover every endpoint (auth, REST, MQTT) is derived from that
    /// one host — there is no WebSocket URL to store any more. Accepts whatever
    /// shape was saved or typed: `wss://host/ws`, `https://host`, or a bare host.
    var serverHost: String? {
        guard let raw = serverURL?.trimmingCharacters(in: .whitespacesAndNewlines),
              !raw.isEmpty else { return nil }
        // The port is part of the server's identity, not decoration: a home
        // server on a non-default port (a self-hosted box, the local e2e stack)
        // was silently pointed at :443 when only `url.host` was kept.
        if let url = URL(string: raw), let host = url.host, !host.isEmpty {
            if let port = url.port { return "\(host):\(port)" }
            return host
        }
        // Bare host (possibly with a path) — take the first component.
        return raw.split(separator: "/").first.map(String.init)
    }
    
    /// Get public key as Data
    var publicKey: Data? {
        return Data(hexString: publicKeyHex)
    }

    /// This identity's CLIENT ID — `sha256(lowercase-hex(publicKeyHex))`.
    ///
    /// What the server, the broker and every peer call this profile: the MQTT
    /// client id and username, the owner of `u/{id}/presence`, and the `sender`
    /// on every frame it publishes. Derived rather than stored, because it is a
    /// pure function of a column that never changes — a stored copy could only
    /// ever be a way for the two to disagree.
    var peerID: String {
        PeerID.from(publicKeyHex: publicKeyHex)
    }
}

