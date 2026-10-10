import Foundation

/// Everything that ties this build to one deployment: the official app's
/// defaults. Each value can also be overridden per build through the Info.plist
/// key named beside it; a user reaches another server through a profile's home
/// server, not by rebuilding.
///
/// Nothing secret belongs here: it ships inside the app bundle.
enum Deployment {

    /// The default home server. Overridable per build with Info.plist `ServerHost`,
    /// and per profile in the app (a profile is an identity plus a home server).
    ///
    /// A profile with no `serverURL` follows this value, so changing it moves
    /// every such profile on update. A profile that names a host keeps it.
    static let serverHost = "api.hqchat.app"

    /// The host of the site and legal pages, served by the Cloudflare Worker.
    /// It is not `serverHost`: the apex is the Worker, `api.` is the origin.
    static let siteHost = "hqchat.app"

    /// The published legal pages, under `siteHost`.
    ///
    /// Each path must be listed in `worker_paths` (`infra/terraform/cloudflare.tf`),
    /// which takes exact paths. A missing one falls through to the origin and
    /// answers a REST 404; a site test checks the list.
    static var siteURL: URL { URL(string: "https://\(siteHost)")! }
    static var eulaURL: URL { siteURL.appendingPathComponent("eula") }
    static var privacyURL: URL { siteURL.appendingPathComponent("privacy") }
    static var termsURL: URL { siteURL.appendingPathComponent("terms") }
    static var supportURL: URL { siteURL.appendingPathComponent("support") }

    /// SHA-256 of the server's SubjectPublicKeyInfo, base64: the TLS pins.
    ///
    /// Empty means system trust only. A wrong pin locks every installed copy out
    /// with no server-side fix, so before filling this in
    /// (`scripts/compute-spki-pins.sh` prints candidates):
    ///
    /// 1. **Pin the CA or intermediate, not the leaf.** Cloudflare rotates leaf
    ///    certificates on its own schedule.
    /// 2. **Ship at least two pins** from different issuers, so one revocation
    ///    does not strand every install.
    ///
    /// Overridable per build with the Info.plist array `ServerPinnedSPKIHashes`.
    static let pinnedSPKIHashes: [String] = []

    /// The default server's hqn/1 gateway: host, port and its pinned static public
    /// keys. Empty means the build relies on `GET /auth/transport` discovery, and
    /// connects over WSS when nothing is discovered. Fill from
    /// `services/server/scripts/noise-gw-keys.ts --public` (current and next key id).
    static let hqnHost: String? = nil
    static let hqnPort: UInt16 = 443
    static let hqnKeys: [NoiseHQN.ServerKeys] = []

    static func hqnEndpoint(forHost host: String) -> HQNEndpoint? {
        guard host == serverHost, let h = hqnHost, !hqnKeys.isEmpty else { return nil }
        return HQNEndpoint(host: h, port: hqnPort, keys: hqnKeys)
    }

    /// Sentry DSN for the app's project. Send-only, so it ships in the bundle
    /// ("" turns reporting off). Overridable per build with Info.plist
    /// `SENTRY_DSN`. The Deploy workflow warns when it is empty.
    static let sentryDSN = "https://38295ab9575bb93ce6bec38f8ed6b6d5@o4505907327926272.ingest.us.sentry.io/4511834382401536"
}
