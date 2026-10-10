import Foundation

/// User profile and directory lookups over REST.
@MainActor
class UserService: ObservableObject {

    private let api: APIClient
    @Published var currentUsername: String?
    @Published var userDirectory: [UserListItem] = []

    private static let usernameUserDefaultsKey = "app.hqchat.currentUsername"

    init(api: APIClient) {
        self.api = api
        self.currentUsername = UserDefaults.standard.string(forKey: Self.usernameUserDefaultsKey)
    }

    /// Set or update the username, then reflect the server's acceptance locally.
    func setUsername(_ username: String) async throws {
        try await api.setUsername(username)
        updateCurrentUsername(username)
    }

    /// Exact-username lookup → client id. The server exposes no bulk directory
    /// (privacy), so an empty query returns nothing rather than "everyone".
    func searchUsers(query: String) async throws {
        let q = query.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !q.isEmpty else {
            userDirectory = []
            return
        }
        if let id = try await api.lookupUser(username: q) {
            userDirectory = [UserListItem(username: q, id: id)]
        } else {
            userDirectory = []
        }
    }

    /// Permanently delete this account and all server-side data (App Store
    /// Guideline 5.1.1(v)). The caller wipes local data afterwards.
    func deleteAccount() async throws {
        try await api.deleteAccount()
    }

    /// Register this device's APNs token. `token` arrives from PushManager as
    /// "platform:hextoken".
    func registerPushToken(_ token: String) async throws {
        let parts = token.split(separator: ":", maxSplits: 1).map(String.init)
        guard parts.count == 2 else { return }
        try await api.registerPushToken(platform: parts[0], token: parts[1])
    }

    /// Update current username (called when the server confirms).
    func updateCurrentUsername(_ username: String) {
        self.currentUsername = username
        UserDefaults.standard.set(username, forKey: Self.usernameUserDefaultsKey)
    }

    /// Update user directory.
    func updateUserDirectory(_ users: [UserListItem]) {
        self.userDirectory = users
    }
}
