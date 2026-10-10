import Foundation


/// A user as returned by the directory lookup (exact username → client id).
///
/// `id`, not `pk`: the directory deals in `sha256(lowercase-hex(publicKey))`,
/// which is what every other layer names a person by. The key itself is fetched
/// once the person becomes a contact — and verified against this id before it is
/// pinned, which is what makes the lookup safe to trust at all.
struct UserListItem: Codable {
    let username: String
    let id: String
}
