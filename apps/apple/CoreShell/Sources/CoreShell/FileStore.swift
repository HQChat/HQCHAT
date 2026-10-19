import Foundation
import HQChatCore

/// The core's `Store` on the file system: one file per blob under `root`
/// (the profile's directory in Application Support), written atomically.
///
/// Every blob is already sealed by the core, to the device key or under the
/// data key. Files are protected until the first unlock after boot, not
/// completely: frames that arrive while the phone is locked must still be
/// kept, as ciphertext, for the unlock to open. Excluded from backups: the
/// sessions are bound to this device's key and are useless anywhere else.
public final class FileStore: Store, @unchecked Sendable {
    private let root: URL
    private let lock = NSLock()

    public init(root: URL) throws {
        self.root = root
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        var values = URLResourceValues()
        values.isExcludedFromBackup = true
        var dir = root
        try dir.setResourceValues(values)
    }

    /// The engine's keys (`state`, `session/…`, `msg/…/…`): every segment is
    /// letters, digits, `-` or `_`, never empty, `.` or `..`; anything else has
    /// no file.
    private func url(for key: String) -> URL? {
        let segments = key.split(separator: "/", omittingEmptySubsequences: false)
        let valid = !segments.isEmpty && segments.allSatisfy { segment in
            !segment.isEmpty && segment.allSatisfy { $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "-" || $0 == "_") }
        }
        guard valid else { return nil }
        return segments.reduce(root) { $0.appendingPathComponent(String($1), isDirectory: false) }
    }

    public func get(key: String) -> Data? {
        guard let url = url(for: key) else { return nil }
        return lock.withLock { try? Data(contentsOf: url) }
    }

    public func put(key: String, value: Data) throws {
        guard let url = url(for: key) else { throw StoreError.Write(message: "bad key \(key)") }
        try lock.withLock {
            do {
                try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
                #if os(iOS)
                try value.write(to: url, options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])
                #else
                try value.write(to: url, options: .atomic)
                #endif
            } catch {
                throw StoreError.Write(message: error.localizedDescription)
            }
        }
    }

    public func delete(key: String) {
        guard let url = url(for: key) else { return }
        lock.withLock { _ = try? FileManager.default.removeItem(at: url) }
    }

    public func list(prefix: String) -> [String] {
        lock.withLock {
            guard let walker = FileManager.default.enumerator(
                at: root, includingPropertiesForKeys: [.isRegularFileKey], options: [.skipsHiddenFiles]
            ) else { return [] }
            let base = root.resolvingSymlinksInPath().path + "/"
            var keys: [String] = []
            for case let file as URL in walker {
                guard (try? file.resourceValues(forKeys: [.isRegularFileKey]).isRegularFile) == true else { continue }
                let path = file.resolvingSymlinksInPath().path
                guard path.hasPrefix(base) else { continue }
                let key = String(path.dropFirst(base.count))
                if key.hasPrefix(prefix) { keys.append(key) }
            }
            return keys.sorted()
        }
    }
}
