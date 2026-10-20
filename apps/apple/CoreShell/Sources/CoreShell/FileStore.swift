import Foundation
import HQChatCore

/// The core's `Store` on the file system: one file per blob under `root`
/// (the profile's directory in Application Support), written atomically and
/// durably: a put has reached the disk when it returns.
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

    /// Writes `value` to a temporary file beside the blob, flushes it to the
    /// disk, renames it over the blob, then flushes the directory, so the
    /// rename itself survives a power cut (the core's ports.rs: "Durable on
    /// return"). A plain `.atomic` write only reaches the drive's cache: after
    /// a power cut the blob could be the old one, and a rolled-back session
    /// re-derives message keys it already used and loses what follows.
    public func put(key: String, value: Data) throws {
        guard let url = url(for: key) else { throw StoreError.Write(message: "bad key \(key)") }
        try lock.withLock {
            let dir = url.deletingLastPathComponent()
            // Never a key: every key segment starts with a letter, digit, - or _.
            let tmp = dir.appendingPathComponent(".tmp-\(url.lastPathComponent)", isDirectory: false)
            do {
                let created = try createDirectories(dir)
                try writeDurably(value, to: tmp)
                guard rename(tmp.path, url.path) == 0 else {
                    throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
                }
                try Self.flush(directory: dir)
                // A directory just made is an entry in its parent: flush those too.
                for parent in created { try Self.flush(directory: parent.deletingLastPathComponent()) }
            } catch {
                try? FileManager.default.removeItem(at: tmp)
                throw StoreError.Write(message: error.localizedDescription)
            }
        }
    }

    /// Creates `dir` and any missing parent up to `root`; returns the ones it made.
    private func createDirectories(_ dir: URL) throws -> [URL] {
        var missing: [URL] = []
        var cursor = dir.standardizedFileURL
        let top = root.standardizedFileURL.path
        while cursor.path.count > top.count, !FileManager.default.fileExists(atPath: cursor.path) {
            missing.append(cursor)
            cursor = cursor.deletingLastPathComponent()
        }
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return missing
    }

    private func writeDurably(_ value: Data, to tmp: URL) throws {
        var attributes: [FileAttributeKey: Any] = [.posixPermissions: 0o600]
        #if os(iOS)
        attributes[.protectionKey] = FileProtectionType.completeUntilFirstUserAuthentication
        #endif
        guard FileManager.default.createFile(atPath: tmp.path, contents: nil, attributes: attributes) else {
            throw CocoaError(.fileWriteUnknown, userInfo: [NSFilePathErrorKey: tmp.path])
        }
        let handle = try FileHandle(forWritingTo: tmp)
        defer { try? handle.close() }
        try handle.write(contentsOf: value)
        try Self.fullSync(handle.fileDescriptor)
    }

    /// Flushes `fd` to the disk itself, past the drive's cache: `fsync` alone
    /// stops at the cache on Apple platforms. Falls back to `fsync` where the
    /// file system has no `F_FULLFSYNC`.
    private static func fullSync(_ fd: Int32) throws {
        if fcntl(fd, F_FULLFSYNC) == 0 { return }
        guard fsync(fd) == 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
    }

    private static func flush(directory: URL) throws {
        let fd = open(directory.path, O_RDONLY)
        guard fd >= 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
        defer { close(fd) }
        try fullSync(fd)
    }

    public func delete(key: String) {
        guard let url = url(for: key) else { return }
        lock.withLock { _ = try? FileManager.default.removeItem(at: url) }
    }

    /// Walks only the directory the prefix names up to its last `/`
    /// (`msg/<peer>/` is one peer's messages), not the whole profile: the
    /// core lists a conversation on every message, receipt and status change.
    public func list(prefix: String) -> [String] {
        // The part of the prefix that names directories; a key under it must
        // pass the same segment rule, so a prefix that fails it matches nothing.
        let dirPart = prefix.split(separator: "/", omittingEmptySubsequences: false).dropLast()
        let start: URL
        if dirPart.isEmpty {
            start = root
        } else {
            guard let dir = url(for: dirPart.joined(separator: "/")) else { return [] }
            start = dir
        }
        return lock.withLock {
            guard FileManager.default.fileExists(atPath: start.path),
                  let walker = FileManager.default.enumerator(
                at: start, includingPropertiesForKeys: [.isRegularFileKey], options: [.skipsHiddenFiles]
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
