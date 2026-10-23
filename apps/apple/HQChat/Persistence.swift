import CryptoKit
import Foundation
import SQLite3
import SwiftData

struct PersistenceController {
    static let shared = PersistenceController()

    /// DEBUG-only demo mode: launch with env `DEMO_MODE=1` to run against an
    /// in-memory store seeded with sample profiles, friends and messages, for
    /// screenshots without a server.
    static var isDemo: Bool {
        #if DEBUG
        return ProcessInfo.processInfo.environment["DEMO_MODE"] == "1"
        #else
        return false
        #endif
    }

    let container: ModelContainer
    
    init() {
        // The 3.1.1 models stay in the schema until Migration/ goes: the move
        // reads and deletes their rows.
        let schema = Schema([Profile.self, Friend.self, Message.self, PendingFrame.self])
        let config = ModelConfiguration(schema: schema, isStoredInMemoryOnly: Self.isDemo)
        if !Self.isDemo {
            Self.compactIfAsked(config.url)
        }

        do {
            container = try ModelContainer(for: schema, configurations: [config])
            if !Self.isDemo {
                Self.openedStoreURL = config.url
                Self.protectStoreFiles(config.url)
            }
            // Encrypt the store at rest. iOS supports per-file Data Protection
            // (applied below). macOS has no FileProtectionType equivalent, so on
            // the Mac the store relies on FileVault for at-rest encryption — but
            // the identity seed/secret key are never written to this store
            // regardless (they live in the Keychain; see H1), so a readable store
            // does not expose key material.
            if Self.isDemo {
                Self.seedDemoData(into: container)
            }
        } catch {
            fatalError("""
            Failed to create ModelContainer: \(error)
            
            This error usually occurs when the database schema has changed.
            The app will attempt to migrate automatically, but if this persists:
            
            1. Delete the app and reinstall (this will clear all data)
            2. Or manually delete the database file at:
               ~/Library/Containers/app.hqchat.HQChat/Data/Library/Application Support/default.store
            
            Note: All profiles, friends, and messages will be lost if you delete the database.
            """)
        }
    }

    // MARK: - The store's files

    /// The on-disk store this process opened; nil in demo mode and in tests,
    /// whose containers are their own.
    private static var openedStoreURL: URL?

    /// The store's file and its WAL/SHM sidecars.
    private static func storeFiles(_ url: URL) -> [URL] {
        [url, URL(fileURLWithPath: url.path + "-wal"), URL(fileURLWithPath: url.path + "-shm")]
    }

    /// Out of iCloud and Finder backups, and (on iOS) encrypted at rest. It
    /// holds the profile list, and for a profile not yet moved to the core,
    /// 3.1.1 rows with the conversation topics that grant access to them.
    /// None of it is any use elsewhere: the keys it goes with never leave
    /// this device. Applied to the files that exist, so it runs at launch and
    /// again after the store is written for the move.
    static func protectStoreFiles(_ url: URL) {
        for var file in storeFiles(url) where FileManager.default.fileExists(atPath: file.path) {
            var values = URLResourceValues()
            values.isExcludedFromBackup = true
            do {
                try file.setResourceValues(values)
            } catch {
                Log.storage.warning("[Persistence] ⚠️ Could not exclude \(file.lastPathComponent) from backups: \(String(describing: error))")
            }
        }
        #if os(iOS)
        applyFileProtection(to: url)
        #endif
    }

    /// Asks for the store to be compacted at the next launch: SQLite leaves a
    /// deleted row's bytes in free pages and in the WAL, and the 3.1.1 rows
    /// held topic ids. Called once those rows are deleted.
    static func storeNeedsCompacting() {
        guard let url = openedStoreURL else { return }
        protectStoreFiles(url)
        let marker = compactMarker(url)
        if !FileManager.default.createFile(atPath: marker.path, contents: Data()) {
            Log.storage.warning("[Persistence] ⚠️ Could not ask for the store to be compacted")
        }
    }

    private static func compactMarker(_ url: URL) -> URL {
        URL(fileURLWithPath: url.path + ".compact")
    }

    /// Runs the compaction `storeNeedsCompacting` asked for, before anything
    /// opens the store. The marker stays when it fails, so the next launch
    /// tries again.
    private static func compactIfAsked(_ url: URL) {
        let marker = compactMarker(url)
        guard FileManager.default.fileExists(atPath: marker.path) else { return }
        guard compactStore(at: url) else { return }
        do {
            try FileManager.default.removeItem(at: marker)
        } catch {
            Log.storage.warning("[Persistence] ⚠️ Could not clear the compaction request: \(String(describing: error))")
        }
    }

    /// Rewrites the store with nothing in it but live rows: the WAL is folded
    /// in and truncated, then VACUUM rebuilds the file, then the WAL is
    /// truncated again. Nothing else may have the store open.
    static func compactStore(at url: URL) -> Bool {
        var db: OpaquePointer?
        defer { sqlite3_close(db) }
        guard sqlite3_open_v2(url.path, &db, SQLITE_OPEN_READWRITE, nil) == SQLITE_OK, let db else {
            Log.storage.error("[Persistence] ❌ Could not open the store to compact it")
            return false
        }
        for sql in ["PRAGMA wal_checkpoint(TRUNCATE)", "VACUUM", "PRAGMA wal_checkpoint(TRUNCATE)"] {
            guard sqlite3_exec(db, sql, nil, nil, nil) == SQLITE_OK else {
                Log.storage.error("[Persistence] ❌ Compacting the store failed at \(sql): \(String(cString: sqlite3_errmsg(db)))")
                return false
            }
        }
        Log.storage.info("[Persistence] 🧹 store compacted")
        return true
    }

    #if os(iOS)
    /// Encrypt the SwiftData store at rest. `.completeUnlessOpen` keeps the
    /// file encrypted whenever the device is locked, but lets an already-open
    /// store keep working in the background (so we don't lose writes while
    /// handling messages). Applies to the SQLite file and its WAL/SHM sidecars.
    static func applyFileProtection(to url: URL) {
        let fm = FileManager.default
        let paths = [url.path, url.path + "-wal", url.path + "-shm"]
        for path in paths where fm.fileExists(atPath: path) {
            do {
                try fm.setAttributes([.protectionKey: FileProtectionType.completeUnlessOpen],
                                     ofItemAtPath: path)
            } catch {
                Log.storage.warning("[Persistence] ⚠️ Could not set file protection on \(String(describing: path)): \(String(describing: error))")
            }
        }
    }
    #endif

    /// The demo profile, so the profile chrome has something to show.
    static func seedDemoData(into container: ModelContainer) {
        let context = ModelContext(container)
        let profile = Profile(username: "alexrivera", publicKeyHex: "")
        profile.clientID = String(repeating: "a1", count: 32)
        profile.isActive = true
        context.insert(profile)
        try? context.save()
    }

    /// A believable conversation set, served by a store with no engine.
    @MainActor
    static func demoStore() -> ChatStore {
        func id(_ name: String) -> String {
            SHA256.hash(data: Data(name.utf8)).map { String(format: "%02x", $0) }.joined()
        }
        let sarah = id("sarah_k")
        let now = Date()
        let convo: [(String, Bool, TimeInterval, ChatMessage.DeliveryStatus)] = [
            ("Hey! Did the post-quantum keys sync ok?", false, -3600, .sent),
            ("Yep — handshake went through, fully encrypted 🔒", true, -3500, .delivered),
            ("Nice. Calling you in a bit to test voice", false, -3400, .sent),
            ("Standing by 👍", true, -3300, .delivered),
            ("Sent you the build too", true, -120, .queued),
        ]
        let messages = convo.map { text, outgoing, offset, status in
            ChatMessage(id: UUID().uuidString, peer: sarah, isOutgoing: outgoing, content: text,
                        timestamp: now.addingTimeInterval(offset), deliveryStatus: status)
        }
        func friend(_ name: String, online: Bool, secure: Bool) -> Contact {
            Contact(peerID: id(name), username: name, inviteStatus: .accepted, isOnline: online,
                    hasSession: secure, hasPinnedKey: true,
                    lastMessage: name == "sarah_k" ? messages.last : nil)
        }
        let contacts = [
            friend("sarah_k", online: true, secure: true),
            friend("mike99", online: true, secure: true),
            friend("elena.m", online: false, secure: true),
            friend("tom_dev", online: false, secure: false),
            Contact(peerID: id("jordan"), username: "jordan", inviteStatus: .inviteReceived),
        ]
        return ChatStore(demo: contacts, conversations: [sarah: messages], myID: id("alexrivera"))
    }
}
