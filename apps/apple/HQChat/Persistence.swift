import CryptoKit
import Foundation
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

        do {
            container = try ModelContainer(for: schema, configurations: [config])
            // Encrypt the store at rest. iOS supports per-file Data Protection
            // (applied below). macOS has no FileProtectionType equivalent, so on
            // the Mac the store relies on FileVault for at-rest encryption — but
            // the identity seed/secret key are never written to this store
            // regardless (they live in the Keychain; see H1), so a readable store
            // does not expose key material.
            #if os(iOS)
            if !Self.isDemo {
                Self.applyFileProtection(to: config.url)
            }
            #endif
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
