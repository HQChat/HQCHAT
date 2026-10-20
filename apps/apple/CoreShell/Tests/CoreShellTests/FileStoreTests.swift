// The file store under the engine's own keys, and an engine that survives a
// restart on it.

import CoreShell
import Foundation
import HQChatCore
import XCTest

final class FileStoreTests: XCTestCase {
    private var dir: URL!

    override func setUpWithError() throws {
        dir = FileManager.default.temporaryDirectory.appendingPathComponent("filestore-\(UUID().uuidString)")
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: dir)
    }

    func testBlobsRoundTripUnderNestedKeysAndListInOrder() throws {
        let store = try FileStore(root: dir)
        try store.put(key: "state", value: Data([1]))
        try store.put(key: "msg/aa/00000000000000000002/bb", value: Data([2]))
        try store.put(key: "msg/aa/00000000000000000001/cc", value: Data([3]))
        try store.put(key: "msg/ab/00000000000000000001/dd", value: Data([4]))
        XCTAssertEqual(store.get(key: "state"), Data([1]))
        XCTAssertEqual(store.list(prefix: "msg/aa/"), [
            "msg/aa/00000000000000000001/cc",
            "msg/aa/00000000000000000002/bb",
        ])
        try store.put(key: "state", value: Data([9]))
        XCTAssertEqual(store.get(key: "state"), Data([9]), "a put replaces")
        store.delete(key: "state")
        XCTAssertNil(store.get(key: "state"))
        XCTAssertEqual(store.list(prefix: "").count, 3)
        // A prefix that ends inside a segment still matches by prefix.
        XCTAssertEqual(store.list(prefix: "msg/a"), [
            "msg/aa/00000000000000000001/cc",
            "msg/aa/00000000000000000002/bb",
            "msg/ab/00000000000000000001/dd",
        ])
        XCTAssertEqual(store.list(prefix: "msg/aa/00000000000000000002"), ["msg/aa/00000000000000000002/bb"])
        XCTAssertEqual(store.list(prefix: "msg/zz/"), [], "a directory that does not exist lists nothing")
        XCTAssertEqual(store.list(prefix: "../"), [], "a prefix that could leave the directory lists nothing")
    }

    func testAPutLeavesOnlyTheBlobBehindOwnerOnly() throws {
        let store = try FileStore(root: dir)
        try store.put(key: "session/aa", value: Data([1]))
        try store.put(key: "session/aa", value: Data([2, 3]))
        XCTAssertEqual(store.get(key: "session/aa"), Data([2, 3]), "a put replaces")
        let names = try FileManager.default.contentsOfDirectory(atPath: dir.appendingPathComponent("session").path)
        XCTAssertEqual(names, ["aa"], "no temporary file is left beside the blob")
        let mode = try FileManager.default.attributesOfItem(atPath: dir.appendingPathComponent("session/aa").path)[.posixPermissions] as? Int
        XCTAssertEqual(mode, 0o600)
    }

    func testAKeyThatCouldLeaveTheDirectoryHasNoFile() throws {
        let store = try FileStore(root: dir)
        for key in ["", "../escape", "a//b", "a/./b", "/abs", "a b", "é"] {
            XCTAssertThrowsError(try store.put(key: key, value: Data([1])), key)
            XCTAssertNil(store.get(key: key))
        }
        XCTAssertEqual(store.list(prefix: ""), [])
    }

    func testTheDirectoryIsLeftOutOfBackups() throws {
        _ = try FileStore(root: dir)
        XCTAssertEqual(try dir.resourceValues(forKeys: [.isExcludedFromBackupKey]).isExcludedFromBackup, true)
    }

    func testAnEngineReopensItsIdentityFromTheFiles() throws {
        let vault = SoftwareVault()
        let config = Config(serverUrl: "https://hqchat.test", profileId: "p", device: .ios)
        _ = try Engine(config: config, vault: vault, store: try FileStore(root: dir)).createIdentity()
        let restarted = try Engine(config: config, vault: vault, store: try FileStore(root: dir))
        XCTAssertEqual(try restarted.unlock(now: 0), [.friendsChanged])
    }
}
