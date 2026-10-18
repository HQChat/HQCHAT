// The client-to-client wire format: length-prefixed binary whose header is the
// frame's own prefix, so the AAD is a byte range of what arrived and has no
// second encoding to disagree with. Mirrors services/server/test/reference/protocol/envelope.ts
// byte-for-byte; both sides assert envelope-v3-vectors.json.
//
// The header binds the version and the recipient (`to`), so a frame cannot be
// replayed to someone else or reinterpreted under another version.
//
// ── Layout ──────────────────────────────────────────────────────────────────
// All integers big-endian. The header runs from byte 0 to the start of the
// payload length, and that whole span is the AAD.
//
//   0   magic     4 bytes   "HQCE"
//   4   version   u8        3
//   5   kind      u8        0 = msg, 1 = init, 2 = receipt
//   6   flags     u8        bit0 rk, bit1 kemCt, bit2 one-time (ctOt+otId)
//   7   sender    32 bytes  the sender's client id, raw
//   39  to        32 bytes  the recipient's client id, raw
//   71  cid       16 bytes  the chain selector, raw
//   87  n         u32
//   91  pn        u32
//   95  msgIdLen  u8        1..128
//   96  msgId     msgIdLen bytes, UTF-8
//       [rk]      u32 len + rk
//       [kemCt]   u32 len + kemCt
//       [init]    u32 len + senderPk, u32 len + ctId, u32 len + ctMt
//       [oneTime] u32 len + ctOt, u32 otId
//   --- header ends here; everything above is the AAD ---
//       payload   u32 len + bytes

import Foundation

/// One frame on the wire. Binary fields are `Data`; `sender` and `cid` are
/// exposed as hex, the form `PeerID`, `DoubleRatchet.chainId` and stored digests use.
struct ConversationEnvelopeV3: Equatable {

    enum Kind: UInt8 {
        case message = 0   // everything after the handshake
        case initiate = 1  // opens a session; carries the handshake AND a message
        case receipt = 2   // acknowledges the message whose id it carries; laid out as a msg

        /// A `msg` or a `receipt`: an ordinary ratchet frame.
        var isInSession: Bool { self != .initiate }
    }

    let t: Kind
    /// Lowercase hex, 64 characters — decoded from the 32 raw bytes on the wire.
    let sender: String
    /// The recipient's client id: lowercase hex, 64 characters.
    let to: String
    let msgId: String
    /// Lowercase hex, 32 characters.
    let cid: String
    let n: Int
    let pn: Int

    var rk: Data?
    var kemCt: Data?
    var ctId: Data?
    var ctMt: Data?
    var ctOt: Data?
    var otId: Int?
    /// The initiator's full public key, raw (`init` only).
    var senderPk: Data?

    /// AES-GCM `[IV 12][tag 16][ct]`, raw.
    var payload: Data

    // MARK: - The format

    private static let magic = Data("HQCE".utf8)
    static let version: UInt8 = 3

    /// `rk` and `kemCt` have independent bits. A `msg` carries both or neither: a
    /// ratchet key without a ciphertext cannot be acted on, and a ciphertext
    /// without a key names no chain. An `init` carries `rk` alone: it advertises
    /// the initiator's first chain, with no peer ratchet key to encapsulate to.
    private static let flagRk: UInt8 = 0x01
    private static let flagKemCt: UInt8 = 0x02
    private static let flagOneTime: UInt8 = 0x04
    private static let allFlags: UInt8 = 0x07

    private static let offVersion = 4
    private static let offKind = 5
    private static let offFlags = 6
    private static let offSender = 7
    private static let offTo = 39
    private static let offCid = 71
    private static let offN = 87
    private static let offPn = 91
    private static let offMsgIdLen = 95
    private static let offMsgId = 96

    static let idBytes = 32
    static let cidBytes = 16
    static let maxMsgIdBytes = 128

    /// A bound that keeps a hostile length prefix from being read as an
    /// allocation request. Not a size policy — the transport has one of those.
    static let maxFieldBytes = 1 << 20

    /// Why a frame was refused: every refusal names one, so a dropped frame can be
    /// diagnosed.
    enum Rejection: String {
        case notV3            = "not a v3 frame — wrong magic, version, or too short"
        case badKind          = "kind is not msg, init or receipt"
        case unknownFlags     = "a flag bit this build does not understand"
        case unpairedStep     = "a msg carries rk without kemCt, or the reverse"
        case initBadStep      = "an init must advertise rk and must not carry kemCt"
        case badMsgId         = "msgId is empty, over 128 bytes, or not valid UTF-8"
        case truncated        = "a length prefix runs past the end of the frame"
        case emptyField       = "a length-prefixed field is empty or implausibly large"
        case badCounter       = "n, pn or otId is negative or beyond a u32"
        case badChainId       = "cid is not 32 lowercase hex characters"
        case unpairedOneTime  = "ctOt and otId travel together or not at all"
        case trailingBytes    = "bytes after the payload"
        case badSender        = "sender or recipient is not a well-formed client id"
        case initKeyIdMismatch = "init senderPk does not hash to sender — REFUSED, possible substitution"
    }

    // MARK: - Writing

    private static func u32(_ value: Int) -> Data {
        let v = UInt32(truncatingIfNeeded: value)
        return Data([UInt8(truncatingIfNeeded: v >> 24), UInt8(truncatingIfNeeded: v >> 16),
                     UInt8(truncatingIfNeeded: v >> 8), UInt8(truncatingIfNeeded: v)])
    }

    private static func blob(_ d: Data) -> Data { u32(d.count) + d }

    /// The largest counter the format carries (four bytes).
    static let maxCounter = 0xffff_ffff

    /// Why an encoder validates: the two implementations fail differently on
    /// malformed input (TypeScript writes into a fixed buffer, so a short field
    /// leaves zeros; this side appends, so it shifts every later field), and the
    /// same struct must never give different bytes. So: refuse, rather than pad,
    /// shift, wrap or trap.
    ///
    /// The case is reachable: `sealMessage` reads `myID` and `friend.peerID`,
    /// which are empty with no profile loaded or before a directory sync fills an
    /// invited contact.
    func validate() -> Rejection? {
        guard Self.isHex(sender, bytes: Self.idBytes) else { return .badSender }
        guard Self.isHex(to, bytes: Self.idBytes) else { return .badSender }
        guard Self.isHex(cid, bytes: Self.cidBytes) else { return .badChainId }
        guard Self.isCounter(n), Self.isCounter(pn) else { return .badCounter }

        let msgIdBytes = msgId.utf8.count
        guard msgIdBytes > 0, msgIdBytes <= Self.maxMsgIdBytes else { return .badMsgId }

        // Present-but-empty is refused for the same reason the decoder refuses
        // it: a zero-length blob is a field the sender believed in and the
        // receiver cannot use.
        for blob in [rk, kemCt, ctId, ctMt, ctOt, senderPk] {
            if let blob, blob.isEmpty || blob.count > Self.maxFieldBytes { return .emptyField }
        }
        if let otId, !Self.isCounter(otId) { return .badCounter }

        // The pairing rules, applied on the way OUT as well as the way in — an
        // encoder that can emit a frame its own decoder refuses is not much of a
        // contract.
        if t.isInSession, (rk == nil) != (kemCt == nil) { return .unpairedStep }
        if t == .initiate {
            guard rk != nil, kemCt == nil else { return .initBadStep }
            guard let senderPk, ctId != nil, ctMt != nil else { return .initBadStep }
            guard PeerID.matches(publicKeyHex: senderPk.hexString, id: sender) else {
                return .initKeyIdMismatch
            }
        }
        if (ctOt == nil) != (otId == nil) { return .unpairedOneTime }
        return nil
    }

    private static func isHex(_ value: String, bytes: Int) -> Bool {
        value.count == bytes * 2 && value.allSatisfy {
            ("0"..."9").contains($0) || ("a"..."f").contains($0)
        }
    }

    private static func isCounter(_ v: Int) -> Bool { v >= 0 && v <= maxCounter }

    /// The bytes both peers bind as AAD, and the prefix of the frame itself:
    /// `encoded()` appends the payload, and `decode` reports where it ended.
    ///
    /// Nil when the fields cannot make a well-formed frame (see `validate`).
    func canonicalHeader() -> Data? {
        guard validate() == nil,
              let senderRaw = Data(hexString: sender),
              let toRaw = Data(hexString: to),
              let cidRaw = Data(hexString: cid)
        else { return nil }
        let msgIdBytes = Data(msgId.utf8)

        let hasOneTime = ctOt != nil && otId != nil
        var flags: UInt8 = 0
        if rk != nil { flags |= Self.flagRk }
        if kemCt != nil { flags |= Self.flagKemCt }
        if hasOneTime { flags |= Self.flagOneTime }

        var out = Data()
        out.reserveCapacity(Self.offMsgId + msgIdBytes.count)
        out += Self.magic
        out.append(Self.version)
        out.append(t.rawValue)
        out.append(flags)
        out += senderRaw
        out += toRaw
        out += cidRaw
        out += Self.u32(n)
        out += Self.u32(pn)
        out.append(UInt8(truncatingIfNeeded: msgIdBytes.count))
        out += msgIdBytes

        if let rk { out += Self.blob(rk) }
        if let kemCt { out += Self.blob(kemCt) }
        if t == .initiate, let senderPk, let ctId, let ctMt {
            out += Self.blob(senderPk)
            out += Self.blob(ctId)
            out += Self.blob(ctMt)
        }
        if hasOneTime, let ctOt, let otId {
            out += Self.blob(ctOt)
            out += Self.u32(otId)
        }
        return out
    }

    /// Header + payload. The complete frame, or nil when it would not be one.
    func encoded() -> Data? {
        guard !payload.isEmpty, payload.count <= Self.maxFieldBytes,
              let header = canonicalHeader() else { return nil }
        return header + Self.blob(payload)
    }

    // MARK: - Reading

    /// Whether these bytes even claim to be a v3 frame. Cheap, and total.
    static func looksLikeV3(_ raw: Data) -> Bool {
        raw.count >= offMsgId
            && raw.prefix(4) == magic
            && raw[raw.startIndex + offVersion] == version
    }

    static func decode(_ raw: Data) -> ConversationEnvelopeV3? {
        decodeReporting(raw).frame
    }

    /// `decode`, plus the reason when it refuses, plus the AAD as the exact byte
    /// range that arrived.
    static func decodeReporting(
        _ raw: Data
    ) -> (frame: ConversationEnvelopeV3?, aad: Data?, rejection: Rejection?) {
        do {
            // Offsets below are from zero, so a slice is copied first.
            let (frame, aad) = try readFrame(raw.startIndex == 0 ? raw : Data(Array(raw)))
            return (frame, aad, nil)
        } catch {
            return (nil, nil, error)
        }
    }

    private static func readFrame(_ raw: Data) throws(Rejection) -> (ConversationEnvelopeV3, Data) {
        guard looksLikeV3(raw) else { throw .notV3 }
        guard let t = Kind(rawValue: raw[offKind]) else { throw .badKind }

        let flags = raw[offFlags]
        // Unknown bits are refused rather than ignored: the flags byte is inside
        // the AAD, so the tag would still verify over a meaning this build lacks.
        guard flags & ~allFlags == 0 else { throw .unknownFlags }
        let hasRk = flags & flagRk != 0
        let hasKemCt = flags & flagKemCt != 0
        let hasOneTime = flags & flagOneTime != 0
        if t.isInSession, hasRk != hasKemCt { throw .unpairedStep }
        if t == .initiate, !hasRk || hasKemCt { throw .initBadStep }

        let msgIdLen = Int(raw[offMsgIdLen])
        guard msgIdLen > 0, msgIdLen <= maxMsgIdBytes else { throw .badMsgId }
        guard raw.count >= offMsgId + msgIdLen else { throw .truncated }
        let msgIdBytes = raw[offMsgId..<(offMsgId + msgIdLen)]
        // Refused rather than replaced: lenient decoding would substitute U+FFFD
        // and change the bytes the AAD covers.
        guard let msgId = String(data: msgIdBytes, encoding: .utf8),
              Data(msgId.utf8) == msgIdBytes else { throw .badMsgId }

        var reader = FieldReader(raw: raw, cursor: offMsgId + msgIdLen)
        let rk = hasRk ? try reader.blob() : nil
        let kemCt = hasKemCt ? try reader.blob() : nil
        let initFields = t == .initiate
            ? (senderPk: try reader.blob(), ctId: try reader.blob(), ctMt: try reader.blob())
            : nil
        let oneTime = hasOneTime ? (ctOt: try reader.blob(), otId: try reader.u32()) : nil
        // Everything up to here is the header, and the header is the AAD.
        let headerEnd = reader.cursor
        let payload = try reader.blob()
        // Nothing legitimate follows the payload.
        guard reader.cursor == raw.count else { throw .trailingBytes }

        let sender = raw[offSender..<(offSender + idBytes)].hexString
        let to = raw[offTo..<(offTo + idBytes)].hexString
        let cid = raw[offCid..<(offCid + cidBytes)].hexString
        guard PeerID.isWellFormed(sender), PeerID.isWellFormed(to) else { throw .badSender }
        // An `init` must carry the key its `sender` id names: this makes the id a
        // commitment rather than a label.
        if let initFields, !PeerID.matches(publicKeyHex: initFields.senderPk.hexString, id: sender) {
            throw .initKeyIdMismatch
        }

        var frame = ConversationEnvelopeV3(
            t: t, sender: sender, to: to, msgId: msgId, cid: cid,
            n: FieldReader.u32(raw, at: offN), pn: FieldReader.u32(raw, at: offPn), payload: payload
        )
        frame.rk = rk
        frame.kemCt = kemCt
        frame.senderPk = initFields?.senderPk
        frame.ctId = initFields?.ctId
        frame.ctMt = initFields?.ctMt
        frame.ctOt = oneTime?.ctOt
        frame.otId = oneTime?.otId
        return (frame, Data(raw[0..<headerEnd]))
    }
}

extension ConversationEnvelopeV3.Rejection: Error {}

/// Reads length-prefixed fields from a zero-based `raw`, refusing anything
/// short, oversized or empty as `.truncated`.
private struct FieldReader {
    let raw: Data
    var cursor: Int

    static func u32(_ raw: Data, at offset: Int) -> Int {
        (Int(raw[offset]) << 24) | (Int(raw[offset + 1]) << 16) | (Int(raw[offset + 2]) << 8) | Int(raw[offset + 3])
    }

    mutating func u32() throws(ConversationEnvelopeV3.Rejection) -> Int {
        guard raw.count >= cursor + 4 else { throw .truncated }
        defer { cursor += 4 }
        return Self.u32(raw, at: cursor)
    }

    /// A non-empty `u32 len + bytes` field.
    mutating func blob() throws(ConversationEnvelopeV3.Rejection) -> Data {
        let len = try u32()
        guard len > 0, len <= ConversationEnvelopeV3.maxFieldBytes, raw.count >= cursor + len else {
            throw .truncated
        }
        defer { cursor += len }
        return Data(raw[cursor..<(cursor + len)])
    }

}
