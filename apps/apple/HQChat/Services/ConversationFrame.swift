// One frame: what the app calls a conversation message. Mirrors
// services/server/src/protocol/envelope.ts. `ConversationEnvelopeV3` is the
// codec (magic, offsets, blob framing); this is the shape the ratchet, the
// router and the store see.
//
// `decode` returns the AAD as the literal byte range that arrived (the header
// IS the frame prefix), so a receiver binds what it was sent rather than a
// reconstruction.
//
// Sending: the payload is sealed against the header, so the header comes first:
//
//     let aad = fields.header()
//     let payload = try AESService.encryptRaw(text, key: k, aad: aad)
//     let bytes = fields.withPayload(payload).encoded()
//
// `encoded()` re-derives the same header, so the two cannot drift.

import Foundation

/// A conversation frame. Binary fields are `Data`.
struct ConversationFrame: Equatable {

    typealias Kind = ConversationEnvelopeV3.Kind

    var t: Kind
    /// The sender's client id, lowercase hex.
    var sender: String
    /// The recipient's client id, lowercase hex, bound as AAD so a frame cannot be
    /// replayed to anyone else.
    var to: String
    var msgId: String
    /// Chain selector, lowercase hex.
    var cid: String
    var n: Int
    var pn: Int

    var rk: Data?
    var kemCt: Data?
    var ctId: Data?
    var ctMt: Data?
    var ctOt: Data?
    var otId: Int?
    /// The initiator's full public key, raw bytes.
    var senderPk: Data?

    /// AES-GCM `[IV 12][tag 16][ct]`, raw.
    var payload: Data

    // MARK: - Writing

    /// The bytes to bind as AAD for a frame being SENT.
    ///
    /// `payload` is ignored here on purpose: it is the thing being
    /// authenticated, and it does not exist yet when this is called.
    /// Nil when these fields cannot make a well-formed frame — see `validate`.
    func header() -> Data? {
        guard validate() == nil else { return nil }
        return asV3().canonicalHeader()
    }

    /// Checked on the way out as well as in: see
    /// `ConversationEnvelopeV3.validate()`, the one accept set.
    func validate() -> String? {
        asV3().validate()?.rawValue
    }

    /// The complete frame ready to publish, or nil when it would not be one.
    func encoded() -> Data? {
        guard validate() == nil, !payload.isEmpty else { return nil }
        return asV3().encoded()
    }

    func withPayload(_ payload: Data) -> ConversationFrame {
        var copy = self
        copy.payload = payload
        return copy
    }

    // MARK: - Reading

    /// Decodes a frame, with the AAD it must be opened against. The magic and
    /// version byte are inside the AAD; anything that fails there is not a frame.
    static func decode(_ raw: Data) -> (frame: ConversationFrame, aad: Data, rejection: String?)? {
        let got = ConversationEnvelopeV3.decodeReporting(raw)
        guard let env = got.frame, let aad = got.aad else { return nil }
        return (ConversationFrame(env), aad, nil)
    }

    /// `decode`, and the reason when it refuses — a dropped frame with no
    /// explanation is how a broken handshake stays invisible.
    static func decodeReporting(_ raw: Data) -> (result: (frame: ConversationFrame, aad: Data)?, reason: String) {
        let got = ConversationEnvelopeV3.decodeReporting(raw)
        guard let env = got.frame, let aad = got.aad else {
            return (nil, got.rejection?.rawValue ?? "unknown")
        }
        return ((ConversationFrame(env), aad), "")
    }

    // MARK: - The codec

    private init(_ e: ConversationEnvelopeV3) {
        t = e.t
        sender = e.sender
        to = e.to
        msgId = e.msgId
        cid = e.cid
        n = e.n
        pn = e.pn
        rk = e.rk
        kemCt = e.kemCt
        ctId = e.ctId
        ctMt = e.ctMt
        ctOt = e.ctOt
        otId = e.otId
        senderPk = e.senderPk
        payload = e.payload
    }

    init(t: Kind, sender: String, to: String, msgId: String, cid: String,
         n: Int, pn: Int, rk: Data? = nil, kemCt: Data? = nil, ctId: Data? = nil,
         ctMt: Data? = nil, ctOt: Data? = nil, otId: Int? = nil, senderPk: Data? = nil,
         payload: Data = Data()) {
        self.t = t; self.sender = sender; self.to = to
        self.msgId = msgId; self.cid = cid; self.n = n; self.pn = pn
        self.rk = rk; self.kemCt = kemCt; self.ctId = ctId; self.ctMt = ctMt
        self.ctOt = ctOt; self.otId = otId; self.senderPk = senderPk
        self.payload = payload
    }

    private func asV3() -> ConversationEnvelopeV3 {
        var out = ConversationEnvelopeV3(
            t: t,
            sender: sender,
            to: to,
            msgId: msgId,
            cid: cid,
            n: n,
            pn: pn,
            payload: payload
        )
        out.rk = rk
        out.kemCt = kemCt
        out.ctId = ctId
        out.ctMt = ctMt
        out.ctOt = ctOt
        out.otId = otId
        out.senderPk = senderPk
        return out
    }

}
