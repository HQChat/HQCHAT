# End-to-end, in Swift

One command runs a whole interaction through the real implementation:

```bash
bash apps/apple/e2e/run.sh
```

## What it actually exercises

The **real** ratchet, the frame codec, the AEAD, the
identity commitment, the topic vocabulary and the initiator-authentication
handshake — compiled straight from `HQChat/Services`. The KEM is **real HQC**
through the app's own adapter (`HQCKem` → `HQCService` → `libhqc_wrap`), not a
stub, which is what makes this end-to-end rather than a state-machine test.

The script:

1. **Friend request** — each side pins the other's key, and a key that does not
   hash to the id that named it is refused. Who holds which topic id is
   modelled, including the handshake topic, which only the two members are
   handed.
2. **First contact** — an `init` to the peer's inbox, which is *held rather than
   opened*: it proves nothing about who sent it. The receiver challenges, the
   sender proves possession of its identity key, and only then does the message
   open.
3. **Five messages each way**, delivered on every turn so the ratchet actually
   flips direction rather than running as two one-way streams.
4. **Integrity** — every message arrived in order and byte-identical, multi-byte
   text survived, nothing was delivered twice, a byte-identical replay yielded
   nothing, and the conversation survived it.

## The bus is a directory

Every packet is written to a file and read back before it is parsed, so a round
trip through the filesystem is part of the test rather than something the
harness optimises away.

Packets are stored as **hex**, one line per file: hex survives any editor or
diff, and a truncated write is visibly truncated. Each packet's SHA-256 goes in
`manifest.tsv` and is verified on read, so a file that changed between write
and read is caught at the bus rather than as a decryption failure three layers
up.

The transcript is worth reading. From one run:

```
seq  topic                 from      bytes    
1    u/59ee8113…/inbox     5d035cd2  57967B   ← the init (with a one-time prekey)
2    hs/44fd86a7…          59ee8113  14527B   ← the challenge
3    hs/44fd86a7…          5d035cd2    134B   ← the proof
4    u/59ee8113…/inbox     5d035cd2  57935B   ← a burst before the reply: still typed init
5    u/59ee8113…/inbox     5d035cd2  57945B
6    cv/f9f3c3ec…          59ee8113  21841B   ← first reply, stepping the ratchet
7    cv/f9f3c3ec…          5d035cd2    216B   ← an ordinary message
```

An ordinary message is 177–250 bytes; a stepping one about 21.8 kB; an `init`
about 58 kB.

## What it is not

**It is not the app.** `ConversationRouter` is `@MainActor` over SwiftData, so
importing it would mean a model container, a Keychain, a profile and a biometric
prompt — none of which says anything about the protocol. `Party.swift` therefore
**mirrors** the router's orchestration (hold an init, challenge, prove, open),
and that is a real caveat: a divergence between the two would not be caught here.
It is written to be read side by side with the original.

**It is not a broker.** Ordering, QoS and the ACL are modelled; sockets are not.
`services/server/test/scenarios` covers the real EMQX path, and needs Docker to do it.
