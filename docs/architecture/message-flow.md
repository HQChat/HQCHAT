# Message flow

One message end to end: becoming friends, the first contact, ordinary
messages, presence and waking an offline phone. The cryptography is specified
in [e2ee-protocol.md](e2ee-protocol.md); topics and their permissions in
[emqx-acl.md](emqx-acl.md).

## Topics

| Topic | Who subscribes | Who publishes | Carries |
|---|---|---|---|
| `u/{id}/inbox` | its owner | any signed-in client | `init` frames (first contact) |
| `u/{id}/graph` | its owner | the server, through the admin API | a nudge: "your friend graph changed" |
| `u/{id}/presence` | anyone | its owner (retained, and as the Last-Will) | `{"s":"online"}` or `{"s":"offline"}` |
| `cv/{convo_id}` | the two members | the two members | conversation frames |
| `hs/{handshake_id}` | the two members | the two members | handshake challenges and proofs |

`convo_id` and `handshake_id` are random 256-bit ids minted with the
friendship and handed only to its members.

## 1. Becoming friends

```mermaid
sequenceDiagram
    participant A as Alice
    participant S as server
    participant B as Bob
    A->>S: GET /users?username=bob → id
    A->>S: POST /friends/invite { to: "bob" }
    S-->>B: nudge on u/bob/graph
    B->>S: GET /friends/invites
    B->>S: POST /friends/accept { from: alice }
    S->>S: friendship row with fresh convo_id, handshake_id
    S-->>A: nudge on u/alice/graph
    A->>S: GET /friends → { id, convo_id, handshake_id }
    A->>S: GET /peer/{bob}/key
    A->>A: check sha256(hex(key)) == id, pin the key
```

Both clients re-read `/friends` on every nudge and every 60 seconds, subscribe
to each friendship's `cv/` and `hs/` topics and to each friend's presence, and
fetch any identity key they lack (once per contact, verified against its id).
Limits: 150 friends (held under concurrent accepts), 20 invites a day.
Cancelling, declining, removing and blocking all nudge both sides; removing or
blocking also retires the topic ids and drops both members' live
subscriptions to them, and a block makes the blocker's client forget the
session.

## 2. The first message

```mermaid
sequenceDiagram
    participant A as Alice
    participant S as server
    participant E as EMQX
    participant B as Bob
    A->>S: POST /prekeys/claim { peer: bob }
    S-->>A: identity, medium-term and one-time prekey
    A->>A: startAsInitiator, seal "hi"
    A->>E: publish init on u/bob/inbox
    E-->>B: init
    B->>E: challenge on hs/{handshake_id}
    E-->>A: challenge
    A->>E: proof on hs/{handshake_id}
    E-->>B: proof
    B->>B: startAsResponder, open "hi"
    B->>E: reply on cv/{convo_id} (steps the ratchet)
    E-->>A: reply; Alice stops attaching the init fields
```

Bob proves each `init` transcript once while his engine runs: later frames
of the same `init` are opened directly, a new `init` is challenged again.
Until Alice hears back, every frame she sends is an `init` on Bob's inbox, so
any of them can open the session if earlier ones were lost.

## 3. Ordinary messages

The sender seals with the next message key (stepping first when the policy
says so) and publishes the frame at QoS 1 on `cv/{convo_id}`. A message shows
`sent` once published while the peer is online, `queued` when the peer was
offline (the broker holds it in their session), `delivered` when the peer's
receipt arrives, and `failed` if sealing or publishing threw; a failed message
can be retried under the same message id (only a message the user wrote). An
unanswered `init` is resent on its own, 60 s × 2ⁿ apart, at most six times,
while the peer is online. States only move forward, so a receipt that beats
the publish callback is not overwritten. There are no read receipts. Payloads
are padded to 256-byte size classes before sealing.

The receipt is a sealed `receipt` frame on the same topic whose `msgId` names
the message ([e2ee-protocol.md](e2ee-protocol.md#the-frame)): the server sees
one more small frame and learns nothing it could not already infer from timing.

The receiver checks the frame is addressed to it, from that friendship's
member, on the right topic. While the profile is locked, the core seals such a
frame to the device key as it arrived (`pending/…`, at most 1,000, of which 64
first contacts) and acknowledges it only once written; it is opened once the
user unlocks, because the ratchet state it needs is sealed behind the
profile's protection tier (Face ID, or the passcode on the reduced tier).
Nothing about a queued frame needs that unlock: the local notification says
only that a message arrived, and names the sender only for a friend already
proven. Pending frames are opened in arrival order at the unlock. The delivery
receipt is sent when a frame is opened, so a sender sees "delivered" once the
recipient has unlocked, not merely once the phone was reachable. The plaintext
is shown and stored sealed (see
[e2ee-protocol.md](e2ee-protocol.md#at-rest-on-the-device)).

## 4. While a phone is offline

Clients connect with `cleanSession = false` and subscribe at QoS 1, so EMQX
keeps an offline client's session and queues its messages until it reconnects
(EMQX's default session expiry of two hours). Messages older than that are
lost to that client.

## 5. Presence and push

On connect a client publishes `{"s":"online"}`, retained, to its presence
topic; its Last-Will is `{"s":"offline"}`. Going to the background, the app
publishes `offline` itself (`Engine::set_presence`) and holds a background task
until the frame is written, since a suspended socket would keep it "online"
until the broker gives up on the keepalive (60 s, so about 90 s).

The push bridge, inside `hqcat-server`, subscribes to every presence topic and
(through a shared subscription) to every `cv/` topic and every inbox. For each
conversation frame it looks up the friendship's two members and wakes each
member it believes offline; a frame on an offline user's inbox (a first
contact, before the conversation topic is in use) wakes its owner. Anyone can
publish into an inbox, so the bridge bounds what a flood costs: one wake per
recipient per interval (60 s) whatever arrives meanwhile, a remembered "no
such conversation" for unknown ids, and one APNs connection reused for every
wake. The alert is content-free: title "New message", body "You have a new
message". A phone that receives it opens the app, which reconnects and drains
its queued session; reading it still needs the unlock.

In the foreground the app raises its own local notifications for messages and
invites in other conversations, titled with the sender's name and never the
text.

## 6. Reports and blocking

From a message (or the conversation header), a user can report to the
operator, which uploads that message's text as they see it plus a category and
an optional note, and optionally block. The core quotes one message the
friend actually sent, or the report fails visibly. Only conversation members
may report, also for 30 days after the friendship ended, so unfriending first
does not make abuse unreportable. Operators work the queue with
`hqcat-ops reports` ([moderation runbook](../runbooks/moderation.md)); reports
are deleted after 90 days.
