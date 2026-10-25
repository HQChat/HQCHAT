# hqchat — user journey

**Audience:** a designer picking up the app without reading Swift.
**Scope:** the iOS app; macOS shares the sources behind a sidebar-and-split
shell (see the end). The app runs on the Rust core; the screens are the same
as in 3.0.0.

What a person does, screen by screen, the states each screen can be in, and
the constraints the product puts on the design. Gaps are listed in
[Known gaps](#6-known-gaps), not designed away. Component details are in
[design-system.md](design-system.md).

---

## 1. The product in one paragraph

A private messenger where identity is a **key pair on the device**, not an
account. No phone number, email or password, and no recovery. You pick a
**username**; friends find you by typing it exactly. Every message is
end-to-end encrypted with post-quantum keys; the server sees who is friends
with whom and when bytes move, never what they say. So keys must be visible
enough to verify, "who am I talking to" must be answerable at a glance, and
there is no "forgot my password" to fall back on.

## 2. The people

| | **New user** | **Returning user** | **Privacy-motivated user** |
|---|---|---|---|
| Arrives | from a friend's nudge | daily | after reading about the crypto |
| Wants | to reach that one friend | the unread badge gone | proof, not promises |
| Fears | "did I set this up right?" | missing a message | privacy theatre |
| Needs from design | one visible next step | speed, no ceremony | key material surfaced and verifiable |

## 3. The journey

```
launch
  ├── no identity ──► welcome ──► new profile (handle, protection, terms) ──┐
  └── identity ─────► select profile (Face ID or passcode) ────────────────► chats
                                                                              │
                        chats ─────────────── contacts ─────────────── settings
                          │                       │                        │
                     conversation            add contact      account · security · diagnostics
                                                  │
                                    invite ──► they accept ──► conversation
```

### 3.1 Welcome

Logo, wordmark and three promises (end-to-end encrypted, keys stay on your
device, multiple identities), with one action: `new profile`. The only screen
with no way back.

### 3.2 Creating an identity

The `new profile` sheet asks three things, and `create` stays disabled until all
three are answered:

| Answer | Rules |
|---|---|
| **username** | 3–32 of `a–z A–Z 0–9 _`, reserved names refused (`admin`, `support`, `helper`…); the field filters as you type |
| **protection** | **Secure** (Face ID every time the keys are used) or **Quick unlock** (Face ID or passcode, once per session, forgotten when the app goes to the background). Nothing is preselected; choosing Secure asks for Face ID at that moment. A device without biometrics is shown Quick unlock as information, not a choice. Fixed once created |
| **agreement** | the terms checkbox; already checked on a second profile, since the acceptance belongs to the person |

Optional: a home server (blank means the default). Below, a card: *a fresh
keypair is forged on-device — HQC-256 · keys never leave this phone*. Key
generation takes a moment on real hardware.

A device that cannot protect a key at all is told so on the selection screen,
with the remedy, before any form opens.

**States:** empty (no complaint yet) · invalid with the reason inline ·
generating · created · the server refusing the name as taken (arrives after the
first sign-in, as a banner offering to choose another).

### 3.3 Unlocking

Selecting a profile raises **one** prompt (Face ID, or the passcode on Quick
unlock), which covers sign-in and reading the stored messages. A dismissed
prompt returns to profile selection; it never retries on its own. A recent
Touch ID or Face ID unlock of the device itself does not count.

Going to the background drops the unlock, as do (on macOS) a sleeping screen
and a user switch: coming back asks again. While the app is not in front, or
the screen is being recorded or mirrored, the window is covered, so the app
switcher and recordings show no messages. The keyboard learns nothing from
what is typed in a conversation, and Writing Tools are off there.

### 3.4 Home — three tabs

A bottom tab bar: **chats**, **contacts**, **settings**, with badges for unread
messages and pending invites. Each tab root wears the app's own header:

```
hqchat:~/chats$ █                    ● SECURE   [▤]
```

a terminal prompt naming the screen, a connection chip (`SECURE`, `LINK..`,
`AUTH..`, `DOWN`, `NO NET`, `ERROR`) and a server-info control. Swipe left or
right on the content to change tab; swipe right to leave any pushed screen.

### 3.5 Adding someone

Contacts → `[+] add contact`, at the bottom in thumb reach. The search is
**exact username only**; there is no directory, and the empty state says so.
Each result shows where it stands: add button (stranger), `added`, `invited`,
`wants to connect`, or `you`.

### 3.6 The invite

```
you: invite ─────────────► them: "wants to connect" in Contacts
                                       │ accept
you: friend added ◄────────────────────┘ + "hello @you, i'm @them." sent for them
```

Contacts is sectioned: **wants to connect**, **invites you sent**,
**contacts**, **blocked**, **identities that are gone**. A sent invite can be
withdrawn; a contact is removed or blocked by swiping its row, with a
confirmation.

**An accepted contact can be messaged at once.** The session opens from the
contact's published keys with the first message, so there is nothing to wait
for. Accepting sends a short greeting on the accepter's behalf so the
conversation starts with something in it. A contact with no session reads
`ready` and its conversation header `e2e·on first message`.

### 3.7 The helper bot

Every new account is befriended by **@helper**, which sends a welcome once the
conversation is open. It answers `/help`, `/support`, `/game prc`,
`/game guess <n>` and echoes anything else. To the design it is an ordinary
contact: no special bubble or badge.

### 3.8 The conversation

**Header:** `[<]`, avatar with presence, the handle, and a status line that
opens key verification: `live·e2e·ok` (verified, green), `live·e2e·unverified`
(amber, never green), `e2e·on first message`, `e2e·reconnecting`. Then search,
and a menu with **report**. Banners above it: verify the safety number (an
empty, unverified conversation), identity gone, blocked.

**Messages:** day separators; square bubbles, outgoing right on faint green,
incoming left on neutral; under each, the time and for outgoing `sending`,
`sent`, `queued` (they were offline), `delivered` or `failed` (tap to retry).
There are no read receipts. An
empty conversation shows nothing: the composer is enough. Long-press an
incoming message to report it.

**Composer:** `>  type a message…  [send]`, growing to five lines. For a
blocked contact or a vanished identity it is replaced by a notice saying why
nothing can be sent.

**Key verification:** the safety number (12 groups of 5 digits) and its QR
code, the contact's id, `mark as verified` or `clear verification`, and
`rotate keys now`.

**Report:** the message (or the conversation), a category, an optional note, a
plain statement that the message text is uploaded and cannot be verified, and
"also block", checked by default.

### 3.9 Settings

A card with avatar, `@handle`, key fingerprint and `switch profile`. Then:

- **account**: change username; key fingerprint; reset all data on this device
  (every profile; server accounts survive); delete my account (this profile,
  on the server and the device, irreversible; other profiles stay).
- **security**: the active profile's protection tier and what is protected
  where.
- **diagnostics**: the protocol log (key exchanges, greetings, dropped frames,
  with reasons, never content).
- **terms**, **privacy**, **support**: the published pages.

No commerce surface: the app is free; donations happen on the website.

### 3.10 Multiple identities

A profile is an identity plus a home server. The switcher (full screen on iOS)
lists `@handle`, creation date and key stamp, the active one bracketed in green.
Friends, keys and history are separate per profile.

### 3.11 macOS

A sidebar lists friends, or users matching the search; the selected
conversation fills the rest. A narrow column shows the active profile with a
switch button; settings open as a sheet from the toolbar menu.

---

## 4. Cross-cutting states

| State | Where | Treatment |
|---|---|---|
| connecting, authenticating, offline, error | header chip on every tab root; a banner when offline or reconnecting | text and colour |
| username taken | banner, session-wide | `choose` opens Account |
| a contact's identity changed | the old contact is marked gone (read-only); the new one arrives unverified | banner in the old conversation |
| friend or invite limit reached | the error on the action | 150 friends, 20 invites a day |
| error | anywhere | one presentation path |
| empty list | chats, contacts, search | icon, lowercase title, one specific sentence |

## 5. Design system

See [design-system.md](design-system.md). Dark only; everything the app draws is
lowercase; system surfaces keep sentence case.

## 6. Known gaps

1. **Dynamic Type is unclamped.** The dense terminal-style lines (prompt
   header, status line) are the first place to check when adding to a row.
2. **No read receipts and no typing indicator.** Showing them would need a
   protocol change first; delivery receipts exist.
3. **Presence is coarse**: live or offline, no "last seen".
4. **macOS** shares the sources but has had less design attention.
5. **The demo mode** used for screenshots shows blank message bodies on a
   simulator, which cannot seal them.

## 7. Constraints a redesign must respect

- **No account recovery.** Losing the device loses the identity, and on Secure
  protection so does re-enrolling Face ID. Nothing may imply otherwise.
- **Usernames are exact-match only.** No discovery, no contact upload.
- **Username rules are enforced on both ends**, and the client filters as you
  type.
- **Protection is chosen once, with consent,** and shown in Settings; the
  weaker tier is never preselected.
- **Presence comes from the server**, and is only as fresh as the connection.
- **A profile is an identity and a home server**; two profiles share nothing.
- **Creating a profile needs the terms accepted** (App Store Guideline 1.2), as
  a third required answer, not a dialog on the way in.
- **Reporting uploads the message text**, and the UI must say so where the
  report is sent. **A report cannot be verified**, and no copy may imply it can.
- **A blocked contact is kept** read-only with its history, in its own section;
  the block is held by the server across devices and re-invites.

### Where things live in the code

| Step | File (under `apps/apple/HQChat/`) |
|---|---|
| welcome, new profile, switching | `Views/Profiles/` |
| tab shell, swipe navigation | `Views/RootTabView.swift` |
| conversation list | `Views/ChatListView.swift` |
| contacts, invites, blocking | `Views/ContactsView.swift`, `Views/ContactRows.swift`, `Services/ChatStore.swift` (the engine's friends and invites) |
| add contact | `Views/AddContactView.swift` |
| conversation, composer, bubbles, report | `Views/Chat/` |
| key verification | `Views/KeyVerification.swift` |
| settings | `Views/SettingsView.swift`, `AccountSettingsView.swift`, `SecuritySettingsView.swift`, `ProtocolLogView.swift` |
| macOS shell | `Views/Desktop/FriendListView.swift`, `Views/Shell/MainAppView.swift` |
| tokens, components, gestures | `Helpers/Design/` |
| banners, empty states | `Helpers/StatusPresentation.swift` |
| username rules | `Helpers/UsernameRule.swift` |
| the engine behind every screen | `Services/ChatStore.swift`, over `../CoreShell/` and the Rust core |
| the helper bot | `services/bot/src/` |
