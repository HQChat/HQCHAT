# hqchat — component reference

Every reusable piece of the interface, what it is for, its states, and the rule
for when to use it. Pairs with [user-journey.md](user-journey.md) (what a person
does).

Source of truth: `apps/apple/HQChat/Helpers/Design/` (tokens, backdrop,
headers, identity marks, motion, controls, sheets) and
`HQChat/Helpers/StatusPresentation.swift` (state surfaces). None of it touches
app logic.

---

## 1. Foundations

### Colour — `HQColor` (`Design/Tokens.swift`)

Tokens only: no raw `Color(hex:)` in `Views/`. A new colour gets a name here
first.

| Token | Value | Use |
|---|---|---|
| `bgTop` / `bgBottom` | `#101116` / `#16171d` | screen gradient |
| `screen` | `#070809` | header and composer bars |
| `panel` | `#0a0b10` | raised panels |
| `green` / `greenBright` / `greenDeep` | `#16c46e` / `#1bd676` / `#0f7d49` | secure, primary action, you |
| `purple` / `purpleLight` | `#7b2ff7` / `#a06bff` | identity, contacts |
| `warning` | `#ffb23b` | pending, unverified, caution |
| `danger` / `dangerLight` | `#ff5a3c` / `#ff8a72` | destructive, failed |
| `textPrimary` → `textFaint` | `#eef0f3` → `#83858f` | the text ramp |
| `onGreen` | `#06140c` | ink on a green fill |
| `textOnCard`, `textOff` | `#cdcfd6`, `#4a4b52` | card body, disabled label |
| `inkOnGreenBubble` / `inkOnGreyBubble` | `#eafff4` / `#dfe1e8` | message text |
| `hairline`, `fillSoft` | white 8% / 4% | borders, faint fills |

**Contrast rule.** Every text token clears WCAG AA (4.5:1) on `bgTop` and on
the standard card fill. `purple` measures 3.22 and stays a border or fill
colour, never text.

### Type — `HQFont`

Two voices, both scaling with Dynamic Type:

- `HQFont.mono(size, weight:)`: machine text (keys, timestamps, status,
  prompts, section labels).
- `HQFont.ui(size, weight:)`: prose (names, messages, explanations).

Sizes are design points at the default text size; `HQFont.scaled(_:)` applies
the reader's setting through `UIFontMetrics`, and is what a frame that must
keep pace with its text uses. Because `UIFontMetrics` reads UIKit's
content-size category, `ContentView` keys itself on `dynamicTypeSize`, which is
what makes a text-size change take effect.

### Shape and motion

Squares and hairlines. Rounded corners are the exception (avatars, a few
pills); corner brackets mark a selected card. The two perpetual animations,
the background bokeh and the cursor blink, hold still under
`accessibilityReduceMotion`.

### Hit targets — `.hqTapTarget(_:)`

Grows a control's hit area to 44×44 without growing its artwork. Every
icon-only control uses it.

### Voice

**Everything the app draws itself is lowercase**: tab labels, settings rows,
buttons, empty states, headers. Sentence case is for system surfaces (alerts,
share sheets, permission prompts), per Apple's HIG.

---

## 2. Chrome

### `HQPromptHeader` / `HQScreenHeader`

The top bar of the three tab roots.

```
hqchat:~/chats$ █                     ● SECURE   [▤]
```

`HQScreenHeader` is the app-level wrapper: the prompt, a connection chip and
the server-info control with its sheet. **Props:** `path` (the screen name),
`trailing` (status content).

### `HQSubScreenHeader`

The same prompt one segment deeper, with a `[<]` back control, on every pushed
screen: `contacts/add`, `settings/account`, `settings/security`,
`settings/diagnostics`.

**Rule:** pushed screens wear this; **sheets keep system chrome**, because a
modal is a system surface.

### `ConnectionStatusChip`

The connection as a terminal readout, a lit dot and a short code: `SECURE`,
`LINK..`, `AUTH..`, `DOWN`, `NO NET`, `ERROR`. Tappable only when a retry can
help. macOS shows the same states as a round `ConnectionStatusButton` in the
toolbar.

### `HQRule`

The dashed separator used instead of `Divider`.

### `HQSearchField`

A search box with a clear button: the conversation search and the macOS
sidebar search.

---

## 3. Rows

### `ContactRow`

One row, two jobs, selected by `style`:

| | `.conversation` (Chats) | `.contact` (Contacts) |
|---|---|---|
| Second line | last message, `you:` when ours | presence and encryption state |
| Trailing | arrival stamp and unread badge | invite action, if any |
| Key stamp | no | yes, after the name |

The Chats list sorts by recency, the Contacts list by name. An unread badge
appears only where tapping opens the conversation.

**States:** invite sent (amber, withdraw) · wants to connect (violet, accept) ·
accepted (presence and e2e) · unread (badge, brighter preview) · blocked ·
identity gone.

### `UserSearchRow`

A search result in add-contact. The trailing control follows
`ContactRelation`:

| Relation | Shows | Tappable |
|---|---|---|
| `.none` | add button | yes |
| `.added` | green ✓ `added` | no |
| `.invited` | `invited` (amber) | no |
| `.awaitingYou` | `wants to connect` (violet) | no |
| `.you` | `you` | no |

### `ProfileRow`

An identity in the selector: avatar, `@handle`, creation date, key stamp;
select and delete. The active profile gets green corner brackets.

---

## 4. Conversation

### Header (`ChatHeader`)

Back (iOS), avatar with presence, the handle, and a status line that is also
the way into key verification:

| Status | Meaning |
|---|---|
| `live·e2e·ok` (green) | a session exists and the safety number was verified |
| `live·e2e·unverified` (amber) | a session exists, not verified; never green |
| `e2e·on first message` | ready; sending opens the session |
| `e2e·reconnecting` | no session yet, and not ready |

Then search, and a menu with **report**. Above it, `ChatBanners`: verify the
safety number (an empty, unverified conversation), identity gone, blocked.

### `MessageBubble`

Square-cornered, direction by fill: outgoing green 10% on the right, incoming
white 3.5% on the left, each with a 1 pt border (`HQBubble.fill` / `.stroke`).
Below it: the time and, for outgoing, `sending` (clock), `sent` (check),
`queued` (amber clock: they were offline), `delivered` (filled green check) or
`failed` (red, tap to retry). VoiceOver reads the pair as one phrase ("20:48, sent"). A long press on
an incoming bubble offers **report**.

### `DaySeparator`

`──── today ────` whenever the calendar day changes: `today`, `yesterday`,
`mon 18 aug`, lowercase and localised.

### `ChatComposer`

```
>  type a message…                                   [send]
```

The field grows to five lines; send is disabled while empty or sending. A
vanished or blocked contact gets a read-only notice in its place, saying why
nothing can be sent. There is no "setting up" state: the session opens with the
first message.

### `ReportSheet`

The message being reported (or a description of a conversation report), a
category, an optional note, a plain statement of what will be uploaded, and
"also block", checked by default.

---

## 5. State surfaces

### `HQBanner`

A full-width strip for a condition with an action. Kinds: `.offline`,
`.reconnecting`, `.warning`, `.error`. It always carries a verb ("verify",
"choose", "retry").

**Rule: place a banner by its scope.** Session-wide status (offline,
reconnecting, "@name is taken") is rendered once by `ConnectionBanner` and
`AppStatusBanners` in `MainAppView`, above the platform fork. Anything placed
inside one shell (`RootTabView` on iOS, `FriendListView` on macOS) exists on
that platform only, and nothing fails to compile to tell you.

A banner at the root cannot touch a shell's navigation, which is why
`AppState.showAccountSettings()` exists: iOS switches tab, macOS opens a sheet.

### `HQEmptyState`

Icon, lowercase title, one specific sentence saying what would put something
there (seven uses). **An empty conversation gets nothing**: the composer is
enough.

### `LoadingView`

Spinner plus what is happening ("connecting…").

### `.hqError(_:)`

The single presentation path for errors: anything that can fail routes here
rather than being logged and dropped.

---

## 6. Controls

| Style | Use | Height |
|---|---|---|
| `HQPrimaryButtonStyle` | the one main action on a screen | 48 |
| `HQSecondaryButtonStyle` | outlined neutral | 44 |
| `HQDangerButtonStyle` | destructive (dark red fill, red border) | 44 |
| `HQInlineActionStyle` | `[change]` inside a card | inline |

`HQTextField`: caret, optional `@` prefix, an underline that lights green on
focus, height scaling with the text. `HQFieldLabel`: uppercase mono section
label, tinted with its section's accent.

Destructive actions confirm through `alert`, not `confirmationDialog`, whose
cancel action iOS 26 never delivers.

---

## 7. Identity

`HQAvatar`: initials on a violet tile, with an optional presence dot.
`HQFingerprint.short(_:)`: the key as readable groups, always labelled
(`key a1b2 c3d4`). `HQLogoMark`, `HQWordmark`: brand marks, onboarding only.

---

## 8. Navigation

- **Tabs (iOS):** chats · contacts · settings, with badges; swipe left or right
  moves between them.
- **Push:** conversation, add-contact, account, security, diagnostics. Swipe
  right leaves any of them from anywhere on the screen.
- **Sheets:** key verification, server info, report, new profile. The profile
  switcher is full screen on iOS, a sheet on macOS.
- **macOS:** a sidebar of friends (or search results) beside the open
  conversation.

`hqSwipeNavigation(onBack:onForward:)` is a simultaneous gesture with
conservative thresholds (≥ 90 pt horizontal, ≤ 55 pt vertical drift, 2:1
horizontal dominance), so list scrolling and row swipe actions keep short or
diagonal drags.

---

## 9. Adding something new

1. Does a component here already cover it? Extend it with a prop before adding
   a sibling (`ContactRow`'s two styles exist for this reason).
2. Colour from `HQColor`, type from `HQFont`. No literals.
3. Lowercase if the app draws it; sentence case only on system surfaces.
4. Icon-only? `.accessibilityLabel` and `.hqTapTarget()`, both.
5. A decorative icon beside text that already says it? `.accessibilityHidden(true)`.
6. An animation that repeats? Gate it on `accessibilityReduceMotion`.
7. A new state needs a visible, worded state, not a disabled control.
