# HQChat — App Store publishing guide

What it takes to ship the iOS app. ✅ is done in the repository; ☐ needs the
Apple Developer, App Store Connect, Stripe or GitHub account, which only the
owner can do.

---

## 1. In the repository

- ✅ **Account deletion in the app** (Settings → Account → delete my account):
  the server purges the account and the device deletes that profile; other
  profiles stay. "Reset all data on this device" is the separate local wipe.
- ✅ **Free, with no commerce surface.** $0.00, no in-app purchase, no paid tier,
  no price, link or call to action about money anywhere in the app. Donations
  happen on the website, grant nothing and are bound to no account.
- ✅ **Push entitlement** (`HQChat iOS/HQChat_iOS.entitlements`, `aps-environment`).
- ✅ **Privacy, terms, EULA and support pages** served by the site Worker.
- ✅ **Permission strings:** Face ID only. The app asks for no camera,
  microphone, photos, contacts or location.
- ✅ **Version 3.0.0 (22)** on both app targets. Bumps are manual: change
  `MARKETING_VERSION` and `CURRENT_PROJECT_VERSION` in
  `apps/apple/HQChat.xcodeproj/project.pbxproj` for the macOS and iOS targets,
  Debug and Release, in the same commit; build numbers must keep increasing.
- ⚠️ **Export-compliance flag:** `ITSAppUsesNonExemptEncryption` is `YES` on
  macOS and **`NO` on iOS**, which is false for the target that ships. Set it to
  `YES` before submitting (see §3, export compliance).
- ⚠️ **Crash reporting is always on.** The Sentry DSN is compiled into the app,
  so every build sends crash reports, 10% performance samples and, on iOS,
  masked session replays of errors. The privacy answers in §5 must declare it.

## 1b. Release blocker — biometric re-enrolment destroys the account

☐ **Decide what happens when a user re-enrols Face ID.** On the default
protection tier (Secure, `.biometryCurrentSet`), re-enrolling Face ID or adding
a fingerprint makes the identity key and every stored message permanently
unreadable. There is no backup and no
export, and keys never ride a device backup. The app explains what happened,
but cannot recover it.

Before release, either build a recovery path (an exported, separately protected
backup key) or accept it and say so in the onboarding copy. Quick unlock
(`.userPresence`) is not bound to an enrolment, but it is the weaker tier and
not the answer.

## 2. Apple Developer portal — ☐

1. ☐ Enable **Push Notifications** on App ID `martin.rougeron.DissQus-iOS`.
2. ☐ Create an **APNs auth key** (.p8). Put its key id, team id and the two
   topics in the `apns` block of `infra/environments/<environment>.json`, and the
   key itself in the GitHub environment secret `APNS_KEY_P8`
   (`gh secret set APNS_KEY_P8 --env <environment> < AuthKey_XXXX.p8`), then run
   Deploy. Each device registers its token with its own APNs environment
   (sandbox for TestFlight and debug builds, production for the App Store), so
   no server setting picks one. `hqcat-ops check-push <username>` on the app
   host says whether a device can be woken.

## 3. App Store Connect — ☐

### App record

1. ☐ Create the app: bundle id `martin.rougeron.DissQus-iOS`, name **HQChat**,
   category **Social Networking**, age rating **17+** (unrestricted user
   messaging).

### Pricing

2. ☐ Price **Free**; create **no** in-app purchase or subscription. No Paid
   Applications agreement is needed: Apple never pays out.

### Server and donations — ☐

3. ☐ Donations are on when the environment's `donations` block lists Stripe
   price ids (`monthlyPriceIds`, low to high, and `oncePriceId`), and off when it
   is `null`. When on, set the GitHub environment secrets `STRIPE_SECRET_KEY` and
   `STRIPE_WEBHOOK_SECRET`; the server refuses to start without them.
4. ☐ Create the Stripe webhook at `https://<domain>/stripe/webhook`, subscribed
   to **`checkout.session.completed`** only. A recurring donation grants nothing,
   so nothing needs to react to it lapsing.
5. ☐ Enable Stripe's **customer portal** and link it from Stripe's own emails:
   that is how someone stops a recurring donation. The app has no billing UI.

### Export compliance — ☐

6. ☐ Answer **Yes** to "uses encryption" (HQC-256, AES-256-GCM, X25519,
   ChaCha20-Poly1305, Ed25519, P-256). [export-compliance.md](export-compliance.md)
   is the source of truth on which filing applies; it concludes that the
   mass-market self-classification does not cover a not-yet-standard algorithm
   and a classification request is needed. Drafts for **BIS/NSA** and for
   **ANSSI** (France) are in [`filings/`](filings/README.md), unsent and in need
   of review.

### URLs

7. ✅ Privacy `https://hqchat.app/privacy`, support `https://hqchat.app/support`,
   terms `https://hqchat.app/terms`, and the **custom EULA**
   `https://hqchat.app/eula` in the License Agreement field (the page a 1.2
   reviewer opens). Confirm `support@martinrougeron.me` (`CONTACT_EMAIL` in
   `apps/site/src/index.js`) receives mail.

### Privacy label and listing

8. ☐ Fill App Privacy with §5, and the listing with §6 and §7.

## 3b. Guideline 1.2 — user-generated content

Apple wants all of these together:

| 1.2 asks for | Where | Check |
|---|---|---|
| A EULA forbidding objectionable content and abusive users | `/eula` | ☐ opens and says zero tolerance |
| Agreement before use | the new-profile sheet: `create` stays disabled until the terms are ticked | ☐ on a fresh install |
| Reporting content | long-press an incoming message → report; or the conversation menu | ☐ the report appears in `hqcat-ops reports` |
| Blocking a user | contacts → swipe → block, or from the report sheet | ☐ the blocked peer cannot re-invite |
| A contact point that answers | `support@martinrougeron.me` | ☐ send a test and read the reply |
| Acting within 24 hours | [moderation runbook](../runbooks/moderation.md); `ejected` disconnects, `banned` deletes the account | ☐ the runbook is current |

Two answers a reviewer may want, both stated on `/eula`:

- **A reported excerpt cannot be verified**: it is the reporter's own copy, and
  the server cannot decrypt messages. Do not write copy implying otherwise.
- **A ban cannot follow a person**: an identity is generated on the device, so a
  removed person can return as a new identity. A ban ends an account and its
  conversations.

## 4. Smoke test before submitting — ☐

- ☐ The TestFlight build installs and launches.
- ☐ A fresh install creates a profile (handle, protection, terms), signs in,
  and the helper's welcome arrives.
- ☐ Add a friend, message both ways, and verify the safety number.
- ☐ Report a message: the sheet says the text is uploaded and cannot be
  verified; the report reaches `hqcat-ops reports`.
- ☐ Block a contact, wait one directory poll (60 s), reopen: it is listed under
  *blocked* with its history.
- ☐ Settings shows terms, privacy and support, each opening the live page.
- ☐ Settings → Account → delete my account returns to profile selection without
  that profile, any other profile still opens, and a new profile works.
- ☐ A push wakes the phone when the app is in the background.
- ☐ Donate on the website with a test card: the thank-you page appears, and a
  name typed at checkout shows on `/supporters`.
- ☐ No commerce in the app: `git grep -ni "stripe\|checkout\|price\|donat\|storekit" -- 'apps/apple/HQChat/*.swift' 'apps/apple/HQChat iOS/*.swift'`
  finds only the Sentry scrubber's Stripe patterns in `Helpers/Redaction.swift`.

## 5. App Privacy answers

**Data linked to the user** (app functionality, not tracking):

- **User ID**: the username and public key.
- **Identifiers → Device ID**: the push token.
- **User Content → Other User Content**: a reported message's text, uploaded only
  when the user files a report.

**Data not linked to the user:**

- **Diagnostics → Crash Data, Performance Data, Other Diagnostic Data**: Sentry
  crash reports, sampled performance traces and, on iOS, session replays of
  errors with every text and image masked. Scrubbed of keys, ids, handles,
  addresses and tokens before sending.

**Not collected:** contact info, location, photos, contacts, browsing,
purchases (donations happen on the website), usage analytics, advertising
data. Message content is not collected: it is end-to-end encrypted, and leaves
the device in readable form only in a report.

**Tracking:** no. No ad SDK, no third-party trackers.

## 6. Listing copy

**Name:** HQChat
**Subtitle:** Post-quantum private chat

**Promotional text:**
Private by design. End-to-end encrypted messages protected with post-quantum
cryptography; your keys never leave your device.

**Description:**
HQChat is a private messenger built for a future where today's encryption can
be broken. Every message is end-to-end encrypted on your device, with
post-quantum HQC key exchange and AES-256-GCM. Your keys are generated on your
device and never leave it; not even our servers can read your conversations.

Why HQChat:
• Post-quantum end-to-end encryption for every message
• Keys stay on your device, locked behind Face ID or your passcode; stored messages are sealed with the Secure Enclave
• Verify a contact with a safety number to rule out a man in the middle
• Multiple identities, each fully separate
• No ads, no trackers, no contact upload
• Delete your account and its server data from inside the app

HQChat keeps the minimum needed to deliver messages: a username, your public
key and your friend connections, and nothing of what you say.

HQChat is free. Every feature, for everyone: no paid tier, no subscription, no
in-app purchase. It is funded by voluntary donations on its website, which
unlock nothing. The server and its infrastructure are published under the AGPL,
so you can run your own.

**Keywords:** encrypted,private,messenger,chat,post-quantum,secure,e2e,privacy,encryption,messaging

**Support URL:** https://hqchat.app/support · **Marketing URL:** https://hqchat.app ·
**Privacy Policy URL:** https://hqchat.app/privacy

## 7. Screenshots — ☐

6.7" (and 6.5" if required). Good candidates: welcome, a conversation, the
safety-number screen, contacts, settings. `DEMO_MODE=1` seeds sample data, but
a simulator cannot seal message bodies, so conversations show blank bubbles
there; capture conversations on a device.
