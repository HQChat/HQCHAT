# Moderation: a report arrived, act within 24 hours

`/eula` commits this deployment to acting on reported content **within 24
hours**. App Store Guideline 1.2 asks for that commitment, and a commitment with
no procedure behind it is the same acceptable-use clause the whole feature exists
to replace. This is the procedure.

Every step is a real command, run as root on the app host (`ssh root@<app host>`).

## What a report is, and what it is not

A report carries the reporter's own **plaintext copy** of one message, uploaded
because they chose to. Messages are end-to-end encrypted and this server cannot
read them; a report is the one path that hands one over.

**An excerpt is not evidence of what was said.** Nothing here can tell a genuine
excerpt from an invented one — a reporter can type anything into that field. Even
an attached sealed frame does not fix it: the AEAD tag is computed under a
ratchet key the *reporter* holds, so they can mint a well-formed frame saying
whatever they like. What a frame buys is a **consistency check** against what the
broker actually delivered on that conversation topic: a fabrication that never
crossed the wire fails it, and a fabrication swapped for a message that did is
not detectable.

So: read an excerpt as *what somebody handed in*. `hqcat-ops reports` prints that
caveat on every row rather than trusting you to remember it.

## 1. See the queue

```bash
hqcat-ops reports
```

Oldest open report first. Each row carries the category, the two accounts
(truncated), the conversation hash, whether a frame is attached, whatever the
reporter typed, and — the field that usually decides the outcome — **how many
reports exist against that account in total**. One report is a disagreement.
Six against the same id in a day is a pattern.

Reading the queue **deletes lapsed reports** before it selects. That is
deliberate: the 90-day deletion is published on `/eula` and `/privacy`, so it is
a promise rather than a space optimisation, and an operator must not be shown a
report that should no longer exist because the routine sweep was not running.

## 2. Decide

| category | what it means here |
|---|---|
| `csae` | child sexual abuse or exploitation. **Ban immediately and report to the authorities.** No warning, no second look, no waiting for a second report. |
| `harassment` | repeated contact after being asked to stop, threats, intimidation. |
| `sexual` | sexual content sent to someone who did not ask for it. |
| `violence` | threats of violence. |
| `spam` | bulk messaging, scams, phishing. |
| `other` | read the note. |

The reporter has almost certainly blocked them as well — the app offers both from
one gesture, and blocking already ends the friendship, revokes both members'
access to the conversation topic, and cannot be walked around by re-inviting. So
the question here is not "can this person still reach the reporter" (they cannot)
but **"should this account keep using the server at all"**.

## 3. Act and record

```bash
hqcat-ops reports <report-id> no-action|warned|ejected|banned
```

Recording the decision is what takes the report out of the queue, so it is also
what makes "within 24 hours" checkable. It refuses to overwrite a decision
somebody already made, so two operators cannot quietly disagree. Two
dispositions act on the reported account as they are recorded:

| disposition | effect |
|---|---|
| `ejected` | disconnects their live MQTT session now. Blocking already revoked the pair's topics; this ends a connection that is still open. |
| `banned` | deletes the account (friendships, invites, prekeys, push tokens, sessions) and disconnects it. Reports filed against it are kept. |

### ⚠️ What a ban cannot do

An identity here is `sha256(public key)` and the key is generated on the device.
Somebody removed can reinstall the app and arrive as a **new person with a new
id**, and nothing on this architecture follows a human being across that. Do not
tell a reporter that someone has been "banned from the service"; what actually
happened is that an account was ended, its conversations were broken, and anyone
who wants to reach them has to be added by them again.

This is a property of the design, not a gap to close: the alternative is a
durable per-human identifier, which is the thing this app exists not to hold.

## Where a report announces itself

There is no mail path. A filed report calls `logger.event`, which is a **Sentry
message**, deliberately unthrottled: every report is a distinct thing that needs
a person. Without Sentry (`sentryDsn` empty in the environment file) the line
still reaches the journal (`journalctl -u hqcat-server`), and the 24-hour
commitment then rests on somebody running `hqcat-ops reports`.

**If Sentry is off, put a timer on `hqcat-ops reports`.** Otherwise the
commitment on `/eula` stops being true, and that is a page the App Store reads.

## The contact point

`support@martinrougeron.me` (`CONTACT_EMAIL` in `apps/site/src/index.js`) is the
address on `/support`, on `/eula`, and in App Store Connect. A reviewer emails
it. **Confirm it receives mail before a submission** — an unanswered review email
is a rejection with no code change that can fix it.
