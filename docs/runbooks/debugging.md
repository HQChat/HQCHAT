# Debugging: "my message didn't arrive"

The order to look in, and what each answer means. Commands run as root on the
app host unless they say otherwise.

## 0. Get the two client ids

Everything is keyed on client ids: `sha256(lowercase hex public key)`, 64 hex
characters. From a username:

```bash
curl -s "https://<domain>/users?username=<handle>" | jq -r .id
```

## 1. Is the stack healthy at all?

```bash
curl -s 127.0.0.1:8090/health | jq
```

`version` is the deployed commit. `broker: []` means EMQX, its authn hook, its
static ACL (file source loaded, `no_match = deny`, **wildcards off**) and the
database are all up. A non-empty list is your answer: fix that first.

**`emqx.wildcard_subscription`** in that list is a security incident, not a
message problem: with wildcards on, any client can subscribe to `cv/#` and read
every conversation's ciphertext and metadata. See
[emqx-acl.md](../architecture/emqx-acl.md).

## 2. Do both clients hold the conversation topic?

The conversation topic is `cv/{convo_id}`, a random id from the friendship row,
handed to both members by `GET /friends`:

```bash
psql "$(cat /etc/hqcat/secrets/database_url_direct)" \
  -c "SELECT convo_id, handshake_id FROM friendships
      WHERE (id_lo, id_hi) = (LEAST('$ID_A','$ID_B'), GREATEST('$ID_A','$ID_B'))"
```

No row means they are not friends, and there is no topic. The broker refuses a
publish or subscribe to any other topic per packet, without disconnecting.

## 3. Did the message reach the broker?

On the broker host:

```bash
journalctl -u podman-emqx -f
```

The EMQX dashboard listens on the WireGuard address only; tunnel to it through
the app host (`ssh -L 18083:<broker wg address>:18083 root@<app host>`), then
*Diagnose → Topic metrics* on the conversation topic.

- **Nothing published** → it never left the sender. Look at the app (§6).
- **Published, not delivered** → the recipient is not subscribed (§5).

## 4. Was the recipient woken?

```bash
hqcat-ops check-push <username>
```

It answers the three questions that all present as "my phone did not buzz":

1. **Is APNs configured?** An incomplete config (a key with no topic, say) is
   escalated to Sentry at boot and wakes nobody.
2. **Has the device registered?** No row in `push_tokens` means the OS never
   handed the app a token: permission denied, or a build without the
   `aps-environment` entitlement. The app re-registers on every sign-in.
3. **Did the server think they were reachable?** The push bridge wakes only
   members it believes are offline, and decides once, when the message is
   published. A device asleep but still marked online gets nothing for that
   message.

```bash
journalctl -u hqcat-server | grep 'could not wake'
```

Each line names the reason (`no-config`, `no-topic-ios`, `rejected`, …), once
per account per reason.

For (3): the app publishes a retained `offline` when it goes to the background
and holds an iOS background assertion until the frame reaches the socket. If
the device's protocol log shows `could NOT announce offline`, only the
Last-Will corrects it, up to 45 seconds later.

## 5. Is it queued rather than lost?

QoS-1 messages for a disconnected client are held in its MQTT session, not in
the database, and replay when it reconnects with the same client id and
`clean-session = false`.

## 6. On the device

The protocol log (Settings → diagnostics) records connections, subscriptions,
handshakes and every received or dropped frame, with ids, sizes and reasons,
never content:

- **`subscribeRefused`** → the client asked for a topic the server never gave
  it; a directory sync re-asks with the current ones.
- **`dropped`** → the frame arrived and was refused; the stage and reason say
  where (topic binding, decode, decrypt).
- **Nothing received** → the app is not subscribed. Check that sign-in ran a
  directory sync and that the conversation topic is in its subscription set.

## 7. Sentry

Filter by `component` (`server`, `bot`, `noise-gw`). Every REST response
carries `x-request-id`; the same id is on the log line and the Sentry event.

`logger.error()` bills a Sentry event; `warn` and `info` only leave a
breadcrumb. Errors are throttled per fingerprint: the first goes through, then
at most one per `SENTRY_THROTTLE_MS` (default 10 minutes), tagged
`[+N identical suppressed]`. Fingerprints collapse ids, numbers and handles, so
the same failure for a thousand users is one fingerprint.

- `[+N identical suppressed]` is the number that matters, not the event count.
- The journal is never throttled: `journalctl -u hqcat-server -f`.

An expected, self-resolving condition is not an error: a peer without prekeys
yet, a reconnect that will succeed, a retried poll are `warn` or `debug`.

## Quick table

| What you see | Where to look |
|---|---|
| Publishes refused | the clients do not hold the friendship's topic (§2) |
| Delivered to some devices only | per-device subscription or session (§3, §5) |
| Delivered late, in a burst, after opening the app | working as designed: session replay (§5) |
| No push while backgrounded, ever | APNs unconfigured: `check-push` (§4) |
| No push while backgrounded, sometimes | presence stuck online (§4) |
| Arrives but shows nothing | a dropped frame (§6) |
