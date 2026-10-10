# The broker's topic policy

`infra/emqx/acl.conf` is the whole authorization policy for clients. It is a
static file: no database lookup, no cache, and no per-user rows. The push
bridge, a superuser on the internal listener, bypasses it.

## The rules

Evaluated top to bottom, first match wins. `${clientid}` is the authenticated
client id, which the CONNECT proof forces to equal the username.

| Action | Topics | Who |
|---|---|---|
| publish | `u/${clientid}/presence` | the owner (retained, and as the Last-Will) |
| subscribe | `u/+/presence` | any client |
| subscribe | `u/${clientid}/inbox`, `u/${clientid}/graph` | the owner |
| publish, never retained | `u/+/inbox`, `cv/+`, `hs/+` | any client |
| subscribe | `cv/+`, `hs/+` | any client |
| anything else | | denied |

`no_match = deny`, and `deny_action = ignore`: a refused packet is dropped and
the connection stays up.

## Why `cv/+` open to everyone is safe

A conversation or handshake topic is named by a random 256-bit id minted with
the friendship and given only to its two members (`GET /friends`). Knowing the
id is the permission. That holds only because clients cannot subscribe with a
wildcard (`mqtt.wildcard_subscription = false` for every client listener):
otherwise `cv/#` would match these rules and read every conversation's
ciphertext and metadata. The broker watch checks this setting and reports
`emqx.wildcard_subscription` as unhealthy on `/health` if it is ever on.

When a friendship ends, its ids are deleted with the row and the server drops
both members' live subscriptions through the admin API, so a former friend
keeps nothing but an id that no new member will ever be given.

## What the policy does not hide

- **Presence:** any signed-in client can subscribe to any `u/{id}/presence`.
- **Inboxes:** any signed-in client can publish into any inbox, because a first
  contact has nowhere else to go. Clients drop frames from non-contacts, and
  each connection is limited to 50 messages per second.
- **Graph nudges** carry no information: the client's answer is an
  authenticated `GET /friends`.

## Checking a deployed broker

```bash
curl -s 127.0.0.1:8090/health | jq .broker    # on the app host; [] is healthy
```

An empty list means every node runs, authentication answers, the file source
is loaded with `no_match = deny`, and client wildcards are off.
