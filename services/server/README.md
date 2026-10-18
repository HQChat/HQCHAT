# hqchat server

The server half of [hqchat](https://github.com/HQChat/HQCHAT), an
end-to-end encrypted messenger with a post-quantum handshake.

It never sees a message. It proves that a client holds a private key, keeps the
friend graph that decides which conversation topics a client is given, and lets
EMQX fan out ciphertext it has no key for.

Licensed **AGPL-3.0** ([LICENSE](./LICENSE)).

## Layout

| Path | What it is |
|---|---|
| `test/reference/protocol/` | the wire protocol shared by everything: identity, frames, the KEM double ratchet, the handshake proof, CONNECT proofs, hqn/1 Noise, topics |
| `src/server/` | the server (`npm run server`): auth and the EMQX authn hooks, the REST API, the push bridge and the broker watch, in one process on one port |
| `src/gateway/` | noise-gw (`npm run gateway`), the hqn/1 raw-TCP gateway in front of EMQX |
| `test/reference/client/` | the reference TypeScript client: sign-in, the typed REST API, conversations, MQTT over WSS or hqn/1 |
| `src/bot/` | the helper bot (`npm run bot`), built on the client and nothing else |
| `src/common/` | configuration, logging, scrubbing, Sentry, the health monitor |

EMQX (messaging, the static topic ACL, offline sessions) and Postgres run
beside it; `infra/` deploys all of it.

## Running it

```bash
npm ci
npm run typecheck && npm run test:unit
DATABASE_URL=postgres://… npm run migrate && npm run test:integration
bash test/scenarios/run-local.sh    # the full stack in Docker, then the functional scenarios
```

The server needs `DATABASE_URL` pointing at a migrated database and the Rust
core's Node addon (`HQCHAT_NODE`, or `core/hqchat-node/build.sh` inside
`nix develop`), which carries the protocol, the hqn/1 gateway and the bot's
engine. `test/reference/` holds the TS protocol and client the server used to
run on, kept as an independent implementation for the differential fuzzers
and the scenarios.
Configuration is environment variables, with `FOO_FILE` naming a file to read
`FOO` from; there are no defaults pointing at anyone's deployment.

## How it fits together

- [Authentication](../../docs/architecture/auth-flow.md) — the KEM sign-in and the signed MQTT CONNECT
- [Messaging](../../docs/architecture/message-flow.md) — one message end to end, and what each hop can see
- [The protocol](../../docs/architecture/e2ee-protocol.md) — identity, prekeys, the ratchet, the frame
- [Transports and the broker](../../docs/architecture/transport.md) and [the topic policy](../../docs/architecture/emqx-acl.md)
- [Deployment](../../docs/runbooks/deploy.md) — one click from an empty account to a verified environment

Operator tools: `npm run reports` (the moderation queue) and `npm run check-push`
(why a device would or would not be woken); on a host they run as `hqcat-ops`.

## Where this code lives

The server is developed in [one repository](https://github.com/HQChat/HQCHAT)
with the Apple clients, the infrastructure and the runbooks, so it can be
deployed and not just read. Issues and pull requests are welcome there.

## Security

Report vulnerabilities privately: see [SECURITY.md](SECURITY.md), and
[the root policy](../../SECURITY.md) for scope and what counts as serious.
