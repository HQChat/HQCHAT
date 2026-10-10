# Licensing

Two licences, split by directory. The server is free software; the app is
published to be read and checked, not to be reused.

| Path | Licence | In short |
|---|---|---|
| `apps/apple/` | [PolyForm Strict 1.0.0](apps/apple/LICENSE.md) | Read it, build it and run it for any noncommercial purpose. No changes, no redistribution, no apps built from it. |
| everything else: `services/server/`, `native/hqc/`, `infra/`, `apps/site/`, `docs/`, `scripts/` | [AGPL-3.0](LICENSE) | Free for everyone to use, modify and run, including as a service, as long as your changes stay AGPL. |
| third-party components | their own terms | [apps/apple/third-party.md](apps/apple/third-party.md) |

The name, the icon and the domain are covered by neither licence; see
[TRADEMARK.md](TRADEMARK.md).

## Why the app is not open source

The server is the part anyone should be able to run: self-hosting is the
answer to "why trust this server". The app is published so its encryption
claims can be checked against the code, not so it can be cloned. PolyForm
Strict allows exactly that: anyone may read, build and test it, and nobody may
ship it, or a work based on it, as their own app.

## What a licence cannot do

The protocol (the wire format, the handshake, the topic layout) is described in
`docs/architecture/` and implemented in the AGPL server. A licence covers code,
not ideas or interfaces: someone who writes their own client from scratch is not
bound by either licence. What stops them using *this* deployment is its terms of
service, not this file. What stops them using its name is [TRADEMARK.md](TRADEMARK.md).

## Contributions

A contribution under `apps/apple/` is accepted only if its author agrees that
the maintainer may distribute it under any terms, including in the official app
and under a different licence. A contribution anywhere else is under AGPL-3.0,
like the code it changes.

This file is a summary. The licence texts are what apply.
