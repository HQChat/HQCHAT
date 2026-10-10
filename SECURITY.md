# Security policy

## Reporting a vulnerability

Report privately through a [security advisory](https://github.com/HQChat/HQCHAT/security/advisories/new),
not a public issue. If that is not possible, use the contact address on the
website's support page.

Say what you can reproduce and how. A proof of concept is welcome but not
required. We aim to acknowledge within a few days. There is no bounty
programme, and no legal threat: research reported in good faith is welcome.

## Scope

In scope: the server, gateway and bot in `services/server/`, the Apple apps in
`apps/apple/`, the protocol shared by both, the broker configuration in
`infra/emqx/`, the hosts and host agent in `infra/nixos/`, the Terraform in
`infra/terraform/`, and the Deploy workflow.

Out of scope: attacks that need a compromised device OS or an unlocked device
in the attacker's hands; and volumetric denial of service.

Known findings are tracked privately. If you report something already known,
we will say so and when it is expected to close.

## What we consider serious

The product's claim is that the server cannot read messages, so the most
serious bugs are those that undermine it:

- recovering plaintext or private key material from anything the server or the
  network sees;
- reading, publishing to or subscribing to a conversation or handshake topic
  you are not a member of (a topic id is the permission, so any way to learn
  one, or to subscribe by wildcard, breaks confidentiality);
- authenticating as another identity, or replaying a sign-in, a CONNECT proof
  or a handshake;
- getting a client to accept, without a visible change, a key its contact
  does not hold;
- forging a message inside an existing session.

## Before you start

The [architecture docs](docs/architecture/overview.md) describe each surface,
and the [pentest scope](docs/pentest-scope.md) lists what a test should cover.
