# Security policy

Report vulnerabilities privately through a
[security advisory](https://github.com/HQChat/HQCHAT/security/advisories/new)
rather than a public issue.

This server's claim is that it cannot read messages. The most serious bugs
undermine it: recovering plaintext or key material from what the server holds;
publishing to or subscribing to a conversation you are not a member of (a
conversation's random topic id is the permission); authenticating as another
identity; or replaying a sign-in, a CONNECT proof or a handshake.

Known findings are tracked privately. If you report something already known, we will say so and when it is expected
to close.

Full policy, including scope: [SECURITY.md](../../SECURITY.md).
