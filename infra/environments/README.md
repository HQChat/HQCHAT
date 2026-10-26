# Environments

One JSON file per deployment environment. Nix (`flake.nix`) and Terraform
(`infra/terraform`) both read it, so a value lives in exactly one place.

| Field | Meaning |
|---|---|
| `name` | Environment name; prefixes droplets, tags, state key, channels and secret bundles. |
| `domain`, `siteDomains` | The origin's public hostname and extra names on the same vhost (Cloudflare-proxied); these carry the site Worker's routes. |
| `apiHost` | Optional. The hostname the apps call (`Deployment.swift` `serverHost`): proxied to the same origin and on its certificate, with no Worker route. |
| `hqnHost` | DNS-only hostname of the hqn/1 gateway (the broker's reserved IP). |
| `region`, `vpcRange` | DigitalOcean region and the environment's private network. |
| `sizes` | Droplet, database and EMQX volume sizes. |
| `cloudflare` | Account, zone, whether this environment deploys the site Worker and owns the zone-wide settings (TLS, DNSSEC, CAA). Optional: `caaIssuers` (default Let's Encrypt, Google Trust Services, SSL.com) and `rateLimit` (edge rate-limiting rule; needs a plan that allows it). |
| `cache` | Public URL and bucket of the Nix binary cache, and the key closures are signed with. |
| `stateBucket` | R2 bucket holding Terraform state (`<name>/terraform.tfstate`). |
| `apns`, `sentryDsn` | Non-secret push and error-reporting configuration. `sentryDsn` is embedded in the server, gateway and bot units; Deploy warns when it (or the app's `Deployment.sentryDSN`) is empty. |
| `donations` | Stripe price ids, or `null` to run without donations. |
| `botAi` | Optional. `{ "dailyLimit": <n> }` turns on the helper's opt-in AI replies, at most `n` a day for everyone together; `null` or absent, they are off. Needs the `ANTHROPIC_API_KEY` secret first ([runbook](../../docs/runbooks/anthropic-key.md)). |
| `adminSshSources` | Optional. The CIDRs the DigitalOcean firewall admits to the app host's SSH (the broker's is reachable from the app host only). Without it SSH is open to any address, rate-limited per source and key-only on the host. |

Secrets are not here. Each environment has a GitHub Environment of the same
name holding them; `infra/scripts/init-environment.sh <name>` lists, generates
and sets them.
