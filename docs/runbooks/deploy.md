# Deploy

An environment is a JSON file, `infra/environments/<name>.json`, and a GitHub
Environment of the same name holding its secrets. Deploying it is one click:
**Actions → Deploy → Run workflow**, pick the branch or tag ("Use workflow
from") and the environment.

## What a run does

| Job | |
|---|---|
| `ci` | The full CI suite: lint, unit, integration, functional scenarios, Terraform policy tests, the two-VM NixOS stack test. |
| `build` | Builds the app and broker closures and the environment's droplet image, signs the closures and pushes them to the Nix cache; uploads the image if it changed. |
| `infra` | `infra/scripts/terraform.sh <env> apply`: VPC, image, droplets, EMQX volume, reserved IP, firewalls, managed Postgres, DNS, site Worker, origin certificate. Before applying, imports what the plan would create but already exists (a Worker route with the same pattern, a DNS record with the same name and type: `infra/scripts/tf-adopt.sh`), so it converges over a running account or after a half-finished apply. Refuses to destroy droplets, the volume, the database or the reserved IP unless run with `allow_replace`. Then publishes each host's secret bundle. |
| `release` | Moves `channels/<env>/app` and `/mqtt` to the new closures, keeping the old pointers as `.previous`. |
| `verify` | Waits for `https://<domain>/health` to report this commit with a healthy broker, checks only the expected ports answer, then runs the functional scenarios against the live environment. |
| `rollback` | If `verify` fails, puts the channels back on the previous release. |
| `apple` | If `verify` passed and `ship_apple` is on: runs the Apple release workflow (`apple-release.yml`), which archives the iOS and macOS apps, signs them and uploads a new version of each to App Store Connect (`apps/apple/release.sh`). Version and build number are always above everything already uploaded (`apps/apple/asc-next.mjs`). |

Re-running Deploy on the same ref changes nothing. Running it on an older ref
deploys that ref.

## How a host gets there

A droplet boots the environment's base image. `hqcat-netconf` reads
DigitalOcean's metadata service: addresses, its role and the SSH host key
Terraform generated for it. Every two minutes `hqcat-host-agent` fetches the
host's secret bundle (`secrets/<env>/<role>.age`, encrypted to that host key)
and the channel pointer, and switches to the signed closure it names. If the
new generation's `hqcat-health-check` fails within five minutes, it rolls back
and skips that release. Nothing in CI connects to a host.

## A new environment

1. Write `infra/environments/<name>.json` (copy `rescue.json`).
2. Create the credentials by hand, once:
   - a DigitalOcean API token (read/write);
   - a Cloudflare API token: Zone (DNS, Zone Settings, Workers Routes, SSL and
     Certificates: Edit) and Account (Workers Scripts, R2: Edit);
   - an R2 S3 key pair with read/write on the account's buckets.
3. Run, with those in the environment:

   ```bash
   DIGITALOCEAN_TOKEN=… CLOUDFLARE_API_TOKEN=… R2_ACCESS_KEY_ID=… R2_SECRET_ACCESS_KEY=… \
     infra/scripts/init-environment.sh <name>
   ```

   It creates the GitHub Environment and the R2 buckets, serves the cache on
   its hostname, and generates `BOT_SEED`, `NOISE_KEYS` and (if none exists)
   `NIX_CACHE_SIGNING_KEY`. It never overwrites a secret.
4. Optionally set `STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET` and
   `APNS_KEY_P8` on the GitHub Environment. For the `apple` job (on by default
   through the `ship_apple` input), also set `ASC_KEY_ID`, `ASC_ISSUER_ID` and
   `ASC_KEY_P8`: an App Store Connect API key with the App Manager or Admin
   role. The job archives the iOS and macOS apps after `verify`, lets Xcode
   sign them with that key (cloud-managed certificate, nothing stored on the
   runner) and uploads them to TestFlight; submitting them for review stays
   manual. The same Apple release workflow also runs on every push to `main`
   that changes the apps, and by hand with an optional version.
5. Protect the GitHub Environment (Settings → Environments): a required
   reviewer, and deployment branches limited to the release branches. Without
   it, a workflow on any branch can read its secrets.
6. Run Deploy.

The hqn/1 gateway keys (`NOISE_KEYS`) are what the apps pin; an environment
whose keys differ from the ones compiled into `Deployment.swift` still works,
because clients also learn them from `/auth/transport` over HTTPS.

## Break-glass

SSH is for diagnosis, not for changes: `ssh root@<app ip>`, and the broker
through it (`ssh -J root@<app ip> root@<broker vpc ip>`). Host keys are in the
Terraform output `hosts`. Useful units: `hqcat-host-agent`, `hqcat-secrets-sync`,
`hqcat-netconf`, `hqcat-server`, `hqcat-bot`, `podman-emqx`, `hqcat-noise-gw`,
`hqcat-wireguard`.
