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
| `release` | Moves `channels/<env>/app` and `/mqtt` to the new closures: a pointer naming the closure and a release number, signed with the cache key (`channels/<env>/<role>.signed`). Reports the closures it replaced. |
| `verify` | Waits for `https://<domain>/health` to report this commit with a healthy broker, checks only the expected ports answer, then runs the functional scenarios against the live environment. |
| `rollback` | If `verify` fails, puts the channels back on the closures this run's `release` replaced, under a new release number. |
| `apple` | If `verify` passed and `ship_apple` is on: runs the Apple release workflow (`apple-release.yml`), which archives the iOS and macOS apps, signs them and uploads a new version of each to App Store Connect (`apps/apple/release.sh`). Version and build number are always above everything already uploaded (`apps/apple/asc-next.mjs`). |

Re-running Deploy on the same ref changes nothing. Running it on an older ref
deploys that ref.

## How a host gets there

A droplet boots the environment's base image. `hqcat-netconf` reads
DigitalOcean's metadata service: addresses, its role, the SSH host key
Terraform generated for it, and its age post-quantum identity
(`/etc/hqcat/age-identity`, from the `AGE_IDENTITY_<ROLE>` secret). Every two
minutes `hqcat-host-agent` fetches the host's secret bundle
(`secrets/<env>/<role>.age`, sealed to that identity with age's ML-KEM-768 +
X25519 hybrid) and installs it only if `<role>.age.sig` is a statement signed
with the cache key naming this environment, role, the bundle's SHA-256 and a
release no older than the last one installed. Then it fetches the channel
pointer, and switches to the signed closure it names. The
pointer must carry the cache key's signature, name this environment and role,
and have a release number no lower than the last one the host accepted, so
whoever can write to the bucket can neither point a host at another closure
nor replay an older pointer to roll it back. (A host that has never accepted
one, a new droplet, takes the current one on trust.) If the new generation's
`hqcat-health-check` fails within five minutes, it rolls back and skips that
release. Nothing in CI connects to a host.

To return to an earlier release by hand, run Deploy on the earlier ref: it
rebuilds nothing that is in the cache, and signs a new pointer to it.

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
   its hostname, and generates `BOT_SEED`, `NOISE_KEYS`, `AGE_IDENTITY_APP`,
   `AGE_IDENTITY_MQTT` and (if none exists) `NIX_CACHE_SIGNING_KEY`. It never
   overwrites a secret.
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

## Post-quantum secret bundles on hosts that predate them

`publish-secrets.sh` seals bundles only to post-quantum age recipients, and
refuses to run without `AGE_IDENTITY_APP` and `AGE_IDENTITY_MQTT`. A droplet
created before those existed has no identity in its user data (which never
changes after creation), so install one by hand, once per host, before the
next Deploy:

```bash
age-keygen -pq 2>/dev/null | grep '^AGE-SECRET-KEY-PQ-1' >app.id   # and mqtt.id
gh secret set AGE_IDENTITY_APP --env <env> <app.id
ssh root@<app ip> 'umask 077; mkdir -p /etc/hqcat; cat >/etc/hqcat/age-identity' <app.id
# the broker through the app host: ssh -J root@<app ip> root@<broker vpc ip>
rm app.id mqtt.id
```

Until a host has its identity, `hqcat-secrets-sync` fails and leaves the
installed secrets as they are; everything else keeps running. After the
switch, rotate what the earlier, classically sealed bundles held (they stay
readable to anyone who kept a copy and can later break X25519).

## Break-glass

SSH is for diagnosis, not for changes: `ssh root@<app ip>`, and the broker
through it (`ssh -J root@<app ip> root@<broker vpc ip>`). Host keys are in the
Terraform output `hosts` (sensitive: `terraform output -json hosts`). Useful units: `hqcat-host-agent`, `hqcat-secrets-sync`,
`hqcat-netconf`, `hqcat-server`, `hqcat-bot`, `podman-emqx`, `hqcat-noise-gw`,
`hqcat-wireguard`.
