# Deploy

An environment is a JSON file, `infra/environments/<name>.json`, and a GitHub
Environment of the same name holding its secrets. Deploying it is one click:
**Actions → Deploy → Run workflow**, pick the ref ("Use workflow from") and
the environment. The ref must be `main` or an `app-store/<version>` tag on a
commit of `main`; any other is refused before a job that holds a secret
starts.

## What a run does

| Job | |
|---|---|
| `ci` | The full CI suite: lint, the Rust core, unit, integration, functional scenarios, Terraform policy tests, the two-VM NixOS stack test. Skipped when this exact commit already passed CI on its push to `main`. |
| `build` | Builds the app and broker closures (and the sim node's, where the environment sizes one: [sim runbook](sim.md)) and the environment's droplet image, signs the closures and pushes them to the Nix cache; uploads the image if it changed. |
| `infra` | `infra/scripts/terraform.sh <env> apply` (the Terraform the flake pins by hash; its secrets go in private files that do not outlive the run, never on a command line, and the origin's address stays out of the logs): VPC, image, droplets, EMQX volume, reserved IP, firewalls, managed Postgres, DNS, site Worker, origin certificate. Before applying, imports what the plan would create but already exists (a Worker route with the same pattern, a DNS record with the same name and type: `infra/scripts/tf-adopt.sh`), so it converges over a running account or after a half-finished apply. Refuses to destroy droplets, the volume, the database, the reserved IP, the firewalls, the zone settings, DNS records or generated keys, and holds back changes that would open or silently break things, unless run with `allow_replace` (`infra/scripts/tf-guard.sh`). Then publishes each host's secret bundle. |
| `release` | Moves `channels/<env>/app` and `/mqtt` (and `/sim`) to the new closures: a pointer naming the closure and a release number, signed with the cache key (`channels/<env>/<role>.signed`). Reports the closures it replaced. |
| `verify` | Waits for `https://<domain>/health` to report this commit with a healthy broker, checks only the expected ports answer, then runs the functional scenarios against the live environment. |
| `rollback` | If `verify` fails, puts the channels back on the closures this run's `release` replaced, under a new release number. |
| `apple` | If `verify` passed and `ship_apple` is on: runs the Apple release workflow (`apple-release.yml`), which builds the Rust core from this commit, archives the iOS app, signs it and uploads a new version to App Store Connect (`apps/apple/release.sh`). Version and build number are always above everything already uploaded (`apps/apple/asc-next.mjs`). macOS ships only from a manual run that asks for it. |
| `app-store` | If `verify` passed and `app_store_version` is set (the App Store workflow sets it once Apple approves a build): releases that approved version, so the app goes live only against a server proven to speak its protocol. |

Re-running Deploy on the same ref changes nothing.

## Shipping an app version with its server

`app-store.yml` keeps the App Store and the server in step
(`apps/apple/asc-review.mjs`): a manual run from `main` submits the newest
uploaded build for review with a manual release and tags its commit
`app-store/<version>`; every 30 minutes a watcher looks for the newest tagged
version Apple has approved and runs Deploy on that tag with
`app_store_version` set. A tag whose commit is not on `main` is ignored, and a
tag that already has a deploy run is never deployed again by the watcher:
after a failed deploy, re-run Deploy by hand from the tag, with
`app_store_version` set and `ship_apple` off.

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

Hosts also refuse ICMP redirects, keep no core dumps and audit the paths
that hold keys; the root setup units and the operator tools run sandboxed.

To return to an earlier release by hand, revert on `main` and run Deploy: it
rebuilds nothing that is in the cache, and signs a new pointer.

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
   `AGE_IDENTITY_MQTT` and (if none exists) `NIX_CACHE_SIGNING_KEY`, and for
   an environment with `sizes.sim`, `SIM_SEEDS` and `AGE_IDENTITY_SIM`. It
   never overwrites a secret, so it is also how an existing environment gets
   the sim node's.
4. Optionally set `STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET` and
   `APNS_KEY_P8` on the GitHub Environment. For the `apple` and `app-store`
   jobs (`apple` is on by default through the `ship_apple` input), also set
   `ASC_KEY_ID`, `ASC_ISSUER_ID` and `ASC_KEY_P8`: an App Store Connect team
   API key with the Admin role, which cloud-managed distribution signing
   requires. The job builds the core and archives the iOS app after `verify`,
   lets Xcode sign it with that key (nothing stored on the runner) and uploads
   it to TestFlight; submitting for review is the App Store workflow's manual
   run. The Apple release workflow also runs on every push to `main` that
   changes the apps, the core, the HQC library or the toolchain pins, and by
   hand with an optional version.
5. Protect the GitHub Environment (Settings → Environments): a required
   reviewer, and deployment branches limited to `main` and `app-store/*`
   tags. The workflows refuse other refs themselves, but without the
   protection a workflow on any branch could read the secrets.
6. Optionally list the admin addresses in `adminSshSources`, so the
   firewall closes the app host's SSH to everyone else
   ([environments](../../infra/environments/README.md)).
7. Run Deploy.

The hqn/1 gateway keys (`NOISE_KEYS`) are what a build may pin
(`Deployment.hqnKeyPins`). With no pins, clients take the keys
`/auth/transport` serves over HTTPS; a build that pins keys other than an
environment's falls back to WebSocket there, so rotate `NOISE_KEYS` by
shipping the new pin first, with both keys served during the overlap.

## Post-quantum secret bundles on hosts that predate them

`publish-secrets.sh` seals bundles only to post-quantum age recipients, and
refuses to run without `AGE_IDENTITY_APP` and `AGE_IDENTITY_MQTT` (and
`AGE_IDENTITY_SIM` where there is a sim node). A droplet
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

SSH is for diagnosis, not for changes. It accepts keys only, hybrid
post-quantum key exchange only (with AES-256-GCM and SHA-512), and is
rate-limited per source: `ssh root@<app ip>`, and the broker through it (`ssh -J root@<app ip> root@<broker vpc ip>`). Host keys are in the
Terraform output `hosts` (sensitive: `terraform output -json hosts`). Useful units: `hqcat-host-agent`, `hqcat-secrets-sync`,
`hqcat-netconf`, `hqcat-server`, `hqcat-bot`, `podman-emqx`, `hqcat-noise-gw`,
`hqcat-wireguard`; on the sim node, `hqcat-sim` ([sim runbook](sim.md)).
