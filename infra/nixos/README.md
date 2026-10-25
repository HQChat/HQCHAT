# NixOS hosts

Every droplet runs NixOS built from this flake. There are no per-host files:
a system is an environment (`infra/environments/<name>.json`) and a role.

| Output | What it is |
|---|---|
| `nixosConfigurations.<env>-base` / `packages.image-<env>` | the image every droplet boots first |
| `nixosConfigurations.<env>-app` / `packages.toplevel-<env>-app` | nginx, the server and the bot |
| `nixosConfigurations.<env>-mqtt` / `packages.toplevel-<env>-mqtt` | EMQX and the hqn/1 gateway |
| `nixosConfigurations.<env>-sim` / `packages.toplevel-<env>-sim` | the sim node's synthetic accounts (deployed only where the environment sets `sizes.sim`) |
| `checks.x86_64-linux.stack` | both roles on two VMs joined by WireGuard |

## Modules

| Module | Provides |
|---|---|
| `options.nix` | `hqcat.role`, `hqcat.environment`, admin keys |
| `netconf.nix` | addressing, role and SSH host key from DigitalOcean's metadata service |
| `host-agent.nix`, `../hqcat-host-agent.sh` | pull, switch and health-gated rollback from the signed, numbered `channels/<env>/<role>.signed` (`../hqcat-verify-signed.sh` checks the signature) |
| `secrets.nix` | the host's age-encrypted secret bundle, installed under `/etc/hqcat/secrets` |
| `wireguard.nix` | the app ↔ broker link, configured from the bundle |
| `firewall.nix` | nftables per role, inbound and outbound (hosts reach out only on the ports they use); metadata service for root only |
| `cloudflare-ips.nix` | the refresh of Cloudflare's ranges, which hands nftables only validated CIDRs |
| `roles.nix` | everything a host is, independent of the machine (what the stack test imports); `default.nix` adds the DigitalOcean platform |
| `app.nix`, `nginx.nix` | the app role |
| `mqtt.nix` | the broker role |
| `sim.nix` | the sim node role (`docs/runbooks/sim.md`) |
| `units.nix` | the unit every hqcat program runs in: shared environment, credentials, sandbox and memory limits |
| `health.nix` | `hqcat-health-check`, which gates every switch |
| `hardening.nix` | SSH (keys only, hybrid post-quantum key exchange, per-source rate limit), sysctls (no ICMP redirects), no core dumps, audit rules on key paths, and the systemd sandbox every service runs in |
| `hardware.nix`, `image.nix` | the droplet's boot disk and the image built from it |

```bash
nix build .#checks.x86_64-linux.stack -L    # needs KVM
nix build .#toplevel-production-app
```

Deploying is the Deploy workflow; see `docs/runbooks/deploy.md`.
