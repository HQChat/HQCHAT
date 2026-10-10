## What this changes, and why

<!-- The reason first. What was wrong, or what became possible. -->

## How it was verified

<!-- Commands you ran and what they said. "CI is green" is not verification if
     CI does not cover this. Say what you could NOT verify. -->

- [ ] `nix develop --command scripts/check.sh lint`
- [ ] `scripts/check.sh unit` / `integration` / `scenarios` (if `services/server/` or `infra/emqx/` changed)
- [ ] `scripts/check.sh infra` (if `infra/` or `flake.*` changed)
- [ ] `bash apps/apple/verify.sh` (if `apps/apple/` changed): CI does not build
      the Apple apps, so this is the only gate on them
- [ ] the docs describing this are still true

## Anything a reviewer should be told

<!-- Behaviour changes on hot paths, migrations, things left deliberately open. -->
