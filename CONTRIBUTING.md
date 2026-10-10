# Contributing

## Getting a working checkout

```bash
git clone git@github.com:HQChat/HQCHAT.git && cd HQCHAT
cd services/server && npm ci      # Node 22
open apps/apple/HQChat.xcodeproj # Xcode 26+
```

No secret is committed. `infra/environments/<name>.json` is where a server
deployment is described; `apps/apple/HQChat/Deployment.swift` holds the
official app's defaults.

The server and everything outside `apps/apple/` are AGPL-3.0; the app is
PolyForm Strict. Read [LICENSING.md](LICENSING.md) before contributing to
`apps/apple/`: a contribution there is accepted only with the grant it
describes.

## Before you open a PR

Pull requests target the branch they were cut from.

| Change touches | Run |
|---|---|
| anything | `nix develop --command scripts/check.sh lint` |
| `services/server/` | `scripts/check.sh unit`, `scripts/check.sh integration` (needs `DATABASE_URL`) |
| the server, the broker config or the hosts | `scripts/check.sh scenarios` (Docker) |
| `infra/` | `nix develop --command scripts/check.sh infra` |
| `apps/apple/` | `bash apps/apple/verify.sh`; CI does not build the Apple apps |
| anything | make sure the docs that describe it are still true |

CI (`.github/workflows/ci.yml`) runs every one of those layers except the Apple
gate, plus the two-VM stack test when the hosts or the server change.

### Make the Apple gate hard to forget

`verify.sh` is the only thing that runs the Swift suites, both app builds, the UI
tests, the differential fuzzers and the file-bus simulation. Nothing in CI does.
It records what it verified in `apps/apple/.build/verify-stamp`, and there is an
opt-in hook that refuses to push Apple changes that stamp does not cover:

```bash
git config core.hooksPath apps/apple/hooks
```

Bypass with `SKIP_APPLE_VERIFY=1 git push` when you mean to.

### Coverage

Both numbers are measured over every source file, not just the ones a test
imported: a file no test loads reports as zero rather than vanishing from the
average.

```bash
cd services/server && npm run coverage      # server
COVERAGE=1 bash apps/apple/tests/run.sh && bash apps/apple/tests/coverage-report.sh
```

`verify.sh` runs the Swift one for you. Neither enforces a threshold yet; they
report, so the baseline is visible before it is defended.

A skipped check is coverage that left. `apps/apple/tests/expected-skips.txt`
budgets the checks that cannot run in an unsigned local build, and a suite that
skips more than its budget fails.

## House style

**Comments are functional documentation.** Document what a public function,
type, module or script provides, and say *why* inline only where the code
cannot: a security invariant, a wire constant, a non-obvious constraint. Never
narrate history (what the code used to do, which bug a line fixed, which PR
added it); that belongs in the commit message. `scripts/lint-text.sh comments`
flags the common history phrases.

**Commit messages are prose.** Say what changed and *why it needed to*. Not a
bullet list of files.

**No dead code.** If something is retired, delete it.

## This repository is public

Everything committed here is published, history included. No keys, no
personal addresses, no origin IPs: `.gitleaks.toml` and CI catch the shapes
they know, which is not all of them. Deployment identity belongs in
`infra/environments/<name>.json` and `Deployment.swift`; secrets belong in the
GitHub Environment (`infra/scripts/init-environment.sh`).

The server must still build on its own, without reaching into `apps/`.

## Security

Do not open a public issue for a vulnerability — see [SECURITY.md](SECURITY.md).
