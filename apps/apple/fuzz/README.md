# Fuzzing the Apple client

The protocol's parsers (frames, handshake, hqn/1, MQTT) moved to the Rust
core, and are fuzzed there against the TypeScript reference
(`scripts/check.sh core`). What stays in Swift is the Sentry scrubber, the
last thing that runs before an event leaves the device.

| Target | What it fuzzes | Oracle |
|---|---|---|
| `scrub-verdict` | `Redaction.swift` against `services/common/src/scrub.ts` (`scrub-differential.ts`) | the same redactions and the same sensitive-key decisions |

```bash
./run.sh scrub-verdict
(cd ../../../services/server &&
  npx tsx test/fuzz/scrub-differential.ts --iterations 20000 --mode redact &&
  npx tsx test/fuzz/scrub-differential.ts --iterations 20000 --mode key)
```

A differential is only trusted after injecting a divergence into one side and
seeing it reported. `apps/apple/verify.sh` runs it.
