# Fuzzing the Apple client

The client holds the plaintext, so a parser bug here is the attack. These
targets fuzz the code that reads bytes off the network before anything
authenticates them, and hold the Swift and TypeScript implementations of each
shared format to the same answers.

## Drivers

Apple's toolchain has no libFuzzer runtime (`-sanitize=fuzzer` is unsupported
on macOS), so there are two drivers:

| | how | coverage-guided |
|---|---|---|
| **native** (default) | nothing to install | no: a random walk around the seed corpus, bounded by `Mutator.swift` |
| **libFuzzer** | `brew install llvm`, then `--libfuzzer` | yes |

`--asan` adds AddressSanitizer for the C boundary. Linux (`swiftc
-sanitize=fuzzer`) works for targets that use only Foundation.

## Targets

| Target | What it fuzzes | Oracle |
|---|---|---|
| `mqtt-wire` | `MQTTCodec`, the MQTT 3.1.1 decoder fed straight from the socket | no trap or overflow (both kill a Swift process); `.incomplete` only for a packet that could still fit under `maxPacketBytes`, and nothing accepted above it |
| `topic-route` | `MQTTTopics.route`, which picks the conversation from a sender-chosen topic | total, deterministic, agrees with `peer(in:)`, and the app's own topic builders round-trip |
| `ratchet-state` | `RatchetSession.open` against attacker-chosen `n`, `pn` and steps | no hang (a watchdog armed before the call), replays refused, the skipped-key cache bounded; reports its reach (`accepted`, `replays-refused`, `cache-grew`) |
| `envelope-v3-verdict` | the frame decoder, against the TypeScript one (`services/server/test/fuzz/envelope-v3-differential.ts`) | same verdict, same AAD, same decoded fields |
| `envelope-v3-encode-verdict` | the frame encoder, against the TypeScript one (`envelope-v3-encode-differential.ts`) | the same structs refused; accepted ones give identical bytes |
| `handshake-verdict` | the handshake frame, both directions (`handshake-differential.ts`) | `decode`, `encode` and `round` (each side its own inverse) agree |
| `noise-verdict` | hqn/1 messages and transport frames (`noise-differential.ts`) | both sides accept and reject the same bytes |
| `scrub-verdict` | `Redaction.swift` against `src/common/scrub.ts` (`scrub-differential.ts`) | the same redactions and the same sensitive-key decisions |

A differential is only trusted after injecting a divergence into one side and
seeing it reported.

## Layout

| File | Role |
|---|---|
| `Engine.swift` | the native driver: PRNG, corpus, loop, crash capture |
| `Mutator.swift` | mutation strategies |
| `GenSeeds.swift`, `GenTopicSeeds.swift` | seed corpora, built from the real encoders and topic builders |
| `*Target.swift`, `*Main.swift` | in-process targets |
| `*Verdict.swift` | the Swift half of each differential |
| `run.sh` | build and run |

`corpus/` is committed: it is the fuzzer's accumulated knowledge. `findings/`
and `build/` are not.

## Running

```bash
./run.sh seeds && ./run.sh topic-seeds       # regenerate the corpora
./run.sh mqtt-wire --iterations 5000000 --seed 7
./run.sh topic-route --iterations 50000
./run.sh ratchet-state --iterations 10000
./run.sh envelope-v3-verdict                 # then the TypeScript driver:
(cd ../../../services/server && npx tsx test/fuzz/envelope-v3-differential.ts --iterations 5000)
./run.sh repro findings/current-input.bin    # replay one input
```

`apps/apple/verify.sh` runs every target at a modest iteration count.

## When it crashes

A Swift trap kills the process outright, so `Engine.swift` writes each input to
`findings/current-input.bin` **before** running it: whatever is there when the
process dies is the input that killed it.

1. `./run.sh repro findings/current-input.bin` to confirm it reproduces.
2. Copy it aside; the next run overwrites it.
3. Shrink it until every byte matters.
4. Fix the bug.
5. Add the shrunk bytes as a permanent case in the matching test file under
   `apps/apple/tests/`, and the file to `corpus/`. The fuzz run is occasional;
   the regression test runs every time.

## Not covered yet

`ConversationRouter`'s handling of an `init` and a message arriving out of order
on their two topics, and the shared `LAContext` state machine.
