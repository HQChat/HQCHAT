/**
 * The implementation a differential harness compares TypeScript against:
 * the Rust core (`--oracle rust`, the default, runs anywhere `cargo` does) or
 * the Swift app (`--oracle swift`, built by apps/apple/fuzz/run.sh on a Mac).
 * Both speak the same batch-file protocol, one verdict line per input line.
 */

import * as fs from "node:fs";
import * as path from "node:path";

export interface Oracle {
  /** "rust" or "swift", for messages and findings. */
  name: string;
  command: string;
  /** Arguments before the harness's own (mode, batch file, …). */
  args: string[];
}

const REPO = path.join(__dirname, "..", "..", "..", "..");

/**
 * `swiftTarget` names the Swift program (apps/apple/fuzz/build/<name>);
 * `rustMode` the hqchat-verdict subcommand. HQCHAT_VERDICT overrides where
 * the Rust binary is.
 */
export function oracle(swiftTarget: string, rustMode: string): Oracle {
  const argv = process.argv.slice(2);
  const i = argv.indexOf("--oracle");
  const name = i === -1 ? "rust" : (argv[i + 1] ?? "");
  let o: Oracle;
  if (name === "swift") {
    o = { name, command: path.join(REPO, "apps/apple/fuzz/build", swiftTarget), args: [] };
  } else if (name === "rust") {
    const command = process.env.HQCHAT_VERDICT ?? path.join(REPO, "core/target/release/hqchat-verdict");
    o = { name, command, args: [rustMode] };
  } else {
    console.error(`✗ --oracle must be rust or swift, not ${name}`);
    process.exit(2);
  }
  if (!fs.existsSync(o.command)) {
    const build =
      o.name === "swift"
        ? `cd apps/apple/fuzz && ./run.sh ${swiftTarget}`
        : "cd core && cargo build --release -p hqchat-verdict";
    console.error(`✗ missing ${o.command}\n  build it: ${build}`);
    process.exit(2);
  }
  return o;
}
