/**
 * The implementation a differential harness compares TypeScript against: the
 * Rust core's `hqchat-verdict` (built by `cargo build --release -p
 * hqchat-verdict`). It speaks a batch-file protocol, one verdict line per
 * input line. (The Swift app's verdict programs went with the Swift protocol
 * code, when the apps moved onto the core.)
 */

import * as fs from "node:fs";
import * as path from "node:path";

export interface Oracle {
  /** For messages and findings. */
  name: string;
  command: string;
  /** Arguments before the harness's own (mode, batch file, …). */
  args: string[];
}

const REPO = path.join(__dirname, "..", "..", "..", "..");

/** `rustMode` is the hqchat-verdict subcommand; HQCHAT_VERDICT overrides where the binary is. */
export function oracle(rustMode: string): Oracle {
  const command = process.env.HQCHAT_VERDICT ?? path.join(REPO, "core/target/release/hqchat-verdict");
  if (!fs.existsSync(command)) {
    console.error(`✗ missing ${command}\n  build it: cd core && cargo build --release -p hqchat-verdict`);
    process.exit(2);
  }
  return { name: "rust", command, args: [rustMode] };
}
