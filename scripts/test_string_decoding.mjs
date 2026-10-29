// Runs scripts/test_string_decoding.py with the bundled Python: unit tests, the Unicorn end-to-end run, and the real Ghidra acceptance.
// extended tier: needs the bundled runtime, so a missing interpreter or engine is a failure rather than a silent skip.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const python = process.env.IG5_PYTHON || path.join(root, "runtimes", "ghidra", "python", "python.exe");
assert(fs.existsSync(python), `bundled Python not found: ${python} (set IG5_PYTHON)`);
const run = spawnSync(python, ["-I", "-B", "-X", "utf8", path.join(root, "scripts", "test_string_decoding.py"), "--runtime", "ghidra"],
  { cwd: root, encoding: "utf8", timeout: 280000, windowsHide: true });
process.stdout.write(run.stdout || ""); process.stderr.write(run.stderr || "");
assert.equal(run.status, 0, `string decoding tests failed (exit ${run.status})`);
assert.match(run.stdout, /"engine": "ghidra"/, "the real-engine acceptance must have run");
