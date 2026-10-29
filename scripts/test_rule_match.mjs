// Runs scripts/test_rule_match.py with the bundled Python: restricted-subset compiler and rejected syntax,
// text/hex/wildcard/wide/nocase matching against brute-force references, condition semantics, chunk boundaries,
// evidence/occurrence budgets, the real protection corpus and Windows system files, and the real Ghidra
// ig5_scan acceptance (built-in table, caller-supplied rules, a rejected construct, read-only guarantees).
// extended tier: needs the bundled runtime, so a missing interpreter or engine is a failure rather than a silent skip.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const python = process.env.IG5_PYTHON || path.join(root, "runtimes", "ghidra", "python", "python.exe");
assert(fs.existsSync(python), `bundled Python not found: ${python} (set IG5_PYTHON)`);
const run = spawnSync(python, ["-I", "-B", "-X", "utf8", path.join(root, "scripts", "test_rule_match.py"), "--runtime", "ghidra"],
  { cwd: root, encoding: "utf8", timeout: 580000, windowsHide: true });
process.stdout.write(run.stdout || "");
process.stderr.write((run.stderr || "").split("\n").filter(line => !/ResourceWarning|tracemalloc|unclosed file/.test(line)).join("\n"));
assert.equal(run.status, 0, `signature rule matching tests failed (exit ${run.status})`);
assert.match(run.stdout, /"engine": "ghidra"/, "the real-engine acceptance must have run");
assert.match(run.stdout, /"sourceUnchanged": true/, "the acceptance must prove the sample was not modified");
