// Runs scripts/test_packer_analysis.py with the bundled Python: rule-table checks, generated PE/ELF cases, the real protection
// corpus and Windows system files (each skipped loudly when absent), and the real Ghidra ig5_scan acceptance.
// extended tier: needs the bundled runtime, so a missing interpreter or engine is a failure rather than a silent skip.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const python = process.env.IG5_PYTHON || path.join(root, "runtimes", "ghidra", "python", "python.exe");
assert(fs.existsSync(python), `bundled Python not found: ${python} (set IG5_PYTHON)`);
const run = spawnSync(python, ["-I", "-B", "-X", "utf8", path.join(root, "scripts", "test_packer_analysis.py"), "--runtime", "ghidra"],
  { cwd: root, encoding: "utf8", timeout: 580000, windowsHide: true });
process.stdout.write(run.stdout || ""); process.stderr.write((run.stderr || "").split("\n").filter(line => !/ResourceWarning|tracemalloc|unclosed file/.test(line)).join("\n"));
assert.equal(run.status, 0, `packing analysis tests failed (exit ${run.status})`);
assert.match(run.stdout, /"engine": "ghidra"/, "the real-engine acceptance must have run");
