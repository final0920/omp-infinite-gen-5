// Runs scripts/test_firmware.py with the bundled Python: rule table, bounded decompression, SquashFS/ext/cpio/tar/zip readers
// (7-Zip as a second opinion when installed), boot-image parsers, nested scan, safe extraction, hostile inputs and real files.
// extended tier: needs the bundled runtime, so a missing interpreter is a failure rather than a silent skip.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const python = process.env.IG5_PYTHON || path.join(root, "runtimes", "ghidra", "python", "python.exe");
assert(fs.existsSync(python), `bundled Python not found: ${python} (set IG5_PYTHON)`);
const run = spawnSync(python, ["-I", "-B", "-X", "utf8", path.join(root, "scripts", "test_firmware.py")], { cwd: root, encoding: "utf8", timeout: 280000, windowsHide: true });
process.stdout.write(run.stdout || ""); process.stderr.write((run.stderr || "").split("\n").filter(line => !/ResourceWarning|tracemalloc|unclosed file/.test(line)).join("\n"));
assert.equal(run.status, 0, `firmware tests failed (exit ${run.status})`);
