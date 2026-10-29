// Runs the offline Python suite for ig5_dbg op=apitrace with the bundled Python, then the
// live x64dbg acceptance on a generated fixture.
// extended tier: needs the bundled runtime and the owned x64dbg debuggee, so a missing
// interpreter or bridge is a failure rather than a silent skip.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const python = process.env.IG5_PYTHON || path.join(root, "runtimes", "ghidra", "python", "python.exe");
assert(fs.existsSync(python), `bundled Python not found: ${python} (set IG5_PYTHON)`);

const offline = spawnSync(python, ["-I", "-B", "-X", "utf8", path.join(root, "scripts", "test_api_trace.py")],
  { cwd: root, encoding: "utf8", timeout: 120000, windowsHide: true });
process.stdout.write(offline.stdout || ""); process.stderr.write(offline.stderr || "");
assert.equal(offline.status, 0, `API trace offline tests failed (exit ${offline.status})`);
const unit = JSON.parse(offline.stdout.trim().split("\n").pop());
assert.equal(unit.ok, true, "offline suite did not report ok");
assert.ok(unit.tests >= 26, `offline suite ran only ${unit.tests} tests`);

// The live lane starts and executes a generated PE fixture under the debugger bridge.
const live = spawnSync(process.execPath, [path.join(root, "scripts", "test_api_trace_runtime.mjs")],
  { cwd: root, encoding: "utf8", timeout: 240000, windowsHide: true });
process.stdout.write(live.stdout || ""); process.stderr.write(live.stderr || "");
assert.equal(live.status, 0, `API trace live acceptance failed (exit ${live.status})`);
const receipt = JSON.parse(live.stdout.trim().split("\n").pop());
assert.equal(receipt.schema, "ig5.api-trace-runtime.v1");
assert.equal(receipt.nativeTargetExecuted, true);
assert.equal(receipt.cleanupCleared, true);
assert.equal(receipt.targetUnchanged, true);
assert.deepEqual(receipt.calls.map((row) => row.api), ["IsDebuggerPresent", "GetTickCount64", "Sleep"]);
