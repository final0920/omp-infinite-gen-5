// Runs scripts/test_review_20261024_python.py with the bundled Python (IG5_PYTHON overrides).
// extended tier: needs the bundled runtime, so a missing interpreter is a failure rather than a silent skip.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const python = process.env.IG5_PYTHON || path.join(root, 'runtimes', 'ghidra', 'python', 'python.exe');
assert(fs.existsSync(python), `bundled Python not found: ${python} (set IG5_PYTHON)`);
const run = spawnSync(python, ['-I', '-B', '-X', 'utf8', path.join(root, 'scripts', 'test_review_20261024_python.py')],
  { cwd: root, encoding: 'utf8', timeout: 100000, windowsHide: true });
process.stdout.write(run.stdout || '');
process.stderr.write(run.stderr || '');
assert.equal(run.status, 0, `Python regression tests failed (exit ${run.status})`);
const summary = JSON.parse(run.stdout.trim().split(/\r?\n/).at(-1));
assert.equal(summary.ok, true); assert(summary.passed >= 15, 'expected at least 15 checks'); assert.equal(summary.nativeLaunches, 0);
