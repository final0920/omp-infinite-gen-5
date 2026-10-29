// Selection and byte binding only. No target execution or implicit successful-rerun selection.
import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';

const hash = bytes => createHash('sha256').update(bytes).digest('hex');
export function selectNativeAcceptances(root, explicitRuns = []) {
  root = fs.realpathSync(root);
  const folders = explicitRuns.length ? explicitRuns : fs.readdirSync(root)
    .filter(name => /^owned-(phase|branch)-vm64-native-/.test(name));
  assert.equal(folders.length, 1, 'Choose exactly one sealed batch with --native-run; batches are never merged or filtered by success');
  const folder = folders[0];
  assert.equal(path.basename(folder), folder, '--native-run must be a direct child folder name');
  assert(/^owned-(phase|branch)-vm64-native-/.test(folder), 'Unknown native batch name');
  const file = path.join(root, folder, 'acceptance.json');
  for (const item of [path.dirname(file), file]) assert(!fs.lstatSync(item).isSymbolicLink(), 'Linked native batch is not supported');
  const bytes = fs.readFileSync(file), receipt = JSON.parse(bytes);
  assert.equal(receipt.ok, true, 'Selected native batch failed; preserve it and select another batch explicitly');
  assert.equal(receipt.nativeTargetExecuted, true, 'Native execution must be recorded');
  assert(Array.isArray(receipt.captures) && receipt.captures.length === 3, 'Expected three captures in the selected batch');
  return { root, receipt, source: { path: file, sha256: hash(bytes), bytes: bytes.length },
    selection: explicitRuns.length ? 'explicit-single-batch' : 'unique-single-batch' };
}

export function copyNativeCaptures(selected, artifactDir, expectedSha256, inputs) {
  assert.equal(selected.receipt.targetSha256, expectedSha256, 'Selected batch target does not match the exact source');
  const sourceDir = fs.realpathSync(path.join(selected.root, 'artifacts', 'debug-traces'));
  const dest = path.join(artifactDir, 'debug-traces'), seen = new Set();
  inputs.push(selected.source);
  function copy(from, part, name, expected) {
    assert(!fs.lstatSync(from).isSymbolicLink(), 'Linked capture file is not supported');
    const canonical = fs.realpathSync(from), allowed = path.join(sourceDir, part);
    assert.equal(path.dirname(canonical).toLowerCase(), allowed.toLowerCase(), 'Capture must remain in its original store');
    const bytes = fs.readFileSync(canonical);
    assert(bytes.length <= 1024 * 1024, 'Capture file exceeds original limit');
    if (expected) assert.equal(hash(bytes), expected, 'Capture byte digest mismatch');
    fs.mkdirSync(path.join(dest, part), { recursive: true });
    const target = path.join(dest, part, name);
    if (fs.existsSync(target)) assert.equal(hash(fs.readFileSync(target)), hash(bytes), 'Conflicting repeated artifact');
    else fs.writeFileSync(target, bytes, { flag: 'wx' });
    inputs.push({ path: canonical, sha256: hash(bytes), bytes: bytes.length });
    return bytes;
  }
  return selected.receipt.captures.map(capture => {
    const reportBytes = fs.readFileSync(capture.traceReportPath);
    assert.equal(hash(reportBytes), capture.traceReportSha256);
    const report = JSON.parse(reportBytes);
    assert(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(report.id));
    assert(!seen.has(report.id), 'Duplicate native capture'); seen.add(report.id);
    copy(capture.traceReportPath, 'records', report.id + '.json', capture.traceReportSha256);
    const meta = JSON.parse(copy(path.join(sourceDir, 'metadata', report.id + '.json'), 'metadata', report.id + '.json'));
    assert.equal(meta.recordSha256, capture.traceReportSha256);
    for (const digest of [report.result.sha256, report.result.storeEvents.sha256]) {
      assert(/^[0-9a-f]{64}$/.test(digest));
      copy(path.join(sourceDir, 'blobs', digest + '.bin'), 'blobs', digest + '.bin', digest);
    }
    return { recordings: [{ id: report.id, sha256: capture.traceReportSha256 }] };
  });
}
