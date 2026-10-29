// Inspect installed host code only: no profile/session writes, imports or model calls.
import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';

const asar = path.join(process.env.LOCALAPPDATA, 'Programs/DeepSeek Harness/resources/app.asar');
const output = process.argv[2];
assert(output, 'Usage: node scripts/audit_uxr_host.mjs <new-report.json>');
assert(!fs.existsSync(output), 'Preserve prior evidence; choose a new report path');
const fd = fs.openSync(asar, 'r');
try {
  const first = Buffer.alloc(8); assert.equal(fs.readSync(fd, first, 0, 8, 0), 8);
  const size = first.readUInt32LE(4); assert(size > 8 && size <= 16 * 1024 * 1024);
  const header = Buffer.alloc(size); assert.equal(fs.readSync(fd, header, 0, size, 8), size);
  const inventory = JSON.parse(header.subarray(8, 8 + header.readUInt32LE(4)));
  function read(relative) {
    const entry = relative.split('/').reduce((at, part) => at?.files?.[part], inventory);
    assert(entry && !entry.unpacked && Number.isSafeInteger(entry.size) && entry.size <= 4 * 1024 * 1024);
    const bytes = Buffer.alloc(entry.size);
    assert.equal(fs.readSync(fd, bytes, 0, bytes.length, 8 + size + Number(entry.offset)), bytes.length);
    return bytes;
  }
  const prefix = 'dsh/node_modules/@deepseek-ai/';
  const files = [];
  for (const name of ['dsh-agent-loop', 'dsh-session', 'dsh-session-persistence', 'dsh-session-persistence-jsonl']) {
    const metadata = JSON.parse(read(`${prefix}${name}/package.json`));
    const relative = `${prefix}${name}/lib/index.js`, bytes = read(relative), lines = bytes.toString('utf8').split('\n');
    const matches = [];
    for (let i = 0; i < lines.length; i++) {
      if (/async resume\(|resumeWith\(|persistence\.open\(id, "write"|handle\.append\(closers\)|meta: structuredClone\(handle.header\)|setupAndPublish\(ownerCtx, id|Persistence is intentionally|async open\(|async read\(/.test(lines[i])) {
        matches.push({ line: i + 1, text: lines[i].trim() });
      }
    }
    files.push({ package: name, version: metadata.version, source: relative, sha256: createHash('sha256').update(bytes).digest('hex'), matches });
  }
  const loop = files.find(file => file.package === 'dsh-agent-loop').matches;
  assert(loop.some(match => match.text.includes('persistence.open(id, "write"')));
  assert(loop.some(match => match.text.includes('handle.append(closers)')));
  assert(loop.some(match => match.text.includes('meta: structuredClone(handle.header)')));
  const report = {
    schemaVersion: 1, observedAt: new Date().toISOString(), asar, evidence: 'installed-host-source-inspection',
    hostBootVersion: JSON.parse(read(`${prefix}dsh-app-boot/package.json`)).version,
    files, conclusion: {
      hostResumeApiExists: true, hostResumeIsMetadataOnly: false,
      pluginAutomaticResumeImplemented: false,
      reason: 'AgentLoop.resume acquires write ownership, may append interrupted-turn closers, then publishes a live agent. It cannot run in the metadata-only doctor contract.',
      supportedRecovery: 'Host restores the original persisted ancestors; IG5 resolves the original host agent objects and verifies the unchanged shared ledger.',
      actualHistoricalSessionRecoveryVerified: false,
    },
    effects: { profileModified: false, sessionOpened: false, modelCalled: false, targetExecuted: false },
  };
  fs.writeFileSync(output, JSON.stringify(report, null, 2) + '\n', { flag: 'wx' });
  console.log(JSON.stringify({ output: path.resolve(output), hostBootVersion: report.hostBootVersion, inspectedPackages: files.length }));
} finally { fs.closeSync(fd); }
