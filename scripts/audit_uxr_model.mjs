// Independent verifier: inspect saved host events, never call model/tools.
import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
const root = path.resolve(process.argv[2]);
const read = file => JSON.parse(fs.readFileSync(path.join(root, file), 'utf8'));
const acceptance = read('acceptance.json'), plan = read('plan.json'), events = read('events.json');
assert.equal(acceptance.pass, true); assert.equal(acceptance.cleanupConfirmed, true);
const rows = fs.readFileSync(path.join(root, 'tools.jsonl'), 'utf8').trim().split('\n').map(JSON.parse);
const dispatches = rows.filter(row => row.phase === 'dispatch');
assert(dispatches.length <= plan.toolLimit && dispatches.every(row => row.allowed));
const outputs = rows.filter(row => row.phase === 'result');
const dossier = outputs.find(row => row.args?.style === 'dossier').result.value;
const pageOutputs = outputs.filter(row => row.args?.operation === 'read');
const visible = events.filter(event => event.type === 'tool/result').map(event => {
  const message = event.data.message;
  assert.equal(message.isError, false);
  return JSON.parse(message.content.filter(block => block.type === 'text').map(block => block.text).join('\n'));
});
const visiblePages = visible.filter(value => value.kind === 'function-result-page' || typeof value.contentSha256 === 'string' && typeof value.data === 'string');
assert.equal(visiblePages.length, pageOutputs.length);
assert(pageOutputs.length > 1);
let offset = 0, cursor;
const chunks = [];
for (let index = 0; index < pageOutputs.length; index++) {
  const row = pageOutputs[index], page = row.result.value;
  assert.equal(row.args.result_ref.id, dossier.savedResult.id);
  assert.equal(row.args.result_ref.sha256, dossier.savedResult.sha256);
  assert.equal(row.args.cursor || undefined, cursor || undefined);
  assert.equal(page.offset, offset);
  assert.equal(page.nextOffset - page.offset, Buffer.byteLength(page.data));
  assert(Buffer.byteLength(JSON.stringify(page)) <= row.args.page_max_bytes);
  assert.equal(visiblePages[index].data, page.data, 'Model-visible page must contain the exact complete data');
  assert.equal(visiblePages[index].nextCursor, page.nextCursor);
  assert.equal(visiblePages[index].contentSha256, page.contentSha256);
  chunks.push(page.data); offset = page.nextOffset; cursor = page.nextCursor;
}
assert.equal(cursor, null);
const code = chunks.join(''), digest = createHash('sha256').update(code).digest('hex');
assert(visiblePages.every(page => page.contentSha256 === digest));
assert.equal(acceptance.answer.pages, pageOutputs.length);
assert.equal(acceptance.answer.bytes, Buffer.byteLength(code));
assert.equal(acceptance.answer.contentSha256, digest);
const provider = dossier.sections.decompile.completeness.provider;
assert.equal(acceptance.answer.sourceComplete, provider === 'complete' ? true : provider === 'partial' ? false : null);
assert(Array.isArray(acceptance.answer.limitations) && acceptance.answer.limitations.length > 0);
assert(outputs.some(row => row.tool === 'ig5_close' && !row.result.isError));
const report = { pass: true, evidence: 'actual-installed-DSH-CLI-model-and-Ghidra; exact model-visible page contents independently verified',
  route: plan.route, dispatches: dispatches.length, pages: pageOutputs.length, bytes: Buffer.byteLength(code), digest,
  modelVisibleJsonIntact: true, allCursorsLinked: true, sourceCompleteness: provider, cleanupConfirmed: true,
  desktopGuiModelVerified: false, originalIncidentVerified: false, targetExecuted: false };
fs.writeFileSync(path.join(root, 'independent-audit.json'), JSON.stringify(report, null, 2), { flag: 'wx' });
console.log(JSON.stringify(report));
