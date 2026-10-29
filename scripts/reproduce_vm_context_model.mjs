// Import an immutable handler evidence closure into a fresh CAS and derive the
// conservative context model. This never executes the target or a decoder.
import fs from 'node:fs';
import path from 'node:path';
import { AnalysisArtifacts, hashBytes, readStableFile } from '../source/analysis_artifacts.js';
import { runVmContextProfile } from '../source/vm_context_profile.js';

const fail = message => { throw new Error('Context reproduction: ' + message); };
function readRecord(filename, sha256, kind, action) {
  if (!path.isAbsolute(filename) || !/^[a-f0-9]{64}$/.test(sha256 || '')) fail('absolute path and lowercase SHA-256 required');
  const { data } = readStableFile(filename, 8 * 1024 ** 2);
  if (hashBytes(data) !== sha256) fail('source SHA-256 differs: ' + filename);
  const record = JSON.parse(data);
  if (record.kind !== kind || record.action !== action) fail('source record kind differs: ' + filename);
  return { record, bytes: data.length, sha256, path: path.resolve(filename) };
}
function ref(store, saved) { return { id: saved.id, sha256: store.metadata(saved.id).result.recordSha256 }; }
function writeExclusive(filename, value) {
  const bytes = Buffer.from(JSON.stringify(value, null, 2));
  fs.writeFileSync(filename, bytes, { flag: 'wx', mode: 0o600 });
  return { path: path.resolve(filename), bytes: bytes.length, sha256: hashBytes(bytes) };
}
async function main() {
  const [outputRoot, ...pairs] = process.argv.slice(2);
  if (!outputRoot || !path.isAbsolute(outputRoot) || pairs.length < 2 || pairs.length % 2 || pairs.length > 32) fail('usage: OUTPUT_ROOT HANDLER_PATH HANDLER_SHA [HANDLER_PATH HANDLER_SHA ...]');
  fs.mkdirSync(outputRoot, { recursive: false });
  const store = new AnalysisArtifacts(path.join(outputRoot, 'analysis-data')), handlerRefs = [], origins = [];
  try {
    for (let i = 0; i < pairs.length; i += 2) {
      const handler = readRecord(pairs[i], pairs[i + 1], 'vm-recorded-handlers', 'assess'), source = handler.record.result;
      if (source?.schema !== 'ig5-recorded-handlers-v1') fail('handler schema differs');
      const directory = path.dirname(handler.path), recurrencePath = path.join(directory, source.sourceRecurrence.id + '.json');
      const recurrence = readRecord(recurrencePath, source.sourceRecurrence.sha256, 'vm-flow-recurrences', 'validate');
      const selection = readRecord(source.sourceSelection.path, source.sourceSelection.sha256, 'vm-handler-windows', 'select');
      const recurrenceSaved = store.save({ kind: 'vm-flow-recurrences', action: 'validate', result: recurrence.record.result }, { pretty: true, maxBytes: 8 * 1024 ** 2 });
      const selectionSaved = store.save({ kind: 'vm-handler-windows', action: 'select', result: selection.record.result }, { pretty: true, maxBytes: 8 * 1024 ** 2 });
      const importedRecurrence = ref(store, recurrenceSaved), importedSelectionBase = ref(store, selectionSaved);
      const importedSelection = { ...importedSelectionBase, path: path.join(store.directory('records'), selectionSaved.id + '.json') };
      const handlerSaved = store.save({ kind: 'vm-recorded-handlers', action: 'assess', result: { ...source,
        sourceRecurrence: importedRecurrence, sourceSelection: importedSelection } }, { pretty: true, maxBytes: 8 * 1024 ** 2 });
      const importedHandler = ref(store, handlerSaved); handlerRefs.push(importedHandler);
      origins.push({ original: { handlers: { path: handler.path, bytes: handler.bytes, sha256: handler.sha256 },
        recurrence: { path: recurrence.path, bytes: recurrence.bytes, sha256: recurrence.sha256 },
        selection: { path: selection.path, bytes: selection.bytes, sha256: selection.sha256 } },
        imported: { handlers: { ...importedHandler, path: path.join(store.directory('records'), handlerSaved.id + '.json') },
          recurrence: { ...importedRecurrence, path: path.join(store.directory('records'), recurrenceSaved.id + '.json') }, selection: importedSelection } });
    }
    const mgr = { analysis: { artifacts: store }, checkCancelled() {} };
    const context = runVmContextProfile(mgr, { handler_refs: handlerRefs }).context;
    const manifest = { schema: 'ig5-vm-context-reproduction-v1', createdBy: 'scripts/reproduce_vm_context_model.mjs',
      execution: { nativeTargetExecuted: false, decoderExecuted: false, changesExecutionAuthority: false }, origins,
      result: { reportId: context.reportId, reportPath: context.reportPath, reportSha256: context.reportSha256,
        status: context.status, evidence: context.evidence, vmRoleProved: false, businessAccepted: false } };
    const manifestFile = writeExclusive(path.join(outputRoot, 'reproduction.json'), manifest);
    process.stdout.write(JSON.stringify({ ...context, reproduction: manifestFile }) + '\n');
  } finally { await store.dispose(); }
}
main().catch(error => { process.stderr.write(String(error.stack || error) + '\n'); process.exitCode = 1; });
