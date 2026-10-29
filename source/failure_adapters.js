import { createHash } from 'node:crypto';
import { jsonToolOutput } from './json_output.js';
import path from 'node:path';
import { readStableFile, hashBytes } from './analysis_artifacts.js';

const digest = value => createHash('sha256').update(JSON.stringify(value)).digest('hex');
const supported = new Set(['doctor','open','status','funcs','strings','decompile','xrefs','calls','bytes','search','listing','scan','export_diff','cfg','slice','fingerprint',
  'rename','patch_bytes','comment','analyze','set_type','undo','run_idapython','dbg','struct','close','profile','stack','switches','switch_repair','vtables','microcode','bindiff','emulate','ir','sync','crypto','protocol','capture','capture_control'].map(name=>`ig5_${name}`));
/** Fixed tool adapters: hash parameters in memory, never persist raw key/script/body. */
export function failureBinding(operation, args, mgr, error = {}) {
  if (!supported.has(operation)) return { semanticInputs: null };
  const hashes = [];
  const visited = new Set(); let reportBytes = 0;
  let comparable = true;
  const reportContent = (id, expected = null) => {
    if(visited.has(id)||visited.size>=4)throw new Error('Failure binding report budget exceeded');
    visited.add(id);
    const artifacts=mgr.analysis.artifacts, meta=artifacts.metadata(id).result;
    if(expected!==null&&meta.recordSha256!==expected)throw new Error('Changed report');
    const {data}=readStableFile(path.join(artifacts.directory('records'),`${id}.json`),Math.min(256*1024,1024*1024-reportBytes));
    reportBytes+=data.length;
    if(hashBytes(data)!==meta.recordSha256)throw new Error('Changed report bytes');
    const {id:recordId,createdAt,schemaVersion,...content}=JSON.parse(data.toString('utf8'));
    if(recordId!==id||schemaVersion!==1)throw new Error('Invalid report envelope');
    hashes.push(meta.recordSha256);
    return content;
  };
  const normalize = (value, key = '') => {
    if (Array.isArray(value)) return value.map(x => normalize(x, key));
    if (!value || typeof value !== 'object') {
      if (['result_id','report_id'].includes(key) && typeof value==='string' && /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(value)) {
        try { return {semanticReport:digest(normalize(reportContent(value)))}; }
        catch { comparable=false;return {invalidReport:true}; }
      }
      return value;
    }
    // A caller digest on an arbitrary file does not establish trusted content.
    // Do not read new files as an error-handling side effect.
    if(typeof value.path==='string'&&typeof value.sha256==='string')comparable=false;
    if (typeof value.id === 'string' && /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(value.id) && typeof value.sha256 === 'string') {
      try {
        const content = reportContent(value.id, value.sha256);
        return { semanticReport: digest(normalize(content)) };
      } catch { comparable = false; return { invalidReport: true }; }
    }
    return Object.fromEntries(Object.keys(value).sort().filter(k => !(key === 'workspace' && ['next_step', 'hypothesis', 'conclusion', 'expected_task_revision'].includes(k)))
      .map(k => [k, normalize(value[k], k)]));
  };
  const canonical = normalize(jsonToolOutput(args));
  return { semanticInputs: comparable ? { adapter: `${operation}-v1`, inputContentSha256: digest(canonical) } : null,
    inputReportHashes: hashes,
    executionIdentity: { runId: error.runId ?? args.run_id ?? null, stopSeq: error.stopSeq ?? args.expected_stop_seq ?? null,
      executionLocation: error.executionLocation ?? null },
    failedStage: typeof args.level === 'string' ? args.level : typeof args.action === 'string' ? args.action : args.workspace?.action || null };
}
