import fs from 'node:fs';
import path from 'node:path';
import { randomUUID } from 'node:crypto';
import { readStableFile, hashBytes } from './analysis_artifacts.js';
const PIN = '65bf673f1c4304cc2c09076e3b96e368da9e0df72aa0badeba0c2a5cae392934';
const RUNTIME = '8fc4ae42f775f0139aa5f184c912db71f77e68d661c14564ab6f4820d434abea';
const fail = () => { throw new Error('Recorded decoder returned inconsistent bytes, process or evidence scope'); };
export async function runObservedDecode(jobs, sites, signal) {
  if (!Array.isArray(sites) || sites.length > 128 || sites.some(s => !s || !/^0x[0-9a-f]{1,16}$/.test(s.pc) || !/^(?:[0-9a-f]{2}){1,15}$/.test(s.bytes))
    || new Set(sites.map(s => s.pc + ':' + s.bytes)).size !== sites.length) fail();
  if (jobs.closed || signal?.aborted) throw new Error('Recorded decode cancelled');
  if (jobs.active.size >= 2) throw new Error('Analysis busy; maximum two owned requests');
  const raw = Buffer.from(JSON.stringify({ schema: 'ig5-observed-decode-input-v1', sites: sites.map(({ pc, bytes }) => ({ pc, bytes })) }));
  if (raw.length > 65536) fail();
  const input = jobs.artifacts.put(raw), jobId = randomUUID(), parent = path.join(jobs.artifacts.root, 'jobs');
  if (fs.realpathSync(parent) !== parent || !fs.lstatSync(parent).isDirectory()) fail();
  const directory = path.join(parent, jobId); fs.mkdirSync(directory);
  const reply = await jobs.request({ job_id: jobId, sha256: input.sha256 }, signal, 'decode-observed'), p = reply?.process;
  if (reply?.targetSha256 !== input.sha256 || reply.runtimeManifestPin !== RUNTIME || p?.status !== 'completed' || p.exitCode !== 0 || p.limitReason !== null
    || p.childExitConfirmed !== true || p.jobAssignedAtCreation !== true || p.activeProcessLimit !== 1 || p.memoryLimitBytes !== 2 * 1024 ** 3
    || !Number.isSafeInteger(p.pid) || p.pid < 1 || !Number.isSafeInteger(p.elapsedMs) || p.elapsedMs < 0
    || !Number.isSafeInteger(reply.sharedBudgetMs) || reply.sharedBudgetMs < 1 || reply.sharedBudgetMs > 50000
    || !Number.isSafeInteger(reply.processBudgetMs) || reply.processBudgetMs < 1 || reply.processBudgetMs > reply.sharedBudgetMs
    || p.elapsedMs > reply.processBudgetMs + 100 || !Number.isSafeInteger(reply.outputBytes) || reply.outputBytes < 1 || reply.outputBytes > 4 * 1024 ** 2) fail();
  const { data } = readStableFile(path.join(directory, 'stdout.log'), 4 * 1024 ** 2);
  if (data.length !== reply.outputBytes || hashBytes(data) !== reply.outputSha256) fail();
  const result = JSON.parse(data.toString('utf8'));
  if (result.schema !== 'ig5-observed-decode-v1' || result.inputSha256 !== input.sha256 || result.decoderManifestPin !== PIN || result.runtimeManifestPin !== RUNTIME
    || result.decoder !== 'pinned-triton-disassembly-only' || !Array.isArray(result.sites) || result.sites.length !== sites.length
    || result.sites.some((row, index) => row.pc !== sites[index].pc || row.bytes !== sites[index].bytes)
    || ['nativeTargetExecuted','databaseModified','businessAccepted','wholeBinaryVerified'].some(k => result[k] !== false)) fail();
  const record = jobs.artifacts.save({ kind: 'recorded-byte-decode', action: 'decode-observed', input,
    inputMeaning: 'JSON instruction byte strings; input SHA is not an executable target SHA', process: p, result }, { pretty: true, maxBytes: 4 * 1024 ** 2 });
  return { result, process: p, reportPath: path.join(jobs.artifacts.root, 'records', record.id + '.json'), reportSha256: jobs.artifacts.metadata(record.id).result.recordSha256 };
}
