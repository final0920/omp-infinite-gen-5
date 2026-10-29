import fs from 'node:fs';
import path from 'node:path';
import { readStableFile, hashBytes } from './analysis_artifacts.js';
import { JAVA_PROJECTION_RUNTIME_PIN } from './projection_decoder.js';

const runtimePin = '8fc4ae42f775f0139aa5f184c912db71f77e68d661c14564ab6f4820d434abea';
const files = {
  'java-input.json':65536, 'java-decode/started.json':4096,
  'java-decode/stdout.log':4*1024**2, 'java-decode/stderr.log':4*1024**2,
  'java-decode-process.json':16384, 'request.json':65536,
  'state-computation-process.json':16384, 'stdout.log':4*1024**2, 'stderr.log':4*1024**2,
};
const stages = ['preflight','java-runtime','java-decode','java-validation','state-computation','result-validation'];
const sha = value => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
const plain = value => value && typeof value === 'object' && !Array.isArray(value);
const keys = (value, expected) => plain(value) && Object.keys(value).length === expected.length && expected.every(k=>Object.hasOwn(value,k));
const fail = () => { throw new Error('Analysis failure evidence mismatch; original failure remains unverified'); };

/** A failed request stays failed. Import only its bounded, hash-bound diagnostics. */
export function importAnalysisFailure(artifacts, params, kind, nonce, message) {
  if (!['project','project-recorded','compose','discover','decode-observed','flow-semantics','bv-candidate'].includes(kind) || !message.analysisFailure) return undefined;
  const ref = message.analysisFailure;
  if (!keys(ref,['name','bytes','sha256']) || ref.name !== 'analysis-failure.json' ||
      !Number.isSafeInteger(ref.bytes) || ref.bytes < 1 || ref.bytes > 65536 || !sha(ref.sha256) ||
      !/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(params.job_id)) fail();
  const directory = path.join(artifacts.root,'jobs',params.job_id);
  const physical = filename => {
    if (fs.realpathSync(filename) !== filename || fs.lstatSync(filename).isSymbolicLink()) fail();
  };
  physical(path.join(artifacts.root,'jobs')); physical(directory);
  const filename = path.join(directory,ref.name); physical(filename);
  const {data} = readStableFile(filename,65536);
  if (data.length !== ref.bytes || hashBytes(data) !== ref.sha256) fail();
  const result = JSON.parse(data.toString('utf8'));
  const expectedCode = kind === 'compose' ? 'COMPOSITION_FAILED' : kind==='discover' ? 'DISCOVERY_FAILED' : 'PROJECTION_FAILED';
  if (result.schema !== 'ig5-analysis-failure-v1' || result.status !== 'failed-unverified' ||
      result.method !== kind || result.jobId !== params.job_id || result.nonce !== nonce ||
      result.targetSha256 !== params.sha256 || result.projectionDecoder !== (params.projection_decoder || 'native') ||
      result.runtimeManifestPin !== runtimePin || !stages.includes(result.failedStage) ||
      typeof result.cleanupConfirmed !== 'boolean' || result.cleanupConfirmed !== message.cleanupConfirmed ||
      result.error?.code !== expectedCode || result.error.code !== message.error?.code ||
      result.error.message !== message.error?.message || typeof result.error.message !== 'string' || result.error.message.length > 2000 ||
      ['nativeTargetExecuted','databaseModified','businessAccepted','wholeBinaryVerified'].some(k=>result[k] !== false) ||
      !Array.isArray(result.processStages) || result.processStages.length > 2 ||
      !Array.isArray(result.files) || result.files.length !== Object.keys(files).length) fail();
  if (result.projectionDecoder === 'native' ? result.javaDecoderManifestPin !== null :
      result.javaDecoderManifestPin !== JAVA_PROJECTION_RUNTIME_PIN && !(result.failedStage === 'preflight' && result.javaDecoderManifestPin === null)) fail();
  if (result.projectionDecoder === 'native' && (result.processStages.length > 1 || result.failedStage.startsWith('java-'))) fail();
  if(kind==='discover'){
    if(result.projectionDecoder!=='native'||result.discoveryExpectedManifestPin!=='65bf673f1c4304cc2c09076e3b96e368da9e0df72aa0badeba0c2a5cae392934')fail();
  }else if(Object.hasOwn(result,'discoveryExpectedManifestPin'))fail();
  if(kind==='project-recorded'){
    if(result.recordedCoordinatesSha256!==params.recorded_coordinates_sha256||!sha(result.recordedCoordinatesSha256))fail();
  }else if(Object.hasOwn(result,'recordedCoordinatesSha256'))fail();
  const captured = new Map(); let total = 0;
  for (const [index,[name,maximum]] of Object.entries(files).entries()) {
    const row = result.files[index];
    if (!plain(row) || row.name !== name || !['captured','missing','output-limit','unavailable','not-read-cleanup-unconfirmed'].includes(row.status)) fail();
    if (result.cleanupConfirmed === false && row.status !== 'not-read-cleanup-unconfirmed') fail();
    if (result.cleanupConfirmed === true && row.status === 'not-read-cleanup-unconfirmed') fail();
    if (row.status !== 'captured') { if (!keys(row,['name','status'])) fail(); continue; }
    if (!keys(row,['name','status','bytes','sha256']) || !Number.isSafeInteger(row.bytes) || row.bytes < 0 || row.bytes > maximum || !sha(row.sha256)) fail();
    const file = path.join(directory,...name.split('/')); physical(path.dirname(file)); physical(file);
    const {data:raw} = readStableFile(file,maximum);
    if (raw.length !== row.bytes || hashBytes(raw) !== row.sha256 || (total += raw.length) > 17*1024**2) fail();
    captured.set(name,raw);
  }
  let budget = params.budget_ms ?? 50000;
  for (const [index,row] of result.processStages.entries()) {
    const expected = result.projectionDecoder === 'java' && index === 0 ? 'java-decode' : 'state-computation';
    if (!keys(row,['stage','budgetMs','process']) || row.stage !== expected ||
        !Number.isSafeInteger(row.budgetMs) || row.budgetMs < 1 || row.budgetMs > budget) fail();
    budget = row.budgetMs;
    const p = row.process;
    if (!plain(p) || !['completed','cancelled','limited'].includes(p.status) ||
        !Number.isSafeInteger(p.pid) || p.pid < 1 || !Number.isSafeInteger(p.exitCode) ||
        p.childExitConfirmed !== true || p.jobAssignedAtCreation !== true || p.activeProcessLimit !== 1 || p.memoryLimitBytes !== 2*1024**3) fail();
    const raw = captured.get(expected === 'java-decode' ? 'java-decode-process.json' : 'state-computation-process.json');
    // With an unconfirmed later child, earlier receipts are deliberately not
    // read. Such observations are retained as unverified, not certified exits.
    if (result.cleanupConfirmed && (!raw || JSON.stringify(JSON.parse(raw.toString('utf8'))) !== JSON.stringify(p))) fail();
  }
  // Validate every file before committing any report/blob references.
  const blobs = Object.fromEntries([...captured].map(([name,raw])=>[name,artifacts.put(raw)]));
  const receipt = artifacts.put(data);
  const record = artifacts.save({kind:'analysis-failure',action:kind,status:'failed-unverified',
    targetSha256:params.sha256,nativeTargetExecuted:false,databaseModified:false,businessAccepted:false,wholeBinaryVerified:false,
    result:{...result,receipt,blobs}}, {pretty:true,maxBytes:65536});
  return {id:record.id,failedStage:result.failedStage,status:'failed-unverified',
    reportPath:path.join(artifacts.root,'records',`${record.id}.json`),reportSha256:artifacts.metadata(record.id).result.recordSha256,
    cleanupConfirmed:result.cleanupConfirmed,businessAccepted:false,wholeBinaryVerified:false};
}
