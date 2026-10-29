import fs from 'node:fs';
import path from 'node:path';
import { randomUUID } from 'node:crypto';
import { readStableFile, hashBytes } from './analysis_artifacts.js';
import { validateOpaqueProjection } from './projection_opaque.js';
import { selectProjectionDecoder, validateDecoderEvidence, decoderPreview } from './projection_decoder.js';
import {validateRecordedCoordinateInput,validateRecordedCoordinateBinding} from './recorded_projection_coordinates.js';

export const PROJECTION_RUNTIME_PIN = '8fc4ae42f775f0139aa5f184c912db71f77e68d661c14564ab6f4820d434abea';
const registers = new Set('rax rcx rdx rbx rsp rbp rsi rdi r8 r9 r10 r11 r12 r13 r14 r15'.split(' '));
const hex = value => typeof value === 'string' && /^0x[0-9a-f]{1,16}$/i.test(value) && BigInt(value) !== 0n;

export function validateDirectCallControl(control,nodes,decodedPath) {
  if (!control || typeof control!=='object') return;
  const row=decodedPath?.find(r=>r.ea===control.source),called=row?.decoded?.mnemonic==='CALL';
  if (!called && !Object.hasOwn(control,'transfer') && !Object.hasOwn(control,'returnAddress')) return;
  const invalid=()=>{throw new Error('Projection returned inconsistent direct CALL binding');};
  if (!called || control.kind!=='direct' || control.transfer!=='call' || !hex(row.ea) ||
      typeof row.bytes!=='string' || !/^e8[0-9a-f]{8}$/i.test(row.bytes) || row.decoded.size!==5) invalid();
  const code=Buffer.from(row.bytes,'hex'),returnAddress=BigInt(row.ea)+5n,mask=(1n<<64n)-1n;
  const destination=(returnAddress+BigInt(code.readInt32LE(1)))&mask,node=nodes?.[control.target];
  if (returnAddress>mask || control.returnAddress!=='0x'+returnAddress.toString(16) || node?.op!=='const' ||
      node.bits!==64 || typeof node.value!=='string' || !/^0x[0-9a-f]{1,16}$/i.test(node.value) || BigInt(node.value)!==destination) invalid();
  if(code.subarray(1).every(b=>b===0)){
    const raw=row.decoded.pcode,keys=(x,n)=>x&&typeof x==='object'&&!Array.isArray(x)&&Object.keys(x).length===n;
    const v=(x,space,offset)=>keys(x,3)&&x.space===space&&x.size===8&&typeof x.offset==='string'&&/^0x[0-9a-f]{1,16}$/i.test(x.offset)&&BigInt(x.offset)===offset;
    const rsp=x=>v(x,'register',0x20n),constant=(x,n)=>v(x,'const',n);
    if(!Array.isArray(raw)||raw.length!==3||raw.some(op=>!keys(op,3))||raw[0]?.opcode!=='INT_SUB'||!rsp(raw[0].output)||raw[0].inputs?.length!==2||!rsp(raw[0].inputs[0])||!constant(raw[0].inputs[1],8n)||
       raw[1]?.opcode!=='STORE'||raw[1].output!==null||raw[1].inputs?.length!==3||!keys(raw[1].inputs[0],3)||raw[1].inputs[0].kind!=='address-space'||raw[1].inputs[0].space!=='ram'||raw[1].inputs[0].spaceId!==3||!rsp(raw[1].inputs[1])||!constant(raw[1].inputs[2],returnAddress)||
       !['CALL','BRANCH'].includes(raw[2]?.opcode)||raw[2].output!==null||raw[2].inputs?.length!==1||!v(raw[2].inputs[0],'ram',returnAddress))invalid();
  }
}

export function validateProjection(args) {
  if (!args || typeof args !== 'object' || Array.isArray(args)) throw new Error('Projection parameters must be an object');
  const allowed = new Set(['target', 'level', 'projection_path', 'projection_registers', 'projection_mode', 'projection_decoder', 'engine']);
  if (Object.keys(args).some(key => !allowed.has(key))) throw new Error('level=project accepts only target, projection_path, projection_registers and optional projection_mode; omit other level parameters');
  if (args.level !== 'project' || typeof args.target !== 'string' || !path.isAbsolute(args.target) || args.target.includes('\0')) throw new Error('level=project requires an absolute target path');
  if (args.engine !== undefined && !['reverse', 'ghidra'].includes(args.engine)) throw new Error('Projection is independent of database engines');
  if (Object.hasOwn(args, 'projection_mode') && !['strict', 'guarded-path', 'opaque-effects','opaque-status'].includes(args.projection_mode)) throw new Error('projection_mode requires strict, guarded-path, opaque-effects or opaque-status');
  const addresses = args.projection_path, selected = args.projection_registers;
  if (!Array.isArray(addresses) || addresses.length < 1 || addresses.length > 128 || addresses.some(value => !hex(value))) throw new Error('projection_path requires 1..128 nonzero preferred hexadecimal addresses');
  const normalized = addresses.map(value => '0x' + BigInt(value).toString(16));
  if (new Set(normalized).size !== normalized.length) throw new Error('Repeated projection addresses require an unsupported loop model');
  if (!Array.isArray(selected) || selected.length < 1 || selected.length > 16 || selected.some(value => !registers.has(value)) || new Set(selected).size !== selected.length) throw new Error('projection_registers requires 1..16 unique lowercase full-width x64 GPR names');
  return { projection_path: normalized, projection_registers: [...selected], ...selectProjectionDecoder(args), ...(['guarded-path','opaque-effects','opaque-status'].includes(args.projection_mode) ? { projection_mode: args.projection_mode } : {}) };
}

/** Serialized edge/root accounting only; never a semantic proof. */
export function checkedProjectionReferences(result) {
  const fail=()=>{throw new Error('Projection DAG reference/depth accounting scope mismatch');};
  const nodes=result.dag?.nodes, depths=[];
  const valid=id=>Number.isSafeInteger(id)&&!Object.is(id,-0)&&id>=0&&id<nodes.length;
  if(!Array.isArray(nodes)||!nodes.length||nodes.length>2048)fail();
  let count=0;
  nodes.forEach((node,i)=>{
    if(!node||typeof node!=='object'||Array.isArray(node)||node.id!==i||Object.is(node.id,-0)||node.op==='state_binding'||!Array.isArray(node.args))fail();
    if(node.args.length>8192-count||node.args.some(id=>!valid(id)||id>=i))fail();
    count+=node.args.length;
    depths.push(1+Math.max(0,...node.args.map(id=>depths[id])));
    if(depths[i]>128)fail();
  });
  const reference=id=>{if(!valid(id)||++count>8192)fail();};
  const state=registers=>{
    if(!registers||typeof registers!=='object'||Array.isArray(registers))fail();
    Object.values(registers).forEach(reference);
  };
  state(result.initialRegisters);state(result.registers);
  reference(result.initialMemory);reference(result.currentMemory);
  if(!Array.isArray(result.stores)||!result.control||typeof result.control!=='object')fail();
  for(const store of result.stores)for(const key of ['address','value','beforeMemory','afterMemory'])reference(store[key]);
  for(const key of ['target','condition','taken','fallthrough'])if(Object.hasOwn(result.control,key))reference(result.control[key]);
  if(['opaque-effects','opaque-status'].includes(result.projectionMode)){
    result.nondeterministicInputs.forEach(input=>reference(input.node));
    if(result.projectionMode==='opaque-status')for(const e of result.opaqueEffects)if(e.flagImageRefinement)reference(e.flagImageRefinement.valueNode);
  }
  if(result.projectionMode==='guarded-path'){
    reference(result.pathGuard);result.stores.forEach(store=>reference(store.guard));
    for(const point of result.branchPoints)for(const key of ['condition','prefixGuard','continuedGuard','continuedTarget'])reference(point[key]);
    for(const exit of result.sideExits){for(const key of ['guard','target','currentMemory'])reference(exit[key]);state(exit.registers);}
  }
  if(!Number.isSafeInteger(result.dag.references)||Object.is(result.dag.references,-0)||result.dag.references!==count||
     !Number.isSafeInteger(result.dag.depth)||result.dag.depth!==Math.max(...depths))fail();
  return count;
}

/** Uses the shared lifter ownership pool; target bytes are never executed. */
export async function runProjection(jobs, args, signal) {
  return dispatchProjection(jobs,args,signal);
}

/** Internal committed-handler route; no public tool parameter accepts this input. */
export async function runRecordedProjection(jobs,args,coordinates,signal) {
  if(args.projection_decoder!=='java'||args.projection_mode!=='opaque-status')throw new Error('Recorded projection requires fixed Java opaque-status mode');
  return dispatchProjection(jobs,args,signal,coordinates);
}

async function dispatchProjection(jobs,args,signal,coordinates) {
  const selected = validateProjection(args);
  if (jobs.closed || signal?.aborted) throw new Error('Projection cancelled');
  if (jobs.active.size >= 2) throw new Error('Analysis busy; maximum two owned requests');
  const { data } = readStableFile(args.target, 64 * 1024 * 1024);
  const coordinateRaw=coordinates===undefined?undefined:validateRecordedCoordinateInput(coordinates,data);
  if(coordinates!==undefined&&JSON.stringify(selected.projection_path)!==JSON.stringify(coordinates.rows.map(r=>r.preferred)))throw new Error('Recorded preferred projection path differs');
  const coordinateInput=coordinateRaw===undefined?undefined:jobs.artifacts.put(coordinateRaw);
  const input = jobs.artifacts.put(data), jobId = randomUUID(),method=coordinateInput?'project-recorded':'project';
  const parent = path.join(jobs.artifacts.root, 'jobs');
  if (fs.realpathSync(parent) !== parent || !fs.lstatSync(parent).isDirectory()) throw new Error('Projection jobs directory must be physical');
  const directory = path.join(parent, jobId);
  fs.mkdirSync(directory);
  const reply = await jobs.request({ job_id: jobId, sha256: input.sha256, ...selected,
    ...(coordinateInput?{recorded_coordinates_sha256:coordinateInput.sha256}:{}) }, signal, method);
  if (reply?.runtimeManifestPin !== PROJECTION_RUNTIME_PIN || reply?.targetSha256 !== input.sha256 || reply?.process?.childExitConfirmed !== true || reply?.process?.status !== 'completed' || reply?.process?.exitCode !== 0) throw new Error('Projection returned inconsistent process evidence');
  if (!Number.isSafeInteger(reply.outputBytes) || reply.outputBytes < 1 || reply.outputBytes > 4 * 1024 * 1024) throw new Error('Projection output exceeds budget');
  const { data: output } = readStableFile(path.join(directory, 'stdout.log'), 4 * 1024 * 1024);
  if (output.length !== reply.outputBytes || hashBytes(output) !== reply.outputSha256) throw new Error('Projection output digest mismatch');
  const result = JSON.parse(output.toString('utf8'));
  validateDecoderEvidence(selected, result, reply, directory);
  if(coordinateInput)validateRecordedCoordinateBinding(result,coordinates);
  else if(Object.hasOwn(result,'recordedCoordinates')||Object.hasOwn(result,'originalPreferredPath'))throw new Error('Preferred projection returned unrequested runtime coordinates');
  validateDirectCallControl(result.control,result.dag?.nodes,result.decodedPath);
  const guarded = selected.projection_mode === 'guarded-path';
  const opaque = ['opaque-effects','opaque-status'].includes(selected.projection_mode);
  if (result?.schema !== (guarded ? 'ig5-pcode-guarded-projection-v1' : selected.projection_mode==='opaque-status' ? 'ig5-pcode-opaque-status-projection-v1' : opaque ? 'ig5-pcode-opaque-projection-v1' : 'ig5-pcode-projection-v1') || result.targetSha256 !== input.sha256 || result.runtimeManifestPin !== PROJECTION_RUNTIME_PIN ||
      ['nativeTargetExecuted', 'databaseModified', 'businessAccepted', 'wholeBinaryVerified'].some(key => result[key] !== false) ||
      JSON.stringify(result.projectionPath) !== JSON.stringify(coordinateInput?coordinates.rows.map(r=>r.runtimePc):selected.projection_path) || JSON.stringify(result.projectionRegisters) !== JSON.stringify(selected.projection_registers)) throw new Error('Projection returned inconsistent scope');
  if(opaque){if(result.projectionMode!==selected.projection_mode)throw new Error('Projection opaque mode mismatch');validateOpaqueProjection(result);}
  else if(Object.hasOwn(result,'opaqueEffects')||Object.hasOwn(result,'nondeterministicInputs'))throw new Error('Exact projection returned opaque-effect scope');
  if (guarded) {
    const nodes = result.dag?.nodes;
    const ref = (id, type, bits) => Number.isSafeInteger(id) && id >= 0 && Array.isArray(nodes) && id < nodes.length && nodes[id]?.type === type && (bits === undefined || nodes[id]?.bits === bits);
    if (result.projectionMode !== 'guarded-path' || !ref(result.pathGuard, 'bv', 8) ||
        !Array.isArray(result.sideExits) || !Array.isArray(result.branchPoints) ||
        result.sideExits.length !== result.branchPoints.length || result.sideExits.length >= selected.projection_path.length ||
        result.branchPoints.some((point, index) => !ref(point.condition, 'bv', 8) || !ref(point.prefixGuard, 'bv', 8) ||
          !ref(point.continuedGuard, 'bv', 8) || !ref(point.continuedTarget, 'bv', 64) || point.sideExitIndex !== index ||
          !Number.isSafeInteger(point.instructionIndex) || point.instructionIndex < 0 || point.instructionIndex >= selected.projection_path.length - 1 ||
          result.sideExits[index]?.instructionIndex !== point.instructionIndex || !['taken', 'fallthrough'].includes(point.continuedSuccessor)) ||
        result.sideExits.some(exit => !ref(exit.guard, 'bv', 8) || !ref(exit.target, 'bv', 64) || !ref(exit.currentMemory, 'memory') ||
          exit.continuation !== 'not-analyzed' || exit.statusFlags !== 'not-exported' ||
          JSON.stringify(Object.keys(exit.registers || {}).sort()) !== JSON.stringify([...selected.projection_registers].sort()) ||
          Object.values(exit.registers).some(id => !ref(id, 'bv', 64))) ||
        !Array.isArray(result.stores) || result.stores.some(store => !ref(store.guard, 'bv', 8))) throw new Error('Projection returned inconsistent guarded state scope');
  } else if (!opaque && (Object.hasOwn(result, 'projectionMode') || Object.hasOwn(result, 'pathGuard') || Object.hasOwn(result, 'sideExits'))) {
    throw new Error('Strict projection returned guarded state scope');
  }
  const dagReferences=checkedProjectionReferences(result);
  const outputRef = jobs.artifacts.put(output);
  // Keep complete DAGs readable by the host's line-based file reader, while
  // charging indentation against the same 4 MiB projection report budget.
  const record = jobs.artifacts.save({ kind: 'projection', action: method, target: args.target, input, outputRef, process: reply.process, result,
    ...(coordinateInput?{recordedCoordinatesInput:coordinateInput}:{}) },
    { pretty: true, maxBytes: 4 * 1024 * 1024 });
  const metadata = jobs.artifacts.metadata(record.id).result;
  // Full DAG and raw p-code stay in the immutable report. The preview contains
  // explicit node references, never truncated expressions presented as complete.
  // DSH can retain only the head/tail of a long tool result. Keep verified
  // schema/count/scope facts ahead of variable-sized decoder/effect metadata.
  return { reportSchema:result.schema,status:'partial',recoveryStatus:'unverified',
    nodeCount:result.dag.nodes.length,dagReferences,storeCount:result.stores.length,
    nativeTargetExecuted:false,databaseModified:false,businessAccepted:false,wholeBinaryVerified:false,
    ...(opaque ? {projectionMode:result.projectionMode,opaqueEffectCount:result.opaqueEffects.length,
      opaqueEffects:result.opaqueEffects,nondeterministicInputs:result.nondeterministicInputs,
      statistics:result.statistics,memoryNormalization:result.memoryNormalization} : {}),
    ...(guarded ? { projectionMode: 'guarded-path', pathGuard: result.pathGuard,
      branchCount: result.branchPoints.length, sideExitCount: result.sideExits.length,
      sideExitPreview: result.sideExits.slice(0, 8).map(({ instructionIndex, guard, target, currentMemory }) => ({ instructionIndex, guard, target, currentMemory })),
      sideExitPreviewComplete: result.sideExits.length <= 8 } : {}),
    ...decoderPreview(result, reply), backend: result.backend,
    targetSha256: input.sha256, projectionPath: result.projectionPath, projectionRegisters: result.projectionRegisters,
    registers: result.registers, control: result.control, currentMemory: result.currentMemory,
    expressionPreview: 'Node references resolve in the complete report DAG; no independent semantic equivalence proof was performed.',
    scope: result.scope, limits: result.limits, process: reply.process, outputRef,
    reportId: record.id, reportSha256: metadata.recordSha256,
    reportPath: path.join(jobs.artifacts.root, 'records', record.id + '.json') };
}
