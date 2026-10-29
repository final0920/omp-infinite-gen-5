import fs from 'node:fs';
import path from 'node:path';
import { randomUUID } from 'node:crypto';
import { readStableFile, hashBytes } from './analysis_artifacts.js';
import { PROJECTION_RUNTIME_PIN,validateDirectCallControl } from './projection_jobs.js';
import { selectProjectionDecoder, validateDecoderEvidence, decoderPreview } from './projection_decoder.js';
import { validateTransitionChain } from './composition_chain.js';
import { validateOpaqueComposition } from './composition_opaque.js';

const gprs = 'rax rcx rdx rbx rsp rbp rsi rdi r8 r9 r10 r11 r12 r13 r14 r15'.split(' ');
const hex = value => typeof value === 'string' && /^0x[0-9a-f]{1,16}$/i.test(value) && BigInt(value) !== 0n;
const plain = value => value && typeof value === 'object' && !Array.isArray(value) &&
  [Object.prototype, null].includes(Object.getPrototypeOf(value));

export function validateCompositionPlan(plan) {
  if (!plain(plan) || Object.values(Object.getOwnPropertyDescriptors(plan)).some(d => !Object.hasOwn(d, 'value'))) throw new Error('composition_plan must be an address-only object');
  const fields = plan.strategy === 'sequence' ? ['strategy', 'paths'] : ['strategy', 'prefix', 'body', 'suffix'];
  const allowed = [...fields, 'indirect_mode', 'representation', 'template_mode'];
  if (!['sequence', 'constant-loop'].includes(plan.strategy) || fields.some(key => !Object.hasOwn(plan, key)) ||
      Reflect.ownKeys(plan).some(key => !allowed.includes(key))) {
    throw new Error('composition_plan requires exactly the fields of sequence or constant-loop');
  }
  const mode = Object.hasOwn(plan, 'indirect_mode') ? plan.indirect_mode : 'reject';
  if (!['reject', 'guarded-target'].includes(mode)) throw new Error('composition_plan.indirect_mode requires reject or guarded-target');
  const representation = plan.representation ?? 'flat';
  if (Object.hasOwn(plan, 'representation') && !['flat', 'transition-chain'].includes(plan.representation)) throw new Error('composition_plan.representation requires flat or transition-chain');
  if (representation === 'transition-chain' && plan.strategy !== 'sequence') throw new Error('transition-chain requires an explicit sequence; constant-loop inference remains flat');
  const representationField = Object.hasOwn(plan, 'representation') ? { representation } : {};
  const templateMode=Object.hasOwn(plan,'template_mode')?plan.template_mode:'strict';
  if(!['strict','opaque-effects','opaque-status'].includes(templateMode))throw new Error('composition_plan.template_mode requires strict, opaque-effects or opaque-status');
  if(['opaque-effects','opaque-status'].includes(templateMode)&&(representation!=='transition-chain'||plan.strategy!=='sequence'))throw new Error(templateMode+' requires an explicit transition-chain sequence');
  const templateField=Object.hasOwn(plan,'template_mode')?{template_mode:templateMode}:{};
  let occurrences = 0; const distinct = new Set();
  const template = value => {
    if (!Array.isArray(value) || value.length < 1 || value.length > 128 || Array.from(value).some(a => !hex(a))) {
      throw new Error('Each composition template requires1..128 explicit nonzero preferred addresses');
    }
    const normalized = Array.from(value, a => '0x' + BigInt(a).toString(16));
    if (new Set(normalized).size !== normalized.length) throw new Error('Repeated addresses within one composition template are unsupported');
    occurrences += normalized.length; normalized.forEach(a => distinct.add(a));
    if (occurrences > 1024 || distinct.size > 128) throw new Error('Composition plan exceeds1024 provided occurrences or128 distinct instructions');
    return normalized;
  };
  if (plan.strategy === 'sequence') {
    if (!Array.isArray(plan.paths) || plan.paths.length < 1 || plan.paths.length > 64) throw new Error('Sequence composition requires1..64 path applications');
    return { strategy: 'sequence', paths: Array.from(plan.paths, template), indirect_mode: mode, ...representationField, ...templateField };
  }
  if (!Array.isArray(plan.suffix) || plan.suffix.length < 1 || plan.suffix.length >= 64) throw new Error('Constant-loop composition requires1..63 exit suffix paths');
  const prefix = template(plan.prefix), body = template(plan.body);
  return { strategy: 'constant-loop', prefix, body, suffix: Array.from(plan.suffix, template), indirect_mode: mode, ...representationField, ...templateField };
}

export function validateComposition(args) {
  if (!plain(args) || Object.values(Object.getOwnPropertyDescriptors(args)).some(d => !Object.hasOwn(d, 'value')) ||
      Reflect.ownKeys(args).some(key => !['target', 'level', 'composition_plan', 'composition_plan_ref', 'projection_decoder', 'engine'].includes(key))) {
    throw new Error('level=compose accepts only target and one composition plan input; omit other level parameters');
  }
  if (args.level !== 'compose' || typeof args.target !== 'string' || !path.isAbsolute(args.target) || args.target.includes('\0')) throw new Error('level=compose requires an absolute target path');
  if (args.engine !== undefined && !['reverse', 'ghidra'].includes(args.engine)) throw new Error('Composition is independent of database engines');
  if (Object.hasOwn(args, 'composition_plan') === Object.hasOwn(args, 'composition_plan_ref')) throw new Error('Provide exactly one of composition_plan or composition_plan_ref');
  const decoder = selectProjectionDecoder(args);
  if (Object.hasOwn(args, 'composition_plan')) return { composition_plan: validateCompositionPlan(args.composition_plan), ...decoder };
  const ref = args.composition_plan_ref;
  if (!plain(ref) || Reflect.ownKeys(ref).length !== 2 ||
      Reflect.ownKeys(ref).some(key => !['path', 'sha256'].includes(key)) ||
      Object.values(Object.getOwnPropertyDescriptors(ref)).some(d => !Object.hasOwn(d, 'value')) ||
      typeof ref.path !== 'string' || ref.path.length > 4096 || !path.isAbsolute(ref.path) || ref.path.includes('\0') ||
      typeof ref.sha256 !== 'string' || !/^[a-f0-9]{64}$/.test(ref.sha256)) throw new Error('composition_plan_ref requires only absolute path and lowercase SHA-256');
  return { composition_plan_ref: { path:path.resolve(ref.path), sha256:ref.sha256 }, ...decoder };
}

/** A file is address-plan data only, never a script, proof or caller summary. */
export function resolveCompositionPlan(selected) {
  if (selected.composition_plan) return { selected };
  const ref = selected.composition_plan_ref, { data } = readStableFile(ref.path, 65536);
  if (hashBytes(data) !== ref.sha256) throw new Error('Composition plan file SHA-256 mismatch');
  let parsed;
  try { parsed = JSON.parse(new TextDecoder('utf-8', { fatal:true, ignoreBOM:true }).decode(data)); }
  catch { throw new Error('Composition plan file requires strict UTF-8 JSON without BOM'); }
  const plan = validateCompositionPlan(parsed), paths = plan.strategy === 'sequence' ? plan.paths : [plan.prefix,plan.body,...plan.suffix];
  const compositionInput = { kind:'sha256-file', path:ref.path, sha256:ref.sha256, bytes:data.length,
    ref:'sha256:'+ref.sha256, normalizedPlanSha256:hashBytes(Buffer.from(JSON.stringify(plan))),
    providedTemplates:paths.length, providedAddressOccurrences:paths.reduce((n,p)=>n+p.length,0),
    distinctInstructions:compositionAddresses(plan).length,
    ...(plan.strategy === 'sequence' ? { pathApplications:paths.length } : {}) };
  const { composition_plan_ref: omitted, ...options } = selected;
  return { selected:{ ...options, composition_plan:plan }, planBytes:data, compositionInput };
}

export function compositionAddresses(plan) {
  const paths = plan.strategy === 'sequence' ? plan.paths : [plan.prefix, plan.body, ...plan.suffix];
  return [...new Set(paths.flat())];
}

export function validateCompositionResult(result, selected, sha256) {
  const plan = selected.composition_plan, guarded = plan.indirect_mode === 'guarded-target', chain = plan.representation === 'transition-chain', opaque = ['opaque-effects','opaque-status'].includes(plan.template_mode), status=plan.template_mode==='opaque-status';
  if (result?.schema !== (status?'ig5-pcode-opaque-status-transition-chain-v1':opaque ? 'ig5-pcode-opaque-transition-chain-v1' : chain ? 'ig5-pcode-transition-chain-v1' : 'ig5-pcode-composition-v1') || result.representationSchema !==
      (status?'ig5-internal-opaque-status-transition-chain-v1':opaque ? 'ig5-internal-opaque-transition-chain-v1' : chain ? 'ig5-internal-state-transition-chain-v1' : guarded ? 'ig5-internal-guarded-target-composition-v1' : 'ig5-internal-closed-path-composition-v1') ||
      result.targetSha256 !== sha256 || result.runtimeManifestPin !== PROJECTION_RUNTIME_PIN || result.publicToolRouteExposed !== true ||
      result.status !== 'translated-unverified' ||
      ['nativeTargetExecuted', 'databaseModified', 'businessAccepted', 'wholeBinaryVerified'].some(k => result[k] !== false) ||
      JSON.stringify(result.compositionPlan) !== JSON.stringify(plan) ||
      JSON.stringify(result.decodedPath?.map(r => r.ea)) !== JSON.stringify(compositionAddresses(plan))) throw new Error('Composition returned inconsistent scope');
  const nodes = result.dag?.nodes, roots = [];
  const reference = (identity, type, bits) => {
    if (!Number.isSafeInteger(identity) || identity < 0 || !Array.isArray(nodes) || identity >= nodes.length ||
        nodes[identity]?.type !== type || (bits !== undefined && nodes[identity].bits !== bits)) throw new Error('Composition returned an invalid state reference');
    roots.push(identity);
  };
  const state = registers => {
    if (!plain(registers) || JSON.stringify(Object.keys(registers).sort()) !== JSON.stringify([...gprs].sort())) throw new Error('Composition must retain all16 GPRs');
    Object.values(registers).forEach(id => reference(id, 'bv', 64));
  };
  const control = value => {
    validateDirectCallControl(value,nodes,result.decodedPath);
    if (!value || !['fallthrough', 'direct', 'conditional', 'indirect', 'return'].includes(value.kind)) throw new Error('Composition control scope mismatch');
    if (value.kind === 'conditional') {
      reference(value.condition, 'bv', 8); reference(value.taken, 'bv', 64); reference(value.fallthrough, 'bv', 64);
    } else reference(value.target, 'bv', 64);
  };
  if (!Array.isArray(nodes) || nodes.length < 1 || nodes.length > 2048 || nodes.some((node, i) => node.id !== i ||
      !Array.isArray(node.args) || node.args.some(id => !Number.isSafeInteger(id) || id < 0 || id >= i))) throw new Error('Composition DAG budget/order mismatch');
  state(result.initialRegisters); state(result.registers);
  reference(result.initialMemory, 'memory'); reference(result.currentMemory, 'memory'); reference(result.pathGuard, 'bv', 8);
  if (!Array.isArray(result.stores) || !Array.isArray(result.sideExits) || !Array.isArray(result.boundaries) ||
      !Array.isArray(result.steps) || result.steps.length < 1 || result.steps.length > 64 || result.boundaries.length !== result.steps.length ||
      result.sideExits.length >= result.steps.length || !Array.isArray(result.templates) || !result.templates.length || result.templates.length > 64) throw new Error('Composition step/exit budget mismatch');
  for (const store of result.stores) {
    reference(store.address, 'bv', 64); reference(store.value, 'bv', store.size * 8);
    reference(store.beforeMemory, 'memory'); reference(store.afterMemory, 'memory'); reference(store.guard, 'bv', 8);
  }
  for (const exit of result.sideExits) {
    reference(exit.guard, 'bv', 8); reference(exit.target, 'bv', 64); reference(exit.currentMemory, 'memory'); state(exit.registers);
    if (exit.continuation !== 'not-analyzed' || exit.statusFlags !== 'not-exported') throw new Error('Composition exit scope mismatch');
    if (Object.hasOwn(exit, 'selectionCondition')) {
      if (!guarded || !['indirect', 'return'].includes(exit.controlKind)) throw new Error('Unexpected guarded indirect exit');
      reference(exit.selectionCondition, 'bv', 8); reference(exit.selectedTarget, 'bv', 64);
    }
  }
  result.boundaries.forEach((boundary, i) => {
    if (boundary.stepIndex !== i || boundary.templateIndex !== result.steps[i]) throw new Error('Composition boundary order mismatch');
    reference(boundary.entryGuard, 'bv', 8); reference(boundary.continuedGuard, 'bv', 8);
    reference(boundary.currentMemory, 'memory'); state(boundary.registers); control(boundary.control);
  });
  control(result.control);
  const chainValidation=chain?validateTransitionChain(result, plan, reference, state):undefined;
  if (opaque) validateOpaqueComposition(result,plan,reference);
  else if (Object.hasOwn(result,'templateMode') || Object.hasOwn(result,'nondeterministicInputs') ||
           nodes.some(n=>n.op==='nondeterministic') || result.templates.some(t=>Object.hasOwn(t,'opaqueEffects')||Object.hasOwn(t,'flagPolicies'))||result.layers?.some(l=>Object.hasOwn(l,'flagImages'))) throw new Error('Strict composition returned opaque inputs');
  if (!chain && (Object.hasOwn(result, 'layers') || Object.hasOwn(result, 'representation') || nodes.some(n => n.op === 'state_binding'))) throw new Error('Flat composition returned transition bindings');
  const stats = result.statistics, limits = result.compositionLimits;
  const memory = result.memoryNormalization;
  if (!plain(memory) || memory.method !== 'exact-ordered-byte-forwarding' || memory.maxStoreVisits !== 4096 ||
      memory.observedValuesUsed !== false || memory.independentSMTProof !== false ||
      !Number.isSafeInteger(memory.storeVisits) || memory.storeVisits < 0 || memory.storeVisits > 4096 ||
      ['forwardedBytes','disjointStoreBypasses','unknownAliasFallbacks','budgetFallbacks','cacheHits'].some(k =>
        !Number.isSafeInteger(memory[k]) || memory[k] < 0 || memory[k] > 65536)) throw new Error('Composition memory normalization accounting mismatch');
  const expectedLimits = { steps:64, distinctInstructions:128, logicalInstructions:1024, logicalPcodeOperations:65536,
    memoryBytes:1024, dagNodes:2048, dagReferences:8192, dagDepth:128, reportBytes:4*1024**2 };
  if (!plain(limits) || Object.keys(expectedLimits).some(k => limits[k] !== expectedLimits[k]) ||
      !stats || stats.steps !== result.steps.length || stats.templates !== result.templates.length || stats.dagNodes !== nodes.length ||
      !Number.isSafeInteger(stats.distinctInstructions) || stats.distinctInstructions < 1 || stats.distinctInstructions > result.decodedPath.length ||
      !Number.isSafeInteger(stats.logicalInstructions) || stats.logicalInstructions < 1 || stats.logicalInstructions > 1024 ||
      !Number.isSafeInteger(stats.logicalPcodeOperations) || stats.logicalPcodeOperations < 0 || stats.logicalPcodeOperations > 65536 ||
      !Number.isSafeInteger(stats.expandedMemoryBytes) || stats.expandedMemoryBytes < 0 || stats.expandedMemoryBytes > 1024 ||
      !Number.isSafeInteger(result.dag.depth) || result.dag.depth < 1 || result.dag.depth > 128 ||
      result.dag.references !== roots.length + nodes.reduce((n, node) => n + node.args.length, 0) || result.dag.references > 8192) throw new Error('Composition expanded work/DAG budget mismatch');
  if (result.steps.some(id => !Number.isSafeInteger(id) || id < 0 || id >= result.templates.length) ||
      result.templates.some((t, i) => t.id !== i || t.initialFlagsSupplied !== false || t.flagsExported !== false)) throw new Error('Composition template/flags closure mismatch');
  const variable = v => v === null ? null : Object.fromEntries(['kind','space','spaceId','offset','size'].filter(k => Object.hasOwn(v,k)).map(k => [k,v[k]]));
  const canonical = row => ({ea:row.ea,size:row.decoded.size,codeBytes:row.bytes,mnemonic:row.decoded.mnemonic,operands:row.decoded.operands,
    pcode:row.decoded.pcode.map(op=>({opcode:op.opcode,output:variable(op.output??null),inputs:op.inputs.map(variable)}))});
  const decoded = new Map(result.decodedPath.map(row => [row.ea,canonical(row)])), used = new Set();
  const work = result.templates.map(template => {
    if (!Array.isArray(template.instructions) || template.instructions.length < 1 || template.instructions.length > 128) throw new Error('Composition raw template budget mismatch');
    let operations=0,memory=0;
    for (const instruction of template.instructions) {
      if (JSON.stringify(instruction)!==JSON.stringify(decoded.get(instruction.ea))) throw new Error('Composition raw template does not match bound decoding');
      used.add(instruction.ea);operations+=instruction.pcode.length;
      for (const op of instruction.pcode) {
        const size=op.opcode==='LOAD'?op.output?.size:op.opcode==='STORE'?op.inputs[2]?.size:0;
        if (!Number.isSafeInteger(size) || size<0 || size>256) throw new Error('Composition memory accounting mismatch');
        memory+=size;
      }
    }
    return {instructions:template.instructions.length,operations,memory};
  });
  const totals=result.steps.reduce((sum,id)=>({instructions:sum.instructions+work[id].instructions,
    operations:sum.operations+work[id].operations,memory:sum.memory+work[id].memory}),{instructions:0,operations:0,memory:0});
  const depths=[];nodes.forEach(node=>depths.push(1+Math.max(0,...node.args.map(id=>depths[id]))));
  const decodeStats=result.decodeStatistics,provided=plan.strategy==='sequence'?plan.paths:[plan.prefix,plan.body,...plan.suffix];
  if (stats.logicalInstructions!==totals.instructions || stats.logicalPcodeOperations!==totals.operations || stats.expandedMemoryBytes!==totals.memory ||
      stats.distinctInstructions!==used.size || result.dag.depth!==Math.max(...depths) ||
      decodeStats?.instructions!==decoded.size || decodeStats.providedAddressOccurrences!==provided.reduce((n,p)=>n+p.length,0) ||
      decodeStats.rawPcodeOperations!==[...decoded.values()].reduce((n,row)=>n+row.pcode.length,0) || decodeStats.rawPcodeOperations>16384) throw new Error('Composition raw/expanded work accounting mismatch');
  if(chain && result.fitsPublicFixedPathLimits !== (totals.instructions===used.size&&totals.instructions<=128&&totals.memory<=256))throw new Error('Composition fixed-project fit scope mismatch');
  if (plan.strategy === 'constant-loop') {
    const repeat = result.inferredRepeat;
    if (!repeat || repeat.method !== 'exact-constant-closed-state-condition' || repeat.observedValuesUsed !== false || repeat.independentSMTProof !== false ||
        !Number.isSafeInteger(repeat.attempts) || repeat.attempts < 1 || repeat.attempts > 64 ||
        repeat.bodyApplicationsAfterPrefix !== repeat.attempts - 1 || repeat.inferenceWorkLimitEach !== 65536 ||
        !Array.isArray(repeat.trace) || repeat.trace.length !== repeat.attempts || repeat.finalTranslationAccountedSeparately !== true ||
        ['attemptedLogicalInstructions', 'attemptedMemoryBytes'].some(k => !Number.isSafeInteger(repeat[k]) || repeat[k] < 0 || repeat[k] > 65536)) throw new Error('Composition repeat inference scope mismatch');
  } else if (Object.hasOwn(result, 'inferredRepeat')) throw new Error('Sequence composition returned loop inference');
  return chainValidation ? {reportSchema:result.schema, fitsPublicFixedPathLimits:result.fitsPublicFixedPathLimits,
    ...chainValidation,...(opaque?{opaqueEffectsRebound:true,liveFreshUnknowns:result.nondeterministicInputs.length,
      expandedAbstractedInstructions:result.statistics.expandedAbstractedInstructions}:{}),
    ...(status?{statusFlagImagesChecked:result.layers.reduce((n,l)=>n+l.flagImages.length,0),statusFlagsExported:false}:{}),
    validationScope:'Host serialization/provenance and exact state-binding structure checks; no independent CPU/SMT, reachability or protected-business certificate.'} : undefined;
}

/** Same fixed owned process pool as project/lift; no database or PE execution. */
export async function runComposition(jobs, args, signal) {
  const validated = validateComposition(args);
  if (jobs.closed || signal?.aborted) throw new Error('Composition cancelled');
  if (jobs.active.size >= 2) throw new Error('Analysis busy; maximum two owned requests');
  const { selected, planBytes, compositionInput } = resolveCompositionPlan(validated);
  const { data } = readStableFile(args.target, 64*1024**2);
  if (planBytes) jobs.artifacts.put(planBytes);
  const input = jobs.artifacts.put(data), jobId = randomUUID(), parent = path.join(jobs.artifacts.root, 'jobs');
  if (fs.realpathSync(parent) !== parent || !fs.lstatSync(parent).isDirectory()) throw new Error('Composition jobs directory must be physical');
  const directory = path.join(parent, jobId); fs.mkdirSync(directory);
  let reply;
  try { reply = await jobs.request({ job_id:jobId, sha256:input.sha256, ...selected }, signal, 'compose'); }
  catch (error) {
    if (!compositionInput) throw error;
    throw Object.assign(new Error(`Composition rejected after plan-file verification: SHA256=${compositionInput.sha256}; normalizedPlanSHA256=${compositionInput.normalizedPlanSha256}; providedTemplates=${compositionInput.providedTemplates}; addressOccurrences=${compositionInput.providedAddressOccurrences}. ${error.message}`, { cause:error }),
      { ...(error.code === undefined ? {} : { code:error.code }),
        ...(error.analysisFailure ? { analysisFailure:error.analysisFailure } : {}) });
  }
  if (reply?.runtimeManifestPin !== PROJECTION_RUNTIME_PIN || reply?.targetSha256 !== input.sha256 || reply?.process?.childExitConfirmed !== true ||
      reply?.process?.status !== 'completed' || reply?.process?.exitCode !== 0 || reply?.process?.jobAssignedAtCreation !== true ||
      reply?.process?.activeProcessLimit !== 1 || reply?.process?.memoryLimitBytes !== 2*1024**3) throw new Error('Composition returned inconsistent process evidence');
  if (!Number.isSafeInteger(reply.outputBytes) || reply.outputBytes < 1 || reply.outputBytes > 4*1024**2) throw new Error('Composition output exceeds budget');
  const { data:output } = readStableFile(path.join(directory, 'stdout.log'), 4*1024**2);
  if (output.length !== reply.outputBytes || hashBytes(output) !== reply.outputSha256) throw new Error('Composition output digest mismatch');
  const result = JSON.parse(output.toString('utf8'));
  validateDecoderEvidence(selected, result, reply, directory);
  const representationValidation=validateCompositionResult(result, selected, input.sha256);
  const outputRef = jobs.artifacts.put(output);
  const record = jobs.artifacts.save({ kind:'composition', action:'compose', target:args.target, input,
    ...(compositionInput ? { compositionInput } : {}), ...(representationValidation ? {representationValidation}:{}), outputRef, process:reply.process, result },
    { pretty:true, maxBytes:4*1024**2 });
  const metadata = jobs.artifacts.metadata(record.id).result;
  return { reportSchema:result.schema,status:'partial',recoveryStatus:'unverified',
    nodeCount:result.dag.nodes.length,dagReferences:result.dag.references,storeCount:result.stores.length,sideExitCount:result.sideExits.length,
    nativeTargetExecuted:false, databaseModified:false, businessAccepted:false, wholeBinaryVerified:false,
    ...(result.templateMode ? {templateMode:result.templateMode,nondeterministicInputCount:result.nondeterministicInputs.length,
      expandedAbstractedInstructions:result.statistics.expandedAbstractedInstructions}:{}),
    ...(result.templateMode==='opaque-status'?{statusFlagImageCount:result.layers.reduce((n,l)=>n+l.flagImages.length,0)}:{}),
    ...decoderPreview(result, reply), backend:result.backend,
    targetSha256:input.sha256, strategy:selected.composition_plan.strategy,
    ...(compositionInput ? { compositionInput } : {}),
    indirectMode:selected.composition_plan.indirect_mode, statistics:result.statistics,
    ...(result.representation === 'transition-chain' ? { representation:result.representation, representationSchema:result.representationSchema,
      fitsPublicFixedPathLimits:result.fitsPublicFixedPathLimits, representationValidation,
      layerCount:result.layers.length, bindingCount:result.dag.bindingCount, retainedExpressionDepth:result.dag.depth,
      expandedDependencyDepth:result.dag.expandedDependencyDepth } : {}),
    memoryNormalization:result.memoryNormalization,
    pathGuard:result.pathGuard, registers:result.registers, currentMemory:result.currentMemory, control:result.control,
    sideExitPreview:result.sideExits.slice(0,8).map(({stepIndex,guard,target,currentMemory,controlKind}) =>
      ({stepIndex,guard,target,currentMemory,...(controlKind ? {controlKind} : {})})), sideExitPreviewComplete:result.sideExits.length<=8,
    ...(result.inferredRepeat ? { inferredRepeat:{ method:result.inferredRepeat.method,
      bodyApplicationsAfterPrefix:result.inferredRepeat.bodyApplicationsAfterPrefix, attempts:result.inferredRepeat.attempts,
      attemptedLogicalInstructions:result.inferredRepeat.attemptedLogicalInstructions, attemptedMemoryBytes:result.inferredRepeat.attemptedMemoryBytes } } : {}),
    expressionPreview:result.representation === 'transition-chain' ?
      'Resolve every state_binding by its exact earlier source equality in the complete report. Bindings are not independent inputs. Retained depth and expanded dependency depth are separate; no equivalence or reachability proof.' :
      'Node references resolve in the complete report DAG; no independent semantic equivalence or reachability proof was performed.',
    scope:result.scope, limits:result.compositionLimits, process:reply.process, outputRef,
    reportId:record.id, reportSha256:metadata.recordSha256, reportPath:path.join(jobs.artifacts.root,'records',record.id+'.json') };
}
