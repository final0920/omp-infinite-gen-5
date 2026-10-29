import { parentPort, workerData } from 'node:worker_threads';

try {
  if (workerData.kind === 'crypto') {
    const { analyzeCrypto } = await import('./crypto_analysis.js');
    const value = analyzeCrypto(workerData.request);
    parentPort.postMessage({ ok: true, value });
  } else if (workerData.kind === 'apk') {
    const { analyzeApk } = await import('./apk_analysis.js');
    parentPort.postMessage({ ok: true, value: analyzeApk(workerData.request) });
  } else if (workerData.kind === 'protocol') {
    const stateAction = ['state_infer', 'state_validate'].includes(workerData.request.action);
    const analyze = stateAction ? (await import('./protocol_state.js')).analyzeProtocolState : (await import('./protocol_analysis.js')).analyzeProtocol;
    parentPort.postMessage({ ok: true, value: { result: analyze(workerData.request) } });
  } else if (workerData.kind === 'vm-instance-check') {
    const {checkVmInstances}=await import('./vm_instances.js');
    parentPort.postMessage({ok:true,value:checkVmInstances(workerData.request.models)});
  } else if (workerData.kind === 'cff-state-replay') {
    const {analyzeCffState}=await import('./cff_state.js');
    parentPort.postMessage({ok:true,value:analyzeCffState(workerData.request.report,workerData.request.sourceRef)});
  } else if (workerData.kind === 'bv-candidate-generate') {
    const { proposeLocalBitvector } = await import('./bitvector_provider.js');
    parentPort.postMessage({ok:true,value:proposeLocalBitvector(workerData.request.contract)});
  } else if (workerData.kind === 'bv-candidate-replay') {
    const { replayBitvectorAssessment } = await import('./bitvector_replay.js');
    parentPort.postMessage({ ok:true,value:replayBitvectorAssessment(workerData.request) });
  } else if (workerData.kind === 'vm-role-validation') {
    const { validateRecordedRoles } = await import('./vm_role_validation.js');
    parentPort.postMessage({ ok: true, value: validateRecordedRoles(workerData.request) });
  } else if (workerData.kind === 'vm-recorded-function-verify') {
    const { verifyRecordedFunction } = await import('./verifiers/vm_recorded_function.js');
    parentPort.postMessage({ ok: true, value: verifyRecordedFunction(workerData.request.program, workerData.request.contract, workerData.request.recordedRuns) });
  } else if (workerData.kind === 'vm-function-verify') {
    const { verifyFiniteFunction } = await import('./verifiers/vm_function_verify.js');
    parentPort.postMessage({ ok: true, value: verifyFiniteFunction(workerData.request) });
  } else if (workerData.kind === 'vm-context-audit') {
    const { auditVmContext } = await import('./verifiers/vm_context_audit.js');
    parentPort.postMessage({ ok: true, value: auditVmContext(workerData.request) });
  } else if (workerData.kind === 'vm-observations') {
    const { analyzeVmObservations } = await import('./vm_observations.js');
    const analyze = workerData.request.phaseModel === true ? (await import('./vm_phase_model.js')).analyzeVmPhases : analyzeVmObservations;
    parentPort.postMessage({ ok: true, value: analyze(workerData.request) });
  } else if (workerData.kind === 'vm-role-samples') {
    const { selectVmRoleSamples } = await import('./vm_role_samples.js');
    parentPort.postMessage({ ok: true, value: selectVmRoleSamples(workerData.request) });
  } else if (workerData.kind === 'vm-handler-windows') {
    const { selectRecordedHandlerBodies } = await import('./vm_handler_window.js');
    parentPort.postMessage({ ok: true, value: selectRecordedHandlerBodies(workerData.request) });
  } else if (workerData.kind === 'vm-handler-assessment') {
    const { assessRecordedHandler } = await import('./recorded_handler_eval.js');
    parentPort.postMessage({ ok: true, value: assessRecordedHandler(workerData.request) });
  } else if (workerData.kind === 'vm-flow-recurrences') {
    const { analyzeFlowRecurrences } = await import('./vm_flow_recurrences.js');
    parentPort.postMessage({ ok: true, value: analyzeFlowRecurrences(workerData.request) });
  } else if (workerData.kind === 'vm-flow-witness-replay') {
    const { replayFlowAssessment } = await import('./flow_state_eval.js');
    parentPort.postMessage({ ok: true, value: replayFlowAssessment(workerData.request) });
  } else if (workerData.kind === 'vm-flow-window') {
    const { selectVmFlowWindow } = await import('./vm_flow_window.js');
    parentPort.postMessage({ ok: true, value: selectVmFlowWindow(workerData.request) });
  } else throw new Error('Unknown data analysis kind');
} catch (error) {
  const known = error.name === 'CryptoAnalysisError' || /^(ZIP_[A-Z]+|APK_FORMAT|AXML_(FORMAT|LIMIT)|DEX_(FORMAT|LIMIT)|INVALID_INPUT|INVALID_PROTOCOL_(ARGUMENT|SCHEMA|ENCODING|STATE)|PROTOCOL_(INPUT|STATE)_LIMIT|UNSUPPORTED_CAPTURE_FORMAT|INVALID_VM_OBSERVATION|VM_OBSERVATION_LIMIT|INVALID_RECORDED_HANDLER|INVALID_PHASE_CONTEXT|CODE_VERSION_MISMATCH|INVALID_VM_ROLE_VALIDATION|INVALID_VM_PROGRAM|UNRESOLVED_VM_PROGRAM|UNSUPPORTED_VM_PROGRAM|VM_PROGRAM_LIMIT)$/.test(error.code || '');
  parentPort.postMessage({ ok: false, error: { code: known ? error.code : 'ANALYSIS_FAILED', message: known ? String(error.message).slice(0, 512) : 'Data analysis failed; no output was committed' } });
}
