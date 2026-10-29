// Synthetic committed observations, not native VM execution.
import path from 'node:path';
const GPRS = 'rax rbx rcx rdx rdi rsi rbp rsp r8 r9 r10 r11 r12 r13 r14 r15'.split(' ');
const hx = value => '0x' + BigInt(value).toString(16);
const sha = digit => digit.repeat(64);
export function contextPage(page, store) {
  const statuses = Array.from({ length: 8 }, (_, i) => page === 0 || i < 2 ? 'consistent-recorded-ordinary-state' : 'partially-consistent-unknown-preserved');
  const values = page ? [0x23,0xac,0xc9,0x38,0x39,0x5c,0x07,0x3c] : [0x4e,0x88,0x11,0x89,0xfa,0xd0,0x00,0xdb];
  const occurrences = [], selectedBodies = [], handlerBodies = [];
  for (let i = 0; i < 8; i++) {
    const ordinal = page * 8 + i, sourceValue = hx(values[i]), sourceAddress = 0x7000n + BigInt(ordinal), target = 0x4000n + BigInt(values[i] * 16);
    const initialGprs = Object.fromEntries(GPRS.map(name => [name, '0x0']));
    Object.assign(initialGprs, { rsi: hx(sourceAddress), r11: '0x5000', rbp: hx(0x9000n - BigInt(ordinal * 8)), rsp: '0xa000', r8: hx(target) });
    const finalGprs = { ...initialGprs, rax: sourceValue, rsi: hx(sourceAddress + 1n), r8: hx(target) };
    const sourceOccurrence = 100 + ordinal * 10, partial = statuses[i].startsWith('partially');
    occurrences.push({ startGroup: sourceOccurrence, firstRecordingId: '11111111-1111-4111-8111-111111111111', lastRecordingId: '11111111-1111-4111-8111-111111111111',
      sourceAddress: hx(sourceAddress), sourceValue, target: hx(target), initialGprs, finalGprs,
      sourceAddressInputUpdates: [{ name: 'rsi', before: hx(sourceAddress), after: hx(sourceAddress + 1n), deltaModulo64: '0x1' }],
      indexedAddressInputValues: [{ node: 7, inputs: [{ name: 'r11', value: '0x5000' }, { name: 'rsi', value: hx(sourceAddress) }] }] });
    const after = { ...finalGprs, rbp: hx(BigInt(initialGprs.rbp) - 8n) };
    selectedBodies.push({ sourceOccurrence, sourceValue, observedEntry: hx(target), completeNextBoundary: true,
      groups: [{ before: { gprs: initialGprs }, after: { gprs: after }, memoryReads: [{ address: initialGprs.rbp, bytes: 8 }],
        memoryWrites: ordinal ? [] : { status: 'not-recorded-by-this-format', effectsNotInferredFromReads: true } }] });
    const gprs = GPRS.map(name => ({ name, status: partial && name === 'r10' ? 'unknown-preserved' : 'matched' }));
    const orderedStores = partial ? [{ valueStatus: 'unknown-preserved' }, { valueStatus: 'unknown-preserved' }] : [{ valueStatus: 'replayed' }];
    handlerBodies.push({ sourceOccurrence, sourceValue, observedEntry: hx(target), completeNextBoundary: true, status: statuses[i], projection: { path: `C:/projection/${ordinal}.json`, sha256: sha((ordinal % 10).toString()) },
      assessment: { schema: 'ig5-recorded-handler-assessment-v1', status: statuses[i], gprs, orderedStores,
        control: { kind: 'direct', target: '0x2124', selectedSuccessor: 'direct' } } });
  }
  const recurrence = { schema: 'ig5-flow-recurrences-v1', targetSha256: sha('a'), occurrences, distinctRecordedRuns: 1, vmRoleProved: false, businessAccepted: false };
  const selection = { schema: 'ig5-recorded-handler-windows-v1', targetSha256: sha('a'), bodies: selectedBodies };
  let recurrenceRef = { id: `0000000${page + 1}-0000-4000-8000-00000000000${page + 1}`, sha256: sha('b') };
  let selectionRef = { id: `0000000${page + 3}-0000-4000-8000-00000000000${page + 3}`, path: `C:/selection/${page}.json`, sha256: sha('c') };
  if (store) {
    const r = store.save({ kind: 'vm-flow-recurrences', action: 'validate', result: recurrence }, { pretty: true });
    recurrenceRef = { id: r.id, sha256: store.metadata(r.id).result.recordSha256 };
    const s = store.save({ kind: 'vm-handler-windows', action: 'select', result: selection }, { pretty: true });
    selectionRef = { id: s.id, path: path.join(store.directory('records'), s.id + '.json'), sha256: store.metadata(s.id).result.recordSha256 };
  }
  const handlers = { schema: 'ig5-recorded-handlers-v1', targetSha256: sha('a'), sourceRecurrence: recurrenceRef, sourceSelection: selectionRef,
    bodies: handlerBodies, vmRoleProved: false, businessAccepted: false, moduleLoadEpoch: null, memoryEpoch: null };
  return { handlers, recurrence, selection, recurrenceRef, selectionRef };
}
