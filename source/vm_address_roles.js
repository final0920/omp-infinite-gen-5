// Correlate decoded addressing expressions with recorded observations. No CPU
// execution, instruction processing, VM classification or semantic certificate.
const MASK = (1n << 64n) - 1n, hx = n => '0x' + (n & MASK).toString(16);
const fail = text => { throw new Error('Invalid recorded address analysis: ' + text); };
const hex = x => typeof x === 'string' && /^0x[0-9a-f]{1,16}$/.test(x);
const gprs = 'rax rbx rcx rdx rdi rsi rbp rsp r8 r9 r10 r11 r12 r13 r14 r15'.split(' ');
const registers = new Map();
for (const name of [...gprs, 'rip']) registers.set(name, { parent: name, bits: 64, low: 0 });
for (const [parent, names] of Object.entries({ rax: ['eax','ax','al','ah'], rbx: ['ebx','bx','bl','bh'], rcx: ['ecx','cx','cl','ch'], rdx: ['edx','dx','dl','dh'],
  rsi: ['esi','si','sil'], rdi: ['edi','di','dil'], rbp: ['ebp','bp','bpl'], rsp: ['esp','sp','spl'], rip: ['eip'] }))
  names.forEach((name, i) => registers.set(name, { parent, bits: [32,16,8,8][i], low: i === 3 ? 8 : 0 }));
for (let n = 8; n <= 15; n++) for (const [suffix,bits] of [['d',32],['w',16],['b',8]]) registers.set('r' + n + suffix, { parent: 'r' + n, bits, low: 0 });
const mask = bits => (1n << BigInt(bits)) - 1n;
function descriptor(r) {
  const expected = r && registers.get(r.name);
  if (!expected || r.kind !== 'register' || ['parent','bits','low'].some(k => r[k] !== expected[k])) return null;
  return expected;
}
function value(r, group, nextPc = false) {
  const d = descriptor(r); if (!d) return null;
  const observed = d.parent === 'rip' ? (nextPc ? hx(BigInt(group.before.rip) + BigInt(group.instructions[0].bytes.length / 2)) : group.before.rip) : group.before.gprs[d.parent];
  return hex(observed) ? (BigInt(observed) >> BigInt(d.low)) & mask(d.bits) : null;
}
function addressBits(bytes) {
  const b = Buffer.from(bytes, 'hex'); let override = false;
  for (const byte of b) {
    if ([0xf0,0xf2,0xf3,0x2e,0x36,0x3e,0x26,0x64,0x65,0x66,0x67].includes(byte) || byte >= 0x40 && byte <= 0x4f) { if (byte === 0x67) override = true; }
    else break;
  }
  return override ? 32 : 64;
}
export function observedEffectiveAddress(op, group) {
  if (!op || op.kind !== 'memory' || ![1,2,4,8,16,32,64].includes(op.bytes) || ![0,1,2,4,8].includes(op.scale)
    || ![32,64].includes(op.displacementBits) || !hex(op.displacement)) return { status: 'unsupported-expression' };
  const bits = addressBits(group.instructions[0].bytes);
  let sum = BigInt(op.displacement) & mask(bits);
  for (const [r, scale] of [[op.base,1],[op.index,op.scale]]) if (r) {
    if (!descriptor(r) || r.bits !== bits || !scale) return { status: 'unsupported-address-register' };
    const n = value(r, group, true); if (n === null) return { status: 'register-unobserved' };
    sum += n * BigInt(scale);
  }
  sum &= mask(bits);
  let segmentBase = 0n;
  if (op.segment === 'gs') {
    if (!hex(group.gsBaseObservation)) return { status: 'gs-base-unobserved' };
    segmentBase = BigInt(group.gsBaseObservation);
  } else if (op.segment === 'fs') return { status: 'fs-base-unobserved' };
  else if (op.segment !== null && !['cs','ds','es','ss'].includes(op.segment)) return { status: 'unsupported-segment' };
  return { status: 'computed', address: hx(sum + segmentBase), addressBits: bits,
    longModeAssumption: 'recording-format-x64-not-independent-CPU-mode-attestation', segment: op.segment,
    segmentBase: hx(segmentBase), ripUsesNextInstruction: op.base?.parent === 'rip' || op.index?.parent === 'rip' };
}
function matchRead(group, ea, bytes) {
  const rows = group.memoryReads.filter(r => r.address === ea && r.bytes === bytes);
  if (!rows.length) return { status: 'no-matching-recorded-read' };
  if (new Set(rows.map(r => r.littleEndianHex)).size !== 1) return { status: 'conflicting-recorded-reads', sourceLines: rows.map(r => r.sourceLine) };
  return { status: 'matched-recorded-read', littleEndianHex: rows[0].littleEndianHex, sourceLines: rows.map(r => r.sourceLine) };
}
const readValue = read => BigInt('0x' + read.littleEndianHex.match(/../g).reverse().join(''));
function loadCheck(row, group, accesses) {
  const mnemonic = row.text.split(/\s+/)[0].toLowerCase(), [dst, src] = row.operands;
  if (!['mov','movzx','movsx','movsxd'].includes(mnemonic) || row.operands.length !== 2 || src?.kind !== 'memory' || !descriptor(dst)
    || dst.parent === 'rip' || ![1,2,4,8].includes(src.bytes)) return { status: 'not-supported-pure-register-load' };
  const access = accesses.find(a => a.operandIndex === 1);
  if (!access || access.read?.status !== 'matched-recorded-read') return { status: 'load-read-unmatched' };
  if (src.bytes * 8 > dst.bits || mnemonic === 'mov' && src.bytes * 8 !== dst.bits) return { status: 'unsupported-load-width' };
  let loaded = readValue(access.read);
  if (['movsx','movsxd'].includes(mnemonic)) loaded = BigInt.asIntN(src.bytes * 8, loaded) & mask(dst.bits);
  const before = BigInt(group.before.gprs[dst.parent]), after = BigInt(group.after.gprs[dst.parent]);
  const expected = dst.bits === 32 ? loaded & mask(32) : ((before & ~(mask(dst.bits) << BigInt(dst.low))) | ((loaded & mask(dst.bits)) << BigInt(dst.low))) & MASK;
  return { status: expected === after ? 'observed-consistent' : 'observation-mismatch', destination: dst,
    sourceBytes: src.bytes, expectedParentValue: hx(expected), observedParentValue: hx(after),
    sourceOperandIndex: 1, instructionSemanticsProved: false };
}
function controlCheck(row, group, accesses) {
  const bytes = row.bytes, mnemonic = row.text.split(/\s+/)[0].toLowerCase();
  let target = null, kind = null, read = null, stackExpected = null;
  if (/^(c3|c2[0-9a-f]{4})$/.test(bytes) && mnemonic === 'ret') {
    kind = 'recorded-stack-return'; read = matchRead(group, group.before.gprs.rsp, 8);
    if (read.status === 'matched-recorded-read') target = readValue(read);
    const extra = bytes === 'c3' ? 0 : Buffer.from(bytes, 'hex').readUInt16LE(1);
    stackExpected = hx(BigInt(group.before.gprs.rsp) + 8n + BigInt(extra));
  } else if (row.controlFlow && ['jmp','call'].includes(mnemonic) && row.operands.length === 1 && row.operands[0].kind !== 'immediate') {
    kind = 'recorded-indirect-' + mnemonic;
    const op = row.operands[0];
    if (op.kind === 'register' && op.bits === 64) target = value(op, group);
    if (op.kind === 'memory' && op.bytes === 8) { read = accesses[0]?.read; if (read?.status === 'matched-recorded-read') target = readValue(read); }
  } else return { status: 'not-supported-indirect-control' };
  return { kind, status: target === null ? 'target-unobserved' : hx(target) === group.after.rip && (stackExpected === null || stackExpected === group.after.gprs.rsp) ? 'observed-consistent' : 'observation-mismatch',
    target: target === null ? null : hx(target), observedNextRip: group.after.rip, expectedRsp: stackExpected,
    ...(read ? { read } : {}), dispatchRoleProved: false, instructionSemanticsProved: false };
}
export function analyzeVmAddressRoles(samples, decoded) {
  if (samples?.schema !== 'ig5-vm-role-samples-v1' || !Array.isArray(samples.sites) || samples.sites.length > 128
    || decoded?.schema !== 'ig5-observed-decode-v1' || !Array.isArray(decoded.sites) || decoded.sites.length !== samples.sites.length
    || decoded.decoder !== 'pinned-triton-disassembly-only'
    || decoded.decoderManifestPin !== '65bf673f1c4304cc2c09076e3b96e368da9e0df72aa0badeba0c2a5cae392934'
    || ['nativeTargetExecuted','databaseModified','businessAccepted','wholeBinaryVerified'].some(k => decoded[k] !== false)) fail('decoder identity or scope');
  const sites = [], streams = [], contexts = new Map();
  const counts = { sampledGroups: samples.sites.reduce((n,s) => n + s.groups.length,0), decodedGroups: 0, decodedSites: 0, decodeRejectedSites: 0, effectiveAddressMatches: 0, unmatchedAddresses: 0,
    consistentLoads: 0, inconsistentLoads: 0, consistentIndirectControls: 0, inconsistentIndirectControls: 0, coalescedGroupsUnmodeled: 0 };
  for (let index = 0; index < samples.sites.length; index++) {
    const site = samples.sites[index], row = decoded.sites[index];
    if (row.pc !== site.pc || row.bytes !== site.bytes || !Array.isArray(site.groups) || site.groups.length > 8) fail('site byte identity or sample budget');
    if (row.status === 'decode-rejected') { const { groups, ...metadata } = site; counts.decodeRejectedSites++; sites.push({ ...metadata, decoder: row, observations: [] }); continue; }
    if (row.status !== 'decoded' || typeof row.text !== 'string' || row.text.length > 2048 || !Array.isArray(row.operands) || row.operands.length > 8 || typeof row.controlFlow !== 'boolean') fail('decoded operand shape');
    counts.decodedSites++; const results = [], streamSamples = [];
    for (const group of site.groups) {
      counts.decodedGroups++;
      const origin = { groupIndex: group.groupIndex, recordingId: group.recordingId, pauseSequence: group.pauseSequence,
        instructionSourceLine: group.instructions[0].sourceLine };
      if (group.instructions.length !== 1 || !group.intermediateStateAvailable) {
        counts.coalescedGroupsUnmodeled++; results.push({ ...origin, status: 'coalesced-group-no-intermediate-state' }); continue;
      }
      const accesses = [];
      for (const [operandIndex, op] of row.operands.entries()) if (op.kind === 'memory') {
        const ea = observedEffectiveAddress(op, group);
        const read = row.text.split(/\s+/)[0] === 'lea' ? { status: 'lea-is-not-a-memory-read' }
          : ea.status === 'computed' ? matchRead(group, ea.address, op.bytes) : { status: 'address-unresolved' };
        accesses.push({ operandIndex, expression: op, effectiveAddress: ea, read });
        if (read.status === 'matched-recorded-read') {
          counts.effectiveAddressMatches++;
          if (op.base && !op.index && descriptor(op.base) && op.base.parent !== 'rip' && !op.segment) {
            const base = value(op.base, group), id = hx(base), entry = contexts.get(id) || { baseObservation: id, accesses: [] };
            if (entry.accesses.length < 32) entry.accesses.push({ ...origin, pc: site.pc, registerAtThisStop: op.base.name, displacement: op.displacement, address: ea.address, bytes: op.bytes });
            entry.total = (entry.total || 0) + 1; contexts.set(id, entry);
          }
        } else counts.unmatchedAddresses++;
      }
      const load = loadCheck(row, group, accesses), control = controlCheck(row, group, accesses);
      if (load.status === 'observed-consistent') {
        counts.consistentLoads++;
        if (load.sourceBytes <= 2) streamSamples.push({ ...origin, address: accesses.find(a => a.operandIndex === 1).effectiveAddress.address,
          destination: load.destination, source: row.operands[1] });
      } else if (load.status === 'observation-mismatch') counts.inconsistentLoads++;
      if (control.status === 'observed-consistent') counts.consistentIndirectControls++;
      else if (control.status === 'observation-mismatch') counts.inconsistentIndirectControls++;
      results.push({ ...origin, status: 'analyzed-observation-only', accesses, load, control });
    }
    if (streamSamples.length >= 2 && new Set(streamSamples.map(s => s.address)).size >= 2) streams.push({
      pc: site.pc, bytes: site.bytes, kind: 'narrow-load-stream-candidate', samples: streamSamples,
      vmRoleProved: false, ordinaryProgramAmbiguity: 'byte-buffer/string/table traversal also satisfies these observations',
      requiredEvidence: ['read-to-dispatch-dataflow', 'initialization-vs-VM-phase', 'module-and-memory-epochs', 'alternate-inputs-and-VM-instances'] });
    const { groups, ...metadata } = site; sites.push({ ...metadata, decoder: row, observations: results });
  }
  return { schema: 'ig5-vm-address-roles-v1', status: 'hypotheses-only', targetSha256: samples.observation.targetSha256,
    nativeTargetExecuted: false, databaseModified: false, businessAccepted: false, wholeBinaryVerified: false,
    vmModelProved: false, instructionSemanticsProved: false, changesExecutionAuthority: false,
    identity: samples.observation.identity, inputWindows: samples.observation.windows, sampling: samples.sampling, counts,
    phases: 'unclassified', memoryEpoch: null, moduleLoadEpoch: null, streamCandidates: streams,
    contextCandidates: [...contexts.values()].filter(c => new Set(c.accesses.map(a => a.displacement)).size >= 3).slice(0, 64).map(c => ({ ...c,
      evidencePreviewComplete: c.total === c.accesses.length, kind: 'multi-offset-base-observation', vmRoleProved: false,
      ordinaryProgramAmbiguity: 'ordinary stack frames and structures also satisfy these observations' })),
    sites, nextObligations: ['Verify missing read/write and memory epochs', 'Connect observed fetch values to dispatch targets with full dataflow',
      'Separate initialization, SMC and business execution', 'Revalidate across inputs and instances before assigning VIP/VSP/context roles'],
    scope: 'Sampled address/load/control consistency. Decoder and observed values are not an independent CPU proof or complete VM recovery.' };
}
