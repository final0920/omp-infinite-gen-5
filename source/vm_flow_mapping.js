// Bind every recorded byte to a unique executable raw-file region. No runtime
// address becomes a preferred address without the matching file/base evidence.
export function mapVmFlowBytes(data, runtimeBase, groups) {
  const fail = () => { throw new Error('Recorded flow has no unique byte-identical executable PE mapping'); };
  const u16 = at => { if (!Number.isSafeInteger(at) || at < 0 || at + 2 > data.length) fail(); return data.readUInt16LE(at); };
  const u32 = at => { if (!Number.isSafeInteger(at) || at < 0 || at + 4 > data.length) fail(); return data.readUInt32LE(at); };
  if (!Buffer.isBuffer(data) || data.length < 64 || data.length > 64 * 1024 ** 2 || data.toString('ascii',0,2) !== 'MZ'
    || typeof runtimeBase !== 'string' || !/^0x[0-9a-f]{1,16}$/.test(runtimeBase)
    || !Array.isArray(groups) || !groups.length || groups.length > 128) fail();
  const pe = u32(0x3c), count = u16(pe+6), optional = pe+24, optionalSize = u16(pe+20);
  if (pe+24 > data.length || data.toString('hex',pe,pe+4) !== '50450000' || u16(pe+4) !== 0x8664
    || optionalSize < 112 || u16(optional) !== 0x20b || count < 1 || count > 4096 || optional+optionalSize+40*count > data.length) fail();
  const preferredBase = data.readBigUInt64LE(optional+24), runtime = BigInt(runtimeBase), sections = [], used = new Set();
  for (let i=0;i<count;i++) {
    const at=optional+optionalSize+i*40, rva=BigInt(u32(at+12)), size=u32(at+16), offset=u32(at+20);
    if (offset+size > data.length || preferredBase+rva+BigInt(size) > 1n<<64n || runtime+rva+BigInt(size)>1n<<64n) fail();
    sections.push({rva,size,offset,executable:!!(u32(at+36)&0x20000000)});
  }
  const mapping=groups.map(group=>{
    if (!group.intermediateStateAvailable || group.instructions?.length !== 1) throw new Error('Flow projection requires each intermediate recorded state');
    const ins=group.instructions[0], pc=BigInt(ins.pc), bytes=Buffer.from(ins.bytes,'hex'), rva=pc-runtime;
    const matches=sections.filter(s=>rva>=s.rva&&rva+BigInt(bytes.length)<=s.rva+BigInt(s.size));
    if (matches.length!==1||!matches[0].executable) fail();
    const fileOffset=matches[0].offset+Number(rva-matches[0].rva), preferred='0x'+(preferredBase+rva).toString(16);
    if (!data.subarray(fileOffset,fileOffset+bytes.length).equals(bytes)) fail();
    if (used.has(preferred)) throw new Error('Repeated flow instruction needs an unsupported loop model');
    used.add(preferred);
    return {groupIndex:group.groupIndex,recordingId:group.recordingId,runtimePc:ins.pc,preferred,fileOffset,bytes:ins.bytes};
  });
  return {preferredBase:'0x'+preferredBase.toString(16),runtimeBase,mapping,originalOpcodeBytesMatched:true,
    loadedDataImageEquivalenceProved:false,moduleLoadEpoch:null};
}
