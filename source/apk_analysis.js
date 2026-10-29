// APK front end: container, manifest, signing certificates, native libraries, nested payloads and a method-level
// capability scan of every classes*.dex. Static only; nothing in the sample is executed. The report is a set of LEADS
// with the code location that produced each one (class, method, called API), plus the limits that were hit.
//
// Not done here, on purpose: signature VERIFICATION (certificates are identified, not validated against the signed
// bytes), resources.arsc decoding, and de-obfuscation. The report says so in `notRun`.
import { createHash } from 'node:crypto';
import { ZipArchive } from './apk_zip.js';
import { certificatesFromPkcs7, certificatesFromSigningBlock, describeCertificate } from './apk_der.js';
import { DexFile } from './apk_dex.js';
import { parseManifest } from './apk_manifest.js';
import { CATEGORIES, STRENGTH, classifyApi, classifyField, classifyInterface, classifyPermission, classifyString, classifySuperclass, evaluateChains } from './apk_rules.js';

const fail = (code, message) => { throw Object.assign(new Error(message), { code }); };
export const APK_LIMITS = Object.freeze({ manifestBytes: 16 * 1024 * 1024, dexBytes: 128 * 1024 * 1024, totalDexBytes: 512 * 1024 * 1024, dexFiles: 64, certBytes: 256 * 1024, probeEntries: 400, probeBytes: 4 * 1024 * 1024,
  samplesPerRule: 5, classesListed: 200, methodsPerClassListed: 12, stringsListed: 300, nativeListed: 200, entriesListed: 300, deadlineMs: 45000 });

// Namespaces of widely shipped libraries. Hits inside them are kept, but flagged, and chains are judged on app code first.
const LIBRARY_PREFIXES = ['Landroid/', 'Landroidx/', 'Ljava/', 'Ljavax/', 'Lkotlin/', 'Lkotlinx/', 'Lcom/google/android/', 'Lcom/google/firebase/', 'Lcom/google/protobuf/', 'Lcom/google/gson/', 'Lcom/google/common/',
  'Lcom/android/', 'Lokhttp3/', 'Lokio/', 'Lretrofit2/', 'Lcom/squareup/', 'Lio/reactivex/', 'Lorg/apache/', 'Lorg/json/', 'Lcom/bumptech/', 'Lcom/facebook/', 'Lcom/fasterxml/', 'Lorg/jetbrains/', 'Ldagger/', 'Lorg/greenrobot/'];
const isLibrary = type => LIBRARY_PREFIXES.some(prefix => type.startsWith(prefix));
const GATED = new Set(['sms-send', 'sms-read', 'contacts', 'location', 'audio-record', 'camera', 'telephony']);   // categories whose APIs fail without a runtime or install permission
const SEVERITY = { 1: 'low', 2: 'medium', 3: 'high' };
// Namespace and schema URLs appear in nearly every app and say nothing about where it talks to.
const NAMESPACE_URL = /^https?:\/\/(schemas\.android\.com|schemas\.microsoft\.com|ns\.adobe\.com|www\.w3\.org|xmlpull\.org|xml\.apache\.org|apache\.org\/xml|java\.sun\.com)\b/i;
const URL_RE = /^(https?|wss?|ftp):\/\/[^\s"'<>]{4,300}$/i, IP_RE = /^(\d{1,3}\.){3}\d{1,3}(:\d{1,5})?$/;
const EXPECTED_EXTENSIONS = { dex: ['.dex'], elf: ['.so', '.bin', '.elf', '.o', '.node'], zip: ['.zip', '.jar', '.apk', '.aar', '.xapk', '.apks'] };

function entropy(buffer) {
  if (!buffer.length) return 0;
  const counts = new Uint32Array(256);
  for (const byte of buffer) counts[byte]++;
  let bits = 0;
  for (const count of counts) if (count) { const p = count / buffer.length; bits -= p * Math.log2(p); }
  return bits;
}
function magicOf(head) {
  if (head.length >= 8 && head.toString('latin1', 0, 4) === 'dex\n' && /^0\d\d\0$/.test(head.toString('latin1', 4, 8))) return 'dex';
  if (head.length >= 4 && head.readUInt32BE(0) === 0x7f454c46) return 'elf';
  if (head.length >= 4 && head.toString('latin1', 0, 2) === 'PK' && [[3, 4], [5, 6]].some(([a, b]) => head[2] === a && head[3] === b)) return 'zip';
  if (head.length >= 4 && head.toString('latin1', 0, 4) === 'cdex') return 'cdex';
  return null;
}
const extensionOf = name => { const dot = name.lastIndexOf('.'); return dot < 0 ? '' : name.slice(dot).toLowerCase(); };
const safe = (fn, fallback = null) => { try { return fn(); } catch { return fallback; } };

function certificateInfo(der, now) {
  try {
    const info = describeCertificate(der);
    const notAfter = Date.parse(info.notAfter), notBefore = Date.parse(info.notBefore), flags = [];
    if (Number.isFinite(notAfter) && notAfter < now) flags.push('expired');
    if (Number.isFinite(notBefore) && notBefore > now) flags.push('not-yet-valid');
    if (/CN=Android Debug/i.test(info.subject)) flags.push('android-debug-key');
    if (/CN=Android, .*emailAddress=android@android\.com/i.test(info.subject)) flags.push('aosp-test-subject');
    return { ...info, flags };
  } catch (error) { return { error: error.code || 'DER', sha256: createHash('sha256').update(der).digest('hex'), flags: ['unparseable'] }; }
}

function readSignatures(zip, limits, now, anomalies) {
  const out = { v1: [], block: null, certificates: [], verified: false };
  const seen = new Map();
  const add = (source, der) => { const info = certificateInfo(der, now), key = info.sha256; if (!seen.has(key)) { seen.set(key, { ...info, sources: [source] }); } else if (!seen.get(key).sources.includes(source)) seen.get(key).sources.push(source); };
  for (const entry of zip.entries) {
    if (!/^META-INF\/[^/]+\.(RSA|DSA|EC)$/i.test(entry.name)) continue;
    try { const certs = certificatesFromPkcs7(zip.read(entry, limits.certBytes)); out.v1.push({ file: entry.name, certificates: certs.length }); certs.forEach(der => add('v1', der)); }
    catch (error) { anomalies.push({ source: 'signature', code: 'v1-unreadable', file: entry.name, error: error.code || 'ERROR' }); }
  }
  try {
    const block = zip.signingBlock();
    if (block) {
      out.block = { offset: block.offset, size: block.size, ids: block.pairs.map(p => '0x' + p.id.toString(16)) };
      for (const pair of block.pairs) {
        const scheme = pair.id === 0x7109871a ? 'v2' : pair.id === 0xf05368c0 ? 'v3' : pair.id === 0x1b93ad61 ? 'v3.1' : null;
        if (!scheme) continue;
        try { certificatesFromSigningBlock(pair.value).forEach(der => add(scheme, der)); } catch (error) { anomalies.push({ source: 'signature', code: `${scheme}-unreadable`, error: error.code || 'ERROR' }); }
      }
    }
  } catch (error) { anomalies.push({ source: 'signature', code: 'signing-block-unreadable', error: error.code || 'ERROR' }); }
  out.certificates = [...seen.values()];
  return out;
}

function probeEntries(zip, limits, anomalies) {
  const nested = [], blobs = [];
  let probed = 0;
  for (const entry of zip.entries) {
    if (entry.name.endsWith('/') || /^classes\d*\.dex$/.test(entry.name) || entry.name === 'AndroidManifest.xml' || entry.name === 'resources.arsc' || /^META-INF\//.test(entry.name)) continue;
    const extension = extensionOf(entry.name), interesting = /^(assets|res\/raw|res\/xml|lib)\//.test(entry.name) || ['.dex', '.jar', '.apk', '.zip', '.so', '.bin', '.dat', '.db', '.enc'].includes(extension) || !entry.name.includes('/');
    if (!interesting || entry.size < 8 || entry.encrypted) continue;
    if (probed >= limits.probeEntries) { anomalies.push({ source: 'apk', code: 'probe-limit', limit: limits.probeEntries }); break; }
    if (entry.size > limits.probeBytes) { if (['.dex', '.jar', '.apk', '.so'].includes(extension) && !entry.name.startsWith('lib/')) nested.push({ name: entry.name, size: entry.size, by: 'extension', kind: extension.slice(1), probed: false }); continue; }
    let data;
    try { data = zip.read(entry, limits.probeBytes); } catch { continue; }
    probed++;
    const magic = magicOf(data), expected = magic ? EXPECTED_EXTENSIONS[magic === 'cdex' ? 'dex' : magic] : null;
    if (magic && !entry.name.startsWith('lib/')) nested.push({ name: entry.name, size: entry.size, by: 'magic', kind: magic, disguised: expected ? !expected.includes(extension) : false, sha256: createHash('sha256').update(data).digest('hex') });
    else if (!magic && data.length >= 4096 && !/^lib\//.test(entry.name)) {
      const bits = entropy(data.subarray(0, 65536));
      if (bits > 7.5 && !['.png', '.jpg', '.jpeg', '.webp', '.gif', '.mp3', '.mp4', '.ogg', '.aac', '.m4a', '.flac', '.opus', '.wma', '.mkv', '.webm', '.3gp', '.avi', '.mov', '.zip', '.jar', '.gz', '.br', '.ttf', '.otf', '.woff', '.woff2', '.arsc', '.pb', '.prof', '.profm'].includes(extension)) blobs.push({ name: entry.name, size: entry.size, entropy: Number(bits.toFixed(3)), sha256: createHash('sha256').update(data).digest('hex') });
    }
  }
  return { nested, blobs, probed };
}

function nativeLibraries(zip) {
  const libs = [];
  for (const entry of zip.entries) { const m = /^lib\/([^/]+)\/([^/]+\.so)$/.exec(entry.name); if (m) libs.push({ abi: m[1], name: m[2], size: entry.size, crc32: entry.crc.toString(16).padStart(8, '0') }); }
  return libs;
}

function scanDex(dex, name, state, limits, deadline, clock) {
  const methodCache = new Map(), stringCache = new Map(), fieldCache = new Map();
  const info = { name, version: dex.version, size: dex.b.length, checksumOk: dex.checksumOk, signatureOk: dex.signatureOk, classes: dex.classes.size, methods: dex.methods.size, strings: dex.strings.size, fields: dex.fields.size, anomalies: [], scanned: { classes: 0, methods: 0, withCode: 0, truncatedBodies: 0 } };
  const record = (rule, classType, methodText, target, library) => {
    let stat = state.rules.get(rule.id);
    if (!stat) state.rules.set(rule.id, stat = { id: rule.id, category: rule.category, strength: rule.strength, count: 0, appCount: 0, samples: [] });
    stat.count++; if (!library) stat.appCount++;
    const sample = { class: classType, method: methodText, target, library };
    if (stat.samples.length < limits.samplesPerRule) stat.samples.push(sample);
    else if (!library) { const replaceable = stat.samples.findIndex(s => s.library); if (replaceable >= 0) stat.samples[replaceable] = sample; }   // application call sites outrank library ones
    let entry = state.classes.get(classType);
    if (!entry) { if (state.classes.size >= 100000) { state.limits.add('class-hit-table'); return; } state.classes.set(classType, entry = { name: classType, dex: name, library, categories: new Set(), strength: new Map(), methods: new Map() }); }
    entry.categories.add(rule.category); entry.strength.set(rule.category, Math.max(entry.strength.get(rule.category) ?? 0, rule.strength));
    if (methodText && (entry.methods.size < limits.methodsPerClassListed || entry.methods.has(methodText))) { if (!entry.methods.has(methodText)) entry.methods.set(methodText, new Set()); entry.methods.get(methodText).add(rule.id); }
  };
  const interesting = (text, classType, methodText) => {
    if (state.strings.size >= limits.stringsListed || state.strings.has(text) || NAMESPACE_URL.test(text)) return;
    if (URL_RE.test(text) || (IP_RE.test(text) && text.split(/[.:]/).slice(0, 4).every(n => Number(n) <= 255))) state.strings.set(text, { text: text.slice(0, 300), kind: URL_RE.test(text) ? 'url' : 'ip', class: classType, method: methodText });
  };
  let classTicks = 0, methodTicks = 0, shortClasses = 0, appClasses = 0, shortMethods = 0, appMethods = 0;
  for (const classDef of dex.classDefs()) {
    if (state.limits.has('deadline') || (++classTicks % 64 === 0 && clock() > deadline)) { state.limits.add('deadline'); break; }
    const type = classDef.type ?? '?', library = isLibrary(type);
    info.scanned.classes++;
    if (!library) { appClasses++; const simple = type.slice(type.lastIndexOf('/') + 1, -1).replace(/\$.*/, ''); if (simple.length <= 2) shortClasses++; }
    for (const rule of classifySuperclass(classDef.superclass ?? '')) record(rule, type, null, classDef.superclass, library);
    for (const iface of dex.interfaces(classDef)) for (const rule of classifyInterface(iface ?? '')) record(rule, type, null, iface, library);
    let methods;
    try { methods = dex.methodsOf(classDef); } catch (error) { info.anomalies.push({ code: 'class-unreadable', class: type, error: error.code }); continue; }
    for (const method of methods) {
      if (++methodTicks % 256 === 0 && clock() > deadline) { state.limits.add('deadline'); break; }
      info.scanned.methods++;
      if (!library) { appMethods++; if (method.ref.name.length <= 2) shortMethods++; }
      if (!method.codeOffset) continue;
      let scan;
      try { scan = dex.scanCode(method.codeOffset); } catch (error) { info.anomalies.push({ code: 'code-unreadable', method: method.ref.text.slice(0, 160), error: error.code }); continue; }
      if (!scan) continue;
      info.scanned.withCode++; if (scan.truncated) info.scanned.truncatedBodies++;
      const where = method.ref.text;
      for (const index of scan.invokes) {
        let rules = methodCache.get(index);
        if (rules === undefined) { const ref = dex.methodRef(index); rules = ref ? classifyApi(ref.class, ref.name).map(rule => ({ rule, target: ref.text })) : []; methodCache.set(index, rules); }
        for (const { rule, target } of rules) record(rule, type, where, target, library);
      }
      for (const index of scan.fields) {
        let rules = fieldCache.get(index);
        if (rules === undefined) { const ref = dex.fieldRef(index); rules = ref ? classifyField(ref.class, ref.name).map(rule => ({ rule, target: ref.text })) : []; fieldCache.set(index, rules); }
        for (const { rule, target } of rules) record(rule, type, where, target, library);
      }
      for (const index of scan.strings) {
        let cached = stringCache.get(index);
        if (cached === undefined) { const text = dex.string(index); cached = text === null ? { text: null, rules: [] } : { text, rules: classifyString(text) }; stringCache.set(index, cached); }
        if (cached.text === null) continue;
        for (const rule of cached.rules) record(rule, type, where, cached.text.slice(0, 160), library);
        if (!library) interesting(cached.text, type, where);
      }
    }
  }
  info.anomalies.push(...dex.anomalies.slice(0, 20).map(a => ({ ...a })));
  state.obfuscation.classes += appClasses; state.obfuscation.shortClasses += shortClasses; state.obfuscation.methods += appMethods; state.obfuscation.shortMethods += shortMethods;
  return info;
}

/** Analyse one APK file. Throws only when the input is not an analysable APK; everything else is reported. */
export function analyzeApk(request) {
  const limits = { ...APK_LIMITS, ...(request.limits ?? {}) }, now = request.now ?? Date.now(), clock = request.clock ?? Date.now, deadline = clock() + limits.deadlineMs;
  if (typeof request.path !== 'string' || !request.path || request.path.includes('\0')) fail('INVALID_INPUT', 'An explicit APK file path is required');
  const zip = ZipArchive.open(request.path);
  try {
    const anomalies = zip.anomalies.map(a => ({ source: 'zip', ...a })), state = { rules: new Map(), classes: new Map(), strings: new Map(), limits: new Set(), obfuscation: { classes: 0, shortClasses: 0, methods: 0, shortMethods: 0 } };
    const names = zip.entries.map(e => e.name), hasManifest = zip.byName.has('AndroidManifest.xml');
    const dexNames = names.filter(n => /^classes\d*\.dex$/.test(n)).sort((a, b) => (parseInt(a.slice(7)) || 1) - (parseInt(b.slice(7)) || 1));
    if (!hasManifest && !dexNames.length) fail('APK_FORMAT', 'The archive has neither AndroidManifest.xml nor classes.dex; it is not an APK');
    const sha256 = zip.sha256();

    let manifest = null, manifestError = null;
    if (hasManifest) { try { manifest = parseManifest(zip.read('AndroidManifest.xml', limits.manifestBytes)); } catch (error) { manifestError = { code: error.code || 'ERROR', message: String(error.message).slice(0, 200) }; } }
    else anomalies.push({ source: 'apk', code: 'no-manifest' });

    const dexReports = []; let dexTotal = 0;
    for (const name of dexNames.slice(0, limits.dexFiles)) {
      if (clock() > deadline) { state.limits.add('deadline'); break; }
      const entry = zip.byName.get(name);
      if (dexTotal + entry.size > limits.totalDexBytes) { state.limits.add('total-dex-bytes'); break; }
      try {
        const dex = new DexFile(zip.read(entry, limits.dexBytes)); dexTotal += entry.size;
        dexReports.push(scanDex(dex, name, state, limits, deadline, clock));
      } catch (error) { dexReports.push({ name, error: { code: error.code || 'ERROR', message: String(error.message).slice(0, 200) } }); }
    }
    if (dexNames.length > limits.dexFiles) state.limits.add('dex-file-count');

    const signatures = readSignatures(zip, limits, now, anomalies), nativeLibs = nativeLibraries(zip), probe = probeEntries(zip, limits, anomalies);

    // ---- capabilities: permissions + code, joined by category ----
    const permissions = (manifest?.permissions ?? []).map(p => ({ ...classifyPermission(p.name), tag: p.tag, maxSdk: p.maxSdk }));
    const categories = new Map();
    const category = name => { if (!categories.has(name)) categories.set(name, { category: name, description: CATEGORIES[name], strength: 0, permissions: [], rules: [], appCode: false, libraryCode: false }); return categories.get(name); };
    for (const p of permissions) if (p.category) { const c = category(p.category); c.permissions.push(p.name); c.strength = Math.max(c.strength, p.level === 'normal' ? 1 : 2); }
    const ruleStats = [...state.rules.values()].sort((a, b) => b.strength - a.strength || b.count - a.count);
    for (const stat of ruleStats) { const c = category(stat.category); c.rules.push(stat.id); c.strength = Math.max(c.strength, stat.strength); if (stat.appCount) c.appCode = true; if (stat.count > stat.appCount) c.libraryCode = true; }
    const appCategories = new Set(), allCategories = new Set(), appClassSets = [], allClassSets = [];
    for (const [name, c] of categories) { allCategories.add(name); if (c.appCode || c.permissions.length) appCategories.add(name); }
    for (const entry of state.classes.values()) { allClassSets.push([entry.name, entry.categories]); if (!entry.library) appClassSets.push([entry.name, entry.categories]); }
    const appChains = evaluateChains(appCategories, appClassSets), seenChains = new Set(appChains.map(c => c.id));
    const chains = [...appChains.map(c => ({ ...c, libraryOnly: false })), ...evaluateChains(allCategories, allClassSets).filter(c => !seenChains.has(c.id)).map(c => ({ ...c, libraryOnly: true }))];

    const declaredWithoutCode = [...categories.values()].filter(c => c.permissions.length && !c.rules.length && GATED.has(c.category)).map(c => ({ category: c.category, permissions: c.permissions }));
    const usedWithoutPermission = [...categories.values()].filter(c => GATED.has(c.category) && c.appCode && !c.permissions.length && manifest).map(c => ({ category: c.category, rules: c.rules }));

    // ---- indicators ----
    const appClasses = state.obfuscation.classes;
    const indicators = [], add = (id, severity, title, evidence) => indicators.push({ id, severity, title, ...(evidence === undefined ? {} : { evidence }) });
    if (manifest) {
      const a = manifest.application;
      if (a?.debuggable === true) add('app.debuggable', 'medium', 'The application is marked debuggable');
      if (a?.testOnly === true) add('app.test-only', 'low', 'The package is marked testOnly');
      if (a?.usesCleartextTraffic === true) add('app.cleartext', 'low', 'Cleartext network traffic is explicitly allowed');
      if (a?.allowBackup === true) add('app.backup', 'low', 'Backup is explicitly allowed, so app data can be extracted over adb backup on older Android versions');
      if (manifest.sharedUserId) add('app.shared-uid', 'medium', 'Declares a sharedUserId', manifest.sharedUserId);
      const open = manifest.components.filter(c => c.exported && c.enabled && !c.permission && !c.launcher);
      if (open.length) add('manifest.exported-unprotected', 'low', `${open.length} exported component(s) are not protected by a permission`, open.slice(0, 20).map(c => `${c.kind}:${c.name}`));
      const leaky = manifest.components.filter(c => c.kind === 'provider' && c.exported && c.grantUriPermissions === true);
      if (leaky.length) add('manifest.provider-grant', 'medium', 'Exported content provider grants URI permissions', leaky.map(c => c.name));
      for (const anomaly of manifest.anomalies) if (['no-launcher-activity', 'disabled-launcher', 'high-priority-filter', 'duplicate-component', 'attribute-name-mismatch', 'unknown-chunk', 'trailing-bytes'].includes(anomaly.code)) add(`manifest.${anomaly.code}`, ['attribute-name-mismatch', 'unknown-chunk', 'trailing-bytes'].includes(anomaly.code) ? 'medium' : 'low', `Manifest anomaly: ${anomaly.code}`, anomaly);
    } else add('manifest.unreadable', 'high', hasManifest ? 'AndroidManifest.xml could not be decoded' : 'There is no AndroidManifest.xml', manifestError ?? undefined);
    if (!signatures.certificates.length) add('signature.none', 'medium', signatures.v1.length || signatures.block ? 'A signature structure exists but no certificate could be read' : 'The package carries no signature');
    for (const cert of signatures.certificates) {
      if (cert.flags.includes('android-debug-key')) add('signature.debug-key', 'medium', 'Signed with the Android debug certificate', cert.sha256);
      if (cert.flags.includes('aosp-test-subject')) add('signature.aosp-subject', 'medium', 'The certificate carries the subject of the public AOSP test/platform key (anyone can issue a certificate like that; compare the fingerprint with the real platform key before concluding anything)', cert.sha256);
      if (cert.flags.includes('expired')) add('signature.expired', 'low', 'A signing certificate has expired (not a validity problem for Android by itself)', cert.sha256);
      if (cert.flags.includes('unparseable')) add('signature.unparseable', 'medium', 'A signing certificate could not be parsed', cert.sha256);
    }
    if (signatures.v1.length && !signatures.block) add('signature.v1-only', 'low', 'Only the v1 (JAR) signature scheme is present');
    if (signatures.certificates.length > 1 && new Set(signatures.certificates.map(c => c.sha256)).size > 1) add('signature.multiple', 'low', 'More than one distinct signing certificate', signatures.certificates.map(c => c.sha256));
    for (const item of probe.nested) add(item.disguised ? 'payload.disguised' : 'payload.nested', item.disguised ? 'high' : 'medium', `${item.kind} content stored as ${item.name}${item.disguised ? ' (name does not match content)' : ''}`, item);
    if (probe.blobs.length) add('payload.high-entropy', 'low', `${probe.blobs.length} high-entropy asset(s) of unknown format (encrypted or compressed payload candidates)`, probe.blobs.slice(0, 10));
    // Library-only matches stay in capabilities.chains; the headline list is for what application code can do.
    for (const chain of chains) if (!chain.libraryOnly) add(chain.id, SEVERITY[chain.strength], chain.description + (chain.scope === 'class' ? ' (within a single class)' : ''), { scope: chain.scope, classes: chain.classes });
    for (const stat of ruleStats) if (stat.strength === STRENGTH.strong && stat.appCount ) add(`api.${stat.id}`, 'medium', `App code uses ${stat.id} (${CATEGORIES[stat.category]})`, { count: stat.appCount, samples: stat.samples.filter(s => !s.library).slice(0, 3) });
    const shortRatio = appClasses ? state.obfuscation.shortClasses / appClasses : 0;
    if (appClasses >= 20 && shortRatio > 0.5) add('code.obfuscated', 'low', `${Math.round(shortRatio * 100)}% of application classes have one- or two-character names`);
    if (dexReports.some(d => d.error)) add('dex.unreadable', 'high', 'A DEX file could not be parsed', dexReports.filter(d => d.error).map(d => ({ name: d.name, ...d.error })));
    for (const d of dexReports) if (!d.error && (!d.checksumOk || !d.signatureOk)) add('dex.integrity', 'medium', `${d.name} fails its header ${!d.checksumOk ? 'checksum' : 'signature'} (altered after build, or hand-edited)`);
    if (dexReports.length && appClasses > 0 && appClasses <= 2 && nativeLibs.length && manifest?.application?.name) add('code.stub-like', 'medium', 'Very little Java code, an Application subclass and native libraries: the shape of a packer stub');

    const classes = [...state.classes.values()].map(c => ({ name: c.name, dex: c.dex, library: c.library, categories: [...c.categories].sort(), strength: [...c.strength.values()].reduce((a, b) => a + b, 0),
      methods: [...c.methods].map(([method, rules]) => ({ method, rules: [...rules] })) })).sort((a, b) => Number(a.library) - Number(b.library) || b.strength - a.strength || a.name.localeCompare(b.name));
    const interestingStrings = [...state.strings.values()];
    const abis = [...new Set(nativeLibs.map(l => l.abi))].sort();

    return {
      schema: 'ig5.apk.v1',
      file: { path: zip.file, size: zip.size, sha256 },
      summary: `${manifest?.package ?? 'unknown package'} ${manifest?.versionName ?? ''}`.trim() + `: ${dexReports.filter(d => !d.error).length} dex, ${dexReports.reduce((n, d) => n + (d.classes ?? 0), 0)} classes, ${indicators.filter(i => i.severity === 'high').length} high / ${indicators.filter(i => i.severity === 'medium').length} medium indicators`,
      overview: { package: manifest?.package ?? null, versionName: manifest?.versionName ?? null, versionCode: manifest?.versionCode ?? null, minSdk: manifest?.sdk.min ?? null, targetSdk: manifest?.sdk.target ?? null,
        entries: zip.entries.length, dexFiles: dexReports.filter(d => !d.error).length, classes: dexReports.reduce((n, d) => n + (d.classes ?? 0), 0), methods: dexReports.reduce((n, d) => n + (d.methods ?? 0), 0), nativeAbis: abis,
        permissions: permissions.length, components: manifest?.components.length ?? 0, certificates: signatures.certificates.map(c => c.sha256), indicators: { high: indicators.filter(i => i.severity === 'high').length, medium: indicators.filter(i => i.severity === 'medium').length, low: indicators.filter(i => i.severity === 'low').length } },
      manifest: manifest ?? { error: manifestError },
      permissions, signatures,
      dex: dexReports, nativeLibraries: { count: nativeLibs.length, abis, items: nativeLibs.slice(0, limits.nativeListed) }, nestedPayloads: probe.nested, highEntropyAssets: probe.blobs,
      capabilities: { categories: [...categories.values()].sort((a, b) => b.strength - a.strength || a.category.localeCompare(b.category)), rules: ruleStats, chains, declaredWithoutCode, usedWithoutPermission },
      classes: { total: classes.length, listed: classes.slice(0, limits.classesListed) },
      strings: interestingStrings, obfuscation: { appClasses, shortClassRatio: Number(shortRatio.toFixed(3)), appMethods: state.obfuscation.methods, shortMethodRatio: state.obfuscation.methods ? Number((state.obfuscation.shortMethods / state.obfuscation.methods).toFixed(3)) : 0 },
      indicators, anomalies: anomalies.slice(0, 64),
      entries: { total: zip.entries.length, listed: zip.entries.slice(0, limits.entriesListed).map(e => ({ name: e.name, size: e.size, compressed: e.compressed, method: e.method })) },
      limitsHit: [...state.limits],
      notRun: ['signature verification (certificates are identified, not checked against the signed content)', 'resources.arsc decoding', 'native library analysis (use the ELF/Ghidra tools on extracted libraries)', 'any execution of the sample'],
      note: 'Capability hits are leads about what the code can do. Ordinary apps use most of these APIs; judge by the call sites listed.',
    };
  } finally { zip.close(); }
}
