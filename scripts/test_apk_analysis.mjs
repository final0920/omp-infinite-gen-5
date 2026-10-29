// APK front end end-to-end: a small APK is assembled from the test builders (manifest, DEX with known call sites,
// certificates, signing block, native library, disguised and encrypted-looking assets) and analysed from disk.
import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { analyzeApk } from '../source/apk_analysis.js';
import { ANDROID_NS } from '../source/apk_axml.js';
import { buildAxml, buildSigningBlock, buildZip } from './fixtures/apk_builder.mjs';
import { CN, certificate, ecSpki, pkcs7, signerBlockValue } from './fixtures/cert_builder.mjs';
import { I, buildDex } from './fixtures/dex_builder.mjs';

const scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'ig5-apk-'));
process.on('exit', () => fs.rmSync(scratch, { recursive: true, force: true }));
let counter = 0;
const write = (name, bytes) => { const file = path.join(scratch, `${++counter}-${name}`); fs.writeFileSync(file, bytes); return file; };
const codeOf = fn => { try { fn(); } catch (error) { return error.code; } return 'NO-ERROR'; };

const A = (name, resId, type, value) => ({ name, ns: ANDROID_NS, resId, type, value });
const NAME = value => A('name', 0x01010003, 'string', value), EXPORTED = value => A('exported', 0x01010010, 'bool', value);
const el = (name, attrs = [], children = []) => ({ name, attrs, children });
const action = n => el('action', [NAME(n)]), category = n => el('category', [NAME(n)]);
const manifest = ({ permissions = [], debuggable = true, backup } = {}) => buildAxml(el('manifest', [{ name: 'package', type: 'string', value: 'com.evil.app' }, A('versionCode', 0x0101021b, 'int', 7), A('versionName', 0x0101021c, 'string', '2.0')], [
  el('uses-sdk', [A('minSdkVersion', 0x0101020c, 'int', 21), A('targetSdkVersion', 0x01010270, 'int', 30)]), ...permissions.map(p => el('uses-permission', [NAME('android.permission.' + p)])),
  el('application', [NAME('.App'), A('debuggable', 0x0101000f, 'bool', debuggable), ...(backup === undefined ? [] : [A('allowBackup', 0x01010280, 'bool', backup)])], [
    el('activity', [NAME('.Main'), EXPORTED(true)], [el('intent-filter', [], [action('android.intent.action.MAIN'), category('android.intent.category.LAUNCHER')])]),
    el('receiver', [NAME('.SmsReceiver'), EXPORTED(true)], [el('intent-filter', [A('priority', 0x0101001c, 'int', 999)], [action('android.provider.Telephony.SMS_RECEIVED')])])])]), { resourceMap: true });

const SMS_MANAGER = 'Landroid/telephony/SmsManager;', STR = 'Ljava/lang/String;';
const dex = () => buildDex({ classes: [
  { name: 'Lcom/evil/app/SmsReceiver;', superclass: 'Landroid/content/BroadcastReceiver;', methods: [
    { name: 'onReceive', direct: false, code: { registers: 4, insns: [
      I.invoke('static', { class: 'Landroid/telephony/SmsMessage;', name: 'createFromPdu', params: ['[B'], ret: 'Landroid/telephony/SmsMessage;' }, [0]),
      I.constString(1, 'content://sms/inbox'), I.constString(2, 'http://c2.example.net/upload'),
      I.invoke('virtual', { class: 'Ljava/net/URL;', name: 'openConnection', ret: 'Ljava/net/URLConnection;' }, [1]),
      I.invoke('virtual', { class: SMS_MANAGER, name: 'sendTextMessage', params: [STR, STR, STR], ret: 'V' }, [0, 1, 2, 3]), I.returnVoid()] } },
    { name: 'quiet', direct: false, code: { insns: [I.sget(0, { class: 'Landroid/os/Build;', name: 'MODEL', type: STR }), I.returnVoid()] } }] },
  { name: 'Lcom/evil/app/Loader;', superclass: 'Ljava/lang/Object;', methods: [{ name: 'load', direct: false, code: { insns: [
    I.invoke('static', { class: 'Ljavax/crypto/Cipher;', name: 'getInstance', params: [STR], ret: 'Ljavax/crypto/Cipher;' }, [0]),
    I.invoke('virtual', { class: 'Ljava/net/URL;', name: 'openStream', ret: 'Ljava/io/InputStream;' }, [0]), I.returnVoid()] } }] },
  { name: 'Lcom/google/android/gms/Lib;', superclass: 'Ljava/lang/Object;', methods: [{ name: 'x', direct: false, code: { insns: [
    I.invoke('direct', { class: 'Ldalvik/system/DexClassLoader;', name: '<init>', params: [STR, STR, STR, 'Ljava/lang/ClassLoader;'] }, [0, 1, 2, 3, 4]), I.returnVoid()] } }] },
  { name: 'La/a;', superclass: 'Ljava/lang/Object;', methods: Array.from({ length: 3 }, (_, i) => ({ name: 'a' + 'b'.repeat(i), direct: false, code: { insns: [I.returnVoid()] } })) },
] });

const debugCert = certificate({ subject: [[CN, 'Android Debug']], spki: ecSpki('prime256v1') });
const releaseCert = certificate({ subject: [[CN, 'Release Corp']], spki: ecSpki('prime256v1'), notAfter: '2020-01-01T00:00:00Z' });
const ELF = Buffer.concat([Buffer.from([0x7f, 0x45, 0x4c, 0x46]), randomBytes(60)]);
const DEXLIKE = Buffer.concat([Buffer.from('dex\n035\0'), randomBytes(100)]);

function sampleApk(overrides = {}) {
  return buildZip([
    { name: 'AndroidManifest.xml', data: overrides.manifest ?? manifest({ permissions: ['INTERNET', 'READ_SMS', 'RECEIVE_BOOT_COMPLETED', 'CAMERA'] }) }, { name: 'classes.dex', data: overrides.dex ?? dex() },
    { name: 'META-INF/CERT.RSA', data: pkcs7([debugCert]) }, { name: 'META-INF/MANIFEST.MF', data: 'Manifest-Version: 1.0\n' },
    { name: 'lib/arm64-v8a/libnative.so', data: ELF }, { name: 'assets/logo.png', data: DEXLIKE, method: 'store' }, { name: 'assets/blob.bin', data: randomBytes(8192), method: 'store' },
    { name: 'assets/readme.txt', data: 'plain text '.repeat(500) }, ...(overrides.entries ?? [])], { signingBlock: overrides.block === undefined ? buildSigningBlock([{ id: 0x7109871a, value: signerBlockValue([releaseCert]) }]) : overrides.block });
}
const analyze = (bytes, extra = {}) => analyzeApk({ path: write('sample.apk', bytes), now: Date.parse('2026-10-24T00:00:00Z'), ...extra });
const find = (list, id) => list.find(item => item.id === id);

test('overview: identity, counts, hashes and the sample is left untouched', () => {
  const bytes = sampleApk(), file = write('sample.apk', bytes), before = createHash('sha256').update(bytes).digest('hex');
  const report = analyzeApk({ path: file, now: Date.parse('2026-10-24T00:00:00Z') });
  assert.equal(report.schema, 'ig5.apk.v1'); assert.equal(report.file.sha256, before); assert.equal(report.file.size, bytes.length);
  assert.deepEqual([report.overview.package, report.overview.versionName, report.overview.versionCode, report.overview.minSdk, report.overview.targetSdk], ['com.evil.app', '2.0', 7, 21, 30]);
  assert.equal(report.overview.dexFiles, 1); assert.equal(report.overview.classes, 4); assert.deepEqual(report.overview.nativeAbis, ['arm64-v8a']); assert.equal(report.overview.components, 2);
  assert.equal(createHash('sha256').update(fs.readFileSync(file)).digest('hex'), before, 'analysis never writes to the sample');
  assert.equal(report.dex[0].checksumOk, true); assert.equal(report.dex[0].scanned.withCode, 7);
  assert.ok(report.notRun.some(text => /signature verification/.test(text)));
});

test('capabilities carry the call site that produced them, application code first', () => {
  const report = analyze(sampleApk()), rules = id => find(report.capabilities.rules, id);
  const sms = rules('sms.send');
  assert.equal(sms.appCount, 1); assert.deepEqual([sms.samples[0].class, sms.samples[0].method, sms.samples[0].target, sms.samples[0].library],
    ['Lcom/evil/app/SmsReceiver;', 'Lcom/evil/app/SmsReceiver;->onReceive()V', 'Landroid/telephony/SmsManager;->sendTextMessage(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V', false]);
  assert.equal(rules('sms.parse').category, 'sms-read'); assert.equal(rules('str.sms-uri').samples[0].target, 'content://sms/inbox'); assert.equal(rules('build.model').samples[0].method, 'Lcom/evil/app/SmsReceiver;->quiet()V');
  const dcl = rules('dcl.dexclassloader'); assert.equal(dcl.count, 1); assert.equal(dcl.appCount, 0, 'the only DexClassLoader call is inside a known library namespace'); assert.equal(dcl.samples[0].library, true);
  const smsCategory = find(report.capabilities.categories.map(c => ({ id: c.category, ...c })), 'sms-send');
  assert.deepEqual([smsCategory.appCode, smsCategory.permissions, smsCategory.strength], [true, [], 3]);
  const readSms = report.capabilities.categories.find(c => c.category === 'sms-read'); assert.deepEqual(readSms.permissions, ['android.permission.READ_SMS']); assert.equal(readSms.appCode, true);
  const loader = report.classes.listed.find(c => c.name === 'Lcom/evil/app/SmsReceiver;');
  assert.deepEqual(loader.categories, ['emulator-detection', 'network', 'sms-read', 'sms-send']); assert.equal(loader.library, false);
  assert.equal(report.classes.listed.findIndex(c => c.library) > report.classes.listed.findIndex(c => c.name === 'Lcom/evil/app/Loader;'), true, 'library classes are listed after application classes');
});

test('chains are judged on application code, with library-only matches marked', () => {
  const report = analyze(sampleApk()), chains = Object.fromEntries(report.capabilities.chains.map(c => [c.id, c]));
  assert.equal(chains['chain.sms-exfiltration'].libraryOnly, false); assert.equal(chains['chain.sms-exfiltration'].scope, 'class'); assert.deepEqual(chains['chain.sms-exfiltration'].classes, ['Lcom/evil/app/SmsReceiver;']);
  assert.equal(chains['chain.sms-fraud'].libraryOnly, false);
  assert.equal(chains['chain.packed-loader'].libraryOnly, true, 'DexClassLoader + crypto only combine through the library class');
  assert.equal(chains['chain.remote-code'].libraryOnly, true);
  assert.equal(find(report.indicators, 'chain.sms-exfiltration').severity, 'high'); assert.equal(find(report.indicators, 'chain.packed-loader'), undefined, 'library-only matches stay out of the headline indicators');
});

test('permission and code are cross-checked in both directions', () => {
  const report = analyze(sampleApk());
  assert.deepEqual(report.capabilities.declaredWithoutCode, [{ category: 'camera', permissions: ['android.permission.CAMERA'] }]);
  assert.deepEqual(report.capabilities.usedWithoutPermission.map(u => u.category), ['sms-send'], 'sendTextMessage is called but SEND_SMS is not declared');
  assert.equal(analyze(sampleApk({ manifest: manifest({ permissions: ['SEND_SMS', 'READ_SMS', 'INTERNET'] }) })).capabilities.usedWithoutPermission.length, 0);
});

test('signing: v1 and v2 certificates are identified, flags set, and nothing claims verification', () => {
  const report = analyze(sampleApk()), certs = report.signatures.certificates;
  assert.equal(certs.length, 2); const debug = certs.find(c => c.flags.includes('android-debug-key')), release = certs.find(c => c.subject.includes('Release Corp'));
  assert.deepEqual(debug.sources, ['v1']); assert.deepEqual(release.sources, ['v2']); assert.ok(release.flags.includes('expired')); assert.equal(report.signatures.verified, false);
  assert.deepEqual(report.signatures.v1, [{ file: 'META-INF/CERT.RSA', certificates: 1 }]); assert.deepEqual(report.signatures.block.ids, ['0x7109871a']);
  for (const id of ['signature.debug-key', 'signature.expired', 'signature.multiple']) assert.ok(find(report.indicators, id), id);
  const unsigned = analyze(buildZip([{ name: 'AndroidManifest.xml', data: manifest() }, { name: 'classes.dex', data: dex() }]));
  assert.ok(find(unsigned.indicators, 'signature.none')); assert.equal(unsigned.signatures.certificates.length, 0);
  assert.ok(find(analyze(sampleApk({ block: null })).indicators, 'signature.v1-only'));
});

test('hidden payloads: content that does not match its name, encrypted-looking assets, native libraries', () => {
  const report = analyze(sampleApk());
  assert.deepEqual(report.nestedPayloads.map(p => [p.name, p.kind, p.disguised, p.by]), [['assets/logo.png', 'dex', true, 'magic']]);
  assert.equal(find(report.indicators, 'payload.disguised').severity, 'high');
  assert.deepEqual(report.highEntropyAssets.map(b => b.name), ['assets/blob.bin']); assert.ok(report.highEntropyAssets[0].entropy > 7.5);
  assert.equal(report.nativeLibraries.count, 1); assert.deepEqual(report.nativeLibraries.items[0], { abi: 'arm64-v8a', name: 'libnative.so', size: ELF.length, crc32: report.nativeLibraries.items[0].crc32 });
  const honest = analyze(sampleApk({ entries: [{ name: 'assets/extra.dex', data: DEXLIKE, method: 'store' }] }));
  assert.equal(honest.nestedPayloads.find(p => p.name === 'assets/extra.dex').disguised, false);
});

test('strings: URLs and IPs are listed with the method that loads them', () => {
  const report = analyze(sampleApk());
  assert.deepEqual(report.strings.map(s => [s.text, s.kind, s.method]), [['http://c2.example.net/upload', 'url', 'Lcom/evil/app/SmsReceiver;->onReceive()V']]);
});

test('manifest and application findings become indicators', () => {
  const report = analyze(sampleApk());
  assert.ok(find(report.indicators, 'app.debuggable')); assert.ok(find(report.indicators, 'manifest.exported-unprotected').evidence.includes('receiver:com.evil.app.SmsReceiver'));
  assert.equal(report.indicators.some(i => i.id === 'app.debuggable'), true); assert.equal(analyze(sampleApk({ manifest: manifest({ debuggable: false }) })).indicators.some(i => i.id === 'app.debuggable'), false);
});

test('a damaged DEX or manifest is reported, the rest of the analysis still runs', () => {
  const brokenDex = dex(); brokenDex.writeUInt32LE(0x7fffffff, 88);
  const a = analyze(sampleApk({ dex: brokenDex }));
  assert.ok(a.dex[0].error); assert.equal(find(a.indicators, 'dex.unreadable').severity, 'high'); assert.equal(a.overview.package, 'com.evil.app'); assert.equal(a.signatures.certificates.length, 2);
  const b = analyze(sampleApk({ manifest: Buffer.from('this is not binary xml') }));
  assert.equal(find(b.indicators, 'manifest.unreadable').severity, 'high'); assert.equal(b.overview.package, null); assert.equal(b.dex[0].classes, 4);
});

test('bad checksums and signatures inside a DEX are flagged as integrity findings', () => {
  const report = analyze(sampleApk({ dex: Buffer.from(dex().fill(0x01, 200, 204)) }));
  assert.ok(find(report.indicators, 'dex.integrity'));
});

test('inputs that are not APKs are refused with a code', () => {
  assert.equal(codeOf(() => analyzeApk({ path: write('x.apk', Buffer.from('not a zip at all, just text'.repeat(4))) })), 'ZIP_FORMAT');
  assert.equal(codeOf(() => analyzeApk({ path: write('x.apk', buildZip([{ name: 'readme.txt', data: 'hello' }])) })), 'APK_FORMAT');
  assert.equal(codeOf(() => analyzeApk({ path: '' })), 'INVALID_INPUT'); assert.equal(codeOf(() => analyzeApk({ path: 'a\0b' })), 'INVALID_INPUT'); assert.equal(codeOf(() => analyzeApk({})), 'INVALID_INPUT');
  assert.equal(codeOf(() => analyzeApk({ path: scratch })), 'ZIP_INPUT');
});

test('budgets: the deadline stops the scan and says so; caps keep the report bounded', () => {
  const report = analyze(sampleApk(), { limits: { deadlineMs: -1 } });
  assert.ok(report.limitsHit.includes('deadline')); assert.equal(report.overview.package, 'com.evil.app');
  const capped = analyze(sampleApk(), { limits: { samplesPerRule: 1, classesListed: 1, entriesListed: 2, stringsListed: 0 } });
  assert.equal(capped.classes.listed.length, 1); assert.equal(capped.classes.total > 1, true); assert.equal(capped.entries.listed.length, 2); assert.equal(capped.entries.total > 2, true); assert.deepEqual(capped.strings, []);
  assert.ok(Buffer.byteLength(JSON.stringify(report)) < 200000, 'a small APK yields a small report');
});

test('a stub-like package (little code, native library, custom Application) is flagged as a packer lead', () => {
  const stub = buildDex({ classes: [{ name: 'Lcom/evil/app/App;', superclass: 'Landroid/app/Application;', methods: [{ name: 'attachBaseContext', direct: false, code: { insns: [I.returnVoid()] } }] }] });
  assert.ok(find(analyze(sampleApk({ dex: stub })).indicators, 'code.stub-like'));
  assert.equal(find(analyze(sampleApk()).indicators, 'code.stub-like'), undefined);
});

// ---- cases added from mutation checks: each one pins a decision the first tests left open ----

const method = (name, insns) => ({ name, direct: false, code: { insns: [...insns, I.returnVoid()] } });
const cls = (name, methods, superclass = 'Ljava/lang/Object;') => ({ name, superclass, methods });
const SEND = I.invoke('virtual', { class: SMS_MANAGER, name: 'sendTextMessage', params: [STR, STR, STR], ret: 'V' }, [0, 1, 2, 3]);
const CIPHER = I.invoke('static', { class: 'Ljavax/crypto/Cipher;', name: 'getInstance', params: [STR], ret: 'Ljavax/crypto/Cipher;' }, [0]);
const withDex = (classes, entries = []) => sampleApk({ dex: buildDex({ classes }), entries });

test('a sample list prefers application call sites over library ones once it is full', () => {
  const report = analyze(withDex([cls('Lcom/google/android/gms/Lib;', [method('x', [CIPHER])]), cls('Lcom/evil/app/Mine;', [method('y', [CIPHER])])]), { limits: { samplesPerRule: 1 } });
  const sample = find(report.capabilities.rules, 'crypto.cipher').samples;
  assert.deepEqual(sample.map(s => [s.class, s.library]), [['Lcom/evil/app/Mine;', false]]);
});

test('capabilities that exist only in library code do not count as "used without permission"', () => {
  const report = analyze(withDex([cls('Lcom/google/android/gms/Lib;', [method('x', [SEND])]), cls('Lcom/evil/app/Main;', [method('y', [])])]));
  assert.deepEqual(report.capabilities.usedWithoutPermission, []); assert.equal(find(report.capabilities.rules, 'sms.send').appCount, 0);
});

test('strings: only application code contributes, schemes ws/wss/ftp count, impossible IPv4 addresses do not', () => {
  const load = text => method('s' + text.length, [I.constString(0, text)]);
  const report = analyze(withDex([cls('Lcom/evil/app/Main;', ['wss://relay.example/socket', 'ftp://files.example/x', '10.0.0.5:8080', '999.1.1.1', 'http://x', 'plain words'].map(load)),
    cls('Lcom/google/android/gms/Lib;', [load('http://library.example/endpoint')])]));
  assert.deepEqual(report.strings.map(s => [s.text, s.kind]).sort(), [['10.0.0.5:8080', 'ip'], ['ftp://files.example/x', 'url'], ['wss://relay.example/socket', 'url']].sort());
});

test('chain scope ignores library classes: parts spread over application classes stay at app scope', () => {
  const READ = I.invoke('static', { class: 'Landroid/telephony/SmsMessage;', name: 'createFromPdu', params: ['[B'], ret: 'Landroid/telephony/SmsMessage;' }, [0]);
  const NET = I.invoke('virtual', { class: 'Ljava/net/URL;', name: 'openConnection', ret: 'Ljava/net/URLConnection;' }, [0]);
  const report = analyze(withDex([cls('Lcom/evil/app/A;', [method('a', [READ])]), cls('Lcom/evil/app/B;', [method('b', [NET])]), cls('Lcom/google/android/gms/Lib;', [method('c', [READ, NET])])]));
  const chain = report.capabilities.chains.find(c => c.id === 'chain.sms-exfiltration');
  assert.deepEqual([chain.scope, chain.classes, chain.libraryOnly], ['app', [], false]);
});

test('encrypted-looking assets need enough bytes to judge', () => {
  const report = analyze(sampleApk({ entries: [{ name: 'assets/tiny.bin', data: randomBytes(2048), method: 'store' }] }));
  assert.deepEqual(report.highEntropyAssets.map(b => b.name), ['assets/blob.bin']);
});

test('a stub-like shape needs native code; obfuscation is judged on application class names', () => {
  const stub = buildDex({ classes: [cls('Lcom/evil/app/App;', [method('attachBaseContext', [])], 'Landroid/app/Application;')] });
  const noNative = buildZip([{ name: 'AndroidManifest.xml', data: manifest() }, { name: 'classes.dex', data: stub }]);
  assert.equal(find(analyze(noNative).indicators, 'code.stub-like'), undefined);
  const short = analyze(withDex(Array.from({ length: 24 }, (_, i) => cls(`Lx/${String.fromCharCode(97 + i)};`, [method('m', [])]))));
  assert.ok(find(short.indicators, 'code.obfuscated')); assert.equal(short.obfuscation.shortClassRatio, 1);
  const named = analyze(withDex(Array.from({ length: 24 }, (_, i) => cls(`Lcom/evil/app/Feature${i};`, [method('m', [])]))));
  assert.equal(find(named.indicators, 'code.obfuscated'), undefined); assert.equal(named.obfuscation.shortClassRatio, 0);
  const mixed = analyze(withDex([...Array.from({ length: 10 }, (_, i) => cls(`Lx/${String.fromCharCode(97 + i)};`, [method('m', [])])), ...Array.from({ length: 14 }, (_, i) => cls(`Lcom/evil/app/Feature${i};`, [method('m', [])]))]));
  assert.equal(find(mixed.indicators, 'code.obfuscated'), undefined, '42% short names is below the line');
});

test('the deadline is checked inside a large DEX, not only between files', () => {
  let calls = 0;
  const many = withDex(Array.from({ length: 200 }, (_, i) => cls(`Lcom/evil/app/C${i};`, [method('m', [])])));
  const report = analyze(many, { clock: () => (++calls <= 3 ? 0 : 1e12), limits: { deadlineMs: 1000 } });
  assert.ok(report.limitsHit.includes('deadline')); assert.ok(report.dex[0].scanned.classes < 200, 'scan stopped part-way'); assert.ok(report.dex[0].scanned.classes >= 1);
});

test('multi-dex packages are read in numeric order and every v1 signature file type is read', () => {
  const small = n => buildDex({ classes: [cls(`Lcom/evil/app/D${n};`, [method('m', [])])] });
  const report = analyze(sampleApk({ entries: [{ name: 'classes10.dex', data: small(10) }, { name: 'classes2.dex', data: small(2) }, { name: 'META-INF/OTHER.EC', data: pkcs7([releaseCert]) }, { name: 'META-INF/THIRD.DSA', data: pkcs7([debugCert]) }] }));
  assert.deepEqual(report.dex.map(d => d.name), ['classes.dex', 'classes2.dex', 'classes10.dex']);
  assert.deepEqual(report.signatures.v1.map(v => v.file).sort(), ['META-INF/CERT.RSA', 'META-INF/OTHER.EC', 'META-INF/THIRD.DSA']);
});

test('the deadline is also checked inside one very large class', () => {
  let calls = 0;
  const wide = withDex([cls('Lcom/evil/app/Wide;', Array.from({ length: 700 }, (_, i) => method('m' + i, [])))]);
  const report = analyze(wide, { clock: () => (++calls <= 3 ? 0 : 1e12), limits: { deadlineMs: 1000 } });
  assert.ok(report.limitsHit.includes('deadline')); assert.ok(report.dex[0].scanned.methods < 700 && report.dex[0].scanned.methods >= 256, `scanned ${report.dex[0].scanned.methods}`);
});

// ---- cases from running the analyzer over real packages: each one removes a false lead those samples produced ----

test('media and ART profiles are not "encrypted payload candidates"; unknown random data still is', () => {
  const entries = ['assets/voice.aac', 'assets/clip.mkv', 'assets/dexopt/baseline.prof', 'assets/baseline.profm', 'assets/mystery.dat'].map(name => ({ name, data: randomBytes(6000), method: 'store' }));
  const report = analyze(sampleApk({ entries }));
  assert.deepEqual(report.highEntropyAssets.map(b => b.name).sort(), ['assets/blob.bin', 'assets/mystery.dat']);
});

test('XML namespace and schema URLs are not listed as network endpoints', () => {
  const load = text => method('s' + text.length, [I.constString(0, text)]);
  const urls = ['http://schemas.android.com/apk/res/android', 'http://ns.adobe.com/xap/1.0/', 'http://www.w3.org/2001/XMLSchema', 'https://real.example/api'];
  const report = analyze(withDex([cls('Lcom/evil/app/Main;', urls.map(load))]));
  assert.deepEqual(report.strings.map(s => s.text), ['https://real.example/api']);
});

test('the AOSP test-key subject is flagged as a lead, a default backup setting is not', () => {
  const aosp = certificate({ subject: [['2.5.4.6', 'US'], ['2.5.4.8', 'California'], ['2.5.4.7', 'Mountain View'], ['2.5.4.10', 'Android'], ['2.5.4.11', 'Android'], [CN, 'Android'], ['1.2.840.113549.1.9.1', 'android@android.com']], spki: ecSpki('prime256v1') });
  const report = analyze(sampleApk({ entries: [{ name: 'META-INF/PLATFORM.EC', data: pkcs7([aosp]) }] }));
  assert.ok(find(report.indicators, 'signature.aosp-subject')); assert.equal(find(analyze(sampleApk()).indicators, 'signature.aosp-subject'), undefined);
  assert.equal(find(analyze(sampleApk()).indicators, 'app.backup'), undefined, 'unspecified means default; nearly every app');
  assert.ok(find(analyze(sampleApk({ manifest: manifest({ backup: true }) })).indicators, 'app.backup')); assert.equal(find(analyze(sampleApk({ manifest: manifest({ backup: false }) })).indicators, 'app.backup'), undefined);
});
