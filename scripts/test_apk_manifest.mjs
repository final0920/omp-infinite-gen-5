// Manifest reader: identity, SDK levels, permissions, and above all the effective exposure of each component under the
// platform's default rules. Inputs are built with the test AXML writer.
import assert from 'node:assert/strict';
import test from 'node:test';
import { ANDROID_NS } from '../source/apk_axml.js';
import { MANIFEST_LIMITS, parseManifest, qualify } from '../source/apk_manifest.js';
import { buildAxml } from './fixtures/apk_builder.mjs';

const A = (name, resId, type, value) => ({ name, ns: ANDROID_NS, resId, type, value });
const NAME = (value) => A('name', 0x01010003, 'string', value), EXPORTED = value => A('exported', 0x01010010, 'bool', value), ENABLED = value => A('enabled', 0x0101000e, 'bool', value);
const el = (name, attrs = [], children = []) => ({ name, attrs, children });
const filter = (actions, categories = [], data = [], priority) => el('intent-filter', priority === undefined ? [] : [A('priority', 0x0101001c, 'int', priority)], [
  ...actions.map(a => el('action', [NAME(a)])), ...categories.map(c => el('category', [NAME(c)])), ...data.map(d => el('data', Object.entries(d).map(([k, v]) => A(k, 0, 'string', v))))]);
const manifest = ({ pkg = 'com.example.app', sdk = [A('minSdkVersion', 0x0101020c, 'int', 21), A('targetSdkVersion', 0x01010270, 'int', 30)], appAttrs = [], app = [], extra = [] } = {}) => buildAxml(
  el('manifest', [...(pkg ? [{ name: 'package', type: 'string', value: pkg }] : []), A('versionCode', 0x0101021b, 'int', 42), A('versionName', 0x0101021c, 'string', '1.2.3')],
    [...(sdk ? [el('uses-sdk', sdk)] : []), ...extra, el('application', appAttrs, app)]), { resourceMap: true });
const MAIN = filter(['android.intent.action.MAIN'], ['android.intent.category.LAUNCHER']);
const by = (parsed, name) => parsed.components.find(c => c.name === name);

test('identity, sdk levels, permissions and application flags', () => {
  const parsed = parseManifest(manifest({
    extra: [el('uses-permission', [NAME('android.permission.INTERNET')]), el('uses-permission', [NAME('android.permission.WRITE_EXTERNAL_STORAGE'), A('maxSdkVersion', 0x01010271, 'int', 28)]),
      el('uses-permission-sdk-23', [NAME('android.permission.CAMERA')]), el('permission', [NAME('com.example.PRIVATE'), A('protectionLevel', 0x01010009, 'int', 2)]),
      el('uses-feature', [NAME('android.hardware.camera'), A('required', 0x0101028e, 'bool', false)])],
    appAttrs: [NAME('.App'), A('debuggable', 0x0101000f, 'bool', true), A('allowBackup', 0x01010280, 'bool', false), A('usesCleartextTraffic', 0x010104ec, 'bool', true)],
    app: [el('activity', [NAME('.Main')], [MAIN]), el('meta-data', [NAME('channel'), A('value', 0x01010024, 'string', 'official')])] }));
  assert.equal(parsed.package, 'com.example.app'); assert.equal(parsed.versionCode, 42); assert.equal(parsed.versionName, '1.2.3'); assert.deepEqual(parsed.sdk, { min: 21, target: 30, max: null });
  assert.deepEqual(parsed.permissions.map(p => [p.name, p.tag, p.maxSdk]), [['android.permission.INTERNET', 'uses-permission', null], ['android.permission.WRITE_EXTERNAL_STORAGE', 'uses-permission', 28], ['android.permission.CAMERA', 'uses-permission-sdk-23', null]]);
  assert.deepEqual(parsed.declaredPermissions, [{ name: 'com.example.PRIVATE', protectionLevel: 2 }]); assert.deepEqual(parsed.features, [{ name: 'android.hardware.camera', required: false }]);
  assert.deepEqual([parsed.application.name, parsed.application.debuggable, parsed.application.allowBackup, parsed.application.usesCleartextTraffic], ['com.example.app.App', true, false, true]);
  assert.deepEqual(parsed.metaData, [{ name: 'channel', value: 'official' }]); assert.deepEqual(parsed.anomalies, []);
});

test('qualify() resolves relative component names', () => {
  assert.equal(qualify('.Main', 'a.b'), 'a.b.Main'); assert.equal(qualify('Main', 'a.b'), 'a.b.Main'); assert.equal(qualify('x.y.Main', 'a.b'), 'x.y.Main'); assert.equal(qualify('Main', null), 'Main'); assert.equal(qualify(null, 'a.b'), null);
});

test('exposure: explicit value wins, otherwise intent filters decide (components) or the target SDK decides (providers)', () => {
  const app = [
    el('activity', [NAME('.Plain')]), el('activity', [NAME('.Filtered')], [filter(['x.ACTION'])]), el('activity', [NAME('.FilteredButPrivate'), EXPORTED(false)], [filter(['x.ACTION'])]),
    el('service', [NAME('.Open'), EXPORTED(true)]), el('receiver', [NAME('.Boot')], [filter(['android.intent.action.BOOT_COMPLETED'])]), el('provider', [NAME('.Store'), A('authorities', 0x01010018, 'string', 'com.example.store')]),
    el('provider', [NAME('.Shared'), EXPORTED(true), A('grantUriPermissions', 0x0101001b, 'bool', true)]), el('activity-alias', [NAME('.Alias'), A('targetActivity', 0, 'string', '.Plain')])];
  const modern = parseManifest(manifest({ app }));
  assert.deepEqual(['.Plain', '.Filtered', '.FilteredButPrivate', '.Open', '.Boot', '.Store', '.Shared', '.Alias'].map(n => by(modern, 'com.example.app' + n).exported), [false, true, false, true, true, false, true, false]);
  assert.equal(by(modern, 'com.example.app.Store').authorities, 'com.example.store'); assert.equal(by(modern, 'com.example.app.Shared').grantUriPermissions, true);
  assert.equal(by(modern, 'com.example.app.Alias').targetActivity, 'com.example.app.Plain'); assert.equal(by(modern, 'com.example.app.Plain').exportedExplicit, false); assert.equal(by(modern, 'com.example.app.Open').exportedExplicit, true);
  const old = parseManifest(manifest({ sdk: [A('targetSdkVersion', 0x01010270, 'int', 10)], app }));
  assert.equal(by(old, 'com.example.app.Store').exported, true, 'content providers were exported by default before API 17');
  const none = parseManifest(manifest({ sdk: null, app })); assert.equal(by(none, 'com.example.app.Store').exported, true, 'no uses-sdk behaves as an ancient target');
  assert.ok(none.anomalies.some(a => a.code === 'missing-uses-sdk'));
});

test('a filtered component without android:exported on a modern target is reported (Android 12+ refuses to install it)', () => {
  const parsed = parseManifest(manifest({ sdk: [A('targetSdkVersion', 0x01010270, 'int', 33)], app: [el('activity', [NAME('.A')], [MAIN]), el('activity', [NAME('.B'), EXPORTED(true)], [MAIN])] }));
  assert.deepEqual(parsed.anomalies.filter(a => a.code === 'exported-missing-with-filter').map(a => a.name), ['com.example.app.A']);
  assert.equal(parseManifest(manifest({ app: [el('activity', [NAME('.A')], [MAIN])] })).anomalies.some(a => a.code === 'exported-missing-with-filter'), false, 'API 30 is fine');
});

test('intent filters: actions, categories, data, priority and launcher detection', () => {
  const parsed = parseManifest(manifest({ app: [
    el('activity', [NAME('.Main')], [MAIN, filter(['android.intent.action.VIEW'], ['android.intent.category.DEFAULT', 'android.intent.category.BROWSABLE'], [{ scheme: 'https', host: 'example.com', pathPrefix: '/app' }])]),
    el('receiver', [NAME('.Sms')], [filter(['android.provider.Telephony.SMS_RECEIVED'], [], [], 2147483647)])] }));
  const main = by(parsed, 'com.example.app.Main'), sms = by(parsed, 'com.example.app.Sms');
  assert.equal(main.launcher, true); assert.equal(sms.launcher, false);
  assert.deepEqual(main.intentFilters[1], { actions: ['android.intent.action.VIEW'], categories: ['android.intent.category.DEFAULT', 'android.intent.category.BROWSABLE'], data: [{ scheme: 'https', host: 'example.com', pathPrefix: '/app' }], priority: null });
  assert.equal(sms.priority, 2147483647); assert.ok(parsed.anomalies.some(a => a.code === 'high-priority-filter' && a.first === 'com.example.app.Sms'));
});

test('structural anomalies: no launcher, disabled launcher, duplicate names, bad package, wrong root', () => {
  const codes = parsed => parsed.anomalies.map(a => a.code);
  assert.ok(codes(parseManifest(manifest({ app: [el('activity', [NAME('.A')])] }))).includes('no-launcher-activity'));
  assert.ok(codes(parseManifest(manifest({ app: [el('activity', [NAME('.A'), ENABLED(false)], [MAIN])] }))).includes('disabled-launcher'));
  assert.ok(codes(parseManifest(manifest({ app: [el('service', [NAME('.S')]), el('service', [NAME('.S')]), el('activity', [NAME('.A')], [MAIN])] }))).includes('duplicate-component'));
  assert.ok(codes(parseManifest(manifest({ app: [el('service', [])] }))).includes('component-without-name'));
  assert.ok(codes(parseManifest(manifest({ extra: [el('uses-permission', [NAME('p.A')]), el('uses-permission', [NAME('p.A')]), el('uses-permission', [])] }))).includes('duplicate-permission'));
  assert.ok(codes(parseManifest(manifest({ extra: [el('uses-permission', [])] }))).includes('permission-without-name'));
  assert.ok(codes(parseManifest(manifest({ pkg: null }))).includes('missing-package'));
  assert.ok(codes(parseManifest(manifest({ pkg: 'not a package' }))).includes('unusual-package-name'));
  assert.ok(codes(parseManifest(buildAxml(el('resources')))).includes('root-not-manifest'));
  assert.ok(codes(parseManifest(buildAxml(el('manifest', [{ name: 'package', type: 'string', value: 'a.b' }])))).includes('missing-application'));
});

test('attribute names come from resource ids, so a renamed string cannot hide a flag', () => {
  const obfuscated = buildAxml(el('manifest', [{ name: 'package', type: 'string', value: 'com.example.app' }], [el('application', [], [
    el('service', [{ name: 'q', ns: ANDROID_NS, resId: 0x01010003, type: 'string', value: '.Hidden' }, { name: 'zz', ns: ANDROID_NS, resId: 0x01010010, type: 'bool', value: true }])])]), { resourceMap: true });
  const parsed = parseManifest(obfuscated), service = by(parsed, 'com.example.app.Hidden');
  assert.ok(service, 'name read through its resource id'); assert.equal(service.exported, true); assert.equal(service.exportedExplicit, true);
  assert.ok(parsed.anomalies.some(a => a.source === 'axml' && a.code === 'attribute-name-mismatch'), 'and the rename is reported');
});

test('a boolean written as text is not mistaken for an explicit value', () => {
  const parsed = parseManifest(manifest({ app: [el('service', [NAME('.S'), { name: 'exported', ns: ANDROID_NS, resId: 0x01010010, type: 'string', value: 'true' }])] }));
  assert.equal(by(parsed, 'com.example.app.S').exportedExplicit, false); assert.equal(by(parsed, 'com.example.app.S').exported, false);
});

test('budgets: components, filters and long text are bounded', () => {
  const many = parseManifest(manifest({ app: Array.from({ length: 10 }, (_, i) => el('service', [NAME('.S' + i)])) }), { components: 3 });
  assert.equal(many.components.length, 3); assert.ok(many.anomalies.some(a => a.code === 'component-limit'));
  const filters = parseManifest(manifest({ app: [el('activity', [NAME('.A')], Array.from({ length: 10 }, () => filter(['x'])))] }), { filters: 4 });
  assert.equal(filters.components[0].intentFilters.length, 4); assert.ok(filters.anomalies.some(a => a.code === 'many-intent-filters'));
  const long = parseManifest(manifest({ app: [el('service', [NAME('.' + 'x'.repeat(5000))])] }));
  assert.ok(long.components[0].name.length <= MANIFEST_LIMITS.text + 16);
  assert.throws(() => parseManifest(Buffer.from('not axml')), error => error.code === 'AXML_FORMAT');
});

test('boundaries: provider default flips at API 17, the missing-exported check starts at API 31, launcher needs both MAIN and LAUNCHER, priority 1000 is the alert line', () => {
  const sdk = target => [A('targetSdkVersion', 0x01010270, 'int', target)];
  const provider = target => by(parseManifest(manifest({ sdk: sdk(target), app: [el('provider', [NAME('.P')])] })), 'com.example.app.P').exported;
  assert.deepEqual([provider(16), provider(17)], [true, false]);
  const flagged = target => parseManifest(manifest({ sdk: sdk(target), app: [el('activity', [NAME('.A')], [MAIN])] })).anomalies.some(a => a.code === 'exported-missing-with-filter');
  assert.deepEqual([flagged(30), flagged(31)], [false, true]);
  const launcher = (actions, categories) => by(parseManifest(manifest({ app: [el('activity', [NAME('.A')], [filter(actions, categories)])] })), 'com.example.app.A').launcher;
  assert.deepEqual([launcher(['android.intent.action.MAIN'], []), launcher([], ['android.intent.category.LAUNCHER']), launcher(['android.intent.action.MAIN'], ['android.intent.category.LAUNCHER'])], [false, false, true]);
  const alert = priority => parseManifest(manifest({ app: [el('receiver', [NAME('.R')], [filter(['x'], [], [], priority)])] })).anomalies.some(a => a.code === 'high-priority-filter');
  assert.deepEqual([alert(999), alert(1000)], [false, true]);
});
