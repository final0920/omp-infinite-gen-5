// Android capability rules: the tables are internally consistent, the matchers hit what they should and nothing else,
// and chains are reported at the right scope. The class names in the tables are written from the Android SDK reference;
// there is no machine-checkable copy of the SDK here, so a wrong descriptor would show up as a rule that never fires on real apps.
import assert from 'node:assert/strict';
import test from 'node:test';
import * as R from '../source/apk_rules.js';

const tables = () => ({ API_RULES: structuredClone(R.API_RULES), FIELD_RULES: structuredClone(R.FIELD_RULES), STRING_RULES: R.STRING_RULES.map(r => ({ ...r })), SUPERCLASS_RULES: structuredClone(R.SUPERCLASS_RULES),
  INTERFACE_RULES: structuredClone(R.INTERFACE_RULES), PERMISSIONS: new Map(R.PERMISSIONS), CHAINS: structuredClone(R.CHAINS) });
const problems = mutate => { const t = tables(); mutate(t); try { R.validateRules(t); } catch (error) { return error.message; } return ''; };

test('the shipped tables validate and every category is reachable', () => {
  R.validateRules(tables());
  const used = new Set([...R.API_RULES, ...R.FIELD_RULES, ...R.STRING_RULES, ...R.SUPERCLASS_RULES, ...R.INTERFACE_RULES, ...R.PERMISSIONS.values()].map(rule => rule.category));
  for (const category of Object.keys(R.CATEGORIES)) assert.ok(used.has(category), `category ${category} has no rule that can produce it`);
  const inChains = new Set(R.CHAINS.flatMap(chain => chain.requires.flat()));
  for (const category of inChains) assert.ok(used.has(category), `chain requirement ${category} can never be met`);
});

test('validation catches each kind of table mistake', () => {
  assert.match(problems(t => t.API_RULES.push({ ...t.API_RULES[0] })), /duplicate/);
  assert.match(problems(t => { t.API_RULES[0].category = 'smss'; }), /unknown category smss/);
  assert.match(problems(t => { t.API_RULES[0].cls = 'android/telephony/SmsManager'; }), /bad class/);
  assert.match(problems(t => { t.API_RULES[0].strength = 7; }), /strength 7/);
  assert.match(problems(t => { t.API_RULES[0].names = []; }), /empty names/);
  assert.match(problems(t => { t.API_RULES[0].names = ['send text']; }), /bad name/);
  assert.match(problems(t => { t.API_RULES[0].names = ['a', 'a']; }), /repeated name/);
  assert.match(problems(t => { t.STRING_RULES[0].pattern = /x/g; }), /non-global/);
  assert.match(problems(t => { t.SUPERCLASS_RULES[0].superclass = 'x'; }), /bad superclass/);
  assert.match(problems(t => t.PERMISSIONS.set('android.permission.X', { category: 'sms-send', level: 'huge' })), /level huge/);
  assert.match(problems(t => t.PERMISSIONS.set('android.permission.X', { category: 'nope', level: 'normal' })), /unknown category nope/);
  assert.match(problems(t => { t.CHAINS[0].requires = ['network']; }), /two requirements/);
  assert.match(problems(t => { t.CHAINS[0].requires = ['network', 'nope']; }), /unknown category nope/);
  assert.match(problems(t => t.CHAINS.push({ ...t.CHAINS[0] })), /clashes/);
  assert.equal(problems(() => {}), '');
});

test('framework API calls are matched by class and method name', () => {
  assert.deepEqual(R.classifyApi('Landroid/telephony/SmsManager;', 'sendTextMessage').map(r => r.id), ['sms.send']);
  assert.deepEqual(R.classifyApi('Landroid/telephony/SmsManager;', 'getDefault'), []);
  assert.deepEqual(R.classifyApi('Landroid/app/admin/DevicePolicyManager;', 'lockNow').map(r => r.id), ['admin.policy']);
  assert.deepEqual(R.classifyApi('Ldalvik/system/DexClassLoader;', '<init>').map(r => r.category), ['dynamic-code-loading']);
  assert.deepEqual(R.classifyApi('Lcom/example/SmsManager;', 'sendTextMessage'), [], 'same simple name in another package');
  assert.deepEqual(R.classifyApi('Landroid/telephony/SmsManager;', 'SendTextMessage'), [], 'names are case sensitive');
  assert.deepEqual(R.classifyApi('Landroid/net/VpnService$Builder;', 'addAddress').map(r => r.id), ['vpn.service'], 'prefix rules reach nested classes');
  assert.deepEqual(R.classifyApi('Landroid/net/VpnServices;', 'x').map(r => r.id), ['vpn.service'], 'documented: a prefix rule is a plain string prefix');
  assert.deepEqual(R.classifyApi('Ljava/lang/Runtime;', 'exec').map(r => r.id), ['exec.runtime']);
  assert.deepEqual(R.classifyApi('Ljava/lang/Runtime;', 'loadLibrary').map(r => r.id), ['native.runtime']);
});

test('field reads, strings, base classes and interfaces', () => {
  assert.deepEqual(R.classifyField('Landroid/os/Build;', 'MODEL').map(r => r.id), ['build.model']);
  assert.deepEqual(R.classifyField('Landroid/os/Build;', 'SERIAL'), []); assert.deepEqual(R.classifyField('Landroid/os/Build$VERSION;', 'SDK_INT'), []);
  assert.deepEqual(R.classifyString('content://sms/inbox').map(r => r.id), ['str.sms-uri']);
  assert.deepEqual(R.classifyString('content://smsx'), []);
  assert.ok(R.classifyString('/system/xbin/su').some(r => r.id === 'str.su')); assert.deepEqual(R.classifyString('sushi'), []); assert.deepEqual(R.classifyString('result'), []);
  assert.deepEqual(R.classifyString('https://api.telegram.org/bot123456:ABC/sendMessage').map(r => r.id), ['str.telegram-bot']);
  assert.deepEqual(R.classifyString('/proc/self/status').map(r => r.category), ['anti-debug']);
  assert.deepEqual(R.classifyString('x'.repeat(600) + 'TracerPid'), [], 'oversized strings are not scanned'); assert.deepEqual(R.classifyString(''), []); assert.deepEqual(R.classifyString(null), []);
  for (let i = 0; i < 3; i++) assert.equal(R.classifyString('TracerPid:\t0').length, 1, 'no regex state leaks between calls');
  assert.deepEqual(R.classifySuperclass('Landroid/accessibilityservice/AccessibilityService;').map(r => r.category), ['accessibility']); assert.deepEqual(R.classifySuperclass('Landroid/app/Service;'), []);
  assert.deepEqual(R.classifyInterface('Ljavax/net/ssl/X509TrustManager;').map(r => r.category), ['tls-weakening']);
});

test('permissions: known, unlisted platform permissions and custom ones are told apart', () => {
  assert.deepEqual(R.classifyPermission('android.permission.READ_SMS'), { name: 'android.permission.READ_SMS', category: 'sms-read', level: 'dangerous', note: undefined, known: true });
  assert.deepEqual(R.classifyPermission('android.permission.SOMETHING_NEW'), { name: 'android.permission.SOMETHING_NEW', category: null, level: 'unlisted', note: null, known: false });
  assert.equal(R.classifyPermission('com.vendor.permission.PUSH').level, 'custom');
});

test('chains: app scope, class scope, alternatives, and no match on a partial set', () => {
  const ids = result => result.map(c => c.id).sort();
  assert.deepEqual(R.evaluateChains(new Set(['network'])), []);
  assert.deepEqual(ids(R.evaluateChains(new Set(['sms-read', 'network']))), ['chain.sms-exfiltration']);
  const app = R.evaluateChains(new Set(['sms-read', 'network']), [['A', new Set(['sms-read'])], ['B', new Set(['network'])]]);
  assert.equal(app[0].scope, 'app'); assert.deepEqual(app[0].classes, []);
  const same = R.evaluateChains(new Set(['sms-read', 'network']), [['A', new Set(['sms-read', 'network'])], ['B', new Set(['network'])]]);
  assert.equal(same[0].scope, 'class'); assert.deepEqual(same[0].classes, ['A']); assert.equal(same[0].classCount, 1);
  assert.deepEqual(ids(R.evaluateChains(new Set(['anti-debug', 'reflection']))), ['chain.evasion'], 'one category from each group is enough');
  assert.deepEqual(ids(R.evaluateChains(new Set(['anti-debug', 'emulator-detection']))), [], 'both from the same group is not');
  const many = R.evaluateChains(new Set(['sms-read', 'network']), Array.from({ length: 50 }, (_, i) => [`C${i}`, new Set(['sms-read', 'network'])]));
  assert.equal(many[0].classes.length, 20); assert.equal(many[0].classCount, 50);
});
