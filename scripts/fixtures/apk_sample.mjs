// A minimal generated APK (manifest, one DEX with a single SMS call site, a debug-key v1 signature) shared by the tool-level tests.
import { ANDROID_NS } from '../../source/apk_axml.js';
import { buildAxml, buildZip } from './apk_builder.mjs';
import { CN, certificate, ecSpki, pkcs7 } from './cert_builder.mjs';
import { I, buildDex } from './dex_builder.mjs';

const A = (name, resId, type, value) => ({ name, ns: ANDROID_NS, resId, type, value });
export function minimalApk() {
  const manifest = buildAxml({ name: 'manifest', attrs: [{ name: 'package', type: 'string', value: 'com.example.tool' }], children: [
    { name: 'uses-permission', attrs: [A('name', 0x01010003, 'string', 'android.permission.SEND_SMS')] },
    { name: 'application', attrs: [], children: [{ name: 'activity', attrs: [A('name', 0x01010003, 'string', '.Main'), A('exported', 0x01010010, 'bool', true)], children: [] }] }] }, { resourceMap: true });
  const dex = buildDex({ classes: [{ name: 'Lcom/example/tool/Main;', superclass: 'Ljava/lang/Object;', methods: [{ name: 'go', direct: false, code: { insns: [
    I.invoke('virtual', { class: 'Landroid/telephony/SmsManager;', name: 'sendTextMessage', params: ['Ljava/lang/String;', 'Ljava/lang/String;', 'Ljava/lang/String;'], ret: 'V' }, [0, 1, 2, 3]), I.returnVoid()] } }] }] });
  return buildZip([{ name: 'AndroidManifest.xml', data: manifest }, { name: 'classes.dex', data: dex },
    { name: 'META-INF/CERT.RSA', data: pkcs7([certificate({ subject: [[CN, 'Android Debug']], spki: ecSpki('prime256v1') })]) }]);
}
