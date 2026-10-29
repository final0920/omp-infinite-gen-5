// Test-side DER writers: certificates, PKCS#7 SignedData wrappers and APK Signature Scheme v2/v3 block values. Inert bytes only.
import { generateKeyPairSync, randomBytes } from 'node:crypto';


export const length = n => (n < 128 ? Buffer.from([n]) : n < 256 ? Buffer.from([0x81, n]) : n < 65536 ? Buffer.from([0x82, n >> 8, n & 255]) : Buffer.from([0x83, n >> 16, (n >> 8) & 255, n & 255]));
export const der = (tag, ...parts) => { const body = Buffer.concat(parts); return Buffer.concat([Buffer.from([tag]), length(body.length), body]); };
export const seq = (...p) => der(0x30, ...p), set = (...p) => der(0x31, ...p);
export const oid = text => { const n = text.split('.').map(Number); const out = [n[0] * 40 + n[1]]; for (const part of n.slice(2)) { const bytes = [part & 127]; for (let v = part >> 7; v; v >>= 7) bytes.unshift((v & 127) | 128); out.push(...bytes); } return der(0x06, Buffer.from(out)); };
export const utf8 = s => der(0x0c, Buffer.from(s, 'utf8'));
export const name = fields => seq(...fields.map(([k, v, tag]) => set(seq(oid(k), tag === 'bmp' ? der(0x1e, Buffer.from(v, 'utf16le').swap16()) : utf8(v)))));
export const time = date => { const d = new Date(date), p = n => String(n).padStart(2, '0'); return d.getUTCFullYear() >= 2050
  ? der(0x18, Buffer.from(`${d.getUTCFullYear()}${p(d.getUTCMonth() + 1)}${p(d.getUTCDate())}${p(d.getUTCHours())}${p(d.getUTCMinutes())}${p(d.getUTCSeconds())}Z`))
  : der(0x17, Buffer.from(`${p(d.getUTCFullYear() % 100)}${p(d.getUTCMonth() + 1)}${p(d.getUTCDate())}${p(d.getUTCHours())}${p(d.getUTCMinutes())}${p(d.getUTCSeconds())}Z`)); };
export const CN = '2.5.4.3', O = '2.5.4.10', C = '2.5.4.6';
// A positive INTEGER in minimal DER form: the first byte is 1..0x7f, so no 0x00 pad is needed (OpenSSL rejects a non-minimal one).
export const validSerial = () => Buffer.concat([Buffer.from([1 + (randomBytes(1)[0] % 127)]), randomBytes(7)]);
export function certificate({ subject, issuer = subject, serial = validSerial(), notBefore = '2024-01-02T03:04:05Z', notAfter = '2049-12-31T23:59:59Z', spki, signature = '1.2.840.113549.1.1.11' }) {
  // RSA signature algorithms carry an explicit NULL parameter; ECDSA ones must omit it.
  const algorithm = seq(oid(signature), ...(signature.startsWith('1.2.840.113549.1.1.') ? [der(0x05, Buffer.alloc(0))] : []));
  const tbs = seq(der(0xa0, der(0x02, Buffer.from([2]))), der(0x02, serial), algorithm,
    name(issuer), seq(time(notBefore), time(notAfter)), name(subject), spki);
  return seq(tbs, algorithm, der(0x03, Buffer.concat([Buffer.from([0]), randomBytes(32)])));
}
export const rsaSpki = bits => generateKeyPairSync('rsa', { modulusLength: bits }).publicKey.export({ type: 'spki', format: 'der' });
export const lp = (...parts) => { const body = Buffer.concat(parts); const out = Buffer.alloc(4 + body.length); out.writeUInt32LE(body.length); body.copy(out, 4); return out; };;
/** PKCS#7 SignedData holding `certs` (what META-INF/*.RSA contains, minus the signer info we do not parse). */
export const pkcs7 = certs => seq(oid('1.2.840.113549.1.7.2'), der(0xa0, seq(der(0x02, Buffer.from([1])), set(), seq(oid('1.2.840.113549.1.7.1')), der(0xa0, ...certs), set())));
/** Value of an APK Signature Scheme v2/v3 pair: one signer per certificate. */
export const signerBlockValue = certs => lp(...certs.map(cert => lp(lp(lp(lp(Buffer.from('digest-record'))), lp(lp(cert))), lp(Buffer.from('signatures')), lp(Buffer.from('public key')))));
export const ecSpki = curve => generateKeyPairSync('ec', { namedCurve: curve }).publicKey.export({ type: 'spki', format: 'der' });
