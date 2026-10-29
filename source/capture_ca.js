import fs from 'node:fs';
import path from 'node:path';
import net from 'node:net';
import { generateKeyPairSync, randomBytes, sign, X509Certificate, createPrivateKey, createPublicKey } from 'node:crypto';

// Minimal X.509 v3 encoder for a local EC P-256 capture CA. No shell, openssl,
// system trust changes or bundled private keys. TLS remains opt-in per session.
const der = (tag, ...values) => {
  const body = Buffer.concat(values.map(v => Buffer.isBuffer(v) ? v : Buffer.from(v)));
  let length = body.length;
  const bytes = [];
  do { bytes.unshift(length & 255); length = Math.floor(length / 256); } while (length);
  return Buffer.concat([Buffer.from([tag, ...(body.length < 128 ? [body.length] : [128 | bytes.length, ...bytes])]), body]);
};
const seq = (...xs) => der(0x30, ...xs);
const oid = hex => der(6, Buffer.from(hex, 'hex'));
const algorithm = seq(oid('2a8648ce3d040302')); // ecdsa-with-SHA256
const name = value => seq(der(0x31, seq(oid('550403'), der(0x0c, Buffer.from(value, 'utf8')))));
const pem = (label, bytes) => `-----BEGIN ${label}-----\n${bytes.toString('base64').match(/.{1,64}/g).join('\n')}\n-----END ${label}-----\n`;
const time = date => der(0x18, Buffer.from(date.toISOString().replace(/[-:]/g, '').replace(/\.\d+Z$/, 'Z').replace('T', '')));
const extension = (id, value, critical = false) => seq(oid(id), ...(critical ? [der(1, [255])] : []), der(4, value));
function issueCertificate(publicKey, issuerKey, issuer, subject, ca, host) {
  const serial = randomBytes(16); serial[0] &= 0x7f; serial[0] |= 1;
  const now = Date.now();
  const extensions = [extension('551d13', ca ? seq(der(1, [255])) : seq(), true),
    extension('551d0f', der(3, ca ? [1, 6] : [7, 128]), true)];
  if (!ca) {
    const ip = net.isIP(host);
    if (ip === 6) throw new Error('TLS capture certificates currently require a DNS name or IPv4 address');
    extensions.push(extension('551d25', seq(oid('2b06010505070301'))));
    extensions.push(extension('551d11', seq(ip ? der(0x87, host.split('.').map(Number)) : der(0x82, Buffer.from(host)))));
  }
  const tbs = seq(der(0xa0, der(2, [2])), der(2, serial), algorithm, name(issuer),
    seq(time(new Date(now - 300000)), time(new Date(now + (ca ? 365 : 7) * 86400000))),
    name(subject), publicKey.export({ type: 'spki', format: 'der' }), der(0xa3, seq(...extensions)));
  return pem('CERTIFICATE', seq(tbs, algorithm, der(3, Buffer.from([0]), sign('sha256', tbs, issuerKey))));
}
const pair = () => generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
function regular(filename) {
  const st = fs.lstatSync(filename);
  if (!st.isFile() || st.isSymbolicLink() || st.size > 16384) throw new Error('Invalid capture CA file');
}
export function createCaptureCA(root) {
  root = path.resolve(root);
  fs.mkdirSync(root, { recursive: true, mode: 0o700 });
  const dir = fs.lstatSync(root);
  if (!dir.isDirectory() || dir.isSymbolicLink()) throw new Error('Capture CA directory must be a real directory');
  const certificatePath = path.join(root, 'capture-ca.pem'), keyPath = path.join(root, 'capture-ca-key.pem');
  const issuer = 'IG5 Local Capture CA';
  let key, certificate;
  if (fs.existsSync(keyPath) || fs.existsSync(certificatePath)) {
    regular(keyPath); regular(certificatePath);
    key = createPrivateKey(fs.readFileSync(keyPath)); certificate = fs.readFileSync(certificatePath, 'utf8');
  } else {
    const keys = pair(); key = keys.privateKey;
    certificate = issueCertificate(keys.publicKey, key, issuer, issuer, true);
    fs.writeFileSync(keyPath, key.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600, flag: 'wx' });
    fs.writeFileSync(certificatePath, certificate, { mode: 0o600, flag: 'wx' });
  }
  const parsed = new X509Certificate(certificate);
  if (!parsed.ca || !parsed.verify(createPublicKey(key)) || parsed.subject !== 'CN=' + issuer || Date.parse(parsed.validTo) <= Date.now()) throw new Error('Capture CA is invalid, expired or does not match its key');
  const cache = new Map();
  return {
    certificatePath, fingerprint256: parsed.fingerprint256, certificate,
    issue(host) {
      if (typeof host !== 'string' || host.length > 253 || !/^[a-zA-Z0-9.-]+$/.test(host) || host.includes('..')) throw new Error('Invalid capture certificate hostname');
      host = host.toLowerCase();
      if (cache.has(host)) return cache.get(host);
      const keys = pair();
      const result = { key: keys.privateKey.export({ type: 'pkcs8', format: 'pem' }),
        cert: issueCertificate(keys.publicKey, key, issuer, host, false, host), ca: certificate };
      if (cache.size >= 64) cache.delete(cache.keys().next().value);
      cache.set(host, result); return result;
    },
  };
}
