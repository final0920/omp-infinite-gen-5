import { createHash } from 'node:crypto';

// Minimal, bounded DER reader for APK signing data: PKCS#7 SignedData (META-INF/*.RSA|DSA|EC), APK Signing
// Block signers (v2/v3) and X.509 certificate metadata. It extracts and describes; it does NOT verify signatures
// or chains, so what it reports about a certificate is "what the file says", never "this APK is validly signed".
const fail = (code, message) => { throw Object.assign(new Error(message), { code }); };
// No function here recurses: certificates and containers are walked to fixed depths, so nesting cannot exhaust the stack.
const MAX_CERTIFICATES = 16;
const OID_NAMES = { '2.5.4.3': 'CN', '2.5.4.6': 'C', '2.5.4.7': 'L', '2.5.4.8': 'ST', '2.5.4.10': 'O', '2.5.4.11': 'OU', '2.5.4.5': 'serialNumber',
  '1.2.840.113549.1.9.1': 'emailAddress', '0.9.2342.19200300.100.1.25': 'DC' };
const ALGORITHMS = { '1.2.840.113549.1.1.1': 'rsaEncryption', '1.2.840.10045.2.1': 'id-ecPublicKey', '1.2.840.10040.4.1': 'dsa',
  '1.2.840.113549.1.1.5': 'sha1WithRSAEncryption', '1.2.840.113549.1.1.11': 'sha256WithRSAEncryption', '1.2.840.113549.1.1.12': 'sha384WithRSAEncryption',
  '1.2.840.113549.1.1.13': 'sha512WithRSAEncryption', '1.2.840.113549.1.1.4': 'md5WithRSAEncryption', '1.2.840.10045.4.3.2': 'ecdsa-with-SHA256',
  '1.2.840.10045.4.3.3': 'ecdsa-with-SHA384', '1.2.840.10040.4.3': 'dsa-with-sha1', '2.16.840.1.101.3.4.3.2': 'dsa-with-sha256',
  '1.2.840.10045.3.1.7': 'prime256v1', '1.3.132.0.34': 'secp384r1', '1.3.132.0.35': 'secp521r1' };

export function tlv(buffer, offset = 0) {
  if (offset + 2 > buffer.length) fail('DER_TRUNCATED', 'DER element is truncated');
  const tag = buffer[offset];
  if ((tag & 0x1f) === 0x1f) fail('DER_TAG', 'High-tag-number form is not used by certificates');
  let length = buffer[offset + 1], header = 2;
  if (length === 0x80) fail('DER_INDEFINITE', 'Indefinite-length (BER) encoding is not supported');
  if (length > 0x80) {
    const count = length & 0x7f;
    if (count > 4 || offset + 2 + count > buffer.length) fail('DER_LENGTH', 'Unsupported DER length');
    length = 0;
    for (let i = 0; i < count; i++) length = length * 256 + buffer[offset + 2 + i];
    header += count;
  }
  if (offset + header + length > buffer.length) fail('DER_TRUNCATED', 'DER element extends past its container');
  return { tag, header, length, start: offset + header, end: offset + header + length, offset };
}
function children(buffer, element) {
  const list = [];
  for (let at = element.start; at < element.end;) { const child = tlv(buffer, at); if (child.end > element.end) fail('DER_TRUNCATED', 'Child exceeds parent'); list.push(child); at = child.end; if (list.length > 1024) fail('DER_LIMIT', 'Too many DER children'); }
  return list;
}
const slice = (buffer, element) => buffer.subarray(element.start, element.end);

export function decodeOid(bytes) {
  const parts = [];
  let value = 0;
  for (let i = 0; i < bytes.length; i++) {
    value = value * 128 + (bytes[i] & 0x7f);
    if (!(bytes[i] & 0x80)) { parts.push(value); value = 0; }
  }
  if (!parts.length) return '';
  const first = parts.shift();
  return [Math.min(2, Math.floor(first / 40)), first - 40 * Math.min(2, Math.floor(first / 40)), ...parts].join('.');
}
function decodeString(tag, bytes) {
  if (tag === 0x1e) { const swapped = Buffer.from(bytes); swapped.swap16(); return swapped.toString('utf16le'); }   // BMPString
  return bytes.toString(tag === 0x0c ? 'utf8' : 'latin1');
}
function decodeTime(tag, bytes) {
  const text = bytes.toString('ascii'), match = (tag === 0x17 ? /^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?Z$/ : /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?Z$/).exec(text);
  if (!match) fail('DER_TIME', 'Unsupported certificate time');
  let year = Number(match[1]);
  if (tag === 0x17) year += year >= 50 ? 1900 : 2000;
  return new Date(Date.UTC(year, Number(match[2]) - 1, Number(match[3]), Number(match[4]), Number(match[5]), Number(match[6] || 0))).toISOString();
}
function decodeName(buffer, element) {
  const fields = [];
  for (const set of children(buffer, element)) for (const pair of children(buffer, set)) {
    const [oid, value] = children(buffer, pair);
    const key = OID_NAMES[decodeOid(slice(buffer, oid))] || decodeOid(slice(buffer, oid));
    fields.push([key, decodeString(value.tag, slice(buffer, value))]);
  }
  return { fields: Object.fromEntries(fields), text: fields.map(([k, v]) => `${k}=${v}`).join(', ') };
}
const bitLength = bytes => { let i = 0; while (i < bytes.length && bytes[i] === 0) i++; return i === bytes.length ? 0 : (bytes.length - i) * 8 - Math.clz32(bytes[i]) + 24; };

/** What a DER X.509 certificate says about itself. Signatures are not verified. */
export function describeCertificate(der) {
  const certificate = tlv(der, 0);
  if (certificate.tag !== 0x30) fail('DER_CERT', 'A certificate is a SEQUENCE');
  const tbs = children(der, certificate)[0];
  const parts = children(der, tbs);
  const at = parts[0].tag === 0xa0 ? 1 : 0;
  const [serial, signature, issuer, validity, subject, publicKey] = parts.slice(at, at + 6);
  if (!publicKey) fail('DER_CERT', 'The certificate is missing fields');
  const [notBefore, notAfter] = children(der, validity);
  const [keyAlgorithm, keyBits] = children(der, publicKey);
  const algorithmParts = children(der, keyAlgorithm);
  const keyOid = decodeOid(slice(der, algorithmParts[0]));
  const key = { algorithm: ALGORITHMS[keyOid] || keyOid };
  if (keyOid === '1.2.840.113549.1.1.1') {
    const rsa = slice(der, keyBits).subarray(1);                       // skip the unused-bits byte
    const modulus = children(rsa, tlv(rsa, 0))[0];
    key.bits = bitLength(rsa.subarray(modulus.start, modulus.end));
  } else if (keyOid === '1.2.840.10045.2.1' && algorithmParts[1]?.tag === 0x06) {
    const curve = decodeOid(slice(der, algorithmParts[1]));
    key.curve = ALGORITHMS[curve] || curve;
  }
  const issuerName = decodeName(der, issuer), subjectName = decodeName(der, subject);
  return { sha256: createHash('sha256').update(der).digest('hex'), sha1: createHash('sha1').update(der).digest('hex'),
    serialHex: slice(der, serial).toString('hex').replace(/^(00)+(?=.)/, ''), signatureAlgorithm: ALGORITHMS[decodeOid(slice(der, children(der, signature)[0]))] || decodeOid(slice(der, children(der, signature)[0])),
    issuer: issuerName.text, subject: subjectName.text, subjectFields: subjectName.fields,
    notBefore: decodeTime(notBefore.tag, slice(der, notBefore)), notAfter: decodeTime(notAfter.tag, slice(der, notAfter)),
    selfSigned: issuerName.text === subjectName.text, publicKey: key };
}

/** Certificates (DER) inside a PKCS#7 / CMS SignedData blob, as found in META-INF/*.RSA|DSA|EC. */
export function certificatesFromPkcs7(der) {
  const content = tlv(der, 0);
  if (content.tag !== 0x30) fail('DER_PKCS7', 'ContentInfo is a SEQUENCE');
  const [oid, wrapper] = children(der, content);
  if (decodeOid(slice(der, oid)) !== '1.2.840.113549.1.7.2' || wrapper?.tag !== 0xa0) fail('DER_PKCS7', 'This is not PKCS#7 SignedData');
  const signedData = children(der, children(der, wrapper)[0]);
  const certificates = signedData.find(element => element.tag === 0xa0);
  if (!certificates) return [];
  return children(der, certificates).slice(0, MAX_CERTIFICATES).map(element => der.subarray(element.offset, element.end));
}

const lengthPrefixed = (buffer, at, what) => {
  if (at + 4 > buffer.length) fail('SIGNING_BLOCK', `${what} is truncated`);
  const length = buffer.readUInt32LE(at);
  if (at + 4 + length > buffer.length) fail('SIGNING_BLOCK', `${what} extends past its container`);
  return { start: at + 4, end: at + 4 + length };
};
/** Signer certificates (DER) from the value of an APK Signature Scheme v2 / v3 block. */
export function certificatesFromSigningBlock(value) {
  const signers = lengthPrefixed(value, 0, 'signer sequence'), certificates = [];
  for (let at = signers.start; at < signers.end;) {
    const signer = lengthPrefixed(value, at, 'signer');
    const signedData = lengthPrefixed(value, signer.start, 'signed data');
    const digests = lengthPrefixed(value, signedData.start, 'digests');
    const list = lengthPrefixed(value, digests.end, 'certificates');
    for (let c = list.start; c < list.end;) {
      const cert = lengthPrefixed(value, c, 'certificate');
      if (certificates.length < MAX_CERTIFICATES) certificates.push(value.subarray(cert.start, cert.end));
      c = cert.end;
    }
    at = signer.end;
  }
  return certificates;
}
