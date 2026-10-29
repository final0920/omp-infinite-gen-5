// DER / X.509 / PKCS#7 / signing-block extraction. Certificates are generated here and cross-checked against Node's own X509Certificate.
import assert from 'node:assert/strict';
import { X509Certificate, createHash, generateKeyPairSync, randomBytes } from 'node:crypto';
import test from 'node:test';
import { certificatesFromPkcs7, certificatesFromSigningBlock, decodeOid, describeCertificate, tlv } from '../source/apk_der.js';
import { CN, O, C, certificate, der, ecSpki, lp, name, oid, rsaSpki, seq, set, time, utf8, validSerial } from './fixtures/cert_builder.mjs';
const codeOf = fn => { try { fn(); } catch (error) { return error.code; } return 'NO-ERROR'; };

test('an RSA certificate is described exactly as Node reads it', () => {
  const cert = certificate({ subject: [[CN, 'Example Dev'], [O, 'Example Org'], [C, 'XX']], spki: rsaSpki(2048), notBefore: '2023-05-06T07:08:09Z' });
  const ours = describeCertificate(cert), node = new X509Certificate(cert);
  assert.equal(ours.sha256, node.fingerprint256.replace(/:/g, '').toLowerCase());
  assert.equal(ours.serialHex.toUpperCase().replace(/^0+/, ''), node.serialNumber.replace(/^0+/, ''));
  assert.equal(Date.parse(ours.notBefore), Date.parse(node.validFrom)); assert.equal(Date.parse(ours.notAfter), Date.parse(node.validTo));
  assert.equal(ours.subject, 'CN=Example Dev, O=Example Org, C=XX');
  assert.deepEqual(node.subject.split('\n').sort(), ['C=XX', 'CN=Example Dev', 'O=Example Org']);
  assert.equal(ours.subjectFields.CN, 'Example Dev'); assert.equal(ours.selfSigned, true);
  assert.deepEqual(ours.publicKey, { algorithm: 'rsaEncryption', bits: node.publicKey.asymmetricKeyDetails.modulusLength });
  assert.equal(ours.publicKey.bits, 2048); assert.equal(ours.signatureAlgorithm, 'sha256WithRSAEncryption');
});

test('RSA key sizes are measured from the modulus, not assumed', () => {
  for (const bits of [1024, 3072]) assert.equal(describeCertificate(certificate({ subject: [[CN, 'k']], spki: rsaSpki(bits) })).publicKey.bits, bits);
});

test('an EC certificate reports its curve, and an issuer different from the subject is not self-signed', () => {
  const cert = certificate({ subject: [[CN, 'Leaf']], issuer: [[CN, 'Some CA'], [O, 'CA Org']], spki: ecSpki('prime256v1'), signature: '1.2.840.10045.4.3.2' });
  const ours = describeCertificate(cert), node = new X509Certificate(cert);
  assert.deepEqual(ours.publicKey, { algorithm: 'id-ecPublicKey', curve: 'prime256v1' }); assert.equal(node.publicKey.asymmetricKeyDetails.namedCurve, 'prime256v1');
  assert.equal(ours.selfSigned, false); assert.equal(ours.issuer, 'CN=Some CA, O=CA Org'); assert.equal(ours.signatureAlgorithm, 'ecdsa-with-SHA256');
});

test('GeneralizedTime (years from 2050) and BMPString names are decoded', () => {
  const cert = certificate({ subject: [[CN, '中文名称', 'bmp']], spki: ecSpki('secp384r1'), notAfter: '2077-08-09T10:11:12Z' });
  const ours = describeCertificate(cert);
  assert.equal(ours.notAfter, '2077-08-09T10:11:12.000Z'); assert.equal(ours.subjectFields.CN, '中文名称');
  assert.equal(ours.publicKey.curve, 'secp384r1');
});

test('the 128-bit and 256-bit fingerprints are over the exact DER bytes', () => {
  const cert = certificate({ subject: [[CN, 'f']], spki: ecSpki('prime256v1') });
  const ours = describeCertificate(cert);
  assert.equal(ours.sha256, createHash('sha256').update(cert).digest('hex')); assert.equal(ours.sha1, createHash('sha1').update(cert).digest('hex'));
});

test('certificates are extracted from a PKCS#7 SignedData container, in order', () => {
  const a = certificate({ subject: [[CN, 'First']], spki: ecSpki('prime256v1') }), b = certificate({ subject: [[CN, 'Second']], spki: ecSpki('prime256v1') });
  const signedData = seq(der(0x02, Buffer.from([1])), set(), seq(oid('1.2.840.113549.1.7.1')), der(0xa0, a, b), set());
  const pkcs7 = seq(oid('1.2.840.113549.1.7.2'), der(0xa0, signedData));
  const found = certificatesFromPkcs7(pkcs7);
  assert.deepEqual(found.map(c => describeCertificate(c).subjectFields.CN), ['First', 'Second']);
  assert(found[0].equals(a) && found[1].equals(b), 'bytes are returned unchanged so the fingerprint stays valid');
  assert.deepEqual(certificatesFromPkcs7(seq(oid('1.2.840.113549.1.7.2'), der(0xa0, seq(der(0x02, Buffer.from([1])), set(), seq(oid('1.2.840.113549.1.7.1')), set())))), []);
  assert.equal(codeOf(() => certificatesFromPkcs7(seq(oid('1.2.840.113549.1.7.1'), der(0xa0, seq())))), 'DER_PKCS7');
});

test('signer certificates come out of an APK Signature Scheme v2/v3 block value, ignoring the other fields', () => {
  const a = certificate({ subject: [[CN, 'Signer A']], spki: ecSpki('prime256v1') }), b = certificate({ subject: [[CN, 'Signer B']], spki: ecSpki('prime256v1') });
  const signer = (cert, extra = Buffer.alloc(0)) => lp(lp(lp(lp(Buffer.from('digest-record'))), lp(lp(cert)), extra), lp(Buffer.from('signatures')), lp(Buffer.from('public key')));
  const v2 = lp(signer(a), signer(b));
  assert.deepEqual(certificatesFromSigningBlock(v2).map(c => describeCertificate(c).subjectFields.CN), ['Signer A', 'Signer B']);
  const v3 = lp(signer(a, Buffer.concat([Buffer.from([24, 0, 0, 0, 255, 255, 255, 127]), lp(Buffer.from('attributes'))])));
  assert.equal(certificatesFromSigningBlock(v3).length, 1, 'the v3 min/max SDK fields after the certificates do not matter');
  assert.equal(codeOf(() => certificatesFromSigningBlock(lp(lp(Buffer.alloc(10, 1))))), 'SIGNING_BLOCK');
  assert.equal(codeOf(() => certificatesFromSigningBlock(Buffer.from([255, 255, 255, 127]))), 'SIGNING_BLOCK');
});

test('malformed DER is refused with a code, never read past its container', () => {
  const good = certificate({ subject: [[CN, 'x']], spki: ecSpki('prime256v1') });
  assert.equal(codeOf(() => describeCertificate(good.subarray(0, good.length - 40))), 'DER_TRUNCATED');
  assert.equal(codeOf(() => tlv(Buffer.from([0x30, 0x80, 0, 0]))), 'DER_INDEFINITE');
  assert.equal(codeOf(() => tlv(Buffer.from([0x1f, 0x01, 0x00]))), 'DER_TAG');
  assert.equal(codeOf(() => tlv(Buffer.from([0x30, 0x85, 1, 2, 3, 4, 5]))), 'DER_LENGTH');
  assert.equal(codeOf(() => tlv(Buffer.from([0x30, 0x04, 1]))), 'DER_TRUNCATED');
  assert.equal(codeOf(() => describeCertificate(Buffer.from([0x02, 0x01, 0x05]))), 'DER_CERT');
  assert.equal(codeOf(() => describeCertificate(seq(seq(der(0x02, Buffer.from([1])))))), 'DER_CERT');
  let nested = der(0x02, Buffer.from([1])); for (let i = 0; i < 30; i++) nested = seq(nested);
  assert.notEqual(codeOf(() => describeCertificate(nested)), 'NO-ERROR');
});

test('object identifiers are decoded, including multi-byte arcs', () => {
  assert.equal(decodeOid(Buffer.from('2a864886f70d010101', 'hex')), '1.2.840.113549.1.1.1');
  assert.equal(decodeOid(Buffer.from('55040a', 'hex')), '2.5.4.10');
  assert.equal(decodeOid(Buffer.from('2b8104002 2'.replace(' ', ''), 'hex')), '1.3.132.0.34');
});
