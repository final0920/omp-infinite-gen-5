import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import https from 'node:https';
import { X509Certificate } from 'node:crypto';
import { createCaptureCA } from '../source/capture_ca.js';

test('local CA issues trusted DNS/IP certificates; persists without changing system trust', async t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'ig5-ca-test-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const ca = createCaptureCA(root), authority = new X509Certificate(ca.certificate);
  assert(authority.ca);
  const issued = ca.issue('localhost'), leaf = new X509Certificate(issued.cert);
  assert(leaf.verify(authority.publicKey)); assert.equal(leaf.checkHost('localhost'), 'localhost');
  assert.equal(leaf.checkHost('other.example'), undefined);
  assert.equal(new X509Certificate(ca.issue('127.0.0.1').cert).checkIP('127.0.0.1'), '127.0.0.1');
  assert.equal(createCaptureCA(root).fingerprint256, ca.fingerprint256);
  assert.throws(() => ca.issue('bad\nname'));
  const server = https.createServer(issued, (_req, res) => res.end('verified TLS'));
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const body = await new Promise((resolve, reject) => {
    https.get({ hostname: '127.0.0.1', servername: 'localhost', port: server.address().port, ca: ca.certificate }, res => {
      let text = ''; res.on('data', chunk => text += chunk); res.on('end', () => resolve(text));
    }).on('error', reject);
  });
  assert.equal(body, 'verified TLS');
});
