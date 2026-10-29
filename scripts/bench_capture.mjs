// Reproducible loopback benchmark; includes SHA body persistence and metadata.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import { performance, monitorEventLoopDelay } from 'node:perf_hooks';
import { AnalysisArtifacts } from '../source/analysis_artifacts.js';
import { CaptureService } from '../source/capture_service.js';
const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'ig5-capture-bench-'));
const artifacts = new AnalysisArtifacts(path.join(directory, 'analysis-data'));
const service = new CaptureService({ analysis: { artifacts } }, { artifactDir: directory });
const body = Buffer.alloc(65536, 65);
const server = http.createServer((_req, res) => { res.setHeader('content-length', body.length); res.end(body); });
const requests = 100, concurrency = 8;
async function batch(port, target) {
  let next = 0;
  const start = performance.now();
  await Promise.all(Array.from({ length: concurrency }, async () => {
    while (next++ < requests) await new Promise((resolve, reject) => {
      http.get({ host: '127.0.0.1', port, path: target, headers: { host: target.startsWith('http:') ? new URL(target).host : '127.0.0.1:' + port }, agent: false }, response => {
        let bytes = 0; response.on('data', chunk => bytes += chunk.length);
        response.on('end', () => bytes === body.length && response.statusCode === 200 ? resolve() : reject(new Error('Unexpected benchmark response')));
        response.on('error', reject);
      }).on('error', reject);
    });
  }));
  return performance.now() - start;
}
try {
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const origin = 'http://127.0.0.1:' + server.address().port;
  const directMs = await batch(server.address().port, '/');
  const proxy = await service.control({ action: 'start', scope: [origin], port: 0 });
  const delay = monitorEventLoopDelay({ resolution: 10 }); delay.enable();
  const started = performance.now();
  await batch(proxy.port, origin + '/');
  await service.control({ action: 'stop', session_id: proxy.session_id });
  const persistedMs = performance.now() - started; delay.disable();
  const status = service.status();
  if (status.stored !== requests || status.dropped || status.persistenceErrors) throw new Error('Benchmark lost captured records');
  console.log(JSON.stringify({ fixture: 'loopback HTTP/1.1, 100 x 64KiB, concurrency 8, unique metadata/shared identical content-addressed body',
    node: process.version, requests, concurrency, directMs: Math.round(directMs), capturePersistedMs: Math.round(persistedMs),
    captureRequestsPerSecond: Math.round(requests * 1000 / persistedMs), eventLoopP99Ms: Number((delay.percentile(99) / 1e6).toFixed(2)),
    stored: status.stored, dropped: status.dropped, boundary: 'Single local run; no WAN, TLS, long-duration or high-concurrency guarantee.' }, null, 2));
} finally {
  await service.dispose(); await artifacts.dispose(); await new Promise(resolve => server.close(resolve));
  fs.rmSync(directory, { recursive: true, force: true });
}
