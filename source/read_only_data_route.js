import fs from 'node:fs';
import path from 'node:path';
import { readAuditPage } from './audit_history.js';
import { readInvestigationView } from './investigation_view.js';
import { runKnowledge } from './knowledge_catalog.js';

// Existing read-only HTTP surface. Lifecycle and error formatting remain host-owned.
export function installReadOnlyDataRoute(ctx, mgr, cfg, { diagAppend, publicEngineError }) {
  const readTypes = new Set([
    'funcs', 'decompile', 'xrefs', 'strings', 'listing', 'calls', 'bytes',
    'search', 'scan', 'struct', 'cfg', 'slice', 'fingerprint', 'approvals',
    'disasm', 'stack', 'switches', 'vtables', 'microcode',
    'ir', 'debug_state', 'analyses', 'analysis_result',
    'capture_status', 'capture_history', 'capture_detail', 'investigation', 'knowledge',
  ]);
  ctx.inject(['webServer'], (subCtx) => {
    let ws = null;
    try {
      ws = subCtx.webServer ?? (typeof subCtx.get === 'function' ? subCtx.get('webServer') : undefined);
    } catch {
      ws = undefined;
    }
    if (!ws || typeof ws.register !== 'function') {
      diagAppend(cfg, 'host: webServer 不可用（/ig5-data 未挂载）');
      return;
    }
    try {
      const dispose = ws.register({
        kind: 'prefix',
        path: '/ig5-data',
        handler: (req, res) => {
          const url = new URL(String(req.url || '/ig5-data'), 'http://local');
          const type = url.searchParams.get('type') || 'funcs';
          const target = url.searchParams.get('target') || '';
          const engine = url.searchParams.get('engine') || undefined;
          const send = (code, obj) => {
            res.writeHead(code, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' });
            res.end(JSON.stringify(obj));
          };
          if (req.method !== 'GET') {
            send(405, { error: 'Only GET is supported' });
            return;
          }
          if (!readTypes.has(type)) {
            send(400, { error: 'Unsupported read-only data type' });
            return;
          }
          if (type === 'knowledge') {
            try {
              const query = {};
              const allowed = new Set(['type','action','query','category','limit','offset','generation','id','sha256','cursor']);
              for (const key of url.searchParams.keys()) {
                if (!allowed.has(key) || url.searchParams.getAll(key).length !== 1) throw new Error('Unsupported research query parameter');
              }
              query.action = url.searchParams.get('action') || 'status';
              for (const key of ['query','category','generation','cursor']) if (url.searchParams.has(key)) query[key] = url.searchParams.get(key);
              for (const key of ['limit','offset']) if (url.searchParams.has(key)) {
                const value = url.searchParams.get(key);
                if (!/^\d+$/.test(value)) throw new Error('Invalid research paging parameter');
                query[key] = Number(value);
              }
              if (url.searchParams.has('id') || url.searchParams.has('sha256')) query.ref = { id: url.searchParams.get('id'), sha256: url.searchParams.get('sha256') };
              send(200, { type, data: runKnowledge(cfg, query) });
            } catch (error) { send(200, { code: error.code || 'INVALID_ARGUMENT', error: publicEngineError(error, cfg) }); }
            return;
          }
          if (type === 'investigation' && !['list','brief'].includes(url.searchParams.get('action') || 'list')) {
            send(400, { error: 'Investigation view supports list/brief only' });
            return;
          }
          if (type.startsWith('capture_')) {
            try {
              if (!mgr.capture) throw new Error('Capture service is unavailable');
              const data = type === 'capture_status' ? mgr.capture.status()
                : type === 'capture_detail' ? mgr.capture.get(url.searchParams.get('id'), { session_id: url.searchParams.get('session_id') || undefined })
                : mgr.capture.readHistory({ offset: Number(url.searchParams.get('offset') || 0), limit: Number(url.searchParams.get('limit') || 20), session_id: url.searchParams.get('session_id') || undefined });
              Promise.resolve(data).then(value => send(200, { type, data: value }), error => send(200, { error: publicEngineError(error, cfg) }));
            } catch (error) { send(200, { error: publicEngineError(error, cfg) }); }
            return;
          }
          if (type === 'analyses' || type === 'analysis_result') {
            try {
              if (!mgr.analysis) throw new Error('Data analysis service is unavailable');
              const data = type === 'analyses'
                ? mgr.analysis.list({ target: target || undefined, engine, archived: url.searchParams.get('archived') === 'true', offset: Number(url.searchParams.get('offset') || 0), limit: Number(url.searchParams.get('limit') || 20) })
                : mgr.analysis.result(url.searchParams.get('id'), url.searchParams.get('select') || undefined);
              if (type === 'analyses') {
                Promise.resolve(data).then(value => send(200, { target, engine, type, data: value }), error => send(200, { error: publicEngineError(error, cfg) }));
                return;
              }
              if (type === 'analysis_result' && target && (!data.association?.target || mgr.sessionKey(data.association.target, engine) !== mgr.sessionKey(target, engine))) throw new Error('Analysis result belongs to another target');
              if (type === 'analysis_result' && engine && data.association?.engine && data.association.engine !== engine) throw new Error('Analysis result belongs to another engine');
              send(200, { target, engine, type, data });
            } catch (error) { send(200, { error: publicEngineError(error, cfg) }); }
            return;
          }
          if (type === 'debug_state') {
            if (engine && engine !== 'x64dbg') { send(400, { error: 'debug_state requires engine=x64dbg' }); return; }
            const debug = target ? mgr.sessions.get(mgr.sessionKey(target, 'x64dbg')) : [...mgr.sessions.values()].find((s) => s.engine === 'x64dbg');
            send(200, { target: target || debug?.target || '', engine: 'x64dbg', type,
              data: debug?.runtime || { state: 'idle', note: 'Use the approved debug tool to execute a target' } });
            return;
          }
          if (engine && !['reverse', 'ghidra'].includes(engine)) { send(400, { error: 'Unsupported static engine' }); return; }
          const structAction = url.searchParams.get('action') || 'list';
          if (type === 'struct' && !['list', 'get'].includes(structAction)) {
            send(400, { error: 'Only struct list/get is supported by this read-only route' });
            return;
          }
          const session = target ? mgr.sessions.get(mgr.sessionKey(target, engine)) : [...mgr.sessions.values()].find((s) => mgr.alive(s) && s.engine !== 'x64dbg' && (!engine || s.engine === engine));
          if (!session || !mgr.alive(session)) {
            send(200, { error: 'no open target' });
            return;
          }
          const params = { offset: Number(url.searchParams.get('offset') || 0), limit: Number(url.searchParams.get('limit') || 30) };
          if (type === 'approvals') {
            const auditFile = path.join(cfg.artifactDir, 'approvals.jsonl');
            if (!fs.existsSync(auditFile)) {
              send(200, { target: session.target, type, data: { rows: [], total: 0, offset: params.offset, limit: params.limit } });
              return;
            }
            const scope = mgr.sessionKey(session.target, session.engine);
            readAuditPage(auditFile, { offset: params.offset || 0, limit: params.limit || 30,
              cursor: url.searchParams.get('cursor') || undefined, scope,
              predicate: item => {
                const auditTarget = item?.detail?.destination?.target || item?.detail?._ig5?.target || item?.args?.target;
                const auditEngine = item?.detail?.destination?.engine || item?.detail?._ig5?.engine || item?.args?.engine || 'reverse';
                return auditTarget && mgr.sessionKey(auditTarget, session.engine) === scope
                  && (!session.engine || auditEngine === session.engine);
              } })
              .then(data => send(200, { target: session.target, type, data }), err => send(200, { error: publicEngineError(err, cfg) }));
            return;
          }
          if (type === 'funcs') {
            params.filter = url.searchParams.get('filter') || '';
            params.user_only = url.searchParams.get('user_only') === 'true';
          }
          if (type === 'decompile') {
            params.ea = url.searchParams.get('ea') || '';
            params.name = url.searchParams.get('name') || '';
          }
          if (type === 'xrefs') {
            params.ea = url.searchParams.get('ea') || '';
            params.str = url.searchParams.get('str') || '';
          }
          if (type === 'strings') {
            params.offset = Number(url.searchParams.get('offset') || 0);
            params.limit = Number(url.searchParams.get('limit') || 50);
          }
          if (type === 'listing') {
            params.kind = url.searchParams.get('kind') || 'segments';
            params.offset = Number(url.searchParams.get('offset') || 0);
            params.limit = Number(url.searchParams.get('limit') || 100);
          }
          if (type === 'calls') {
            params.ea = url.searchParams.get('ea') || '';
            params.name = url.searchParams.get('name') || '';
            params.direction = url.searchParams.get('direction') || 'callees';
          }
          if (type === 'bytes') {
            params.ea = url.searchParams.get('ea') || '';
            params.size = Number(url.searchParams.get('size') || 64);
          }
          if (type === 'search') {
            params.pattern = url.searchParams.get('pattern') || '';
          }
          if (type === 'scan') {
            // static recon sweep
          }
          if (type === 'struct') {
            params.action = structAction;
            params.name = url.searchParams.get('name') || '';
            params.filter = url.searchParams.get('filter') || '';
          }
          if (type === 'cfg') {
            params.ea = url.searchParams.get('ea') || '';
            params.name = url.searchParams.get('name') || '';
          }
          if (type === 'slice') {
            params.ea = url.searchParams.get('ea') || '';
            params.var = url.searchParams.get('var') || '';
          }
          if (type === 'fingerprint') {
            // full sweep
          }
          if (['disasm', 'stack', 'switches', 'vtables', 'microcode', 'ir'].includes(type)) {
            params.ea = url.searchParams.get('ea') || '';
            params.name = url.searchParams.get('name') || '';
          }
          if (type === 'disasm') params.size = Number(url.searchParams.get('size') || 1024);
          if (type === 'microcode') {
            params.action = url.searchParams.get('action') === 'deobfuscate' ? 'deobfuscate' : 'inspect'; // Only read-only analysis overlays; never optimization or repair.
            params.maturity = url.searchParams.get('maturity') || 'generated';
            if (params.action === 'deobfuscate') {
              params.max_steps = Number(url.searchParams.get('max_steps') || 100000);
              params.max_evidence = Number(url.searchParams.get('max_evidence') || 128);
            }
          }
          if (type === 'ir') {
            params.level = url.searchParams.get('level') || 'high';
            params.max_instructions = Math.max(1, Math.min(params.limit || 120, 1000));
          }
          // A stdout batch can settle a read and then a write before the read's
          // Promise continuation runs. Never label that read with the session's
          // later revision, or serve a replaced attachment as the old selection.
          const identityFields = ['target', 'engine', 'projectId', 'artifactId', 'sha256', 'provider', 'attachmentId', 'dbRevision'];
          let snapshot;
          try {
            const evidence = mgr.evidence(session);
            snapshot = Object.freeze(Object.fromEntries(identityFields.map(field => [field, evidence[field]])));
            if (identityFields.some(field => field === 'dbRevision'
              ? !Number.isSafeInteger(snapshot[field]) || snapshot[field] < 0
              : typeof snapshot[field] !== 'string' || !snapshot[field])) {
              throw new Error('Target database identity is not ready; wait for ig5_open to finish');
            }
            // The view may still hold the previous jobs-feed snapshot when a
            // close/reopen occurs before this request reaches the handler.
            if (url.searchParams.has('expected_snapshot')) {
              let expected;
              try { expected = JSON.parse(url.searchParams.get('expected_snapshot')); } catch {}
              if (url.searchParams.getAll('expected_snapshot').length !== 1
                || !expected || typeof expected !== 'object' || Array.isArray(expected)
                || Object.keys(expected).length !== identityFields.length
                || identityFields.some(field => !Object.hasOwn(expected, field)
                  || (field === 'dbRevision'
                    ? !Number.isSafeInteger(expected[field]) || expected[field] < 0 || Object.is(expected[field], -0)
                    : typeof expected[field] !== 'string' || !expected[field])
                  || expected[field] !== snapshot[field])) {
                throw Object.assign(new Error('Selected database snapshot is invalid or has changed; refresh the target and retry'), { code: 'STALE_DATA_CONTEXT' });
              }
            }
          } catch (error) { send(200, { error: publicEngineError(error, cfg), ...(error?.code ? { code: error.code } : {}) }); return; }
          const assertSnapshot = (data, returned = false) => {
            const current = mgr.evidence(session);
            if (!mgr.alive(session) || session.closing
              || mgr.sessions.get(mgr.sessionKey(snapshot.target, snapshot.engine)) !== session
              || identityFields.some(field => current[field] !== snapshot[field])
              || returned && (!data?._ig5 || identityFields.some(field => data._ig5[field] !== snapshot[field]))) {
              throw Object.assign(new Error('Database snapshot changed while reading; refresh the target and retry'), { code: 'STALE_DATA_CONTEXT' });
            }
          };
          Promise.resolve()
            .then(() => {
              assertSnapshot();
              if (type === 'investigation') return mgr.withSessions([session], () => {
                assertSnapshot();
                return readInvestigationView(mgr, cfg, session, { action: url.searchParams.get('action') || 'list',
                  id: url.searchParams.get('id'), taskRevision: Number(url.searchParams.get('task_revision')) });
              });
              return mgr.rpc(session, type, params, 60_000);
            })
            .then((data) => { assertSnapshot(data, true); send(200, { ...snapshot, type, data }); })
            .catch((e) => send(200, { error: publicEngineError(e, cfg), ...(e?.code ? { code: e.code } : {}) }));
        },
      });
      diagAppend(cfg, 'host: /ig5-data 路由已挂载');
      return () => {
        try {
          if (typeof dispose === 'function') dispose();
        } catch {
          // route already gone
        }
      };
    } catch (e) {
      diagAppend(cfg, `host: /ig5-data 挂载失败 ${e && e.message}`);
    }
  });
}
