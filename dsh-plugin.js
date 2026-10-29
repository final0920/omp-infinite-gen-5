import path from 'node:path';
import os from 'node:os';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import { installWorkflow } from './workflow.js';
import { defineAdvancedTools } from './advanced_tools.js';
import { AsyncLocalStorage } from 'node:async_hooks';
import { createHash } from 'node:crypto';
import { runtimeConfiguration, engineId, terminateTree } from './engine_runtime.js';
import { spawnWorker, attachWorker, doctorWorker } from './source/worker_transport.js';
import { ProjectStore } from './source/project_store.js';
import { defineIntegrationTools } from './integration_tools.js';
import { defineAnalysisTools } from './analysis_tools.js';
import { defineCaptureTools } from './capture_tools.js';
import { exportPatchDiff } from './source/patch_export.js';
import { targetIdentity } from './source/audit_history.js';
import { jsonToolOutput } from './source/json_output.js';
import { resolveReverseRuntime } from './source/reverse_runtime.js';
import { collectFunctionDossier } from './source/function_dossier.js';
import { ResultArtifacts } from './source/result_artifacts.js';
import { FunctionBatches } from './source/function_batches.js';
import { workspaceSchema, runWorkspace, captureDossier } from './source/investigation_workflow.js';
import { installReadOnlyDataRoute } from './source/read_only_data_route.js';
import { autonomyStatus } from './source/autonomy_status.js';
import { recoveryProfileSchema, runRecoveryProfile } from './source/vm_recovery_profile.js';
import { saveDebugTrace } from './source/debug_trace.js';
import { debugTimeout } from './source/debug_timeout.js';
import { RemoteExecutionStore, remoteExecutionKey } from './source/remote_execution_store.js';
import { guestProfileConfiguration, loadGuestProfile, publicGuestProfile, guestTarget } from './source/guest_debug_profile.js';
import { recoverGuestExecution, validateGuestRecoveryArgs } from './source/guest_recovery.js';
import { ig5DashDefinition } from './source/dashboard_projection.js';
import { installLcmBridge, memorySchema } from './source/lcm_bridge.js';
import { runKnowledge, knowledgeSchema } from './source/knowledge_catalog.js';
import { installDelegationControl } from './source/delegation_control.js';
import { diagAppend } from './source/diag_log.js';
import { publicEngineError } from './source/engine_error.js';
import { WorkerManager } from './source/worker_manager.js';
import { IMPLEMENTATION_REVISION, IMPLEMENTATION_LOADED_AT } from './source/implementation_info.js';
import { installApprovalGate, IG5_WRITE_TOOLS } from './source/approval_gate.js';
import { capabilityCatalog } from './source/capability_catalog.js';
import { FailureRecords } from './source/failure_record.js';
import { failureBinding } from './source/failure_adapters.js';
import { planningRequestKey } from './source/planning_identity.js';
import { planningImplementationDigest } from './source/planning_runtime.js';
import { CapabilityAcceptance, runtimeIdentity } from './source/capability_acceptance.js';


// ── 无限五代（IG5）v1.0.0 ──────────────────────────────────────────────────
// DeepSeek Harness 逆向插件：隔离多引擎 Worker 池 + ig5_* 工具面 + ig5dash 投影。
// 零提示词注入；指导载体 = 工具描述 + 会话流卡片。

const PLUGIN_ID = 'dsh-infinite-gen-5';
const PLUGIN_VERSION = '1.3.0';
const HERE = path.dirname(fileURLToPath(import.meta.url));
const WORKER = path.join(HERE, 'worker', 'ig5_worker.py');

// ── Config（cordis.yml 插件行可覆盖；misconfiguration fails loud） ──────────
function resolveConfig(cfg = {}) {
  const runtime = runtimeConfiguration(cfg);
  const reverseProvider = cfg.reverseProvider || 'bundled';
  if (!['bundled', 'commercial'].includes(reverseProvider)) throw new Error('reverseProvider must be bundled or commercial');
  const reverseRuntime = reverseProvider === 'commercial' ? resolveReverseRuntime(cfg, { host: runtime.host }) : {
    available: runtime.ghidra.available, source: runtime.ghidra.source, distribution: 'bundled', provider: 'ghidra',
    readiness: runtime.ghidra.available ? 'ready-to-start' : 'missing-runtime', runtimeReady: null,
    startupVerified: false, validation: 'runtime-metadata-and-files',
    reason: runtime.ghidra.available ? '五代内置 Reverse 核心已就绪；首次检查会验证实际启动。' : runtime.ghidra.reason,
    pythonExe: runtime.ghidra.pythonExe,
  };
  const { idaDir, pythonExe, available: reverseAvailable } = reverseRuntime;
  return {
    ...runtime,
    idaDir,
    reverseAvailable,
    reverseRuntime,
    reverseProvider,
    pythonExe,
    defaultEngine: cfg.defaultEngine ? engineId(cfg.defaultEngine) : 'reverse',
    defaultDebugger: cfg.defaultDebugger || (runtime.x64dbg.available ? 'x64dbg' : 'auto'),
    projectRoot: cfg.projectRoot || (cfg.artifactDir ? path.join(cfg.artifactDir, 'projects') : runtime.projectRoot),
    stateRoot: cfg.stateRoot || (cfg.artifactDir ? path.join(cfg.artifactDir, 'runtime-state') : path.join(runtime.home, 'state')),
    requestTimeoutMs: Number(cfg.requestTimeoutMs ?? 240_000),
    // 后台分析是长任务：单独一档超时，别让 240s 的短超时杀掉大二进制
    openTimeoutMs: Number(cfg.openTimeoutMs ?? 1_800_000),
    maxSessions: Number(cfg.maxSessions ?? 3),
    artifactDir: cfg.artifactDir || path.join(runtime.home, 'artifacts'),
    autoOpenHint: cfg.autoOpenHint !== false,
    backgroundOpen: cfg.backgroundOpen !== false,
    toolset: cfg.toolset || 'core',
    memory: cfg.memory !== false,
    knowledge: cfg.knowledge !== false,
    capture: cfg.capture ?? {},
    guestDebugProfiles: guestProfileConfiguration(cfg.guestDebugProfiles),
    remoteExecutionRoot: path.resolve(cfg.remoteExecutionRoot || path.join(runtime.home, 'remote-executions')),
  };
}



// ── 诊断回路：client POST /ig5-diag → 落盘 artifacts/ig5-diag.log ───────────
function installDiagRoute(ctx, cfg) {
  ctx.inject(['webServer'], (subCtx) => {
    let ws = null;
    try {
      ws = subCtx.webServer ?? (typeof subCtx.get === 'function' ? subCtx.get('webServer') : undefined);
    } catch {
      ws = undefined;
    }
    if (!ws || typeof ws.register !== 'function') {
      diagAppend(cfg, 'host: webServer 不可用（诊断回路未挂载）');
      return;
    }
    try {
      const dispose = ws.register({
        kind: 'prefix',
        path: '/ig5-diag',
        handler: (req, res) => {
          const isPost = req.method === 'POST';
          const isPoll = !isPost && /poll=1/.test(String(req.url || ''));
          if (req.method !== 'POST' && req.method !== 'GET') {
            res.writeHead(405);
            res.end();
            return;
          }
          if (isPoll) {
            // 命令通道：读 ig5-cmd.json（一次性），返回后删除
            const cmdFile = path.join(cfg.artifactDir, 'ig5-cmd.json');
            let payload = 'ok';
            try {
              if (fs.existsSync(cmdFile)) {
                payload = fs.readFileSync(cmdFile, 'utf8');
                fs.unlinkSync(cmdFile);
              }
            } catch {
              payload = 'ok';
            }
            res.writeHead(200, { 'content-type': 'application/json' });
            res.end(payload);
            return;
          }
          const chunks = [];
          req.on('data', (c) => {
            if (chunks.length < 64) chunks.push(c);
          });
          req.on('end', () => {
            try {
              const body = Buffer.concat(chunks).toString('utf8').slice(0, 200_000);
              diagAppend(cfg, `[client ${req.method}] ${body || '(empty)'}`);
            } catch {
              diagAppend(cfg, 'host: diag body 读取失败');
            }
            res.writeHead(200, { 'content-type': 'text/plain' });
            res.end('ok');
          });
          req.on('error', () => {
            try { res.end(); } catch { /* already gone */ }
          });
        },
      });
      diagAppend(cfg, 'host: /ig5-diag 路由已挂载');
      return () => {
        try {
          if (typeof dispose === 'function') dispose();
        } catch {
          // route already gone
        }
      };
    } catch (e) {
      diagAppend(cfg, `host: 挂载失败 ${e && e.message}`);
    }
  });
}


// ── 作业进度回路：client 轮询 GET /ig5-jobs → 工作台渲染进度条 ──────────────
function installJobsRoute(ctx, mgr, cfg) {
  ctx.inject(['webServer'], (subCtx) => {
    let ws = null;
    try {
      ws = subCtx.webServer ?? (typeof subCtx.get === 'function' ? subCtx.get('webServer') : undefined);
    } catch {
      ws = undefined;
    }
    if (!ws || typeof ws.register !== 'function') {
      diagAppend(cfg, 'host: webServer 不可用（/ig5-jobs 未挂载）');
      return;
    }
    try {
      const dispose = ws.register({
        kind: 'prefix',
        path: '/ig5-jobs',
        handler: (req, res) => {
          let body;
          try {
            body = JSON.stringify(mgr.snapshot());
          } catch (e) {
            body = JSON.stringify({ error: publicEngineError(e, cfg) });
          }
          res.writeHead(200, {
            'content-type': 'application/json; charset=utf-8',
            'cache-control': 'no-store',
          });
          res.end(body);
        },
      });
      diagAppend(cfg, 'host: /ig5-jobs 路由已挂载');
      return () => {
        try {
          if (typeof dispose === 'function') dispose();
        } catch {
          // route already gone
        }
      };
    } catch (e) {
      diagAppend(cfg, `host: /ig5-jobs 挂载失败 ${e && e.message}`);
    }
  });
}


// ── M1-C 数据回路：client 工作台 GET /ig5-data（funcs/decompile 只读代理） ──
function installDataRoute(ctx, mgr, cfg) {
  return installReadOnlyDataRoute(ctx, mgr, cfg, { diagAppend, publicEngineError });
}

function formatProgress(payload) {
  const pct = typeof payload?.pct === 'number' ? payload.pct : 0;
  const stage = payload?.stage ?? 'working';
  const parts = [`${stage} ${pct}%`];
  if (payload?.segment) parts.push(`段 ${payload.segment}`);
  if (typeof payload?.functions === 'number') parts.push(`${payload.functions} 函数`);
  if (typeof payload?.bytes === 'number' && typeof payload?.totalBytes === 'number') {
    parts.push(`${(payload.bytes / 1048576).toFixed(1)}/${(payload.totalBytes / 1048576).toFixed(1)} MB`);
  }
  if (payload?.detail) parts.push(String(payload.detail));
  return parts.join(' · ');
}

function dimsOf(info) {
  return {
    engine: info.engine,
    provider: info.provider,
    projectId: info.projectId,
    artifactId: info.artifactId,
    sha256: info.sha256,
    attachmentId: info.attachmentId,
    dbRevision: info.dbRevision,
    partial: info.partial === true,
    ...(info.analysis ? { analysis: info.analysis } : {}),
    ...(info.analysisProfile ? { analysisProfile: info.analysisProfile, analysisComplete: info.analysisComplete,
      skippedAnalyzers: info.skippedAnalyzers || [] } : {}),
    target: info.target,
    bits: info.bits,
    proc: info.proc,
    n_funcs: info.n_funcs,
    segments: info.segments,
    entries: info.entries,
    entriesMeaning: 'Provider analysis entrypoints; may include program entry and TLS callbacks. Not the PE export table. Use ig5_listing kind=exports for exports.',
    elapsedMs: info.elapsedMs ?? null,
    alreadyOpen: !!info.alreadyOpen,
  };
}

// ── 工具面（ig5_*，模型视角描述 + 手工参数校验 + canonical JSON 返回） ────────
function textRender(_args, value) {
  return [{ type: 'text', text: JSON.stringify(value, null, 1) }];
}

function requireString(args, field) {
  const v = args?.[field];
  if (typeof v !== 'string' || !v.trim()) {
    throw new Error(`参数 ${field} 缺失或非法（需要非空字符串）`);
  }
  return v.trim();
}

function defineIg5Tools(ctx, mgr, cfg) {
  const spill = (session, ea, code) => {
    const dir = path.join(cfg.artifactDir, 'decompile', session.artifactId, session.engine);
    fs.mkdirSync(dir, { recursive: true });
    const file = path.join(dir, `func_${String(ea).replace(/[^\w.-]/g, '_')}-r${session.dbRevision}.c`);
    fs.writeFileSync(file, code, 'utf8');
    return file;
  };

  return [
    {
      name: 'ig5_profile',
      description:
        'Return IG5 engines, projects, active tools and skills, plus the calling agent\'s host Goal availability/state. Optionally switch core (8 tools) or full (43) for the calling agent. guest_debug inspects a configured VMCI guest profile and returns its bindingSha256 before an approved debugger call; reads files only. history stats/archive/restore retain report IDs and refs. Address conversion, capability dimensions, local knowledge/memory and the shared collaboration budget are separate single-operation calls. For sustained reverse engineering use ig5-reverse-agent and native Goal tools. Investigation task notes and system evidence moved to ig5_workspace; recovery/failure planning moved to ig5_recovery.',
      parameters: { type: 'object', properties: { target: { type: 'string', description: 'Explicit opened target, used by address conversion' }, guest_debug: { type: 'string', description: 'Inspect a configured VMCI guest profile and obtain its bindingSha256 before an approved debugger call; reads files only' }, toolset: { type: 'string', enum: ['core', 'full'] }, history: { type: 'object', properties: { action: { type: 'string', enum: ['stats', 'archive', 'restore'] }, ids: { type: 'array', minItems: 1, maxItems: 1000, items: { type: 'string' } } }, required: ['action'], additionalProperties: false } }, additionalProperties: false },
      output: { schema: { type: 'object', additionalProperties: true }, render: textRender },
      async execute(args = {}, execution) {
        if (args.knowledge !== undefined) {
          if (Object.keys(args).some(k => k !== 'knowledge')) throw new Error('Use knowledge separately from other profile operations');
          return { knowledge: runKnowledge(cfg, args.knowledge) };
        }
        if (args.address !== undefined) {
          if (Object.keys(args).some(k => !['address','target','engine'].includes(k))) throw new Error('Use address conversion separately');
          const session = mgr.get(requireString(args, 'target'));
          return mgr.rpc(session, 'address_convert', args.address);
        }
        if (args.capabilities !== undefined) {
          if (args.capabilities !== true || Object.keys(args).some(k => !['capabilities', 'engine'].includes(k))) throw Object.assign(new Error('Use capabilities=true separately from other profile operations'), { code: 'INVALID_ARGUMENT' });
          return { capabilities: capabilityCatalog(mgr, cfg, { engine: args.engine }) };
        }
        if (args.memory !== undefined) {
          if (Object.keys(args).some(k => !['memory', 'engine'].includes(k))) throw new Error('Use memory separately from other profile operations');
          return { memory: await mgr.memory.handle(execution?.agent, args.memory) };
        }
        if (args.collaboration !== undefined) {
          if (Object.keys(args).some(k => !['collaboration', 'engine'].includes(k))) throw new Error('Use collaboration separately from other profile operations');
          return { collaboration: mgr.coordination.budget(execution?.agent, args.collaboration) };
        }
        if (args.recovery !== undefined) throw new Error('Use ig5_recovery for recovery and failure-planning operations');
        if (args.workspace !== undefined) throw new Error('Use ig5_workspace for investigation task operations');
        if (args.toolset !== undefined) {
          if (!mgr.workflow) throw new Error('IG5 workflow is not ready');
          mgr.workflow.setToolset(args.toolset, execution);
        }
        return {
          plugin: PLUGIN_ID,
          version: PLUGIN_VERSION,
          implementationRevision: IMPLEMENTATION_REVISION,
          engine: cfg.defaultEngine || 'reverse',
          host: cfg.host,
          runtimeSource: Object.fromEntries(['ghidra', 'x64dbg'].map(id => [id, cfg[id]?.source || null])),
          engines: mgr.engines?.() || [],
          projects: mgr.projects?.listProjects?.() || [],
          ...(mgr.workflow?.snapshot(execution) || { toolset: cfg.toolset || 'core' }),
          autonomy: autonomyStatus(ctx, execution),
          ...(args.history ? { history: await mgr.analysis.history(args.history) } : {}),
          engineConfigured: cfg.defaultEngine === 'reverse' ? cfg.reverseAvailable : !!cfg[cfg.defaultEngine]?.available,
          pythonConfigured: cfg.defaultEngine === 'reverse' ? !!cfg.pythonExe : !!cfg[cfg.defaultEngine]?.pythonExe,
          requestTimeoutMs: cfg.requestTimeoutMs,
          maxSessions: cfg.maxSessions,
          capture: mgr.capture?.status() || { state: 'idle' },
          guestDebugProfiles: Object.keys(cfg.guestDebugProfiles || {}),
          ...(args.guest_debug !== undefined ? { guestDebug: publicGuestProfile(loadGuestProfile(cfg, args.guest_debug)) } : {}),
          tools: [
            'ig5_doctor', 'ig5_open', 'ig5_status', 'ig5_funcs', 'ig5_strings',
            'ig5_decompile', 'ig5_xrefs', 'ig5_calls', 'ig5_bytes', 'ig5_search',
            'ig5_listing', 'ig5_scan', 'ig5_export_diff', 'ig5_cfg', 'ig5_slice', 'ig5_fingerprint',
            'ig5_rename*', 'ig5_patch_bytes*', 'ig5_comment*', 'ig5_analyze*', 'ig5_set_type*',
            'ig5_undo*', 'ig5_run_idapython*', 'ig5_dbg*', 'ig5_struct*', 'ig5_close', 'ig5_profile',
            'ig5_workspace', 'ig5_recovery',
            'ig5_stack', 'ig5_switches', 'ig5_switch_repair*', 'ig5_vtables', 'ig5_microcode', 'ig5_bindiff', 'ig5_emulate*',
            'ig5_ir', 'ig5_sync*',
            'ig5_crypto', 'ig5_protocol', 'ig5_package',
            'ig5_capture', 'ig5_capture_control*',
          ],
          writeGated: [...IG5_WRITE_TOOLS],
          lineage: 'dsh-infinite-gen-4 (提示词层) -> dsh-infinite-gen-5 (逆向工具面、按需 Skill 与宿主持久 Goal；无全局 persona 注入)',
        };
      },
    },
    {
      name: 'ig5_workspace',
      description:
        'Static investigation notes and system evidence for an explicitly opened target: create/get/brief/list/update, evidence snapshots, handoff/claim/submit/review, plan/resume, research scope/revisions/dependencies/verification, private case index/search/read, fixed method registry/applicability, experiment-shadow proposals, bounded bit-vector candidate checks and CFF state/overlay reads. Updates require expected_task_revision; research-update requires both task and research revisions. A narrow pass never accepts the whole contract. Child reads exact task evidence; the parent reviews returned snapshot IDs. No agent spawning, permission grants or automatic completion. Reports are saved as immutable evidence.',
      parameters: { type: 'object', properties: { workspace: workspaceSchema, target: { type: 'string', description: 'Explicit opened static target; required by every workspace action' } }, required: ['workspace'], additionalProperties: false },
      output: { schema: { type: 'object', additionalProperties: true }, render: textRender },
      async execute(args = {}, execution) { return runWorkspace(mgr, cfg, args, execution); },
    },
    {
      name: 'ig5_recovery',
      description:
        'Bounded failure/dependency planning and recorded-observation recovery. case_ref reads a bounded recovery case. observations imports committed debug-trace reports into ordered source-bound pages. roles samples recorded addressing/load/control observations using an owned disassembly-only job. flow revalidates a committed role report plus recordings and checks structural load/index/target dependencies. instances captures explicit SHA-bound local small-VM model files; instance_check checks finite input/initial-result pairs in the original bounded data worker. role_compare/role_validate, declare_contract/program/function_check check owned executable models over finite contract domains. No native execution, invented intermediate state, VM/business proof, whole-function proof or ARM64 instance inference. All modes save immutable reports and reject unrelated options.',
      parameters: { type: 'object', properties: { recovery: recoveryProfileSchema }, required: ['recovery'], additionalProperties: false },
      output: { schema: { type: 'object', additionalProperties: true }, render: textRender },
      async execute(args = {}) { return runRecoveryProfile(mgr, args, cfg); },
    },
    {
      name: 'ig5_doctor',
      description:
        'Self-check the selected IG5 engine/provider. Default Reverse and Ghidra use the bundled Ghidra runtime; only explicitly selected commercial Reverse requires a licensed local installation. x64dbg reads file layout and retained launch-policy blocks without launching its debugger. not-probed is unknown; known blocks deny native launch before process creation. File presence is not startup verification; no OS policy changes.',
      parameters: { type: 'object', properties: { operation: { type: 'string', enum: ['engine', 'session'], description: 'Default engine may launch a probe. session must be used alone: local executing-session metadata, no RPC or budget changes; reachable when ancestry is unavailable.' } }, additionalProperties: false },
      output: { schema: { type: 'object', additionalProperties: true }, render: textRender },
      async execute(args = {}, execution) {
        if (args.operation === 'session') return mgr.coordination.diagnose(execution?.agent, args);
        if (args.operation !== undefined && args.operation !== 'engine') throw new Error('doctor operation must be engine or session');
        if (typeof mgr.doctor === 'function') return mgr.doctor(args.engine || cfg.defaultEngine || 'reverse');
        let child;
        try {
          child = mgr.spawnWorker();
          const result = await doctorWorker(child, { timeoutMs: 60_000,
            formatError: error => new Error(publicEngineError(error, cfg)) });
          return { ok: true, engine: 'Reverse (headless)', python: result.python,
            runtimeReady: result.idalib === 'loaded', caps: {
              planAndWait: result.caps?.['ida_auto.plan_and_wait'] === true,
              wait: result.caps?.['ida_auto.auto_wait'] === true,
              makeCode: result.caps?.['ida_auto.auto_make_code'] === true }, artifactDir: cfg.artifactDir };
        } catch (error) { throw new Error(publicEngineError(error, cfg)); }
        finally { try { child?.kill(); } catch {} }
      },
    },
    {
      name: 'ig5_open',
      description:
        'Open a binary in the selected static engine and run auto-analysis. Returns project/artifact identity, engine, database revision, architecture, segments, function count and entries. One worker per target and engine. Analysis defaults to a native background job; pass background:false for inline results. A runtime pack is required for the selected engine.',
      parameters: {
        type: 'object',
        properties: {
          path: { type: 'string', description: 'Absolute path of the target binary' },
          auto_analysis: { type: 'boolean', description: 'Run automatic analysis using the selected profile (default true)' },
          analysis_timeout: { type: 'number', description: 'Ghidra analysis budget in seconds, 1..600; returns explicitly partial evidence if exhausted' },
          analysis_profile: { type: 'string', enum: ['interactive', 'full'], description: 'Ghidra: interactive (default) skips batch Decompiler Parameter ID; full enables that batch analyzer. Function decompilation is available in both.' },
          background: {
            type: 'boolean',
            description: 'Run the analysis as a background job (default true). false = block this call until analysis finishes.',
          },
          fresh: {
            type: 'boolean',
            description: 'Ignore and back up an adjacent existing .i64/.idb so the database is re-analyzed from scratch (default false = reuse)',
          },
        },
        required: ['path'],
      },
      output: { schema: { type: 'object', additionalProperties: true }, render: textRender },
      async execute(args, exec) {
        const target = requireString(args, 'path');
        if (!fs.existsSync(target)) throw new Error(`文件不存在: ${target}`);
        const auto = args?.auto_analysis !== false;
        const fresh = args?.fresh === true;
        if (args.analysis_timeout !== undefined && (!Number.isSafeInteger(args.analysis_timeout) || args.analysis_timeout < 1 || args.analysis_timeout > 600)) throw new Error('analysis_timeout must be an integer from 1 to 600');
        if (args.analysis_profile !== undefined && !['interactive', 'full'].includes(args.analysis_profile)) throw new Error('analysis_profile must be interactive or full');

        const runInline = async () => {
          const info = await mgr.open(target, auto, {
            fresh,
            engine: args.engine,
            analysisTimeout: args.analysis_timeout,
            analysisProfile: args.analysis_profile,
            onProgress: (p) => mgr.noteProgress(target, p),
          });
          return { ...dimsOf(info), background: false };
        };

        const wantsInline = args?.background === false || !cfg.backgroundOpen;
        if (wantsInline) return runInline();

        const jobs = ctx.get('jobs');
        if (!jobs || typeof jobs.start !== 'function') {
          // 部署里没有作业控制器时降级为同步，而不是失败
          return { ...(await runInline()), background: false, backgroundUnavailable: true };
        }

        // Agent 身份就是 SessionId（Agent.id），作业归属以它为准
        const owner = exec?.agent?.id ?? exec?.agent?.sessionId;
        const label = `IG5 分析 ${path.basename(target)}`;
        const jobId = jobs.start({
          kind: 'ig5-open',
          label,
          ...(owner ? { owner } : {}),
          run: (job) => {
            mgr.trackJob(job.id, target, label);
            const done = (async () => {
              try {
                const info = await mgr.open(target, auto, {
                  fresh,
                  engine: args.engine,
                  analysisTimeout: args.analysis_timeout,
                  analysisProfile: args.analysis_profile,
                  onProgress: (p) => {
                    job.updateProgress(formatProgress(p));
                    mgr.noteProgress(target, p, job.id);
                  },
                });
                const summary = `IG5 ${info.partial ? '分析预算到期，返回部分结果' : '分析完成'}: ${path.basename(info.target ?? target)} · ${info.n_funcs} 函数 · ${info.bits} 位 · ${((info.elapsedMs ?? 0) / 1000).toFixed(1)}s`;
                job.append(summary + '\n', { channel: 'stdout' });
                mgr.finishJob(job.id, 'completed', `${info.partial ? '部分分析 · ' : ''}${info.n_funcs} 函数`);
                return { status: 'completed', detail: `${info.partial ? '部分分析 · ' : ''}${info.n_funcs} 函数`, result: JSON.stringify(dimsOf(info)) };
              } catch (e) {
                const msg = publicEngineError(e, cfg);
                job.append(`IG5 分析失败: ${msg}\n`, { channel: 'stderr' });
                mgr.finishJob(job.id, 'failed', msg.slice(0, 200));
                return { status: 'failed', detail: msg.slice(0, 200) };
              }
            })();
            return {
              cancel: (reason) => {
                mgr.close(target, false, args.engine);
                mgr.finishJob(job.id, 'killed', reason ?? 'cancelled');
              },
              done,
            };
          },
        });

        return {
          kind: 'background',
          jobId,
          target,
          hint: '分析在后台运行：右栏 IG5 工作台实时显示进度；用 job_output 取结果，job_kill 取消。',
        };
      },
    },
    {
      name: 'ig5_status',
      description:
        'List open IG5 workers and pending remoteExecutions. Separately remoteCleanupEvidence revalidates at most eight stored terminal receipts against original bindings and byte hashes; missing/corrupt evidence stays unknown. An empty pending list is not proof of cleanup. Stored receipt validation is not a new HMAC exchange or authority for newer processes.',
      parameters: { type: 'object', properties: {}, additionalProperties: false },
      output: { schema: { type: 'object', additionalProperties: true }, render: textRender },
      execute() {
        const sessions = mgr.status();
        return { sessions, count: sessions.length, remoteExecutions: mgr.remoteExecutionStatus?.() || [], remoteCleanupEvidence: mgr.remoteCleanupEvidence(), config: { engine: cfg.defaultEngine || 'reverse', engines: mgr.engines?.() || [], maxSessions: cfg.maxSessions } };
      },
    },
    {
      name: 'ig5_funcs',
      description:
        'List functions of an open target, paged: address (EA), name, size. Use filter for a name substring. EA is the stable handle for every other ig5 tool.',
      parameters: {
        type: 'object',
        properties: {
          target: { type: 'string', description: 'Target path previously opened with ig5_open' },
          offset: { type: 'number', description: 'Skip first N functions (cursor paging)' },
          limit: { type: 'number', description: 'Max rows (default 30, max 200)' },
          filter: { type: 'string', description: 'Case-insensitive name substring filter' },
          user_only: { type: 'boolean', description: 'Exclude functions classified as library-related by the active provider. The bundled core excludes external/thunk functions only; remaining functions are not proof of user-authored logic.' },
        },
        required: ['target'],
      },
      output: { schema: { type: 'object', additionalProperties: true }, render: textRender },
      async execute(args) {
        const target = requireString(args, 'target');
        const session = mgr.get(target);
        const result = await mgr.rpc(session, 'funcs', {
          offset: Number(args?.offset ?? 0),
          limit: Number(args?.limit ?? 30),
          filter: typeof args?.filter === 'string' ? args.filter : '',
          user_only: args?.user_only === true,
        });
        return { target: session.target, ...result };
      },
    },
    {
      name: 'ig5_strings',
      description:
        'List strings of an open target with addresses, paged. First hop for locating license checks, messages, URLs, and crypto constants.',
      parameters: {
        type: 'object',
        properties: {
          target: { type: 'string', description: 'Target path previously opened with ig5_open' },
          offset: { type: 'number' },
          limit: { type: 'number', description: 'Max rows (default 30, max 200)' },
        },
        required: ['target'],
      },
      output: { schema: { type: 'object', additionalProperties: true }, render: textRender },
      async execute(args) {
        const target = requireString(args, 'target');
        const session = mgr.get(target);
        const result = await mgr.rpc(session, 'strings', {
          offset: Number(args?.offset ?? 0),
          limit: Number(args?.limit ?? 30),
        });
        return { target: session.target, ...result };
      },
    },
    {
      name: 'ig5_decompile',
      description:
        'Decompile one function by EA or exact name. style=dossier aggregates pseudocode, CFG, callers, callees and stack under one database revision, with explicit section status, response limits and provenance. Optional task_id records a system observation in an existing investigation task. style=llm returns provider-specific supporting metadata when available. Plain results over ~12KB spill to an artifact file with a preview. Read-only; does not execute the sample or verify hypotheses.',
      parameters: {
        type: 'object',
        properties: {
          target: { type: 'string', description: 'Target path previously opened with ig5_open' },
          ea: { type: 'string', description: 'Function address, hex string like 0x140001070' },
          name: { type: 'string', description: 'Exact function name (used when ea is absent)' },
          style: { type: 'string', enum: ['', 'llm', 'dossier'], description: 'Omit for plain pseudocode; llm metadata depends on the provider; dossier aggregates real function context' },
          operation: { type: 'string', enum: ['collect', 'read', 'batch'], description: 'Default collect. read retrieves a committed section. batch creates/runs/status/cancels a durable explicit function list, up to 8 sequential items per run with normal per-item charging.' },
          batch: { type: 'object', properties: { action: { type: 'string', enum: ['create','status','run','cancel'] }, id: { type: 'string' }, functions: { type: 'array', minItems: 1, maxItems: 72, items: { type: 'string' } }, max_items: { type: 'integer', minimum: 1, maximum: 8 } }, required: ['action'], additionalProperties: false },
          result_ref: { type: 'object', properties: { id: { type: 'string' }, sha256: { type: 'string' }, expiresAt: { type: 'string' } }, required: ['id', 'sha256'], additionalProperties: false },
          section: { type: 'string', enum: ['decompile', 'cfg', 'callers', 'callees', 'stack'] },
          format: { type: 'string', enum: ['text', 'records', 'json-text'], description: 'Default code text for decompile, stable records for other sections. json-text retrieves all saved section fields including oversized records.' },
          cursor: { type: 'string', description: 'Authenticated continuation returned by a previous page of this result/section/format.' },
          page_max_bytes: { type: 'integer', minimum: 4000, maximum: 64000, description: 'Whole serialized page UTF-8 bytes including provenance and cursor; default 8000.' },
          dossier_max_bytes: { type: 'number', description: 'Dossier body UTF-8 response budget, 4000..64000 bytes, default 16000; not a total backend computation budget' },
          dossier_max_rows: { type: 'number', description: 'Dossier per-array row cap, 1..128, default 32' },
          refresh: { type: 'boolean', description: 'Dossier only: bypass response cache for this normally charged collection; does not force whole-program reanalysis.' },
          task_id: { type: 'string', description: 'Existing workspace task UUID; requires style=dossier and records only system-produced observations' },
        },
        required: ['target'],
      },
      output: { schema: { type: 'object', additionalProperties: true }, render: textRender },
      async execute(args, execution) {
        const target = requireString(args, 'target');
        const session = mgr.get(target);
        if (args.operation === 'batch') {
          if (Object.keys(args).some(k => !['operation','target','engine','batch'].includes(k))) throw new Error('Use batch parameters separately');
          return mgr.functionBatches.execute(mgr, session, args, execution);
        }
        if (args.batch !== undefined) throw new Error('batch requires operation=batch');
        if (args.operation === 'read') {
          if (Object.keys(args).some(k => !['operation','target','engine','result_ref','section','format','cursor','page_max_bytes'].includes(k))) throw new Error('Use saved result read parameters separately from collection');
          mgr.checkCancelled();
          return mgr.functionResults.read(args.result_ref, mgr.evidence(session), args);
        }
        if (args.operation !== undefined && args.operation !== 'collect') throw new Error('decompile operation must be collect or read');
        if (['result_ref','section','format','cursor','page_max_bytes'].some(k => args[k] !== undefined)) throw new Error('Saved-result parameters require operation=read');
        if (args.style !== undefined && !['', 'llm', 'dossier'].includes(args.style)) throw new Error('style must be empty, llm or dossier');
        if (args.style === 'dossier') {
          const dossier = await collectFunctionDossier(mgr, session, args);
          return args.task_id === undefined ? dossier : { ...dossier, investigation: captureDossier(mgr, cfg, dossier, args.task_id, execution) };
        }
        if (['task_id', 'dossier_max_bytes', 'dossier_max_rows', 'refresh'].some(key => args[key] !== undefined)) throw new Error('Dossier parameters require style=dossier');
        const style = args?.style === 'llm' ? 'llm' : '';
        const key = `${session.dbRevision}|${args?.ea ?? ''}|${args?.name ?? ''}|${style}`;
        let result = session.cache.get(key);
        if (!result) {
          result = await mgr.rpc(session, 'decompile', { ea: args?.ea, name: args?.name, style });
          session.cache.set(key, result);
          if (session.cache.size > 256) session.cache.delete(session.cache.keys().next().value);
        }
        const code = String(result.code ?? '');
        const base = {
          ea: result.ea,
          name: result.name,
          size: result.size,
          lines: result.lines,
          target: session.target,
          ...(result._ig5 || mgr.evidence?.(session) || {}),
          ...(result._ig5 ? { _ig5: result._ig5 } : {}),
          ...(result.meta ? { meta: result.meta } : {}),
          ...(result.addresses ? { addresses: result.addresses } : {}),
        };
        if (code.length > 12_000) {
          const file = spill(session, result.ea, code);
          return {
            ...base,
            spilled: true,
            path: file,
            preview: code.slice(0, 2_000),
            note: '伪代码超过 12KB，已落盘为工件；用 read 工具按 offset/limit 分页细读该文件',
          };
        }
        return { ...base, code };
      },
    },
    {
      name: 'ig5_close',
      description:
        'Close one open target and recycle its worker process. The analysis database stays on disk next to the target; reopening with ig5_open reuses it.',
      parameters: {
        type: 'object',
        properties: { target: { type: 'string', description: 'Target path to close' } },
        required: ['target'],
      },
      output: { schema: { type: 'object', additionalProperties: true }, render: textRender },
      async execute(args) {
        const target = requireString(args, 'target');
        const existed = await mgr.close(target);
        return { target, closed: existed };
      },
    },
    {
      name: 'ig5_xrefs',
      description:
        'Cross-references of an open target: references to an address/function, from it, or to strings matching a substring (str). Rows carry the other side EA and its containing function. Read-only.',
      parameters: {
        type: 'object',
        properties: {
          target: { type: 'string', description: 'Target path previously opened with ig5_open' },
          ea: { type: 'string', description: 'Hex address, e.g. 0x140001070' },
          name: { type: 'string', description: 'Exact function name (alternative to ea)' },
          str: { type: 'string', description: 'String substring — lists xrefs to every matching string literal' },
          direction: { type: 'string', description: '"to" (default) or "from"' },
          limit: { type: 'number', description: 'Max rows (default 30, max 200)' },
        },
        required: ['target'],
      },
      output: { schema: { type: 'object', additionalProperties: true }, render: textRender },
      async execute(args) {
        const target = requireString(args, 'target');
        return mgr.rpc(mgr.get(target), 'xrefs', {
          ea: args?.ea || '',
          name: args?.name || '',
          str: args?.str || '',
          direction: args?.direction === 'from' ? 'from' : 'to',
          limit: args?.limit,
        });
      },
    },
    {
      name: 'ig5_rename',
      description:
        'Rename a function or label. WRITE OPERATION: gated behind one-time human approval and recorded in approvals.jsonl. Provide ea or name plus new_name.',
      parameters: {
        type: 'object',
        properties: {
          target: { type: 'string', description: 'Target path previously opened with ig5_open' },
          ea: { type: 'string', description: 'Hex address' },
          name: { type: 'string', description: 'Current function name (alternative to ea)' },
          new_name: { type: 'string', description: 'New name' },
        },
        required: ['target', 'new_name'],
      },
      output: { schema: { type: 'object', additionalProperties: true }, render: textRender },
      async execute(args) {
        const target = requireString(args, 'target');
        if (!args?.new_name || !String(args.new_name).trim()) throw new Error('new_name is required');
        return mgr.rpc(mgr.get(target), 'rename', {
          ea: args?.ea || '',
          name: args?.name || '',
          new_name: String(args.new_name).trim(),
        });
      },
    },
    {
      name: 'ig5_patch_bytes',
      description:
        'Patch raw bytes at an address, e.g. hex "74 05" or "74E8". WRITE OPERATION: gated behind one-time human approval; the result carries before/after hex for the diff and everything is recorded in approvals.jsonl.',
      parameters: {
        type: 'object',
        properties: {
          target: { type: 'string', description: 'Target path previously opened with ig5_open' },
          ea: { type: 'string', description: 'Hex address to patch' },
          hex: { type: 'string', description: 'Byte payload as hex, spaces optional' },
          expected: { type: 'string', description: 'Expected original hex bytes; mismatch rejects before mutation' },
        },
        required: ['target', 'ea', 'hex'],
      },
      output: { schema: { type: 'object', additionalProperties: true }, render: textRender },
      async execute(args) {
        const target = requireString(args, 'target');
        requireString(args, 'ea');
        requireString(args, 'hex');
        return mgr.rpc(mgr.get(target), 'patch', { ea: args.ea, hex: args.hex, expected: args.expected });
      },
    },
    {
      name: 'ig5_comment',
      description:
        'Set a disassembly comment at an address. WRITE OPERATION: gated behind one-time human approval and recorded.',
      parameters: {
        type: 'object',
        properties: {
          target: { type: 'string', description: 'Target path previously opened with ig5_open' },
          ea: { type: 'string', description: 'Hex address' },
          name: { type: 'string', description: 'Function name (alternative to ea)' },
          text: { type: 'string', description: 'Comment text' },
          repeatable: { type: 'boolean', description: 'Repeatable comment (default false)' },
        },
        required: ['target', 'text'],
      },
      output: { schema: { type: 'object', additionalProperties: true }, render: textRender },
      async execute(args) {
        const target = requireString(args, 'target');
        if (!args?.text) throw new Error('text is required');
        return mgr.rpc(mgr.get(target), 'comment', {
          ea: args?.ea || '',
          name: args?.name || '',
          text: String(args.text),
          repeatable: args?.repeatable === true,
        });
      },
    },
    {
      name: 'ig5_calls',
      description:
        'Call graph of a function: callees (who it calls, with reference counts) or callers (who calls it). Read-only; pairs well with ig5_decompile style=llm.',
      parameters: {
        type: 'object',
        properties: {
          target: { type: 'string', description: 'Target path previously opened with ig5_open' },
          ea: { type: 'string', description: 'Hex address' },
          name: { type: 'string', description: 'Function name (alternative to ea)' },
          direction: { type: 'string', description: '"callees" (default) or "callers"' },
          limit: { type: 'number', description: 'Max rows (default 30, max 200)' },
        },
        required: ['target'],
      },
      output: { schema: { type: 'object', additionalProperties: true }, render: textRender },
      async execute(args) {
        const target = requireString(args, 'target');
        return mgr.rpc(mgr.get(target), 'calls', {
          ea: args?.ea || '',
          name: args?.name || '',
          direction: args?.direction === 'callers' ? 'callers' : 'callees',
          limit: args?.limit,
        });
      },
    },
    {
      name: 'ig5_analyze',
      description:
        'Explicit static analysis-engine control: create_function, delete_function, undefine, mark_code, reanalyze. Range analysis does not certify completion of the whole program. WRITE OPERATION: approval-gated and recorded.',
      parameters: {
        type: 'object',
        properties: {
          target: { type: 'string', description: 'Target path previously opened with ig5_open' },
          action: {
            type: 'string',
            description: 'One of: create_function, delete_function, undefine, mark_code, reanalyze',
          },
          ea: { type: 'string', description: 'Hex address' },
          end: { type: 'string', description: 'Hex end address (create_function / mark_code ranges)' },
          size: { type: 'number', description: 'Byte count (undefine default 16; range fallback 4096)' },
        },
        required: ['target', 'action'],
      },
      output: { schema: { type: 'object', additionalProperties: true }, render: textRender },
      async execute(args) {
        const target = requireString(args, 'target');
        const action = requireString(args, 'action');
        if (!['create_function', 'delete_function', 'undefine', 'mark_code', 'reanalyze'].includes(action)) {
          throw new Error(`unknown action: ${action}`);
        }
        return mgr.rpc(mgr.get(target), 'analyze', {
          action,
          ea: args?.ea || '',
          end: args?.end || '',
          size: args?.size,
        });
      },
    },
    {
      name: 'ig5_set_type',
      description:
        'Apply a type to an address/function: either a local-types name (typename) or a C declaration (decl, e.g. "int check_serial(int a, int b)"). WRITE OPERATION: approval-gated; uses parse_decl + apply_tinfo.',
      parameters: {
        type: 'object',
        properties: {
          target: { type: 'string', description: 'Target path previously opened with ig5_open' },
          ea: { type: 'string', description: 'Hex address' },
          name: { type: 'string', description: 'Function name (alternative to ea)' },
          decl: { type: 'string', description: 'C declaration snippet' },
          typename: { type: 'string', description: 'Existing local-type name' },
        },
        required: ['target'],
      },
      output: { schema: { type: 'object', additionalProperties: true }, render: textRender },
      async execute(args) {
        const target = requireString(args, 'target');
        if (!args?.decl && !args?.typename) throw new Error('decl or typename is required');
        return mgr.rpc(mgr.get(target), 'set_type', {
          ea: args?.ea || '',
          name: args?.name || '',
          decl: args?.decl || '',
          typename: args?.typename || '',
        });
      },
    },
    {
      name: 'ig5_bytes',
      description:
        'Read raw bytes currently in the analysis database at an address (static view). Returns hex.',
      parameters: {
        type: 'object',
        properties: {
          target: { type: 'string', description: 'Target path previously opened with ig5_open' },
          ea: { type: 'string', description: 'Hex address' },
          name: { type: 'string', description: 'Function name (alternative to ea)' },
          size: { type: 'number', description: 'Byte count (default 64, max 4096)' },
        },
        required: ['target'],
      },
      output: { schema: { type: 'object', additionalProperties: true }, render: textRender },
      async execute(args) {
        const target = requireString(args, 'target');
        return mgr.rpc(mgr.get(target), 'bytes', {
          ea: args?.ea || '',
          name: args?.name || '',
          size: args?.size,
        });
      },
    },
    {
      name: 'ig5_search',
      description:
        'Byte-pattern search across the analysis database with ?? wildcards, e.g. "48 8B ?? 90" or "637C777B" for the AES sbox. Returns hit EAs. Read-only.',
      parameters: {
        type: 'object',
        properties: {
          target: { type: 'string', description: 'Target path previously opened with ig5_open' },
          pattern: { type: 'string', description: 'Hex pattern, space-separated, ?? = wildcard byte' },
          start: { type: 'string', description: 'Hex start address (default first segment)' },
          end: { type: 'string', description: 'Hex end address' },
          limit: { type: 'number', description: 'Max hits (default 30, max 200)' },
        },
        required: ['target', 'pattern'],
      },
      output: { schema: { type: 'object', additionalProperties: true }, render: textRender },
      async execute(args) {
        const target = requireString(args, 'target');
        requireString(args, 'pattern');
        return mgr.rpc(mgr.get(target), 'search', {
          pattern: args.pattern,
          start: args?.start || '',
          end: args?.end || '',
          limit: args?.limit,
        });
      },
    },
    {
      name: 'ig5_listing',
      description:
        'Enumerate static structures: segments, imports, exports (actual export directory, may be partial/unsupported), or entries (analysis entrypoints, NOT exports; may include TLS callbacks and program entry). Preserve source, entryKind and diagnostics. Paged, read-only.',
      parameters: {
        type: 'object',
        properties: {
          target: { type: 'string', description: 'Target path previously opened with ig5_open' },
          kind: { type: 'string', enum: ['segments', 'imports', 'exports', 'entries'], description: 'exports is distinct from analysis entries/TLS callbacks' },
          offset: { type: 'number', description: 'Skip first N rows' },
          limit: { type: 'number', description: 'Max rows (default 100, max 500)' },
        },
        required: ['target', 'kind'],
      },
      output: { schema: { type: 'object', additionalProperties: true }, render: textRender },
      async execute(args) {
        const target = requireString(args, 'target');
        const kind = requireString(args, 'kind');
        if (!['segments', 'imports', 'exports', 'entries'].includes(kind)) throw new Error(`unknown kind: ${kind}`);
        return mgr.rpc(mgr.get(target), 'listing', { kind, offset: args?.offset, limit: args?.limit });
      },
    },
    {
      name: 'ig5_undo',
      description:
        'Roll back the most recent IG5 write operation via the in-worker operation journal (bytes/rename/comment/set_type/create_function/delete_function). action=list lists the journal without undoing. WRITE OPERATION: approval-gated.',
      parameters: {
        type: 'object',
        properties: {
          target: { type: 'string', description: 'Target path previously opened with ig5_open' },
          action: { type: 'string', description: '"list" to inspect the journal (default: undo one step)' },
        },
        required: ['target'],
      },
      output: { schema: { type: 'object', additionalProperties: true }, render: textRender },
      async execute(args) {
        const target = requireString(args, 'target');
        return mgr.rpc(mgr.get(target), 'undo', { action: args?.action === 'list' ? 'list' : 'undo' });
      },
    },
    {
      name: 'ig5_scan',
      description:
        'Bounded static sweep in Reverse/Ghidra: AES, MD5/shared initial-state, SHA-256/SHA-512 and CRC constants; categorized API imports; sampled segment entropy and string families. `behaviors` groups categorized APIs per function and names multi-API patterns found inside one function (for example another-process memory access, remote code injection, service/driver loading), including API names stored as strings; start there for a first overview, then drill down with ig5_decompile/ig5_xrefs. `packing` judges the file itself (entry point, empty or high-entropy executable sections, imports) as plain/suspected/protected/packed and says it did not unpack; check it first on unknown samples. `ruleMatches` applies the built-in signature table (packers/protectors, installers, managed runtimes) or a caller-supplied restricted YARA-style source (`rules`) to the same sampled bytes; each hit is a signature lead, not proof of packing, behavior or identity. Returns addresses, evidence, coverage and truncation. Hits, patterns and high entropy are clues, not proof of behavior, intent or an algorithm. Read-only.',
      parameters: {
        type: 'object',
        properties: {
          target: { type: 'string', description: 'Target path previously opened with ig5_open' },
          max_bytes: { type: 'number', description: 'Global sampled bytes: default 8 MiB, maximum 64 MiB' },
          max_segment_bytes: { type: 'number', description: 'Per-segment sampled bytes: default 1 MiB, maximum 16 MiB' },
          max_matches: { type: 'number' }, max_imports: { type: 'number' }, max_strings: { type: 'number' },
          max_segments: { type: 'number' }, max_api_matches: { type: 'number' }, max_string_chars: { type: 'number' },
          max_rule_matches: { type: 'number', description: 'Recorded rule-match locations: default 256, maximum 4096' },
          rules: {
            type: 'string', maxLength: 65536,
            description: 'Optional restricted YARA-style rule source that replaces the built-in signature table. Supports text and hex strings (?? / ?h / h? wildcards), description meta and conditions over $ids with all/any/N of them, not, and, or, parentheses. Jumps, regex, alternatives, fullword, counts and for-loops are rejected. Max 64 rules, 256 strings, 256 bytes per pattern.',
          },
        },
        required: ['target'],
      },
      output: { schema: { type: 'object', additionalProperties: true }, render: textRender },
      async execute(args) {
        const target = requireString(args, 'target');
        const params = {};
        for (const key of ['max_bytes', 'max_segment_bytes', 'max_matches', 'max_imports', 'max_strings', 'max_segments', 'max_api_matches', 'max_string_chars', 'max_rule_matches']) if (args[key] !== undefined) params[key] = args[key];
        if (args.rules !== undefined) {
          if (typeof args.rules !== 'string' || !args.rules.trim()) throw new Error('rules must be a non-empty restricted YARA-style source string');
          if (Buffer.byteLength(args.rules, 'utf8') > 65536) throw new Error('rules is longer than 65536 bytes');
          params.rules = args.rules;
        }
        return mgr.rpc(mgr.get(target), 'scan', params);
      },
    },
    {
      name: 'ig5_run_idapython',
      description:
        'Execute approved Python in the selected analysis worker and capture bounded stdout. The bundled core exposes currentProgram, flat_api and a documented common legacy Reverse Python API subset; unavailable APIs fail explicitly. Database writes use one transaction with session Undo; external Python effects are not reversible. This is not a sandbox. Hanging scripts are stopped with their owned worker by the RPC timeout.',
      parameters: {
        type: 'object',
        properties: {
          target: { type: 'string', description: 'Target path previously opened with ig5_open' },
          code: { type: 'string', description: 'Python source; bundled core: Ghidra FlatProgramAPI/currentProgram or documented legacy Reverse API subset, max 64 KiB' },
        },
        required: ['target', 'code'],
      },
      output: { schema: { type: 'object', additionalProperties: true }, render: textRender },
      async execute(args) {
        const target = requireString(args, 'target');
        const code = requireString(args, 'code');
        return mgr.rpc(mgr.get(target), 'idapython', { code }, cfg.requestTimeoutMs);
      },
    },
    {
      name: 'ig5_dbg',
      description:
        'Debug lane using bundled x64dbg by default. Optional paired VMCI guest execution requires backend=x64dbg plus an explicitly inspected guest_profile and guest_binding_sha256 on every call; targets must match its pre-provisioned catalog. op=recover queries the original authenticated terminal cleanup receipt after disconnect, without executing a target: send only target/op/backend/guest_profile/guest_binding_sha256 and optional engine/control; omit timeout and expected_run_id/expected_stop_seq. No matching retained execution is not cleanup proof. Host/bridge exit alone cannot release guest custody. Optional win32/Bochs require the commercial Reverse provider. Approval-gated; start executes the debuggee. Runtime addresses must not be confused with static database addresses.',
      parameters: {
        type: 'object',
        properties: {
          target: { type: 'string', description: 'Target path previously opened with ig5_open' },
          op: {
            type: 'string',
            description: 'load | start | bpt | unbpt | regs | setreg | threads | callstack | modules | state | event | step | stepover | trace | apitrace | cont | suspend | readmem | writemem | stop | recover',
          },
          kind: { type: 'string', enum: ['software', 'hardware'], default: 'software', description: 'Breakpoint kind for bpt/unbpt' },
          access: { type: 'string', enum: ['execute', 'write', 'readwrite'], default: 'execute', description: 'Hardware breakpoint access' },
          backend: { type: 'string', enum: ['auto', 'x64dbg', 'bochs', 'win32'], description: 'Explicit debugger selection; auto resumes the selected debugger, otherwise uses the configured default (bundled x64dbg). bochs/win32 require the commercial Reverse provider.' },
          guest_profile: { type: 'string', description: 'Configured VMCI guest profile alias; requires explicit backend=x64dbg and its inspected binding digest on every guest call' },
          guest_binding_sha256: { type: 'string', pattern: '^[a-f0-9]{64}$', description: 'Exact bindingSha256 returned by ig5_profile guest_debug; fixes guest/catalog/key-reference configuration' },
          control: { type: 'string', enum: ['claim', 'takeover', 'release'], description: 'Explicit approval-gated debugger ownership change' },
          expected_stop_seq: { type: 'number', description: 'Reject a plan made for a previous debugger pause' },
          expected_run_id: { type: 'string' },
          reg: { type: 'string', description: 'Register name for setreg' },
          value: { type: 'string', description: 'Integer register value for setreg, decimal or hex' },
          ea: { type: 'string', description: 'Hex address (bpt/unbpt/readmem/writemem)' },
          rva: { type: 'string', description: 'Explicit main-module RVA for x64dbg; mapped against the current loaded module' },
          address_space: { type: 'string', enum: ['runtime', 'database', 'rva'], description: 'Explicit address interpretation for x64dbg ea; default runtime' },
          max_steps: { type: 'number', description: 'Bounded x64dbg single-step trace budget' },
          api_names: { type: 'array', items: { type: 'string' }, minItems: 1, maxItems: 64, description: 'op=apitrace only: optional imported API names (case-insensitive; module!name and #ordinal accepted). Omit to select imported APIs in the behavior taxonomy, breadth-first.' },
          max_api_calls: { type: 'number', description: 'op=apitrace only: recorded API-entry hit budget, 1..1024 (default 128)' },
          max_apis: { type: 'number', description: 'op=apitrace only: selected imported API budget, 1..256 (default 64)' },
          record_trace: { type: 'boolean', description: 'op=trace only: record actual x64 registers, opcode bytes and memory reads to a hash-bound artifact, max_steps 1..512. Uses approved native single steps; optional explicit ABI widths below enable recoveryArgs.' },
          record_image: { type: 'boolean', description: 'With record_trace, capture readable main-image pages at the same initial pause, max module 8 MiB. Saves holes and provenance; does not reconstruct imports or patch the original file.' },
          record_events: { type: 'boolean', description: 'With record_trace, optionally capture bytes at decoded store locations before/after each owned native stop. Shares the original 1 MiB evidence/512 stop/40s budget; preserves unavailable bytes and pause mismatches. Not causal CPU write or VM phase proof. Guest requires an updated verified bundle.' },
          until: { type: 'string', description: 'Optional trace stop address as an explicit main-module runtime VA, hex' },
          interrupt_method: { type: 'string', enum: ['native-pause', 'break-process'], description: 'op=suspend only. break-process uses the standard Windows breakpoint interrupt on the already debugged process inside our cleanup job; can interrupt blocked system calls. May switch the current thread; refresh regs/threads afterward.' },
          thread_id: { type: 'number', description: 'op=regs only: read a selected existing owned x64 debuggee thread while the debugger is paused. Returns selectedThreadRegs and readonly selectedThreadDebuggerVisibility; failed NT visibility queries remain null/unknown. Preserves the active debugger thread/cache.' },
          anti_debug_profile: { type: 'string', enum: ['none', 'scyllahide-thread-context'], description: 'Explicit x64dbg op=start only. Installs the bundled GPL-3.0 ScyllaHide user-mode context hooks into the owned debuggee after startup pause. Modifies the target environment; records provenance. No drivers or OS security settings changes. Default none.' },
          exception_disposition: { type: 'string', enum: ['preserve', 'handled'], description: 'Explicit backend=x64dbg op=cont at an observed exception pause only. handled resumes with DBG_CONTINUE and consumes that exception; preserve keeps the debugger default. Changes exception delivery, requires approval, and records the consumed exception.' },
          trace_inputs: { type: 'array', minItems: 2, maxItems: 2, items: { type: 'string', enum: ['dil', 'sil', 'di', 'si', 'edi', 'esi', 'rdi', 'rsi', 'cl', 'dl', 'cx', 'dx', 'ecx', 'edx', 'rcx', 'rdx'] } },
          trace_output: { type: 'string', enum: ['al', 'ax', 'eax', 'rax'] },
          expected: { type: 'string', description: 'Optional original register or memory value checked before modification' },
          size: { type: 'number', description: 'Memory byte count (default 64); hardware bpt size 1|2|4|8, execute requires 1' },
          hex: { type: 'string', description: 'Byte payload (writemem)' },
          path: { type: 'string', description: 'Debuggee path override (start)' },
          timeout: { type: 'number', description: 'Event wait seconds (default 15; start/cont 30; recorded trace 45), max 60. Explicit backend=x64dbg op=cont allows max 120 with bounded RPC cleanup margin; capture/solver budgets remain unchanged.' },
        },
        required: ['target', 'op'],
      },
      output: { schema: { type: 'object', additionalProperties: true }, render: textRender },
      async execute(args) {
        const target = requireString(args, 'target');
        const op = requireString(args, 'op');
        if (!['load', 'start', 'bpt', 'unbpt', 'regs', 'setreg', 'threads', 'callstack', 'step', 'stepover', 'cont', 'suspend', 'readmem', 'writemem', 'stop', 'state', 'event', 'modules', 'trace', 'apitrace', 'recover'].includes(op)) {
          throw new Error(`unknown dbg op: ${op}`);
        }
        if (args.guest_profile !== undefined || args.guest_binding_sha256 !== undefined || op === 'recover') {
          if (args.backend !== 'x64dbg' || typeof args.guest_profile !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$/.test(args.guest_profile)
              || !/^[a-f0-9]{64}$/.test(args.guest_binding_sha256 || '')) throw new Error('Guest debugging requires backend=x64dbg, guest_profile and its inspected guest_binding_sha256');
        }
        if (op === 'recover') {
          validateGuestRecoveryArgs(args);
          return mgr.recoverGuest(target, args);
        }
        if (op === 'bpt' && args.kind === 'hardware' && args.size !== undefined && ![1, 2, 4, 8].includes(args.size)) throw new Error('Hardware breakpoint size must be 1, 2, 4 or 8');
        if (args.record_trace !== undefined && typeof args.record_trace !== 'boolean') throw new Error('record_trace must be boolean');
        if (args.record_trace && op !== 'trace') throw new Error('record_trace requires op=trace');
        if (args.record_image !== undefined && typeof args.record_image !== 'boolean') throw new Error('record_image must be boolean');
        if (args.record_image && !args.record_trace) throw new Error('record_image requires record_trace=true');
        if (args.record_events !== undefined && typeof args.record_events !== 'boolean') throw new Error('record_events must be boolean');
        if (args.record_events && !args.record_trace) throw new Error('record_events requires record_trace=true');
        if ((args.trace_inputs || args.trace_output) && !args.record_trace) throw new Error('Trace recovery registers require record_trace=true');
        if (args.until !== undefined && op !== 'trace') throw new Error('until requires op=trace');
        if (args.api_names !== undefined) {
          if (op !== 'apitrace') throw new Error('api_names requires op=apitrace');
          if (!Array.isArray(args.api_names) || args.api_names.length < 1 || args.api_names.length > 64
              || args.api_names.some(name => typeof name !== 'string' || !name || name.length > 64 || /[\x00-\x1f\x7f]/.test(name))) {
            throw new Error('api_names requires 1..64 printable names of at most 64 characters');
          }
        }
        if (args.max_api_calls !== undefined && (op !== 'apitrace' || !Number.isSafeInteger(args.max_api_calls) || args.max_api_calls < 1 || args.max_api_calls > 1024)) throw new Error('max_api_calls requires op=apitrace and an integer in 1..1024');
        if (args.max_apis !== undefined && (op !== 'apitrace' || !Number.isSafeInteger(args.max_apis) || args.max_apis < 1 || args.max_apis > 256)) throw new Error('max_apis requires op=apitrace and an integer in 1..256');
        if (args.interrupt_method !== undefined && (op !== 'suspend' || !['native-pause', 'break-process'].includes(args.interrupt_method))) throw new Error('interrupt_method requires a typed op=suspend choice');
        if (args.thread_id !== undefined && (op !== 'regs' || !Number.isSafeInteger(args.thread_id) || args.thread_id <= 0 || args.thread_id >= 2 ** 32)) throw new Error('thread_id requires op=regs and a positive DWORD thread ID');
        if (args.anti_debug_profile !== undefined && (!['none', 'scyllahide-thread-context'].includes(args.anti_debug_profile) || args.anti_debug_profile !== 'none' && (op !== 'start' || args.backend !== 'x64dbg'))) throw new Error('anti_debug_profile requires an explicit typed x64dbg start');
        if (args.exception_disposition !== undefined && (!['preserve', 'handled'].includes(args.exception_disposition) || args.exception_disposition !== 'preserve' && (op !== 'cont' || args.backend !== 'x64dbg'))) throw new Error('exception_disposition requires an explicit typed x64dbg continuation');
        if (args.record_trace && args.max_steps !== undefined && (!Number.isSafeInteger(args.max_steps) || args.max_steps < 1 || args.max_steps > 512)) throw new Error('Recorded trace max_steps must be 1..512');
        if (args.trace_inputs && !['dil,sil', 'di,si', 'edi,esi', 'rdi,rsi', 'cl,dl', 'cx,dx', 'ecx,edx', 'rcx,rdx'].includes(args.trace_inputs.join(','))) throw new Error('Trace inputs must be an explicit equal-width RDI/RSI or RCX/RDX pair');
        const timeout = debugTimeout(args, cfg);
        return mgr.rpc(mgr.get(target), 'dbg', {
          op,
          backend: args?.backend || 'auto',
          guest_profile: args.guest_profile, guest_binding_sha256: args.guest_binding_sha256,
          kind: args.kind || 'software', access: args.access || 'execute',
          reg: args?.reg,
          value: args?.value,
          ea: args?.ea || '',
          size: args?.size,
          hex: args?.hex || '',
          path: args?.path || '',
          timeout: timeout.seconds,
          rva: args.rva, count: args.max_steps, addressSpace: args.address_space, expected: args.expected,
          api_names: args.api_names, max_api_calls: args.max_api_calls, max_apis: args.max_apis,
          record_trace: args.record_trace, record_image: args.record_image, record_events: args.record_events, until: args.until, trace_inputs: args.trace_inputs, trace_output: args.trace_output,
          interrupt_method: args.interrupt_method,
          thread_id: args.thread_id,
          anti_debug_profile: args.anti_debug_profile,
          exception_disposition: args.exception_disposition,
          control: args.control, expected_stop_seq: args.expected_stop_seq, expected_run_id: args.expected_run_id,
        }, timeout.rpcTimeoutMs);
      },
    },
    {
      name: 'ig5_export_diff',
      description:
        'Export a patched copy and changes report for audited byte regions, reading their current bytes from the open database so undone patches are excluded. Read-only to the analysis database; writes deliverable files.',
      parameters: {
        type: 'object',
        properties: { target: { type: 'string', description: 'Target path previously opened with ig5_open' } },
        required: ['target'],
      },
      output: { schema: { type: 'object', additionalProperties: true }, render: textRender },
      async execute(args) {
        return exportPatchDiff({ target: requireString(args, 'target'), mgr, cfg });
      },
    },
    {
      name: 'ig5_struct',
      description:
        'Type system & Struct synthesizer (Local Types / Til). Define C struct declarations, inspect struct fields and offsets, list all user-defined types, or apply struct types to memory addresses. WRITE OPERATION (action=define/apply): approval-gated.',
      parameters: {
        type: 'object',
        properties: {
          target: { type: 'string', description: 'Target binary path (omit for active session)' },
          action: {
            type: 'string',
            enum: ['define', 'get', 'list', 'apply'],
            description: "Action to perform: 'define' (compile C struct decl), 'get' (inspect struct fields), 'list' (list local types), 'apply' (apply struct to EA)",
          },
          decl: { type: 'string', description: "C language struct or typedef declaration (required for action='define'). E.g., 'struct Context { int id; char name[32]; void *buf; };'" },
          name: { type: 'string', description: "Type/struct name (required for action='get' or 'apply')" },
          ea: { type: 'string', description: "Target address (hex string, required for action='apply')" },
          filter: { type: 'string', description: "Filter string for action='list'" },
          limit: { type: 'number', description: "Max results for action='list' (default 100)" },
        },
        required: ['action'],
        additionalProperties: false,
      },
      output: { schema: { type: 'object', additionalProperties: true }, render: textRender },
      async execute(args) {
        const target = args?.target || mgr.selectedTarget();
        if (!target) throw new Error('No open target found');
        return mgr.rpc(mgr.get(target), 'struct', {
          action: args.action,
          decl: args.decl,
          name: args.name,
          ea: args.ea,
          filter: args.filter,
          limit: args.limit,
        });
      },
    },
    {
      name: 'ig5_cfg',
      description:
        'Control Flow Graph (CFG) extraction. Generates a basic block topology map and standard Mermaid flowchart diagram (flowchart TD) for a function, revealing decision branches, loop cycles, and basic blocks. Read-only.',
      parameters: {
        type: 'object',
        properties: {
          target: { type: 'string', description: 'Target binary path (omit for active session)' },
          ea: { type: 'string', description: 'Function entry EA (e.g. 0x140001000)' },
          name: { type: 'string', description: 'Function name (alternative to ea)' },
        },
        required: [],
        additionalProperties: false,
      },
      output: { schema: { type: 'object', additionalProperties: true }, render: textRender },
      async execute(args) {
        const target = args?.target || mgr.selectedTarget();
        if (!target) throw new Error('No open target found');
        return mgr.rpc(mgr.get(target), 'cfg', { ea: args.ea, name: args.name });
      },
    },
    {
      name: 'ig5_slice',
      description:
        'Inspect decompiler variable metadata and optionally return pseudocode lines matching a variable name. Available metadata and lexical matching depend on the provider. This does not compute microcode slicing, complete def-use dependencies or taint analysis. Read-only.',
      parameters: {
        type: 'object',
        properties: {
          target: { type: 'string', description: 'Target binary path (omit for active session)' },
          ea: { type: 'string', description: 'Function EA (e.g. 0x140001000)' },
          var: { type: 'string', description: 'Optional variable name for provider-specific lexical pseudocode-line filtering; omit to inspect variable metadata.' },
        },
        required: ['ea'],
        additionalProperties: false,
      },
      output: { schema: { type: 'object', additionalProperties: true }, render: textRender },
      async execute(args) {
        const target = args?.target || mgr.selectedTarget();
        if (!target) throw new Error('No open target found');
        return mgr.rpc(mgr.get(target), 'slice', { ea: args.ea, var: args.var });
      },
    },
    {
      name: 'ig5_fingerprint',
      description:
        'Report compiler/ABI information and existing provider function classifications. The bundled core counts external/thunk functions only; this does not identify all static libraries or prove standard-library equivalence. Read-only.',
      parameters: {
        type: 'object',
        properties: {
          target: { type: 'string', description: 'Target binary path (omit for active session)' },
        },
        required: [],
        additionalProperties: false,
      },
      output: { schema: { type: 'object', additionalProperties: true }, render: textRender },
      async execute(args) {
        const target = args?.target || [...mgr.sessions.values()].find((s) => mgr.alive(s))?.target;
        if (!target) throw new Error('No open target found');
        return mgr.rpc(mgr.get(target), 'fingerprint', {});
      },
    },
    ...defineAdvancedTools(mgr, cfg, textRender),
    ...defineIntegrationTools(mgr, cfg, textRender),
    ...defineAnalysisTools(mgr, cfg, textRender),
    ...defineCaptureTools(ctx, mgr, cfg, textRender),
  ];
}

// ── ig5dash 会话投影（只折叠已提交的 tool 事件，model-visible ⟺ logged） ────
// ── 插件入口（具名导出，无 default export） ─────────────────────────────────
export const name = PLUGIN_ID;
export const inject = ['tools', 'sessionProjections'];

export function apply(ctx, config = {}) {
  const cfg = resolveConfig(config);
  diagAppend(cfg, `host: implementation=${IMPLEMENTATION_REVISION} module=${fileURLToPath(import.meta.url)}`);
  const mgr = new WorkerManager(cfg);
  // AnalysisArtifacts is installed by defineAnalysisTools later in registration.
  let failureRecords, capabilityAcceptance;
  Object.defineProperties(mgr, {
    failures: { get: () => failureRecords ||= new FailureRecords({ root: cfg.projectRoot, artifacts: mgr.analysis.artifacts }) },
    capabilityAcceptance: { get: () => capabilityAcceptance ||= new CapabilityAcceptance({ root: cfg.projectRoot, artifacts: mgr.analysis.artifacts, cfg }) },
  });
  mgr.coordination = installDelegationControl(ctx, cfg);
  mgr.memory = installLcmBridge(ctx, cfg);
  ctx.effect(() => () => mgr.memory.dispose());
  installDiagRoute(ctx, cfg);
  installJobsRoute(ctx, mgr, cfg);
  installDataRoute(ctx, mgr, cfg);
  installApprovalGate(ctx, cfg);

  ctx.effect(() => {
    // omp 的工具注册表只增不减：整批交给宿主先注册，Core/Full 之后只切激活集合
    const catalog = defineIg5Tools(ctx, mgr, cfg);
    if (typeof ctx.registerCatalog === 'function') ctx.registerCatalog(catalog);
    const definitions = catalog.map((definition) => {
      const execute = definition.execute;
      if (definition.name === 'ig5_profile') {
        definition.parameters.properties.address = { type: 'object', properties: {
          value: { type: 'string' }, space: { type: 'string', enum: ['ghidra_va','elf_vaddr','file_offset','module_offset','runtime_va'] },
          to_space: { type: 'string', enum: ['ghidra_va','elf_vaddr','file_offset','module_offset','runtime_va'] } },
          required: ['value','space','to_space'], additionalProperties: false, description: 'Use with target separately. Exact ELF PT_LOAD + actual Ghidra source mapping; BSS/overlays/ambiguity reject. module_offset is relative to lowest PT_LOAD vaddr; runtime_va remains unavailable without trusted live load context.' };
        definition.parameters.properties.capabilities = { type: 'boolean', const: true, description: 'Use separately: read current capability dimensions without probes or execution' };
        definition.description += ' capabilities=true reads capability dimensions and scoped acceptance history without probes.';
        definition.parameters.properties.memory = memorySchema;
        definition.parameters.properties.knowledge = knowledgeSchema;
        definition.description += ' knowledge={action:"status"|"search"|"methods"|"documents"|"read"} explicitly looks up local methods or imported original research texts. documents optionally accepts query; read uses the returned exact ref/cursor. Review notes and relatedReferences preserve caveats and links. Use separately, without target/engine. References are never current-target proof or execution permission.';
        definition.description += ' memory={action:"restore"|"search"|"read"|"expand"|"checkpoint"|"status"} accesses the executing session\'s local LCM history after compaction; source refs carry exact hashes, summaries are unverified navigation. Use memory separately.';
      }
      const isCapture = ['ig5_capture', 'ig5_capture_control'].includes(definition.name);
      const isGlobal = isCapture || ['ig5_profile', 'ig5_workspace', 'ig5_recovery', 'ig5_status', 'ig5_crypto', 'ig5_protocol', 'ig5_package'].includes(definition.name);
      const isData = isCapture || ['ig5_crypto', 'ig5_protocol', 'ig5_package'].includes(definition.name);
      if (!isCapture) definition.parameters.properties.engine = { type: 'string', enum: definition.name === 'ig5_doctor'
        ? ['reverse', 'ghidra', 'x64dbg'] : ['reverse', 'ghidra'],
        description: isData ? 'Optional result association or static source backend; standalone byte/file/ref analysis does not require an engine.' : 'Explicit backend. Omit to use the configured primary static engine; results identify their source.' };
      if (definition.name === 'ig5_profile') definition.parameters.properties.collaboration = {
        type: 'object', properties: { action: { type: 'string', enum: ['start', 'status'] },
          max_calls: { type: 'integer', minimum: 1, maximum: 1000, description: 'start only: persistent shared cap for parent + all descendant IG5 dispatches; cannot be reset/enlarged' } },
        required: ['action'], additionalProperties: false,
        description: 'Use separately BEFORE work: start shared budget, or status (exempt control-plane query). Counts all IG5 calls incl. child profile/open/evidence/errors, not just parent calls. No token/non-IG5 limit.' };
      if (!isCapture && IG5_WRITE_TOOLS.has(definition.name) && definition.name !== 'ig5_sync') definition.parameters.properties.expected_revision = {
        type: 'number', description: 'Reject this operation if the selected database revision has changed since planning' };
      definition.execute = (args = {}, execution) => mgr.scope.run({ engine: args.engine || (definition.name === 'ig5_ir' && cfg.reverseProvider !== 'bundled' ? 'ghidra' : cfg.defaultEngine), agentId: execution?.agent?.id || execution?.agent?.sessionId, signal: execution?.signal }, async () => {
        try {
        if (execution?.signal?.aborted) throw new Error('IG5 operation cancelled');
        if (definition.name === 'ig5_doctor' && args.operation === 'session')
          return jsonToolOutput(mgr.coordination.diagnose(execution?.agent, args));
        mgr.coordination.charge(execution?.agent, definition.name, args);
        await mgr.memory.activate(execution?.agent);
        if (args.engine) engineId(args.engine);
        const selected = !args.target && !isGlobal && !['ig5_open', 'ig5_doctor', 'ig5_bindiff', 'ig5_sync'].includes(definition.name)
          && !definition.parameters.required?.includes('target') ? mgr.selectedTarget() : args.target;
        if (selected) args = { ...args, target: selected };
        const standaloneKernel = definition.name === 'ig5_ir' && ['kernel', 'trace', 'lift', 'project'].includes(args.level);
        const session = selected && !isData && !standaloneKernel ? mgr.get(selected) : null;
        const selectedAttachment = session?.attachmentId;
        const perform = async () => {
        if (session?.state === 'opening') {
          await mgr.launching.get(session.key);
          if (session.state !== 'open' || mgr.get(session.target, session.engine) !== session) throw new Error('Target did not finish opening');
        }
        // A failed predecessor can recycle its worker while this operation is
        // queued. execute() resolves target again; never let old planning and
        // expected_revision checks transfer to a newly opened attachment.
        if (session && (mgr.get(session.target, session.engine) !== session
          || selectedAttachment !== undefined && session.attachmentId !== selectedAttachment)) {
          throw Object.assign(new Error('Target session changed while this operation was queued; reopen its context and review the operation again'), { code: 'STALE_SESSION_CONTEXT' });
        }
        mgr.checkCancelled();
        if (session?.closing) throw new Error('Target is closing; wait for it to finish');
        if (args.expected_revision !== undefined && (!session || session.dbRevision !== args.expected_revision)) {
          throw new Error('Database revision changed; read current evidence and review the operation again');
        }
        let result = await execute(args, execution);
        if (['ig5_xrefs','ig5_calls','ig5_cfg'].includes(definition.name) && result && typeof result === 'object') {
          const rows = result.hits || result.calls || result.blocks || [];
          const total = result.total ?? result.total_blocks;
          const truncated = result.truncated === true || Number.isSafeInteger(total) && total > rows.length;
          const incomplete = session?.info?.analysisComplete === false || session?.info?.partial === true;
          result = { ...result, queryState: { status: result.error ? 'error' : truncated ? 'truncated' : incomplete ? 'analysis_incomplete' : rows.length ? 'observed' : 'empty',
            empty: rows.length === 0, returned: rows.length, total: Number.isSafeInteger(total) ? total : null,
            analysisComplete: typeof session?.info?.analysisComplete === 'boolean' ? session.info.analysisComplete : null,
            coverage: 'provider-observations-only', unresolvedIndirectCalls: 'unknown' } };
        }
        if (definition.name === 'ig5_decompile' && args.style === 'dossier' && args.operation !== 'read') {
          try { mgr.capabilityAcceptance.registerDossier(result); }
          catch (error) { diagAppend(cfg, `host: capability acceptance not indexed: ${error.code || 'ACCEPTANCE_RECORD_FAILED'}`); }
        }
        return jsonToolOutput(result && typeof result === 'object' && !Array.isArray(result) && session && !isGlobal
          ? { ...result, _ig5: result._ig5 || mgr.evidence(session) } : result);
        };
        const batchControl = definition.name === 'ig5_decompile' && args.operation === 'batch' && ['cancel','status'].includes(args.batch?.action);
        const queuedRead = definition.name === 'ig5_decompile' && !batchControl || definition.name === 'ig5_workspace' || definition.name === 'ig5_profile' && args.address !== undefined;
        if (!session || !(IG5_WRITE_TOOLS.has(definition.name) || definition.name === 'ig5_export_diff' || queuedRead) || ['ig5_sync', 'ig5_dbg'].includes(definition.name)) return await perform();
        return await mgr.withSessions([session], perform);
        } catch (error) {
          // Keep the original Error/receipt and rejection semantics. Diagnostics are advisory.
          try {
            const current = args.target ? mgr.get(args.target) : null;
            const scope = current && mgr.alive(current) ? mgr.evidence(current) : null;
            const failure = mgr.failures.add({ operation: definition.name, scope, ...failureBinding(definition.name, args, mgr, error), error,
              planningKey: planningRequestKey({ tool: definition.name, ...args }, scope, planningImplementationDigest),
              runtimeDigest: runtimeIdentity(cfg, definition.name==='ig5_dbg'?'x64dbg':current?.engine||args.engine||cfg.defaultEngine),
              ...(error.analysisFailure?.failedStage || error.stage ? { failedStage: error.analysisFailure?.failedStage || error.stage } : {}) });
            if (error && typeof error === 'object' && Object.isExtensible(error)) error.investigationFailure = failure;
          } catch (diagnosticError) {
            if(error&&typeof error==='object'&&Object.isExtensible(error))error.investigationFailureStatus={persisted:false,code:diagnosticError.code||'FAILURE_RECORD_UNAVAILABLE'};
          }
          throw error;
        }
      });
      return definition;
    });
    const workflow = installWorkflow(ctx, { cfg, mgr, definitions, formatError: publicEngineError });
    mgr.workflow = workflow;
    return async () => {
      await workflow.dispose();
      await mgr.capture?.dispose();
      await mgr.analysis?.dispose();
      await mgr.kernel?.dispose();
      await mgr.trace?.dispose();
      await mgr.lifter?.dispose();
      await Promise.all([...mgr.sessions.values()].filter((s) => s.engine !== 'x64dbg').map((s) => mgr.close(s.target, true, s.engine, { force: true })));
      await Promise.all([...mgr.sessions.values()].map((s) => mgr.close(s.target, true, s.engine, { force: true })));
    };
  }, `${PLUGIN_ID}: ig5 tool surface`);

  const projections = ctx.get('sessionProjections');
  if (projections !== undefined && typeof projections.register === 'function') {
    ctx.effect(() => projections.register(ig5DashDefinition(), `${PLUGIN_ID}: ig5dash projection`));
  }
}
