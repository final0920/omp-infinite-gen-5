// Explicit live acceptance through the installed DSH CLI and installed IG5 tools.
import fs from 'node:fs';
import path from 'node:path';
import { spawn, spawnSync } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import assert from 'node:assert/strict';
import { buildPE64Fixture } from './fixtures/pe64.mjs';

const output = path.resolve(process.argv[2] || '');
assert(process.argv[2] && !fs.existsSync(output), 'Supply a new evidence directory');
fs.mkdirSync(output, { recursive: true });
const fixture = buildPE64Fixture(), target = path.join(output, 'owned-review-smoke.exe');
fs.writeFileSync(target, fixture.image);
const electron = path.join(process.env.LOCALAPPDATA, 'Programs/DeepSeek Harness/DeepSeek Harness.exe');
const modules = path.join(path.dirname(electron), 'resources/app.asar/dsh/node_modules');
const providerPatch = path.join(output, 'provider.private.patch.yml');
const discovery = `const fs=require('fs'),path=require('path');const yaml=require(${JSON.stringify(path.join(modules, 'yaml'))});const rows=yaml.parseDocument(fs.readFileSync(path.join(process.env.USERPROFILE,'.dsh/profiles/desktop/cordis.patch.yml'),'utf8')).toJSON();const row=rows.find(r=>r.id==='llm-pi-ai');const p=row?.config?.providers?.experi;if(!p||!p.models?.some(m=>(typeof m==='string'?m:m.id)==='deepseek-v4.1-flash'))throw Error('Previously verified provider route is no longer configured');fs.writeFileSync(${JSON.stringify(providerPatch)},JSON.stringify([{id:row.id,config:{providers:{experi:p}}}]),{flag:'wx',mode:0o600});console.log(JSON.stringify({provider:'experi',model:'deepseek-v4.1-flash'}));`;
const env = { ...process.env, ELECTRON_RUN_AS_NODE: '1', DSH_HOME: path.join(process.env.USERPROFILE, '.dsh'), DSH_TELEMETRY_DISABLED: '1', DSH_MAX_TOKENS_AS_SUCCESS: 'false' };
const discovered = spawnSync(electron, ['-e', discovery], { env, windowsHide: true, encoding: 'utf8', timeout: 15000 });
assert.equal(discovered.status, 0, 'Configured model route could not be resolved; private diagnostics withheld');
const route = JSON.parse(discovered.stdout.trim());
const plugin = path.join(process.env.USERPROFILE, '.dsh/plugins/dsh-infinite-gen-5');
const log = path.join(output, 'tools.jsonl'), guardPatch = path.join(output, 'guard.patch.yml');
fs.writeFileSync(guardPatch, JSON.stringify([{ insert: [
  { id: 'ig5-uxr-static', name: path.join(plugin, 'index.js'), config: { toolset: 'full', defaultEngine: 'ghidra', memory: false, artifactDir: path.join(output, 'artifacts'), projectRoot: path.join(output, 'projects'), stateRoot: path.join(output, 'state') } },
  { id: 'ig5-uxr-live-guard', name: fileURLToPath(new URL('review_smoke_guard.mjs', import.meta.url)), config: { log, target, ea: fixture.ea } },
] }]));
const prompt = `Run the user-authorized smoke on ONLY ${JSON.stringify(target)}. Use engine=ghidra for every target tool. Exactly in order: ig5_open path=target background=false; ig5_funcs target limit=5; ig5_decompile target ea=0x140001000; then ig5_dbg target backend=x64dbg op=load; op=start; op=regs; op=step; op=stop; finally ig5_close target engine=ghidra. These debugging operations are explicitly authorized by bai for this generated fixture only. Do not call other tools, modify profiles or run scripts. Stop and report tool failures, always stop any started debuggee and close the target. Final output JSON {"completed":true,"limitations":[]}.`;
fs.writeFileSync(path.join(output, 'plan.json'), JSON.stringify({ route, targetSha256: createHash('sha256').update(fixture.image).digest('hex'), plugin, prompt, toolLimit: 20, elapsedLimitMs: 300000, targetExecutionAuthorized: true }, null, 2));
const child = spawn(electron, ['--expose-internals', path.join(modules, '@deepseek-ai/dsh-desktop-host/lib/cli.js'), '--profile', 'ig5-eval-v2', '--patch', providerPatch, '--patch', guardPatch], { cwd: output, env, windowsHide: true });
let buffer = '', seq = 0, received = false, exited = false, resolveIdle;
const pending = new Map(), events = [], idle = new Promise(resolve => { resolveIdle = resolve; });
child.stdout.on('data', chunk => {
  buffer += chunk.toString(); let at;
  while ((at = buffer.indexOf('\n')) >= 0) {
    const line = buffer.slice(0, at); buffer = buffer.slice(at + 1); let message;
    try { message = JSON.parse(line); } catch { continue; }
    if (message.id !== undefined && !message.method) {
      const waiter = pending.get(message.id);
      if (waiter) { pending.delete(message.id); message.error ? waiter.reject(new Error(message.error.message)) : waiter.resolve(message.result); }
    }
    if (message.method === 'session.event') { events.push(message.params.event); if (message.params.event.type === 'agent/inbox/spliced') received = true; }
    if (message.method === 'session.status' && received && message.params.status === 'idle') resolveIdle();
    if (message.method && message.id !== undefined) child.stdin.write(JSON.stringify({ jsonrpc: '2.0', id: message.id, error: { code: -32601, message: 'This static acceptance has no interactive permissions' } }) + '\n');
  }
});
child.stderr.on('data', () => {});
child.on('exit', () => { exited = true; for (const waiter of pending.values()) waiter.reject(new Error('DSH exited')); pending.clear(); resolveIdle(); });
function request(method, params, timeout = 30000) {
  return new Promise((resolve, reject) => {
    const id = ++seq, timer = setTimeout(() => { pending.delete(id); reject(new Error(`DSH ${method} timeout`)); }, timeout);
    pending.set(id, { resolve: value => { clearTimeout(timer); resolve(value); }, reject: error => { clearTimeout(timer); reject(error); } });
    child.stdin.write(JSON.stringify({ jsonrpc: '2.0', id, method, params }) + '\n');
  });
}
const result = { actualModelCall: true, targetExecutionAuthorized: true, pass: false, cleanupConfirmed: false };
const started = Date.now();
try {
  await request('initialize', { cwd: output, ...route, maxTokens: 4096 });
  await request('session/prompt', { sessionId: `ig5-uxr-${randomUUID()}`, contentBlocks: [{ type: 'text', text: prompt }] });
  let timer;
  await Promise.race([idle, new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('Model acceptance timeout')), 300000); })]).finally(() => clearTimeout(timer));
  const assistant = events.filter(event => event.type === 'assistant/message').at(-1);
  const content = assistant?.data?.message?.content || assistant?.data?.content || [];
  const text = content.filter(block => block.type === 'text').map(block => block.text).join('\n').replace(/^```(?:json)?\s*/, '').replace(/\s*```$/, '').trim();
  result.answer = JSON.parse(text);
} catch (error) { result.error = String(error.message).slice(0, 180); }
finally {
  if (!exited) { try { await request('shutdown', {}, 10000); } catch {} child.stdin.end(); }
  if (!exited) await Promise.race([new Promise(resolve => child.once('exit', resolve)), new Promise(resolve => setTimeout(resolve, 5000))]);
  result.cleanupConfirmed = exited; result.elapsedMs = Date.now() - started;
  fs.unlinkSync(providerPatch);
  fs.writeFileSync(path.join(output, 'events.json'), JSON.stringify(events, null, 2));
  const rows = fs.existsSync(log) ? fs.readFileSync(log, 'utf8').trim().split('\n').filter(Boolean).map(JSON.parse) : [];
  result.dispatches = rows.filter(row => row.phase === 'dispatch').length;
  result.denied = rows.filter(row => row.phase === 'dispatch' && !row.allowed).length;
  const values = rows.filter(row => row.phase === 'result');
  result.observed = values.map(row => ({tool:row.tool,op:row.args?.op,isError:row.result?.isError,value:row.result?.value}));
  const successful = (tool,op) => values.some(r => r.tool===tool && (op===undefined || r.args?.op===op) && r.result?.isError!==true && r.result?.value?.ok!==false);
  result.pass = result.cleanupConfirmed && result.denied===0 && successful('ig5_open') && successful('ig5_funcs') && successful('ig5_decompile') && ['load','start','regs','step','stop'].every(op=>successful('ig5_dbg',op)) && successful('ig5_close');
  fs.writeFileSync(path.join(output, 'acceptance.json'), JSON.stringify(result, null, 2));
  console.log(JSON.stringify(result));
}
if (!result.pass) process.exitCode = 1;
