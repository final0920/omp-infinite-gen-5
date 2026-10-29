import test from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { LiftJobs, validateLift } from '../source/lift_jobs.js';
import { defineIntegrationTools } from '../integration_tools.js';

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ig5-lift-tests-'));
const selected = { target: path.join(dir,'fixture.exe'), level:'lift', ea:'0x140001000', initial_flags:'0x0' };
const tick = () => new Promise(resolve => setImmediate(resolve));
function fixture(onRequest) {
  const children = [];
  const jobs = new LiftJobs({ artifactDir:dir, host:{id:'win32-x64'}, requestTimeoutMs:500,
    ghidra:{available:true,pythonExe:'fixture-never-executed.exe'} }, {
    stopTimeoutMs:20,
    spawnProcess(exe,args,options) {
      assert.equal(options.windowsHide,true); assert.equal(options.shell,undefined);
      assert(!Object.hasOwn(options.env,'IG5_FAKE_SECRET'));
      const child = new EventEmitter(); child.pid = 80000+children.length;
      child.stdout = new EventEmitter(); child.stderr = new EventEmitter(); child.stdin = new EventEmitter();
      child.sent = []; child.kills = 0;
      child.frame = value => child.stdout.emit('data',Buffer.from(JSON.stringify(value)+'\n'));
      child.exit = () => { if(!child.exited){child.exited=true; child.emit('exit',0);} };
      child.close = () => { if(!child.closed){child.closed=true; child.emit('close',0);} };
      child.finish = () => { child.exit(); child.close(); };
      child.stdin.write = raw => { const request=JSON.parse(raw);child.sent.push(request);onRequest?.(child,request); };
      child.stdin.end = () => {};
      child.kill = () => {child.kills++;};
      children.push(child); queueMicrotask(()=>child.frame({ig5:'ready'})); return child;
    }
  });
  return {jobs,children};
}
const request = {job_id:'00000000-0000-0000-0000-000000000000',sha256:'a'.repeat(64),...validateLift(selected)};
const acknowledge = (child, req, result={ok:true}) => child.frame({id:1,nonce:req.params.nonce,cleanupConfirmed:true,result});

test('explicit flags preserve zero and exact 64-bit addresses; incompatible fields reject', () => {
  assert.equal(validateLift(selected).initial_flags,'0x0');
  assert.equal(validateLift({...selected,ea:'0xffffffffffffffff'}).ea,'0xffffffffffffffff');
  for(const extra of [{initial_flags:undefined},{initial_flags:'0x1000'},{initial_flags:0},{ea:'0'},{ea:'0x10000000000000000'},
    {lift_inline:['0x1','0x01']},{lift_inline:Array(17).fill('0x1')},{max_blocks:0},{max_blocks:4097},{max_blocks:true},
    {action:'decompile'},{traces:[]},{trace_image_only:true},{max_instructions:100}]) assert.throws(()=>validateLift({...selected,...extra}));
});

test('public entry routes without opening a database; lift_inline rejected elsewhere', async () => {
  const mgr={lifter:{run:async args=>({route:args.level})}};
  const tool=defineIntegrationTools(mgr,{projectRoot:dir}).find(t=>t.name==='ig5_ir');
  assert(tool.parameters.properties.level.enum.includes('lift'));
  assert.deepEqual(await tool.execute(selected),{route:'lift'});
  for(const level of ['raw','high','kernel','trace']) assert.throws(()=>tool.execute({...selected,level,lift_inline:[]}),/requires level=lift/);
});

test('successful result needs ACK and root exit before releasing its slot', async () => {
  const h=fixture((child,req)=>{if(req.id===1)queueMicrotask(()=>acknowledge(child,req));});
  assert.deepEqual(await h.jobs.request(request),{ok:true});
  assert.equal(h.jobs.active.size,1); assert.equal(h.children[0].kills,1);
  h.children[0].finish(); await h.jobs.dispose(); assert.equal(h.jobs.active.size,0);
});

test('cancel stays connected for late cleanup ACK and returns no result', async () => {
  const h=fixture((child,req)=>{if(req.id===0)queueMicrotask(()=>acknowledge(child,child.sent[0]));});
  const controller=new AbortController(), pending=h.jobs.request(request,controller.signal);
  await tick(); controller.abort(); await assert.rejects(pending,/cancelled/);
  assert.equal(h.children[0].sent[1].method,'cancel');
  assert.equal(h.jobs.active.size,1); h.children[0].finish(); await h.jobs.dispose();
});

test('unknown descendant exit retains ownership even after root exit', async () => {
  const h=fixture((child,req)=>{if(req.id===1)queueMicrotask(()=>child.finish());});
  await assert.rejects(h.jobs.request(request),/worker exited/);
  assert.equal(h.jobs.active.size,1);
  await assert.rejects(h.jobs.dispose(),/cleanup unconfirmed/);
});

test('maximum two requests, each ACK and exit independent; wrong nonce ignored', async () => {
  const h=fixture();
  const a=h.jobs.request(request),b=h.jobs.request(request); await tick();
  await assert.rejects(h.jobs.request(request),/maximum two/);
  const [ca,cb]=h.children;
  ca.frame({id:1,nonce:'wrong',cleanupConfirmed:true,result:{bad:true}});
  assert.equal(h.jobs.active.size,2);
  acknowledge(ca,ca.sent[0]); await a; ca.finish(); assert.equal(h.jobs.active.size,1);
  acknowledge(cb,cb.sent[0]); await b; cb.finish(); await h.jobs.dispose();
});

test('root exit before final stdout ACK still completes and releases the lift slot', async () => {
  const h=fixture();
  const pending=h.jobs.request(request);
  let settled;
  const observed=pending.then(value=>{settled={value};},error=>{settled={error};});
  await tick();
  const child=h.children[0]; child.exit(); await tick();
  assert.equal(settled,undefined,'exit alone must allow the final stdout frame to drain');
  assert.equal(h.jobs.active.size,1);
  acknowledge(child,child.sent[0],{drained:true}); child.close();
  await observed;
  assert.deepEqual(settled,{value:{drained:true}});
  assert.equal(child.kills,0,'an already exited root must not be killed again');
  assert.equal(h.jobs.active.size,0);
  await h.jobs.dispose();
});

test('wrong nonce after root exit cannot confirm cleanup when stdout closes', async () => {
  const h=fixture();
  const rejected=assert.rejects(h.jobs.request(request),/worker exited/);
  await tick();
  const child=h.children[0]; child.exit();
  child.frame({id:1,nonce:'unrelated-owner',cleanupConfirmed:true,result:{bad:true}});
  child.close(); await rejected;
  assert.equal(h.jobs.active.size,1);
  await assert.rejects(h.jobs.dispose(),/cleanup unconfirmed/);
});
