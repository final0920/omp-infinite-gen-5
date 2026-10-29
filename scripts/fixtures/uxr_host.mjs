import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { apply } from '../../index.js';

/** Actual plugin wrappers, disposable project storage, no native calls by default. */
export function uxrHost(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'ig5-uxr-host-'));
  const tools = new Map(), agents = new Map(), disposers = [], events = new Map();
  const ctx = {
    tools: { register(def) { tools.set(def.name, def); return () => tools.delete(def.name); } },
    get(name) { return name === 'tools' ? ctx.tools : name === 'agents' ? agents : undefined; },
    on(name, fn) { const list = events.get(name) || []; list.push(fn); events.set(name, list); return () => {}; },
    inject(names, fn) { const remove = names.every(n => ctx.get(n)) ? fn(ctx) : undefined; const dispose = async () => { if (typeof remove === 'function') await remove(); }; disposers.push(dispose); return { dispose }; },
    effect(fn) { const remove = fn(); if (typeof remove === 'function') disposers.push(remove); },
  };
  apply(ctx, { artifactDir: path.join(root, 'artifacts'), projectRoot: path.join(root, 'projects'), stateRoot: path.join(root, 'state'), toolset: 'full', memory: false });
  t.after(async () => {
    for (const dispose of disposers.reverse()) await dispose();
    if (path.dirname(root) !== path.resolve(os.tmpdir()) || !path.basename(root).startsWith('ig5-uxr-host-')) throw new Error('Unexpected test root');
    fs.rmSync(root, { recursive: true, force: true });
  });
  return { root, tools, agents, events, call(name, args, agent) { return tools.get(name).execute(args, { agent, signal: new AbortController().signal }); } };
}
