/**
 * 冒烟自检：用假的 ExtensionAPI 加载引擎，验证宿主适配层
 *   1) 能装配 43 个工具、Core8 默认激活；
 *   2) Core/Full 切换只动 IG5 自己的工具；
 *   3) 切换过程绝不改写宿主的工具选择（MCP 工具保留、用户关掉的工具保持关闭）；
 *   4) 受限会话（--tools / 子代理白名单）不在启动时被塞入 IG5 工具。
 *
 * 不连真实模型、不启动 Ghidra/x64dbg。运行：node omp/smoke.mjs
 */
import assert from 'node:assert/strict';
import { createHost } from './host.js';

/** 极简 zod 替身：只记录结构性调用，用来确认 schema 转换不抛错。 */
function fakeZod() {
	const make = (kind, meta = {}) => {
		const node = {
			kind,
			...meta,
			min(value) { node._min = value; return node; },
			max(value) { node._max = value; return node; },
			int() { node._int = true; return node; },
			regex() { return node; },
			optional() { node._optional = true; return node; },
			nullable() { node._nullable = true; return node; },
			describe(text) { node._description = text; return node; },
			passthrough() { node._passthrough = true; return node; },
			default() { return node; },
		};
		return node;
	};
	return {
		object: (shape) => make('object', { shape }),
		array: (element) => make('array', { element }),
		string: () => make('string'),
		number: () => make('number'),
		boolean: () => make('boolean'),
		null: () => make('null'),
		unknown: () => make('unknown'),
		any: () => make('any'),
		literal: (value) => make('literal', { value }),
		enum: (values) => make('enum', { values }),
		union: (schemas) => make('union', { schemas }),
	};
}

/**
 * 假宿主，按 omp 的真实语义建模：
 * - 非 defaultInactive 的扩展工具注册即进激活集；
 * - 已注册但被用户关掉的工具（如 grep）不在激活集里；
 * - MCP 工具由宿主另行注入，同时在激活集与 getAllTools 里。
 */
function createFakePi({ initialActive = ['read', 'bash', 'edit', 'write', 'mcp__hindsight_retain', 'mcp__hindsight_recall'], restricted = false } = {}) {
	const tools = new Map();
	const commands = new Map();
	const handlers = new Map();
	const disabledButRegistered = ['grep', 'glob', 'find'];
	const active = new Set(initialActive);
	const activeHistory = [];
	const pi = {
		zod: fakeZod(),
		logger: {
			debug() {},
			info() {},
			warn() {},
			error(message) { console.error('[logger.error]', message); },
		},
		registerTool(definition) {
			if (tools.has(definition.name)) throw new Error(`重复注册工具 ${definition.name}`);
			tools.set(definition.name, definition);
			// 受限会话里扩展工具不会自动进入激活集
			if (!restricted && !definition.defaultInactive) active.add(definition.name);
		},
		registerCommand(name, options) {
			commands.set(name, options);
		},
		on(event, handler) {
			if (!handlers.has(event)) handlers.set(event, []);
			handlers.get(event).push(handler);
			return () => {};
		},
		getActiveTools: () => [...active],
		async setActiveTools(names) {
			active.clear();
			for (const name of names) active.add(name);
			activeHistory.push(names);
		},
		getAllTools: () => [
			...[...tools.values()].map((t) => ({ name: t.name, description: t.description, parameters: t.parameters, sourceInfo: {} })),
			...[...active].filter((n) => n.startsWith('mcp__')).map((n) => ({ name: n, description: 'mcp tool', parameters: {}, sourceInfo: {} })),
			...disabledButRegistered.map((n) => ({ name: n, description: 'disabled by user', parameters: {}, sourceInfo: {} })),
		],
		sendMessage: (message) => { pi.sentMessages.push(message); },
		sentMessages: [],
		async exec() { return { stdout: '', stderr: '', code: 0 }; },
	};
	return { pi, tools, commands, handlers, active, activeHistory, disabledButRegistered };
}

const CORE = ['ig5_doctor', 'ig5_open', 'ig5_status', 'ig5_funcs', 'ig5_strings', 'ig5_decompile', 'ig5_close', 'ig5_profile'];
const countIg5 = (set) => [...set].filter((n) => n.startsWith('ig5_')).length;

const extCtx = {
	agent: { id: 'smoke-session' },
	cwd: process.cwd(),
	hasUI: false,
	ui: { notify(message) { console.log('[notify]', message.slice(0, 200)); } },
	sessionManager: { getSessionId: () => 'smoke-session', getBranch: () => [] },
};

// ── 场景一：普通会话 ──────────────────────────────────────────────────────
const fake = createFakePi();
const host = createHost(fake.pi);
await new Promise((resolve) => setImmediate(resolve));
const { apply } = await import('../dsh-plugin.js');
apply(host.ctx, host.engineConfig);
await new Promise((resolve) => setImmediate(resolve));

const registered = [...fake.tools.keys()].filter((n) => n.startsWith('ig5_')).sort();
console.log(`数据根: ${host.config.home}`);
console.log(`已注册工具: ${registered.length}`);

assert.equal(registered.length, 43, `期望 43 个工具，实际 ${registered.length}`);
assert.equal(countIg5(fake.active), 8, 'Core 默认应只激活 8 个工具');
for (const name of CORE) assert.ok(fake.active.has(name), `Core 应包含 ${name}`);
assert.equal(fake.activeHistory.length, 0, '加载期不得调用 setActiveTools 改写激活表');
assert.ok(fake.commands.has('ig5'), '应注册 /ig5 命令');
assert.ok(fake.handlers.has('resources_discover'), '应注册技能发现');
assert.ok(fake.handlers.get('resources_discover').some((h) => h({ type: 'resources_discover', cwd: process.cwd(), reason: 'startup' })?.skillPaths?.length), '技能路径为空');

for (const handler of fake.handlers.get('session_start') ?? []) await handler({ type: 'session_start' }, extCtx);
await new Promise((resolve) => setImmediate(resolve));
assert.equal(fake.activeHistory.length, 0, 'session_start 不得改写激活表');

const statusResult = await runTool(fake.tools.get('ig5_status'), {}, extCtx);
console.log('ig5_status 输出前 120 字:', statusResult.slice(0, 120).replace(/\n/g, ' '));

const profile = fake.tools.get('ig5_profile');
await runTool(profile, { toolset: 'full' }, extCtx);
await new Promise((resolve) => setImmediate(resolve));
console.log(`full 后 IG5 激活数: ${countIg5(fake.active)}`);
assert.equal(countIg5(fake.active), 43, 'toolset=full 应激活全部 43 个工具');
for (const name of ['mcp__hindsight_retain', 'mcp__hindsight_recall']) assert.ok(fake.active.has(name), `full 切换后不得丢失 ${name}`);
for (const name of fake.disabledButRegistered) assert.ok(!fake.active.has(name), `full 切换不得重新点亮用户已关闭的 ${name}`);
for (const name of ['read', 'bash', 'edit', 'write']) assert.ok(fake.active.has(name), `内建 ${name} 应保留`);

await runTool(profile, { toolset: 'core' }, extCtx);
await new Promise((resolve) => setImmediate(resolve));
console.log(`core 后 IG5 激活数: ${countIg5(fake.active)}`);
assert.equal(countIg5(fake.active), 8, 'toolset=core 应只留 8 个工具');
assert.ok(fake.active.has('mcp__hindsight_retain'), 'core 切换后 MCP 工具仍必须激活');
for (const name of fake.disabledButRegistered) assert.ok(!fake.active.has(name), `core 切换不得重新点亮用户已关闭的 ${name}`);
console.log(`setActiveTools 调用次数: ${fake.activeHistory.length}（只应有两次切换）`);
assert.equal(fake.activeHistory.length, 2, '只允许两次 toolset 切换各触发一次同步');

await host.dispose();

// ── 场景二：受限会话（--tools / 子代理白名单）────────────────────────────
const restricted = createFakePi({ initialActive: ['read'], restricted: true });
const restrictedHost = createHost(restricted.pi);
await new Promise((resolve) => setImmediate(resolve));
apply(restrictedHost.ctx, restrictedHost.engineConfig);
await new Promise((resolve) => setImmediate(resolve));
for (const handler of restricted.handlers.get('session_start') ?? []) await handler({ type: 'session_start' }, extCtx);
await new Promise((resolve) => setImmediate(resolve));
console.log(`受限会话激活集: ${[...restricted.active].join(', ') || '(空)'}`);
assert.deepEqual([...restricted.active], ['read'], '受限会话不得被塞入 IG5 工具');
assert.equal(restricted.activeHistory.length, 0, '受限会话启动期不得调用 setActiveTools');
await restrictedHost.dispose();

console.log('SMOKE OK');

async function runTool(definition, args, context) {
	const result = await definition.execute('call-1', args, undefined, undefined, context);
	return result.content.map((part) => part.text ?? '').join('\n');
}
