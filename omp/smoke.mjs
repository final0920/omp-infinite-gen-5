/**
 * 冒烟自检：用假的 ExtensionAPI 加载引擎，验证宿主适配层能装配 43 个工具、
 * Core8/Full 切换落到 setActiveTools、以及工具执行链路能走通。
 *
 * 不连真实模型、不启动 Ghidra/x64dbg：只覆盖"装配 + 派发"，环境类失败按提示输出。
 * 运行：node omp/smoke.mjs
 */
import assert from 'node:assert/strict';
import { createHost } from './host.js';

/** 极简 zod 替身：只记录结构性调用，用来确认 schema 转换不抛错。 */
function fakeZod() {
	const make = (kind, meta = {}) => {
		const node = {
			kind,
			...meta,
			_min: undefined,
			_max: undefined,
			_int: false,
			_optional: false,
			_nullable: false,
			_passthrough: false,
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

function createFakePi() {
	const tools = new Map();
	const commands = new Map();
	const handlers = new Map();
	const active = new Set(['read', 'bash', 'edit', 'write']);
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
		getAllTools: () => [...tools.values()].map((t) => ({ name: t.name, description: t.description, parameters: t.parameters, sourceInfo: {} })),
		sendMessage: (message) => { pi.sentMessages.push(message); },
		sentMessages: [],
		async exec() { return { stdout: '', stderr: '', code: 0 }; },
	};
	return { pi, tools, commands, handlers, active, activeHistory };
}

const CORE = ['ig5_doctor', 'ig5_open', 'ig5_status', 'ig5_funcs', 'ig5_strings', 'ig5_decompile', 'ig5_close', 'ig5_profile'];

const { pi, tools, commands, handlers, active, activeHistory } = createFakePi();
const host = createHost(pi);
await new Promise((resolve) => setImmediate(resolve));

await loadEngine(host);
await new Promise((resolve) => setImmediate(resolve));

function ig5Names() {
	return [...tools.keys()].filter((name) => name.startsWith('ig5_')).sort();
}

const registered = ig5Names();
console.log(`数据根: ${host.config.home}`);
console.log(`已注册工具: ${registered.length}`);
for (const name of registered) console.log(`  ${name}`);

assert.equal(registered.length, 43, `期望 43 个工具，实际 ${registered.length}`);
assert.equal([...active].filter((n) => n.startsWith('ig5_')).length, 8, 'Core 默认应只激活 8 个工具');
for (const name of CORE) assert.ok(active.has(name), `Core 应包含 ${name}`);
for (const builtin of ['read', 'bash', 'edit', 'write']) assert.ok(active.has(builtin), `内建工具 ${builtin} 不应被移除`);
assert.ok(commands.has('ig5'), '应注册 /ig5 命令');
assert.ok(handlers.has('resources_discover'), '应注册技能发现');

const skillPaths = handlers.get('resources_discover').map((handler) => handler({ type: 'resources_discover', cwd: process.cwd(), reason: 'startup' }));
assert.ok(skillPaths.some((result) => result?.skillPaths?.length), '技能路径为空');

const extCtx = {
	agent: { id: 'smoke-session' },
	cwd: process.cwd(),
	hasUI: false,
	ui: { notify(message) { console.log('[notify]', message.slice(0, 200)); } },
	sessionManager: { getSessionId: () => 'smoke-session', getBranch: () => [] },
};

const status = tools.get('ig5_status');
const statusResult = await runTool(status, {}, extCtx);
console.log('ig5_status 输出前 200 字:', statusResult.slice(0, 200).replace(/\n/g, ' '));

const profile = tools.get('ig5_profile');
await runTool(profile, { toolset: 'full' }, extCtx);
await new Promise((resolve) => setImmediate(resolve));
const fullCount = [...active].filter((n) => n.startsWith('ig5_')).length;
console.log(`切换 full 后激活工具数: ${fullCount}`);
assert.equal(fullCount, 43, 'toolset=full 应激活全部 43 个工具');

await runTool(profile, { toolset: 'core' }, extCtx);
await new Promise((resolve) => setImmediate(resolve));
const coreCount = [...active].filter((n) => n.startsWith('ig5_')).length;
console.log(`切回 core 后激活工具数: ${coreCount}`);
assert.equal(coreCount, 8, 'toolset=core 应只留 8 个工具');

await host.dispose();
console.log(`setActiveTools 调用次数: ${activeHistory.length}`);
console.log('SMOKE OK');

async function loadEngine(target) {
	const { apply } = await import('../dsh-plugin.js');
	apply(target.ctx, target.engineConfig);
}

async function runTool(definition, args, context) {
	const result = await definition.execute('call-1', args, undefined, undefined, context);
	return result.content.map((part) => part.text ?? '').join('\n');
}
