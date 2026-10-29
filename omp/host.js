/**
 * omp 侧宿主适配层：把 IG5 引擎对 dsh（Cordis 插件）的宿主契约，映射成 omp 扩展 API。
 *
 * 引擎只依赖以下宿主能力，全部在这里落地：
 *   ctx.tools.register / ctx.on('tools/pre-execute'|'tools/post-execute') / ctx.get('approval')
 *   ctx.inject(['skills'|'commands'|'webServer'|'agents']) / ctx.get('…') / ctx.effect(fn)
 * 没有等价物的一律"注册即空转"：dsh 的 webServer 路由、jobs 面板、session 投影在 omp 的
 * 终端界面里没有落点，引擎自身已按"服务不可用"分支降级。
 */
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { CORE_TOOL_NAMES } from '../workflow.js';
import { IG5_WRITE_TOOLS } from '../source/approval_gate.js';
import { jsonSchemaToZod } from './schema.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
export const PLUGIN_ROOT = path.resolve(HERE, '..');

// 会真正拉起进程/执行代码的写工具按 exec 审批，其余写工具按 write，读工具不拦。
const EXEC_TOOL_NAMES = new Set(['ig5_run_idapython', 'ig5_dbg', 'ig5_emulate', 'ig5_capture_control']);
const CORE = new Set(CORE_TOOL_NAMES);
const CONFIG_FILE = path.join(os.homedir(), '.omp', 'agent', 'omp-infinite-gen-5.json');

/** 读用户覆盖配置；坏 JSON 直接忽略，不让配置错误阻断扩展加载。 */
function readOverrides() {
	try {
		if (fs.existsSync(CONFIG_FILE)) return JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf8')) ?? {};
	} catch {
		/* 配置损坏按默认值启动 */
	}
	return {};
}

/** IG5 引擎默认把工程/产物写在 ~/.dsh/ig5，omp 侧统一改到 ~/.omp/ig5 互不干扰。 */
function resolveConfig(overrides, extra) {
	const home = path.resolve(overrides.home || process.env.IG5_HOME || path.join(os.homedir(), '.omp', 'ig5'));
	return {
		...overrides,
		home,
		artifactDir: overrides.artifactDir || path.join(home, 'artifacts'),
		projectRoot: overrides.projectRoot || path.join(home, 'projects'),
		stateRoot: overrides.stateRoot || path.join(home, 'runtime-state'),
		toolset: overrides.toolset || 'core',
		...extra,
	};
}

function approvalTierFor(name) {
	if (!IG5_WRITE_TOOLS.has(name)) return 'read';
	return EXEC_TOOL_NAMES.has(name) ? 'exec' : 'write';
}

function textResult(text, details) {
	return { content: [{ type: 'text', text }], details: details ?? {} };
}

/** 引擎的返回值可能是 JSON 字符串（jsonToolOutput）或普通对象，统一压成可读文本。 */
function renderValue(definition, value) {
	if (typeof value === 'string') return value;
	const render = definition.output?.render;
	if (typeof render === 'function') {
		try {
			const rendered = render(value);
			if (typeof rendered === 'string') return rendered;
		} catch {
			/* 渲染器失败时退回原始 JSON */
		}
	}
	if (value === undefined) return 'IG5 操作完成（无返回值）';
	try {
		return JSON.stringify(value, null, 2);
	} catch {
		return String(value);
	}
}

/** 依据命令原始输入给出子命令补全，omp 侧只是提示，不参与解析。 */
function completionsFor(command, prefix) {
	const hint = command?.input?.hint;
	if (!hint) return null;
	const items = hint
		.split('|')
		.map((part) => part.trim().split(/\s+/)[0])
		.filter((word) => word && word.startsWith(prefix))
		.map((word) => ({ value: word, label: word }));
	return items.length ? items : null;
}

export function createHost(pi, options = {}) {
	const overrides = { ...readOverrides(), ...(options.config ?? {}) };
	const config = resolveConfig(overrides);
	const z = pi.zod;

	const catalog = new Map();
	const registered = new Set();
	const enabled = new Set();
	const disposers = [];
	const preMiddleware = [];
	const postMiddleware = [];
	const skills = new Map();
	const commands = new Map();
	let disposed = false;
	let syncChain = Promise.resolve();
	// 配置成 full 的会话在注册期就全量激活，之后不需要再碰全局激活表
	const initialFull = config.toolset === 'full';

	function agentOf(extCtx) {
		const identity = extCtx?.agent;
		const id = identity?.id ?? identity?.name ?? extCtx?.sessionManager?.getSessionId?.() ?? 'omp';
		return { id: String(id), sessionId: String(id) };
	}

	function ensureRegistered(definition) {
		if (registered.has(definition.name)) return;
		registered.add(definition.name);
		pi.registerTool(buildTool(definition));
	}

	function buildTool(definition) {
		return {
			name: definition.name,
			label: `IG5 ${definition.name.replace(/^ig5_/, '').replace(/_/g, '-')}`,
			description: definition.description,
			parameters: jsonSchemaToZod(z, definition.parameters ?? { type: 'object', properties: {} }),
			approval: approvalTierFor(definition.name),
			defaultInactive: initialFull ? false : !CORE.has(definition.name),
			loadMode: config.essentialCore === false || !CORE.has(definition.name) ? 'discoverable' : 'essential',
			async execute(toolCallId, params, signal, onUpdate, extCtx) {
				const args = params && typeof params === 'object' ? params : {};
				const agent = agentOf(extCtx);
				const exec = { name: definition.name, arguments: args, callId: toolCallId, signal, agent, ctx: extCtx };
				const decision = await runChain(preMiddleware, exec);
				if (decision?.kind === 'deny') return textResult(decision.reason ?? 'IG5 操作未获批准，未派发', { denied: true });
				if (decision?.kind === 'cancel') return textResult(decision.reason ?? 'IG5 操作已取消，未派发', { cancelled: true });
				let value;
				try {
					value = await definition.execute(args, { agent, signal });
				} catch (error) {
					await runChain(postMiddleware, exec, { isError: true, error, value: undefined });
					throw error;
				}
				await runChain(postMiddleware, exec, { isError: false, value });
				return textResult(renderValue(definition, value), { toolCallId });
			},
		};
	}

	/** Cordis 的 next() 链：每个中间件拿到 (payload, next)，返回 deny/cancel 即短路。 */
	async function runChain(handlers, first, second) {
		if (!handlers.length) return { kind: 'allow' };
		const list = [...handlers];
		let index = 0;
		const step = async () => {
			if (index >= list.length) return { kind: 'allow' };
			const handler = list[index++];
			const outcome = second === undefined ? await handler(first, step) : await handler(first, second, step);
			return outcome ?? { kind: 'allow' };
		};
		return step();
	}

	const tools = {
		register(definition) {
			catalog.set(definition.name, definition);
			ensureRegistered(definition);
			enabled.add(definition.name);
			scheduleSync();
			return () => {
				enabled.delete(definition.name);
				scheduleSync();
			};
		},
	};

	const skillsService = {
		register(skill) {
			skills.set(skill.name, skill);
			return () => skills.delete(skill.name);
		},
	};

	const commandsService = {
		register(command) {
			commands.set(command.name, command);
			try {
				pi.registerCommand(command.name, {
					description: command.description,
					getArgumentCompletions: (prefix) => completionsFor(command, prefix),
					handler: async (args, extCtx) => {
						const invocation = { rawInput: args ?? '', signal: undefined, agent: agentOf(extCtx) };
						const outcome = await command.handler(invocation);
						const text = outcome?.text ?? String(outcome ?? '');
						sendOutput(extCtx, text);
					},
				});
			} catch (error) {
				// 与宿主已有命令撞名时不能拖垮整个扩展，只丢这条命令
				pi.logger?.warn?.(`omp-infinite-gen-5: /${command.name} 注册失败`, { error: String(error) });
			}
			return () => commands.delete(command.name);
		},
	};

	// omp 的注册表没有"卸载工具"，只能调整激活集合；因此 Core/Full 切换落到 setActiveTools。
	// 关键约束：setActiveTools 传的是"完整激活列表"，而 MCP 工具是异步挂载的，
	// 启动早期拿到的名单里还没有 mcp__* —— 这时按名单覆盖激活集合会把 hindsight 这类
	// MCP 工具整批挤掉。所以只在用户真正切换 toolset 时才同步，且只按 IG5 名字过滤，
	// 非 IG5 工具一律原样保留。注册阶段的默认态（Core 激活、其余 defaultInactive）本来就对，
	// 不调用 setActiveTools。
	let syncArmed = false;
	let syncPending = false;
	function scheduleSync() {
		if (disposed || !syncArmed || syncPending) return;
		syncPending = true;
		queueMicrotask(() => {
			syncPending = false;
			syncChain = syncChain.then(syncActiveTools).catch((error) => {
				try {
					pi.logger?.warn?.('omp-infinite-gen-5: 同步激活工具失败', { error: String(error) });
				} catch {
					/* 日志不可用时保持静默，不能影响工具调用 */
				}
			});
		});
	}

	async function syncActiveTools() {
		if (disposed || typeof pi.setActiveTools !== 'function') return;
		// 基线只取当前有效集（omp 的 getEnabledToolNames，已含 MCP 与 xd:// 挂载项）。
		// 不拿 getAllTools 当全集：那会把用户主动关掉的工具重新点亮，等于改写宿主的工具选择。
		const current = pi.getActiveTools?.() ?? [];
		if (!current.length) return;
		const keep = current.filter((name) => !catalog.has(name));
		const wanted = [...new Set([...keep, ...[...enabled].filter((name) => registered.has(name))])];
		await pi.setActiveTools(wanted);
	}

	/** omp 终端里没有自定义消息渲染通道时退回 ui.notify，保证命令输出不丢。 */
	function sendOutput(extCtx, text) {
		if (!text) return;
		try {
			if (typeof pi.sendMessage === 'function') {
				pi.sendMessage({ customType: 'ig5', content: [{ type: 'text', text }], display: true });
				return;
			}
		} catch {
			/* 落回通知 */
		}
		extCtx?.ui?.notify?.(text, 'info');
	}

	const approval = {
		/**
		 * 写工具在 omp 侧已经是 write/exec 审批层，用户批准后才会进到 execute；
		 * 这里只对"载荷超限"这类引擎侧硬约束做二次拒绝，不再重复弹窗。
		 */
		async request(request) {
			if (request?.signal?.aborted) return 'cancelled';
			return 'allowed-once';
		},
	};

	const services = { tools, skills: skillsService, commands: commandsService };

	const ctx = {
		logger: pi.logger,
		tools,
		config,
		registerCatalog(definitions) {
			for (const definition of definitions) {
				catalog.set(definition.name, definition);
				ensureRegistered(definition);
			}
			scheduleSync();
		},
		on(event, handler) {
			if (typeof handler !== 'function') return () => {};
			if (event === 'tools/pre-execute') {
				preMiddleware.push(handler);
				return () => removeFrom(preMiddleware, handler);
			}
			if (event === 'tools/post-execute') {
				postMiddleware.push(handler);
				return () => removeFrom(postMiddleware, handler);
			}
			return () => {};
		},
		inject(names, callback) {
			if (typeof callback !== 'function') return () => {};
			// dsh 的 inject 只在依赖服务全部就绪时运行回调；缺一个就永远不运行。
			if (!names.every((name) => services[name])) return () => {};
			const scope = { get: (name) => services[name] };
			for (const name of names) scope[name] = services[name];
			const dispose = callback(scope);
			if (typeof dispose === 'function') disposers.push(dispose);
			return () => {};
		},
		get(name) {
			if (name === 'approval') return approval;
			return services[name];
		},
		effect(factory) {
			if (typeof factory !== 'function') return;
			const dispose = factory();
			if (typeof dispose === 'function') disposers.push(dispose);
		},
	};

	// 技能不靠这个事件加载：本版 omp 只定义 emitResourcesDiscover，没有调用方，
	// 真正生效的是设置项 skills.customDirectories（由 install.ps1 登记）。这里保留贡献，
	// 供将来消费该事件的宿主版本使用；返回空对象而不是空数组，避免误清空别的来源。
	pi.on('resources_discover', () => {
		const dir = path.join(PLUGIN_ROOT, 'skills');
		return fs.existsSync(dir) ? { skillPaths: [dir] } : {};
	});
	pi.on('session_start', async () => {
		// 只上闩：注册期的批量 register/dispose 不触发全局同步，也不在启动时改激活表。
		// 受限会话（--tools / 子代理白名单）下 IG5 工具不该被硬塞进去，这里什么都不做。
		syncArmed = true;
	});
	pi.on('session_shutdown', async () => {
		// 关闭可能等 Ghidra/x64dbg 会话收敛；设上限，别让 IG5 拖住宿主退出
		await Promise.race([dispose(), new Promise((resolve) => setTimeout(resolve, 5000))]);
	});

	async function dispose() {
		if (disposed) return;
		disposed = true;
		for (const remove of disposers.splice(0).reverse()) {
			try {
				await remove();
			} catch (error) {
				try {
					pi.logger?.warn?.('omp-infinite-gen-5: 释放资源失败', { error: String(error) });
				} catch {
					/* 关闭阶段的异常不能再抛回宿主 */
				}
			}
		}
	}

	return { ctx, config, engineConfig: { ...overrides, home: config.home }, dispose, syncActiveTools, registeredTools: () => [...registered] };
}

function removeFrom(list, handler) {
	const index = list.indexOf(handler);
	if (index >= 0) list.splice(index, 1);
}
