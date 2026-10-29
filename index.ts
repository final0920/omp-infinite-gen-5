/**
 * omp-infinite-gen-5 扩展入口。
 *
 * omp 的扩展目录（~/.omp/agent/extensions/<名字>/）要求根目录有 index.ts/index.js，
 * 并默认导出 `(pi: ExtensionAPI) => void`。这里把 dsh 侧原封不动的插件入口
 * dsh-plugin.js（Cordis apply(ctx, config)）接到 omp 宿主适配层上：
 * 引擎、worker、Ghidra/x64dbg 适配器、skills 全部复用，只有宿主胶水换掉。
 */
import type { ExtensionAPI } from "@oh-my-pi/pi-coding-agent";
import { apply as installIg5 } from "./dsh-plugin.js";
import { createHost } from "./omp/host.js";

export default function ompInfiniteGen5(pi: ExtensionAPI) {
	const host = createHost(pi);
	try {
		installIg5(host.ctx, host.engineConfig);
	} catch (error) {
		const message = error instanceof Error ? (error.stack ?? error.message) : String(error);
		pi.logger.error(`omp-infinite-gen-5: 引擎挂载失败 ${message}`);
		throw error;
	}
	pi.logger.debug("omp-infinite-gen-5: 引擎已挂载", {
		home: host.config.home,
		toolset: host.config.toolset,
		tools: host.registeredTools().length,
	});
}
