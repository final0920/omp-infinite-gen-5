# dsh → omp 移植说明（无限五代 IG5）

上游项目 `Minglink/dsh-infinite-gen-5` 是 DeepSeek Harness（dsh，Cordis 插件体系）的逆向工作台插件：
43 个 `ig5_*` 工具、8 个原生技能、独立 worker 池、Ghidra/x64dbg 双引擎、LCM 会话记忆、Web 侧栏工作台。

本仓库把它改造成 omp（`@oh-my-pi/pi-coding-agent`，`omp` 命令）的扩展，包名 `omp-infinite-gen-5`。
**引擎层一行没改**——`source/`、`worker/`、`adapters/`、`skills/`、`scripts/`、`third_party/` 原样复用；
换掉的只有宿主胶水。

## 一、宿主契约对照

dsh 插件通过 Cordis 的 `apply(ctx, config)` 拿到宿主能力；omp 扩展通过 `ExtensionAPI`。
两边能力对不上的地方，全部落在 `omp/host.js` 一处。

| 引擎用到的宿主能力 | dsh 形态 | omp 落点 |
|---|---|---|
| 注册工具 | `ctx.tools.register(def)` → disposer | `pi.registerTool({…})`；disposer 改为从激活集合里摘除（omp 没有反注册 API） |
| 工具执行前后拦截 | `ctx.on('tools/pre-execute'\|'tools/post-execute', (exec, next))` | 同一套中间件链，由 `host.js` 在 `execute` 包装里按序调用 |
| 写操作审批 | `ctx.get('approval').request(...)` 弹宿主审批 | omp 工具自带的 `approval` 层：写工具登记为 `write`，起进程/执行代码的登记为 `exec`，读工具为 `read`。用户在 omp 里批准后才会进 `execute`，所以 `approval.request` 只做载荷超限复核与取消判定 |
| 技能注册 | `ctx.inject(['skills'])` + `skills.register(skill)` | `pi.on('resources_discover', () => ({ skillPaths: [<root>/skills] }))` |
| 斜杠命令 | `ctx.inject(['commands'])` + `commands.register({name, handler})` | `pi.registerCommand('ig5', {…})`，输出走 `pi.sendMessage`，不可用时退回 `ui.notify` |
| 生命周期 | `ctx.effect(() => disposer)` | 加载时执行工厂，`session_shutdown` 时按逆序释放 |
| Web 路由 `/ig5-diag`、`/ig5-jobs`、`/ig5-data` | `ctx.inject(['webServer'])` | omp 无 HTTP 宿主：`inject` 判定服务缺失后不回调，引擎自身走"未挂载"分支 |
| 会话投影 `ig5dash` | `ctx.get('sessionProjections')` | 无等价物，不注册 |
| 多 agent 作用域工具面 | 真实 `agent.ctx.tools.restrict()` | omp 没有 per-agent 工具注册表，`toolsetScope` 固定为 `plugin-instance` |
| 子代理预算共享 | `ctx.on('subagent/start'\|'subagent/end')` + `ctx.get('agents')` | 事件不存在，`ig5_profile collaboration` 只统计当前会话的调用 |

## 二、Core8 / Full 切换

dsh 侧靠"注册/反注册"实现 Core8 与 Full 43 的切换。omp 的注册表只增不减，因此改为：

1. `index.ts` 加载时把 43 个定义**全部**注册给 omp：
   Core8（`ig5_doctor/open/status/funcs/strings/decompile/close/profile`）用 `loadMode: "essential"`；
   其余 35 个用 `defaultInactive: true` + `loadMode: "discoverable"`，默认不占工具位。
2. `ig5_profile toolset=full|core` 触发的 `tools.register`/disposer 只改"期望激活集合"。
3. 每次变化后 `pi.setActiveTools(当前非 IG5 工具 + 期望激活的 IG5 工具)`，保留 `read`/`bash` 等内建工具。

为此在 `dsh-plugin.js` 里加了一行钩子：构建完定义后调用 `ctx.registerCatalog(definitions)`（dsh 侧没有这个函数，行为不变）。

## 三、路径与状态

| 内容 | dsh 默认 | 本移植默认 |
|---|---|---|
| 数据根 | `~\.dsh\ig5` | `~\.omp\ig5` |
| 工程/修订 | `~\…\projects` | `~\.omp\ig5\projects` |
| 产物 | `~\…\artifacts` | `~\.omp\ig5\artifacts` |
| 运行态 | `~\…\state` | `~\.omp\ig5\runtime-state` |
| 诊断日志 | `artifacts\ig5-diag.log` | 同（在 omp 的数据根下） |
| 审批留痕 | `artifacts\approvals.jsonl` | 同 |

覆盖方式：`~/.omp/agent/omp-infinite-gen-5.json`（引擎的同名配置键直接透传，例如
`defaultEngine`、`toolset`、`maxSessions`、`openTimeoutMs`、`runtimeRoot`、`projectRoot`、`artifactDir`），
或环境变量 `IG5_HOME`、`IG5_RUNTIME_ROOT`、`IG5_GHIDRA_RUNTIME`、`IG5_X64DBG_RUNTIME`。

## 四、保留 / 未移植

保留：

- 全部 43 个工具与三个引擎路由（`reverse`、`ghidra`、`x64dbg`）；
- 8 个原生技能（`skills/*/SKILL.md`，omp 按 Agent Skills 规范直接加载）；
- `/ig5` 命令（status / engines / open / export / deobfuscate / state / state-validate / toolset）；
- worker 传输、作业预算、工程锁与修订、审批审计 `approvals.jsonl`、诊断日志。

未移植（omp 侧没有承载面，文档与 `ig5_status` 输出会如实标为不可用）：

- `client.js`（dsh Web 工作台：函数表、CFG 视图、审计分页、结构体草稿）、`ig5dash` 会话投影；
- `/ig5-diag`、`/ig5-jobs`、`/ig5-data` 三个 HTTP 端点；
- per-agent 工具作用域与子代理共享预算计数。

## 五、安装与验证

```powershell
# 目录 Junction（默认）：改源码后重启 omp 生效
.\install.ps1

# 复制快照（分发/对照用）
.\install.ps1 -Copy -Force

# 卸载
.\install.ps1 -Uninstall
```

验证顺序：

1. `.\install.ps1 -Check` 看 node / omp / 扩展目录是否就位；
2. 重启 omp，会话里跑 `/ig5 status`，应返回引擎清单与 `toolset: core`；
3. `ig5_doctor engine=ghidra`：随包运行时若未下载，会明确报 `missing-runtime`，不是静默降级；
4. `ig5_open path=<样本> engine=ghidra` 打开一个真实样本，再 `ig5_decompile` 取函数。

运行时资产（`runtimes/ghidra`、`runtimes/x64dbg`、`third_party/sources`）不在源码仓库里，`.gitignore` 也把它们排除了。
补齐方式：下载上游 Release 里的完整包（`IG5-<版本>-Windows-x64-*-full-*.zip`），把其中的 `runtimes/`
与 `third_party/sources/` 解到本仓库根目录即可，omp 启动时按"已加载模块的物理目录"解析运行时，
不读 `~/.dsh` 的历史副本。上游 `install-dsh.ps1` 只服务于 dsh 的 profile 安装，omp 侧不要执行它的安装步骤。

## 六、移植中遇到的宿主差异

1. **omptype 的 zod 层拒绝无序 union**
   工具参数原本是 JSON Schema，含数值枚举（如 `enum: [1,2,3]`）。直接映射成 `z.union([z.literal(1), …])`
   会在扩展加载期抛 `an unordered union with overlapping morph inputs is indeterminate`，整个扩展加载失败。
   现在数值枚举退化为 `z.number()`（整数枚举加 `.int()`）并在描述里列出可选值，`oneOf`/`anyOf` 多分支退化为
   `z.unknown()`：宿主层放宽，真正的取值校验仍由引擎按原 JSON Schema 做。
2. **工具注册只增不减**
   omp 没有反注册 API，且注明"registerTool 必须在扩展加载期调用"。因此不是按 Core/Full 增量注册，
   而是一次性注册 43 个（非 Core 用 `defaultInactive`），切换只改 `setActiveTools`。
   一次 toolset 变更会连续触发几十次 register/dispose，激活集合的同步必须合并到同一轮微任务，
   否则会重复调用几十次 `setActiveTools`。
3. **`pi.zod` 不是真 zod**
   可用面是 `object/array/string/number/boolean/null/unknown/literal/enum/union` 与链式
   `min/max/int/regex/optional/nullable/describe/passthrough/default`，没有 `z.record` 之外的组合器，
   也没有 `z.infer` 之外的运行时推断，转换器只使用这一层保证可用的方法。
4. **命令输出通道**
   omp 的斜杠命令 handler 返回 `void`，输出要么走 `pi.sendMessage`（自定义消息），要么 `ctx.ui.notify`。
   当前优先 `sendMessage`，抛错时退回通知，避免命令静默无输出。
5. **没有 `webServer` / `sessionProjections` / `agents` 服务**
   `ctx.inject` 按 dsh 语义「依赖不全就永不回调」，引擎自身走降级分支：路由不挂载、投影不注册、
   协作预算只统计当前会话。

