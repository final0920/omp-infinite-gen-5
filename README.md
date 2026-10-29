# omp-infinite-gen-5（无限五代 · omp 版）

把 [dsh-infinite-gen-5](https://github.com/Minglink/dsh-infinite-gen-5)（DeepSeek Harness 逆向工作台插件）
移植成 **omp**（`@oh-my-pi/pi-coding-agent`）扩展：同一套引擎、同一组工具、同一批技能，宿主换成 omp。

- 43 个 `ig5_*` 工具，默认只展开 Core8，`ig5_profile toolset=full` 展开全部
- 三引擎路由：内置 Reverse 车道、Ghidra 静态车道、x64dbg 无头调试
- 8 个原生技能：`ig5-triage`、`ig5-deep-dive`、`ig5-patch-and-sign`、`ig5-diff`、`ig5-debug-live`、`ig5-crypto`、`ig5-protocol`、`ig5-reverse-agent`
- `/ig5` 命令：`status`、`engines`、`open`、`export`、`deobfuscate`、`state`、`state-validate`、`toolset`
- 写工具走 omp 的 `write`/`exec` 审批层，执行后追加 `approvals.jsonl` 审计行

## 安装

```powershell
git clone <this-repo> omp-infinite-gen-5
cd omp-infinite-gen-5
.\install.ps1            # 在 ~/.omp/agent/extensions/omp-infinite-gen-5 建目录 Junction
```

重启 omp，会话里：

```
/ig5 status
```

卸载：`.\install.ps1 -Uninstall`。安装脚本支持 `-Check`（只看环境）、`-Copy`（复制快照而非链接）、`-Force`。

## 目录

| 路径 | 作用 |
|---|---|
| `index.ts` | omp 扩展入口（默认导出），把 `dsh-plugin.js` 接到宿主适配层 |
| `omp/host.js` | dsh → omp 宿主契约适配：工具注册、审批、命令、技能、生命周期 |
| `omp/schema.js` | 工具参数的 JSON Schema → zod 转换 |
| `dsh-plugin.js` | 原 dsh 插件入口（`apply(ctx, config)`），引擎装配在这里 |
| `workflow.js` | Core8/Full 工具面、`/ig5` 命令、技能加载 |
| `source/`、`worker/`、`adapters/`、`third_party/` | 原样复用的引擎与适配器 |
| `skills/` | 8 个 SKILL.md，omp 通过 `resources_discover` 加载 |
| `docs/PORTING_OMP.md` | 逐项宿主契约对照、保留/未移植清单、路径映射 |

## 默认路径

数据根从 dsh 的 `~\.dsh\ig5` 改为 `~\.omp\ig5`（工程、产物、运行态、诊断日志、审批审计都在其下）。
覆盖用 `~/.omp/agent/omp-infinite-gen-5.json` 或环境变量 `IG5_HOME`。

## 验证

| 层级 | 结果 |
|---|---|
| 装配（假宿主） | `node omp/smoke.mjs`：注册 43 个工具、Core 默认激活 8 个、`ig5_status` 返回 JSON、`toolset=full` 后激活 43、切回 core 回到 8，内建 `read/bash/edit/write` 全程保留 |
| 真机装配 | `omp` 加载扩展后 `~/.omp/ig5/artifacts/ig5-diag.log` 记录 `implementation=20261026-release-1.3.0` 与审批门挂载 |
| 工具链闭环 | `omp -p "调用 ig5_status …"` 由模型实际发起工具调用并正确解释返回（count=0、sessions=[]，且指出三引擎缺运行时） |
| 技能 | `omp -p … --skills=ig5-*` 列出全部 8 个技能：triage / deep-dive / patch-and-sign / diff / debug-live / crypto / protocol / reverse-agent |
| 引擎 | 未做：Ghidra/x64dbg 运行时资产不在源码仓库，`ig5_doctor engine=ghidra` 目前如实报 `missing-runtime` |

## 与上游的差异

dsh 的 Web 工作台（`client.js`）、`ig5dash` 会话投影、`/ig5-diag`、`/ig5-jobs`、`/ig5-data` 三个 HTTP 端点、
per-agent 工具作用域与子代理预算共享，在 omp 的终端宿主里没有承载面，未移植；
其余工具面、审批语义、预算、证据口径与上游一致。详见 [docs/PORTING_OMP.md](docs/PORTING_OMP.md)。

## 许可

引擎与随包资产沿用上游许可（自有代码 CC BY-NC-SA 4.0，第三方组件各自许可，见 `LICENSE`、
`THIRD_PARTY_NOTICES.txt`）。本移植层（`index.ts`、`omp/`、`install.ps1`、本 README、`docs/PORTING_OMP.md`）同样按 CC BY-NC-SA 4.0 发布。
