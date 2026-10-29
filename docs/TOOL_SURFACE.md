# 工具面与体积预算(P2,2026-10-25)

> 目的:让模型可见的工具面保持"少而稳、渐进披露",并把体积纳入默认门禁。本文只记录**可复测的测量口径**与拆分边界,不声称任何模型的真实 tokenizer 计数或选错率收益。

## 1. 现状

| 项 | 值 |
|---|---|
| Core 8 | `ig5_doctor`、`ig5_open`、`ig5_status`、`ig5_funcs`、`ig5_strings`、`ig5_decompile`、`ig5_close`、`ig5_profile` |
| Full | 43 = 28 非审批静态入口 + 13 审批 + 2 生命周期/配置 |
| Core 8 估算体积 | **3,478 / 4,000** token |
| 单工具上限 | 4,000 token(当前最大 `ig5_workspace` 3,406) |
| Full 43 合计 | 27,946 token(仅用于比较,不是预算) |
| 关键变化 | `ig5_profile` 8,308 → 1,406 token |

**契约变更状态**:所有者 2026-10-25 复核确认“拆分方向可接受”,但暂不整批确认契约变更。Full 41→43,新增 `ig5_workspace`(第 42)与 `ig5_recovery`(第 43);不接受时可把两个新工具并回 `ig5_profile`,但这会恢复原体积。

## 2. 拆分边界

| 工具 | 承载内容 |
|---|---|
| `ig5_profile` | 状态/引擎/toolset 切换、`guest_debug`、地址转换、`capabilities`、`memory`、`knowledge`、`collaboration` |
| `ig5_workspace` | 调查任务(`create/get/brief/list/update`)、系统证据快照、`handoff/claim/submit/review`、`plan/resume`、研究合同、私有案例索引、固定方法库、shadow 提案、有界位向量候选与 CFF 覆盖层读取 |
| `ig5_recovery` | VM 恢复规划(`case_ref`)与录制观察(`observations`/`roles`/`flow`/`recurrences`/`handlers`/`context` 及 progression/instance 模式) |

两个新工具都是**静态、无目标执行**入口(不执行样本、不开引擎、不发网络),不新增审批门;但它们**不是“只读文件”**:`ig5_workspace` 会更新本会话任务存储并写不可变分析报告(与拆分前 `ig5_profile.workspace` 一致),`ig5_recovery` 会写不可变报告。因此与旧 `ig5_profile.workspace` 同属"有意不审批"清单。对 `ig5_profile` 传 `workspace` 或 `recovery` 会**显式报错**并指向新工具,不会静默忽略。

## 3. 测量口径

`tools/ci/tool-surface-size.mjs`(默认门禁 `tool-surface-size`):

1. 用桩上下文调用真实 `apply()`,拿到实际注册的 43 个定义;
2. 与 `scripts/fixtures/tool_classification.mjs` 的 `ALL_TOOLS` 双向对账,注册集不同即失败;
3. 对每个工具计算 `JSON.stringify({name, description, parameters}).length / 4`,**向上取整**;
4. 断言 Core 8 合计 ≤ 4,000、每个单工具 ≤ 4,000;打印全表。

**这是保守估算,不是测量**:`字符数/4` 与任何具体 tokenizer 的实际计数都可能有偏差(中文、长英文单词、JSON 标点都会影响)。4,000 是内部预算线,不是宿主限额,也不代表"模型一定不会选错"。若将来要比较收益,需要同预算、配对的选错率实验,届时另记。

## 4. 迁移

| 旧调用 | 新调用 |
|---|---|
| `ig5_profile workspace={...}` | `ig5_workspace workspace={...}` |
| `ig5_profile.workspace` | `ig5_workspace.workspace` |
| `ig5_profile recovery={...}` | `ig5_recovery recovery={...}` |
| `ig5_profile.recovery` | `ig5_recovery.recovery` |

`target` 仍是 `ig5_workspace` 的顶层参数,必须是已打开的静态目标(`x64dbg` 会话不接受)。`ig5_recovery` 不接受 `target/engine/toolset/history/workspace`,只接受 `recovery`。

## 5. 证据与限制

- 体积断言:默认门禁与 `npm run ci`;数值来自本轮真实注册定义。
- 行为回归:`scripts/test_host_sdk.mjs`(实际安装 DSH SDK)、`scripts/test_public_tool_catalog.mjs`(真实原生引擎 + 真实 `ig5_workspace`/`ig5_recovery` 调用)、`scripts/test_tool_classification.mjs`(13 审批门双向对账)、`scripts/test_capture_pack.ps1`(便携包根文件白名单与未登记代码拒绝)。
- **未验证**:不同宿主的工具清单缓存/重载行为、其他模型的 tokenizer 计数、真实会话里的选错率变化。`ig5_workspace` 仍是体积最大的单工具;若继续增长需再拆或收紧描述。

调用级验收与证据路径见桌面 `IG5-工具面瘦身P2实施验收-20261025.md`。
