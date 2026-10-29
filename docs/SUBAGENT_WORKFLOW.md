# DSH 子代理协作

## 2026-10-20 受控交接与预算

先单独调用 `ig5_profile collaboration={action:"start",max_calls:20}` 开启当前 DSH 根会话及全部后代的共享 IG5 调用上限。父、子、孙代理的 profile/open/evidence、配置切换、失败的已分发调用均计数；超额在执行前拒绝。`collaboration={action:"status"}` 为免计数控制面查询，耗尽后仍可查账。额度持久化，不能通过重复 start 或重载放大；这是该根会话的固定试验额度，新试验应使用新会话。未显式 start 时不启用预算；不是从提示词自动抽取数字，不计 tokens、非 IG5 工具或外部 provider 的执行。

新 DSH 会话中的 handoff 返回 `mode=tracked` 和 `handoffId`。父代理应把返回包及这个 ID 交给实际 DSH 原生子代理；插件仍不代派工。

1. 子代理 `workspace={action:"claim",id:<task>,expected_task_revision:<rev>,handoff_id:<handoffId>}`。只接受真实会话父子身份及已观察的同次原生 subagent run，不能由父代理自称子代理。
2. 子代理 get 任务、定位相关架构、`action=evidence` 读取需要的完整报告。插件只记录“报告确实已交付给这个 agent”，不声称能验证模型理解或强制阅读外部文档。
3. 子代理 `action=submit`，提供同 task/revision/handoff_id 和 1..8 个已读取、未 stale 的 `snapshot_ids`，再输出候选结论与未知并结束。submit 是证据回交记录，不是语义结论认证。
4. 父代理等真实子代理结束后，以 `action=review` 和 `handoff_id` 核验其实际提交的完整快照集合。缺回交、缺同 run 的 completed/output、目标/修订变化、错误快照、重载后旧 ticket，均拒绝正式复核。

无 `handoff_id` 的旧 review 保留为 `reviewStage=integrity-precheck, delegationVerified=false`；不能当子代理验收。受控成功为 `reviewStage=post-return, delegationVerified=true`，仍保持 `semanticAcceptanceVerified=false`。没有可靠宿主身份/生命周期时返回 untracked 或拒绝受控调用，不伪造支持。

安装后应冷启动 DSH，并检查 `ig5_profile.implementationRevision=20261020-controlled-delegation-1`。仅插件开关可能复用旧模块，不能据版本号 1.1.0 或磁盘 SHA 一致就认定加载成功。旧 handoff ticket 不跨宿主重载继承运行完成证据，需重新 handoff；共享预算不随重载清零。

以下旧接口示例中，省略 handoff_id 的 review 只作完整性预检查。

通过现有 `ig5_workspace` 交接静态调查，保持 Core8/Full40、八个技能和十三个审批入口。插件不调用模型、不派出代理。父代理使用 DSH 原生派工能力，把交接响应作为任务上下文；目前没有自动拦截宿主派工或强制子代理阅读的功能。

## 父代理准备

先确认明确的 target、engine、当前调查任务和 taskRevision。必要时先收集少量 `ig5_decompile style=dossier task_id=...`，随后重读任务，因为捕获证据会增加 taskRevision。

调用 `ig5_workspace`，显式指定 target、engine 和以下 workspace：

```json
{
  "action": "handoff",
  "id": "<task UUID>",
  "expected_task_revision": 1,
  "question": "追踪该函数的输入如何影响输出，并指出关键分支",
  "acceptance": "结论引用本任务 dossier，列明未验证的内存和调用行为",
  "constraints": "只读调查；修改建议交父代理；不控制动态调试"
}
```

返回目标 SHA、project/artifact、engine/provider、attachment/database 修订、任务声明、证据引用、开工步骤与回交格式。合同文字只是调用者声明，不是操作系统访问控制。handoff 不保存新的调查任务，不锁定目标、不授予执行权限；受控模式另存交接 ticket 与宿主身份，`coordinationModified=true`，不改变 taskRevision 或数据库。引用列表尚未重读报告，`reportsVerified=false`。

## 子代理开工与回交

在自己的 agent 范围确认工具集；读取任务并核对交接身份与修订。只定位相关输入、处理、输出、已有事实和未知项，不重复全库扫描。用 `workspace action=evidence` 读取需要的完整报告，保留 partial、截断和不可用章节。证据或任务变化后重新交接。

回交 taskId/taskRevision/context、candidateConclusion、snapshot_ids、coverage、unknowns、next_action。新取 dossier 后使用最新任务修订。若需要各自保存笔记，可为每个子问题创建独立调查任务；当前没有自动父子任务关联或候选提升状态机。不要由子代理直接把共享任务标 completed。

## 父代理复核

显式 target、engine，调用 `workspace={action:"review",id:"<task UUID>",expected_task_revision:1,snapshot_ids:["<snapshot UUID>"]}`。一次检查 1..8 个不重复、属于本任务的快照。逐份核验报告摘要、来源、函数和章节，返回各自原始分析状态及 stale 标记。摘要损坏或外来快照拒绝；过期快照保留历史观察，并返回 staleEvidence=true。

`reportsVerified=true` 只代表引用完整性与来源核验。验收正确性、覆盖和合同仍需独立判断，`semanticAcceptanceVerified=false`；不会自动批准结论、提升证据等级或完成任务。需要完整正文时继续使用 evidence，review 的章节状态摘要不能替代正文。

多个 agent 共享引擎数据库。静态读取可以分工，数据库修改应协调单一负责人；现有队列只保证执行顺序，不能消除意图冲突。动态操作沿用控制所有权、显式 takeover、run/stop 身份和公共审批。

## 验证范围

`scripts/test_investigation_workflow.mjs` 使用真实报告存储和合成 dossier，验证跨 agent、CAS、过期与篡改检查；不代表真实模型理解或派工效果。完整验收还需 DSH 主代理实际派出两个子代理并回交、复核。
