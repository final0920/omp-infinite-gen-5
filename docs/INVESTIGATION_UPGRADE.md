# 调查能力改造 PR 01—04（2026-10-22 修订）

实现标识：`20261022-investigation-brief-2`。保留已有 LCM 改动、v1 task schema、completed 原义、Core8/Full40、13 门及原调用预算。

## PR 01：可运行基准与真实对照

登记 12 开发 + 8 保留任务，绑定规格、预算、验收和独立 oracle 摘要。build_targets.ps1 使用 MSVC 实际编译 15 个静态/内存副作用/toy VM 目标，另有 5 个数据输入；freeze.mjs 重验 C/PE/MAP/规格及编译器版本。
verify_targets.mjs 通过原审批入口使用 Unicorn；20 例资产检查、75 次列出输入的返回/内存写核对通过并完成清理。这不是原生调试采集、全输入证明或完整 VM 恢复。

model_guard.mjs 是宿主访问边界：只允许固定 JSON 证据读取，无路径参数，其他工具分发全部拒绝。实际 SDK 检查了渲染、额外路径拒绝和非白名单拒绝。只有该边界内的真实运行标 isolated；普通源码工作区仍算 exposed。

已对真实静态引擎生成的恢复证据做 baseline/brief 各三次真实模型回放，使用相同模型、提示、证据及预算，每次新会话。保留原始事件、工具日志、冻结计划、被测脚本快照和独立 audit。

| 指标（每组 3 次） | baseline | brief |
|---|---:|---:|
| 完整输出合同独立通过 | 1 | 3 |
| 返回值与当前来源检查通过 | 2 | 3 |
| 调用者接受且独立通过 | 1 | 2 |
| 错误接受 | 0 | 0 |
| 工具请求/分发数 | 12 | 10 |
| 内联字节 | 59,714 | 46,123 |
| 总耗时（毫秒） | 76,235 | 85,723 |
| 提供方报告累计 token | 330,779 | 322,069 |

baseline 一次 JSON 后有正文，一次缺 accepted 字段，均未补跑替换。一次 brief 独立满足有限合同却声明 accepted=false，因此独立结果与调用者接受分别统计。
本例只验五个列出输入的返回、函数位置、当前来源及旧证据识别；不是完整函数语义验证。调用与字节减少但耗时增加，不能由三次推断可靠性。其余 19 个任务没有模型效果结论。
初期 provider 未注册和 renderer 故障批次保留为评测故障，不混入功能改善数据。

## PR 02：能力维度与限定验收记录

`ig5_profile {capabilities:true}` 单独查询，可带 engine，不混入配置或执行。十类意图区分声明、文件检查、启动、功能证据、策略与会话；不运行 doctor、RPC 或引擎。Reverse 内置与 Ghidra 共用 provider。runtimeDigest 绑定 manifest 字节，不冒充全运行包认证。

内部 CapabilityAcceptance 固定注册 dossier 结构验收：五个章节、函数入口与同一数据库快照。记录绑定报告 UUID/SHA、函数、attachment、dbRevision、runtime manifest、验证规则代码摘要和 startup ID，不接受公共 path/SHA 或 caller pass。
本次且范围匹配为 verified-in-scope；重载、修订或运行包变化后为 historical；篡改为 unverified；没有记录为 not-tested。记录明确排除语义正确性、其他函数及完整业务合同。

## PR 03：简报与按缺口导航

`ig5_workspace {target:"已打开的绝对路径",workspace:{action:"brief",id:"任务UUID"}}` 在原静态队列聚合任务、当前 scope、已保存 dossier、能力记录和持久失败，不重新反编译。
默认正文 12 KiB，可用 max_bytes=4096..32768；cursor 绑定 taskId/taskRevision/attachment/dbRevision。省略项明确列出，完整 taskRef 和报告 UUID/SHA 保留；前后核对、最多一次重读。
旧 attachment/revision 不进入当前 observations；已有当前 dossier 时不反复推荐补采。最多三项建议，只在缺少历史前提时给出 LCM 导航。恢复顺序为 brief → 按缺口回读 → 当前身份重验。

研究 sidecar 属于方案 PR 05，通用规划器属于 PR 08，不应列为 PR 03 MVP 的缺陷。本批仍明确显示 acceptance=not-assessed、researchRevision=null、resourceStatus=unknown，不从 completed、结构验收或历史错误推导业务通过或资源释放。

## PR 04：持久失败与各通道适配

原工件库保存不可变 failure report；独立 failure-records-v1 metadata 使用原 owner lock 和原子发布。失败可跨进程恢复，旧 attachment/revision 标历史；最多索引 4096 条，上限时不隐式删除。
报告与索引分别提交；关联失败保留 reportSaved/indexed/indexError 与报告引用。长消息和结构化原生回执另存 blob；超过上限明确标记。原 Error 继续抛出，诊断存储故障不会替换原错误，并附加 persisted=false。

固定适配覆盖 40 工具参数，已提交报告按稳定内容重验，保留来源 SHA；仅持久化参数内容摘要，不存原始密钥、脚本或正文。run/stop/location/runtime 参与绑定。任意文件引用、超预算报告、未知工具明确 comparable=false，不在错误处理时另读任意文件。
最多读取四份报告、每份 256 KiB、累计 1 MiB。重复计数跨重载；笔记改写、同内容换 UUID 不构成新观察。
路由复用 RECOVERY_FAILURES 并适配实际 ERUNTIME_POLICY/ERUNTIME。环境失败不是语义反例；清理未确认优先检查原 owner，不授予执行或资源释放权限。失败索引损坏时简报标 unavailable，不把空列表解释为没有失败。

## 验证与回滚

`npm run test:investigation-upgrade`、`node scripts/test_host_sdk.mjs`、`node scripts/test_investigation_runtime.mjs`。
重建基准：build_targets.ps1 → freeze.mjs → verify_targets.mjs；模型对照及独立审计见 scripts/evals/README.md。
按 AGENTS.md 完成语法/编译、回归、备份、镜像和冷重载，部署状态单列记录。无旧任务或报告迁移；回滚恢复原代码，保留新增 sidecar 和报告。
