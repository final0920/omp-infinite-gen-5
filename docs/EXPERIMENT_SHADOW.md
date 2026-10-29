# F06 固定实验建议 shadow

实现标识 `20261024-experiment-shadow-1`。通过已打开静态目标、真实执行 agent 上的 `ig5_workspace.workspace` 显式调用：

```json
{"action":"experiment-shadow","id":"当前任务 UUID","mode":"shadow"}
{"action":"experiment-shadow","id":"当前任务 UUID","mode":"off"}
```

默认 mode=shadow；旧 action=plan/resume/brief 完全不接入新建议。off 精确走原 plan，跳过方法/私有索引/新失败历史读取。shadow 在旧 plan 的独立 `shadow` 字段返回最多三项建议；旧 candidates、优先级和预算字段保持原值。参数仅允许 action/id/mode/max_bytes，不接任意模板、请求、谓词、预算、路径或 confidence；assist 明确拒绝。公共 HTTP 路由不接受此私有入口。

先按 F04 初始化当前合同并显式刷新私有索引。F05 的八类方法条件在同一可信捕获上评估，前后重绑来源、合同 ABA 修订、索引 generation、资源/共享预算及失败历史。只有 applicable 方法生成建议，缺少架构/纯 IR/实例参数时不合成算法执行请求。方法来源撤回、损坏、跨范围或旧索引保持 needs-evidence/blocked。

固定模板包括：回读已报告结果、回读绑定来源、补全静态来源、复核声明冲突、比较 callee 来源。每项 ExperimentProposal 含 question/competingHypotheses/inputRefs/scope/predictedOutcomes/existingToolRequest/estimatedCost/stopCondition/missingPrerequisites/dedupKey。请求只由固定代码生成，正文是数据，不 eval、不动态导入、不派发工具、不修改任务或数据库。模板是 F06 只读提案渲染器，不冒充已登记研究实验或性质验证器。

优先序：已报告结果复用 → 地址/来源/完整性补齐 → 冲突复核 → 区分观察。环境/cleanup、原 planner 的优先级保持；cleanup-pending 时新建议让位，静态能力/启动/原策略/会话不满足时不提出新静态采集。最多三项，成本之和不超过原公共调用与输入预算；这是替代建议，没有额外额度或预算预留。用户明确采用后，原 dispatcher 仍重新核对身份、审批、计费和并发资源。

多 callee 只在同一完整性已绑定的快照内选取两个不同 EA，按数值顺序确定性选择，不声称地址距离代表语义差异。两个收集提案分别请求原 dossier 工具观察一个 callee；同一请求的家族分组/实例分离方法来源合并，保留 methodRefs/dedupKeys。竞争解释明确区分“共享变换但种子/表/输入不同”和“不同局部变换/实例”，缺独立实例输入及 seed/table/bytecode 身份时只提来源观察，不执行实例语义实验。不同地址不证明算法不同，同结构不证明等价。

dedupKey 包含样本/项目/函数/表达式空值、来源输入摘要、完整静态环境前提、方法与模板/验证器/工具实现版本、runtimeDigest 和请求预算。复用原持久化 FailureRecords 的 planningKey 与完整失败回执校验：相同请求、运行时和已知输入报告集合抑制；旧记录缺输入集合时保守抑制相同请求，不猜测已经变更输入。输入集合或运行时变化允许重新建议并列 retryChanges；其他不同请求仅说明有不同 key 的历史，不能据此声称具体重试已经有新证据。历史读取限原 bounded index/exact keys + 最近诊断，始终 completeHistory=false；损坏或不可读为 unknown，新静态收集暂缓。未执行过的同一建议可再次返回，生成提案不算一次实验。

回执绑定 F05 输入、方法回执摘要、版本、当前完整范围，最多32KiB。max_bytes=4096..32768（默认32768）是总响应预算，旧 plan 使用其原规则/默认预算；只裁 shadow 建议，披露 omittedForResponse 并重算建议成本，不裁旧 candidates/条件绑定。如果必需字段仍放不下则报错，不返回伪完整计划。

`npm run test:shadow` 覆盖 off 对照、原输出相等、方法/范围失效、多 callee、持久化失败去重、输入/运行时变化、预算耗尽、cleanup/历史故障与响应界限。`scripts/accept_experiment_shadow.mjs CASE_BUNDLE CASE_ROOT NEW_OUTPUT` 是显式离线 VS1.5 回放：原 SHA/范围核对后保存 shadow-plans/quality；不打开真实 native 目标、不发布真实私有索引。质量按已有结果、区分结果、关键缺件、无效重复四项预定标准观察，不使用模型 confidence；此 exposed 夹具不能计真实模型收益、盲测或默认 assist 的依据。

旧失败记录缺运行时摘要或当前运行时未知时，保守视为不可区分，抑制同请求/同输入；只有两侧运行时摘要都已知且不同，才能标 runtime-identity-changed。缺元数据不是新版本证据。

Core8/Full40、13审批门、worker/求解/公共调用预算和 runtime/distribution pins 保持。实际打开静态目标上的正向使用与模型配对收益仍须另验；无收益证据时 assist=false。
