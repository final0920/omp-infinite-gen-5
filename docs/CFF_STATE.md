# F09 跨块状态语义

实现 `20261024-cff-crossblock-1`，沿用原 Core8/Full40、13 审批门和 worker 生命周期。

先在当前静态目标创建任务并初始化研究合同；调用原 `ig5_microcode`，`action=deobfuscate` 时显式附带 `task_id`。宿主只封存这次 RPC 的原始 typed HighFunction、目标完整字节及数据库身份，返回 `sourceRef`。未附带 task_id 的旧行为保持。调用者不能提交图、PHI、状态标签或验证结果。

随后 `ig5_workspace.workspace={action:"cff-state",id:<任务>,source_ref:{id,sha256}}`。原 Python SCCP 生成的入口边条件路由由独立 JS 在原 AnalysisJobs worker 重新计算，范围仅为“刚经过原 predecessor→dispatcher 边之后”的 SSA 路由。两者路径、PHI 状态证据及完整图定点均匹配，才标 `verified-in-scope`。它不证明该入口边可执行、native lifting 正确或整个函数恢复。

依赖按完整 SSA 身份、定义支配关系和原有序 PHI 入边保存，包含跨块 COPY、循环依赖和全部竞争 PHI。未选择唯一状态变量，不自动判断 CFF；普通 switch、协议状态机、解释器等解释保持。LOAD、STORE、CALL、间接控制、volatile/异常和不完整图不被消除。原图所有块/边及状态写保存。未知条件、循环边界、路径及工作预算截断明确报告。

上限 128 块/512 边/2048 操作、1..64 位、8 竞争 PHI、每闭包128定义、4096依赖边、64路由、每路径16块、共享100000工作步；worker仍64MiB/15秒/单活动+4排队。原始报告与目标重绑合计8MiB，单 source报告2MiB，HTML1MiB，完整派生报告4MiB，摘要24KiB。超限拒绝或降为候选，不补全未知。

`cff-read` 读取该不可变报告并重绑任务、合同 ABA、目标、数据库和实现；过期历史保留。HTML保存原图/覆盖层及完整 JSON，scriptless CSP，无写 DB、执行或默认 assist。

`npm run test:cff` 与 `accept_cff_state.mjs --plugin-root <源码或安装目录> --evidence <新目录>` 包含真实纯 Python 分析器和实际 JS worker，但输入是明确自产合成 SSA，不是原生 Ghidra/保护目标证据。受4551阻断的原生组件不重试。
