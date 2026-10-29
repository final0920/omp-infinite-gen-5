# F09：只读控制流覆盖层

实现 `20261024-cff-overlay-1`。这是有界 CFG 与局部纯 BV 条件的调查视图。普通 switch、协议状态机、解释器与 flattening 可以有相同拓扑；所有分类保持 unknown，不因高扇出或回边宣称识别 CFF。

在已打开静态目标、当前任务研究合同下，通过 `ig5_workspace.workspace`：

```json
{"action":"cff-overlay","id":"任务 UUID","snapshot_id":"当前任务系统 dossier snapshot UUID"}
```

只接受任务成员 dossier、完整 UUID/SHA、当前项目/样本/attachment/DB/任务和研究合同修订。无原生 RPC、DB 写入、脚本/图/状态变量/预算注入；不启用 assist。原始 dossier 即使部分也保留，最多 128 块、512 边；超限明确拒绝而不截断冒充完整图。

完整 provider 图须原 section 的 provider/response 明确 complete、原响应未截断、总计精确、块地址不重叠、全部端点与双向邻接一致。缺任一项，providerGraphComplete=false。即使满足，也只代表该 provider 的有限拓扑模型，异常、间接目标或未建模控制仍 unknown，wholeFunctionRecovered 永远 false。

比较最多 8 个分支块候选，披露遗漏；每个记录扇出、入边、可回到自己的后继及竞争解释。最多 64 条局部拓扑见证保留原路径、原块、图/路径摘要与版本；内块只有单一报告后继才沿链，环与未知端点停止。observed 只指 provider 报告边；candidate 是结构推测；verified-in-scope 必须带 scope：拓扑见证仅 reported-CFG-topology-only，绝不证明动态可达或状态转移。unknown 原样保留。

可选 `verification_ref={id,sha256}` 必须指向当前 F07 独立回执，调用既有 candidate-read 逐层重验合同、源字节/完整 IR、查询/模型摘要、验证器版本与 cleanup。仅无调用者前提、P SAT/差异 UNSAT 且独立 JS 回放通过的单常量候选可用。该合同 root 必须正是源 strict projection 的 terminal conditional condition；条件采用 nonzero-is-taken，投影从一个原块的精确起点开始，全部地址位于该块内且末地址为 control.source，目标必须是原 CFG 边。报告仅标 selected-pure-BV-terminal-condition-only，不删另侧边，不证明 native 对应。错 root、SAT 反例、unknown、调用者前提或旧回执均拒绝。

有该纯条件回执时，显示其真实 SSA 初始 GPR 依赖并比较全部变量；每个变量的 stateRole/writes 仍 unknown，不自动选全局状态变量。无此证据时，CFG 文本不足以提供 SSA 读写，状态依赖明确 unknown。本包没有跨块状态赋值/PHI/LOAD/CALL/volatile/异常的数据流适配器，不能声称已恢复它们。STORE/CALL/volatile/异常、状态写入、全部原块与原边保留，不优化用户 DB。

不可变完整报告与 `viewRef`（SHA blob）保存在原 analysis artifacts；返回小型 summary，未知出口预览最多 16 项并披露遗漏，完整报告不裁剪。`cff-read` 只收 report_ref，重新绑定代码身份、合同 ABA、dossier 与可选 F07 回执、HTML 全字节；过期历史返回 stale。脚本为空、无外部资源的自包含 HTML 将原图和覆盖层并列，黄色候选、绿色局部条件，完整来源/条件/范围/回执可在同页检查。原边灰色始终显示，不替换数据库；线方向以 from/to 明细为准。该 artifact 可导出查看，未增加 F12 的产品交互 UI。

验证：`npm run test:cff`；`node scripts/accept_cff_overlay.mjs --plugin-root <源或安装根> --evidence <新独立目录>`。后者使用合成 CFG/IR 与真实固定求解器、独立 worker 和原 Job 清理，不能当实际 Ghidra 解码/真实保护目标或模型收益。已有 4551 阻断不得重试。Core8/Full40、13审批门、原 worker/SMT 预算与全部 pins 保持。
