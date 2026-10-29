# 固定性质与义务有效状态（A01—A03 首批）

此入口复用 ig5_workspace / ig5_recovery，不新增工具、执行权限、审批门或原生采集路线。只使用固定验证器和现有有界数据 worker；回执保存与研究 CAS 关联仍是两个提交。

## 已登记性质

| property | verifier | 可以关闭 |
|---|---|---|
| vm-context-candidate-derivation-and-provenance | vm-context-audit-v1 | 指定 context 的派生和来源 |
| recorded-fetch-body-source-binding | vm-recorded-source-v1 | 指定 context 与完整原录制的 fetch/body 重绑 |
| fixed-owned-model-return-and-output-memory-equivalence | vm-finite-model-v1 | 精确程序和函数合同的完整有限模型域 |
| fixed-owned-recorded-return-and-output-conformance | vm-recorded-function-v1 | 指定原录制中合同域内实际输入的返回及输出符合性 |

模型和原生性质分开执行。原生范围外的记录保留，但不计入闭合输入；例如原记录为 `{0,1,uint64_max}`、函数合同为 `0..255`，只有 `{0,1}` 可关闭对应原生义务。模型穷举 256 次不增加原生覆盖。

## 调用顺序

1. 经原 recovery.declare_contract / program / function_check 得到不可变函数评估报告，或 role_compare / role_validate 得到原始来源验证报告。
2. workspace.research-update 使用 `operation=link-verifier-evidence` 和顶层 `report_ref={id,sha256}`。已有 `link-vm-context` 与 dossier 入口继续可用。
3. 从返回 evidenceLinks 读取 `id` 与 `propertyScopes[property]`。提出义务时指定 property、对应 verifier、`scope=evidence:<UUID>`、dependencies，以及完整 propertyScope。所有这些字段均为提案；调用者不能写 closed-in-scope。
4. workspace.research-verify 仍只传精确 task/research revision、scope_digest、evidence_id、obligation_id 和可选 experiment_id。验证器由静态目录选取，不能指定路径、脚本、参数表达式或 oracle。
5. CAS 冲突时回执保留，重新读取修订后用 research-link-verification 关联原回执，不重复执行。research-verification 读取历史完整回执。

propertyScope 包含目标 SHA、程序/比较报告 UUID/SHA、结构化函数合同 UUID/SHA、环境摘要及精确域。首版仅精确匹配；不实现整数区间包含、不合并不同记录的输入域、不比较自然语言合同。函数合同仍为原 v1。

## 回执、有效性和失效

JSON Schema 冻结在 `schemas/verification-result-v2.schema.json`；生产结构在 `source/verification_schema.js`。v2 保留旧描述性字段供调用方读取，并增加 propertyId、subject/contract/obligation 引用、scope、verifier、cleanup。coverageRef/counterexampleRef/cleanupReceiptRef 首批固定 null；实际覆盖、反例和 owned worker 退出确认内联在不可变 outcome/cleanup 中，不伪造另一个资源回执。

v1 仅历史读取，不升级为 v2，不为新的有效投影闭合义务。旧任务/研究状态读取不写入迁移；新增 typed evidence 通过显式写操作进入已有 research v2。旧版本若不理解新字段，应保留文件并拒绝写入，不降级覆盖。

结果 pass/fail/unknown/unsupported/error 与当前 validity=current/stale/unverified 分开。当前规则、主体、合同或必要来源不再匹配时，旧 pass 原文保留。读取不运行验证器或引擎；只按最多 8 个回执、64 个分析报告、8 MiB 预算重核输入。未读到的旧回执记 omittedOlder，并返回 receipt-read-budget-incomplete / assessment=unverified，不能用较新的 pass 遮住未读取的潜在反例；此时暂停所有新的有效闭合，分页投影留待后续扩展。录制总指令仍最多 50k，输入报告另外最多 48 个原始引用，超限明确未验证。

obligation_evaluator 对最多 64 个义务做有界拓扑投影：有效 pass 且依赖闭合才 closed-in-scope；同义务有效反例为 contested；未闭合父依赖为 blocked，父合同/规则/提案修订失效传播为 stale。未知/错误回执不撤销仍有效的 pass。superseded 提案不自动重定向依赖，新版本需显式修订。循环、自依赖和未来引用拒绝。

实现身份在模块加载时按静态依赖闭包冻结，并绑定 Node 可执行文件、运行时与规则摘要。执行前后与读取时复核；热换文件要求重新加载，不能让旧加载代码为新文件签发身份。模型求值与原生录制验证共享部分实现，回执明确记录这种相关性，不声称独立 CPU 验证。

## 验证与回退

`npm run test:research`、`npm run test:semantic-isolation`，以及原 `test:vm-function`、`test:planner`、观察层与 SDK 回归。`scripts/accept_research_properties.mjs` 显式选择单个既有原生批次，演示模型/原生独立闭合、未执行输入拒绝、原字节改动/合同变化失效及历史回读；只回读原录制，不执行 PE。

回退部署代码时保留所有研究状态、报告、反例和孤立回执。新格式不被旧代码理解时停止写入，不删除或转换新数据。实验性语义发现与完整盲测仍未上线。
