# F05 固定方法合同与适用性回执

实现标识 `20261024-method-applicability-1`，注册表 `20261024-methods-1`。在已打开静态目标的 `ig5_workspace.workspace` 上显式读取；不修改 plan/resume/brief，不执行实验，不启用 assist，不增加工具、审批门或预算。

```json
{"action":"method-registry","id":"当前任务 UUID"}
{"action":"method-applicability","id":"当前任务 UUID","method_id":"truncated-source-completion"}
```

先初始化并确认当前研究合同，再按 F04 `case-status/case-index` 显式刷新私有索引。可传 `generation` 固定当前私有 generation；不同则报错。调用者不能提供谓词、架构、IR、路径、项目、实例身份、评分或执行参数。HTTP 公共 knowledge 和 investigation 不接此入口。

| 方法 ID | 适用的调查步骤 | 固定依据 |
|---|---|---|
| known-result-readback | 回读调用者已报告的结果 | 当前任务非空 conclusion，仍是 reported |
| address-space-check | 核对地址空间 | 当前已提交 dossier；不声称映射已正确 |
| truncated-source-completion | 补全截断来源 | dossier 明确 truncated |
| argument-prototype-check | 核对实参与原型 | 当前 dossier；原型可用性单列 unknown |
| callee-family-grouping | 先分组再选择区分观察 | 同一快照至少两个不同 callee EA |
| vm-instance-separation | 收集实例区分证据 | 同上；VM 实例身份仍 unknown |
| pure-expression-simplification | 研究纯表达式候选简化 | 架构支持、类型化 IR、纯度都须有证据；冲突阻断 |
| conflicting-evidence-review | 回读声明冲突的证据 | 当前 hypothesis 同时有 supporting/opposing 链接 |

所有 MethodSpec 都含 id/version/sourceRefs/supportedArchitectures/supportedIRs/requiredPredicates/excludedPredicates/missingEvidenceActions/experimentTemplateId/verifierId/budgetClass；informativePredicates 是补充观察，不是隐含前提。八份 F03 原创深审笔记的精确 UUID/SHA 引用固定在源码；公开 store 每次确认引用仍 active/reviewed 并重验完整正文摘要。分数、相似度、文章自然语言不参与规则，不加载或执行上游算法。受限 typed-bitvector-expression-v1 适配器尚未注册，因此架构、类型化表达式及纯度保持 unknown，不能仅凭反编译字符串通过。supportedArchitectures 是方法声明范围，不是目标检测结果。

每个条件返回字符串 true/false/unknown、原因及有界 evidenceRefs。只有明确完整的 section 才允许作否定判断；unsupported/error/数据缺失不当作 false。EA 按整数规范化，同一 EA 的大小写/前导零不计多个 callee；不跨函数快照拼接。不同地址不证明不同算法，同结构不证明语义等价；种子/表/实例无结构化适配器时不从名称、注释、地址猜测。已知结果只够回读导航，不等于算法解释。

required 有 false 得 inapplicable，required 或 excluded 有 unknown 得 needs-evidence，excluded 有 true 得 blocked，其余 applicable。applicable 仅表示该调查步骤的必要导航前提满足。声明的支持/反对链接使冲突复核适用，但不代表独立裁定了语义矛盾。完整性诊断使回执 blocked，过期/缺失私有索引或缺失/撤回审核来源使 needs-evidence，不隐式发布或回退到旧文章。

ApplicabilityReceipt 绑定可信完整静态 scope、任务修订、研究修订、合同摘要与 contractRevision、公开/私有索引 generation、sourceStamp、注册表版本/摘要、methodVersion、inputDigest 和 receiptDigest。合同 A→B→A 也失效。前后两次独立重读校验来源与身份，漂移拒绝；未保存回执，不提供可重放执行令牌。单份 JSON ≤32KiB，继承 F04 每类8份/共64来源选择与显式遗漏，completeHistory=false；不会把有界阴性结果推广到全部历史。

verifierId=method-structure-v1 仅指固定结构条件评估器，不是语义性质验证器；experimentTemplateId 仅引用已有模板 ID，不渲染、不安排、不执行。所有回执 semanticVerified/algorithmExplained/executionAuthorized/assistEnabled=false。缺少合同的响应只说明缺件，不能作为完整适用性证书。

测试：`npm run test:methods`，旧 case-index/research/planner/knowledge/LCM/data-route/实际 SDK、打包缺件检查。scripts/fixtures/method-public-v2 是 F03 已发布的公开原创笔记不可变测试快照，测试只复制数据到临时目录，不读取用户实时资料库。真实打开目标上的正向适用性和实际模型收益须另验，不由夹具或 SDK 注册通过替代。
