# F08 单一有界局部位向量候选器

实现 `20261024-local-bv-provider-1`，固定提供方 `ig5-local-bv-rewrite-v1`、规则版本 `20261024-local-bv-1`。本包按蓝图“先局部化简基线、再考虑线性MBA/msynth”的顺序，适配项目自产局部代数规则到 F07 纯 JSON AST 合同；没有安装 msynth/SiMBA/Xyntia 或额外依赖，没有宣称复现其能力。

```json
{"action":"candidate-simplify","id":"当前任务 UUID","candidate_ref":{"id":"F07合同 UUID","sha256":"合同 SHA"}}
```

要求已打开的静态目标、当前任务/研究合同及 F07 candidate-prepare 的原始来源绑定。仅接受 action/id/candidate_ref；不能选提供方、传候选代码/路径/预算/verified。公共HTTP不可访问。旧prepare/手动verify/read、planner、shadow的默认行为保持。

候选生成在原 AnalysisJobs settled data worker 中运行，64MiB、15秒、单worker+4队列不变。只做一个拓扑pass，最多128源节点、512次规则检查、64次替换，输出≤64KiB；所有输入沿用F07的6变量/128节点/深32/1..64位限制。原式只读、变量按SSA身份；不能引入变量、隐式宽度转换或去掉LOAD/CALL/flags/内存等未支持依赖。

规则限定同宽的零/单位元、同值减法或异或、位运算幂等、全一掩码、双重取反/取负、常量或同分支ITE、完整extract，以及精确 `(x XOR y)+2*(x AND y) -> x+y`。最后一项是模同宽加法恒等式，不是通用线性MBA分类器。扩展/截断顺序、不同系数、未注册模式保持。共享结构只用于候选构造，不作为语义等价证明。

候选输出由宿主再次检查完整AST、变量/位宽、摘要、原式绑定、规则身份/工作上限及成本。reachable node数和非leaf operator数都严格减少才继续验证；无收益返回原式逐字段相同，不为“换一种规范形式”消耗SMT。提供方没有求解器或解释器依赖，不读取文件/网络/数据库，不接动态模块或oracle/pickle。提供方代码及适配器/worker/lifecycle摘要在装载时固定，查询时重验，依赖仅项目原JS与Node，许可沿用仓库LICENSE；无新增上游commit或包。

新入口显式串行：读绑定合同 → 原dataworker生成并确认退出 → 当前来源/研究修订重验 → 保存不可变bitvector-proposal → 仅对更小候选运行原F07独立求解 → 返回结果。F07仍先P SAT及独立见证回放，再差异UNSAT或SAT反例；提供方verified永远false。只有当前F07 pass才返回可使用候选，其他结果候选字段为null。报告通过proposalRef和verification.reportRef分别保留，不能将proposal当作验证回执。

超时、崩溃、损坏/超限输出、缺依赖、未确认清理均保留原合同与原式；新静态/原生后端不会为候选失败而启动。未确认清理必须显示false并由原pool保留owner。取消按原错误传播，不当作成功回退；原式仍不改写。无收益不启动求解。已产生提案不意味着已执行实验或修改数据库。candidate-read可读取proposal，重验当前合同/来源/提供方身份；旧或ABA合同回执stale。F05方法适用性和旧义务不会自动升级。

成本仅衡量合成IR表示复杂度。`accept_bitvector_provider.mjs`的显式协议在运行前冻结四个组合表达式和四个对照：正例要求独立F07通过且节点/运算合计严格下降；对照要求无变化或不接受。额外注入的结构合法错误候选必须由F07检出SAT并独立回放。协议不使用confidence，不宣称真实模型、整体wall-clock、p95、native/CPU/VM或业务收益；求解和worker本身有额外耗时。当前保持assist=false。

`npm run test:provider` 覆盖纯规则、8位全域检查、输出篡改、无收益、实际原dataworker的1ms测试期限终止、模拟崩溃/缺模块/超限、未确认清理和宿主无求解回退。实际工作内存/默认期限保持原值；1ms仅为测试实例更严期限。`scripts/accept_bitvector_provider.mjs --plugin-root ABS --evidence NEW_ABS --protocol PROTOCOL_JSON` 使用自产合成已提交IR与fixture manager，真实运行固定候选worker和原Z3/Windows Job/独立回放；不是实际打开native目标或完整算法恢复验收。

Core8/Full40、13审批门、公开调用计费、原worker/求解预算和runtime/solver/distribution pins保持。F09再扩展CFF只读覆盖层；本包不修改用户数据库、删除副作用或自动执行F06建议。
