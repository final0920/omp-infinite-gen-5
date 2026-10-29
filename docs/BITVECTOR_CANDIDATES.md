# F07 纯位向量候选合同与独立验证

实现标识 `20261024-bv-independent-verifier-1`。F07 先建立来源合同和独立验证器，未接入 F08 候选算法，不自动执行 F06 提案、不更新旧 obligation 或数据库，不启用 assist。

通过原 `ig5_workspace.workspace` 显式操作已打开静态目标/当前任务与研究合同：

```json
{"action":"candidate-prepare","id":"当前任务 UUID","source_ref":{"id":"投影报告 UUID","sha256":"报告 SHA"},"root_node":3}
{"action":"candidate-verify","id":"当前任务 UUID","candidate_ref":{"id":"合同 UUID","sha256":"合同 SHA"},"candidate_ast":{"nodes":[{"id":0,"op":"var","bits":8,"args":[],"name":"ssa_0"}],"root":0}}
{"action":"candidate-read","id":"当前任务 UUID","report_ref":{"id":"合同或验证报告 UUID","sha256":"报告 SHA"}}
```

上述 AST 仅为形状示例，变量名/宽度必须来自实际 prepare 返回。工具参数不能指定路径、命令、验证器、超出预算、verified 状态或原表达式文本。HTTP 公共路由不接此入口。

## 来源与合同

source_ref 仅接受 lifter artifact 中 kind=projection/action=project、schema=ig5-pcode-projection-v1 的完整 strict preferred-address 投影报告。完整报告/IR blob/归档源字节/当前目标字节都重验摘要及当前目标身份；共享源读取上限8MiB，超出拒绝。当前适配器来自已有 x64 p-code 投影，不能据此宣称 ARM64 已接入；guarded/opaque/recorded 路径未注册为本包原式来源。

原式从指定 root_node 的完整依赖闭包派生；只认初始普通 GPR 的明确 SSA 身份。六变量上限，源式+前提合计≤128节点、候选≤128节点，深≤32、宽1..64。变量不可新增或改宽；候选可消除不再需要的变量使用，但合同变量全集不变。LOAD/CALL/PHI/未知flags/opaque输入、未支持算子及混合宽度隐式转换均 unsupported，不裁掉依赖继续验证。原报告中的其他寄存器/内存/控制效果保留，不能凭局部值等价删除。

AST 是拓扑排序 DAG：每节点 id 等于数组位置，args 只指先前节点，无死节点/隐藏字段。const 使用位宽内规范无符号十六进制，var 使用 prepare 给出的 SSA 名；二元同宽 add/sub/mul/and/or/xor/shl/lshr/ashr，单元 not/neg，显式 zext/sext/extract(offset)/concat（高到低），eq/ult/slt 产一位，ite 条件一位。移位计数使用完整同宽无符号值，不擅自套 x86 的计数掩码；超宽逻辑移位为零，算术右移保持符号。

prepare 默认 P=true；可显式提供同变量全集的一位 premise AST，作为 caller-declared-structured-assumption，不能推定在原生路径可达。合同绑定任务/研究修订、样本、引擎/provider、attachment/DB、研究合同摘要与 ABA 修订、来源根、原式/前提摘要和版本。候选验证不能另换前提。

## 验证及回执

1. 宿主重新加载合同、完整原来源及当前身份，候选再做结构/大小/变量/位宽检查。
2. 固定 Python 翻译器构造原式 O、候选 C、前提 P；不执行候选代码，不复用候选提供方的 verified 字段或求值器。
3. 首查 P。SAT 模型必须由独立 JS BigInt 解释器确认 P 为真；P UNSAT 得 unsupported/infeasible-premise，unknown/unverified 不形成等价通过。
4. 再查 `P ∧ (O ≠ C)`。只有 UNSAT 且前提见证成立才 pass/equivalentInIR。SAT 必须独立回放 P、O、C，保存有效反例才 fail；unknown 保留原式与候选，无通过。
5. 两层进程结束确认、输入/代码/pins 完整性与当前范围重验完成后保存回执。若求解后上下文变化，保留 computedStatus 和完整报告，但当前结果 unknown/equivalentInIR=false。

求解复用 LiftJobs 两槽、Windows Job 创建时绑定、单child/2GiB/50秒和原60秒请求/5秒清理；本功能最多2次SMT查询、每次≤2秒/512MiB，继承1MiB查询/2048式/8192词/128深限制。查询+模型+结果合计≤4MiB；源及验证材料组合读取仍受8MiB限制。SAT回放走原 AnalysisJobs 64MiB/15秒、单worker+4队列的 settled 路径。没有新增池、预算或审批通道；取消或退出未确认不提交 pass。

原固定 solver manifest SHA `65bf673f1c4304cc2c09076e3b96e368da9e0df72aa0badeba0c2a5cae392934` 保持，DLL SHA 按该清单及物理字节重验，实际 C API 版本记录在 assessment.solverVersion；当前实际验收为 Z3 4.13.3.0，supplier distribution 为1.0.0rc4，二者不是同一版本概念。运行包 pin 仍 `8fc4ae42f775f0139aa5f184c912db71f77e68d661c14564ab6f4820d434abea`。仅加载原固定 Z3，不加载/启动受4551阻断的 SLEIGH 或 headless，也不执行目标文件。

完整 bitvector-verification 回执保存原式/候选/前提及摘要、来源和合同引用、binding、固定验证器代码摘要、依赖版本/pins、完整查询及模型 SHA blob、进程预算和清理确认、JS回放及反例。candidate-read 重新核对当前合同、源、代码与查询模型材料，区分 current/stale；历史 pass 不能当作当前通过。响应超过32KiB拒绝，完整本地不可变报告保留；工具响应不把裁剪 AST 冒充完整证书。

## 明确边界与验证

pass 仅为“所选纯 BV 表达式在确切 P 下的 IR 等价”。IR 对原生指令的完整对应、可达性、其他寄存器/flags/内存/控制副作用、全函数、VM或业务正确性均未由本包证明。研究自然语言合同不会自动成为 P；有限输出一致也不产生全宽证明。F05 的纯表达式适用性适配未自动升级，F06 的旧 planner/shadow 行为保持。

`npm run test:candidates` 为纯 AST/见证/宿主来源夹具；`scripts/test_bitvector_worker.py` 为独立 Python 编码与模拟 unknown/UNSAT 边界，不加载native库。`scripts/accept_bitvector_candidates.mjs --plugin-root ABS --evidence NEW_ABS` 显式运行自产合成已提交 IR 来源，使用实际固定 Z3/Windows Job/独立 data worker；它不能称真实打开目标、native解码、VS1.5算法恢复或模型收益。安装后实际 SDK、宿主重载和原资料回读另验。

F08 的单一本地候选提供方见 [BITVECTOR_PROVIDER.md](BITVECTOR_PROVIDER.md)，仅新 candidate-simplify 显式入口调用。原 candidate-prepare/verify/read 合同及独立验证权限保持。
