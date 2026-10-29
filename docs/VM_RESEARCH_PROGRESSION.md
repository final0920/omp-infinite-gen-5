# PR11—14：研究推进入口与当前范围

2026-10-23 后续修订 `20261023-investigation-final-2`：`role_validate` 的跨运行状态按重绑后的不同 runId 计数，多个 context 或不同入口值不能代替不同运行。宿主 `/ig5-data` 已抽取至 `source/read_only_data_route.js`，原宿主仍注入错误脱敏和诊断，注册与注销沿用原 webServer 生命周期；没有增加路由或执行入口。下文原版本记录的能力范围继续有效，新增原生和桌面结果以本批单独验收记录为准。

版本 `20261023-vm-research-2`。这些入口保留 Core8/Full40、13 个审批门、原生采集/worker/求解和清理协议。新增分支只读封存证据或显式 SHA 的固定自产参考输入，另存派生报告；不启动引擎、客体、求解器或任意 oracle 程序。有限验证复用原 64 MiB/15 秒、单活动+4 排队数据 worker，并确认退出后提交。

## 使用顺序

通过 `ig5_recovery` 的互斥 `recovery` 分支操作(原 `ig5_profile.recovery`)：

1. `declare_contract={contract}`：封存 `ig5-function-contract-v1` 调用者声明。要求目标 SHA、入口 RVA、正常 RET、RCX 无符号位宽/上下界、RAX 返回值、最多 16 个不重叠输出内存区、明确环境及排除项。它不是验收结果；目前只支持单线程、无外部调用的拟定范围。
2. `role_compare={context_refs:[{id,sha256}],contract_ref:{id,sha256}}`：1..8 个不同 context。共享 8 MiB/64 份已提交报告读取预算，逐层验证候选/handlers/recurrence/selection 的 UUID、SHA、种类及独立候选复算。比较五类寄存器候选和 fetch 增量；关系不一致完整保留。
3. `program={comparison_ref:{id,sha256}}`：重新读取并复算比较闭包后，建立最多 1024 个已观察候选节点，保留所有普通状态 assessment、未知 GPR/STORE、原投影及选择来源。仅确切同 context 的 nextFetchGroup→startGroup 建观察边；遗漏或歧义转未决边，每个节点另保留未观察分支。
4. 普通候选图的 `function_check={program_ref:{id,sha256}}` 仍返回 `unsupported-incomplete-program-semantics`，不能把未知语义升级为通过。下述固定自产模型车道已接有界执行与独立 oracle。

## 第二批：原始重绑与有限函数验证

`role_validate={comparison_ref,recording_bindings:[{context_ref,recordings:[{id,sha256}]}]}` 要求绑定顺序与 comparison 一致。重新校验所有原报告、blob、STORE、完整窗口和每个已选 fetch/body；假 context 即使候选派生审计通过，原始重绑也会拒绝。RCX 仅在实际首 PC 匹配合同入口时计入输入独立性。代码观察点保留实际 PC/字节，不对地址、GPR 或数据做未经验证的 ASLR 归一化。留出关系使用全部选中父对象，不能拿首八个示例冒充全部覆盖。key 模型和通用 VM 实例缺失时仍明确 unknown/unsupported。

`program={image_ref:{path,sha256},contract_ref}` 是互斥的固定来源车道，读取本地普通文件（无链接祖先、最多 64 KiB）并封存全部输入字节。当前只注册三份精确 SHA：

| 参考 | 精确输入 SHA | 范围 |
|---|---|---|
| owned-phase-vm64 | `71d1ceaedaebeb572c63c33485405fa7612beab047aff0c00f96044bd92223f0` | 已有自产 PE，字节码 `010200`，入口 RVA 0x1000、native-ret |
| owned-branch-vm64 | `d9bf31e34c5e95307f88fcc7ce544101bd61e566c284a4622afc9700f29da61c` | 自产分支与跨 handler 写后读原生解释器，入口 RVA 0x1000、native-ret |
| branch-memory bytecode | `6e71d6e35ce1939e6a44825918979e3188cd5c83f3d9d3afafa7d136b979224e` | 自产字节码 `07070305090855060b010400`，入口 0、bytecode-halt；有输入相关分支与跨 handler 写后读 |

三份合同均为 RCX 无符号输入、RAX 返回和 RVA 0x3000 的完整八字节输出；只支持这一明确无别名输出布局。固定 source profile 不是通用 x64→VM 翻译器；未知 PE、修改过的来源、额外输出布局均拒绝。测试源码在 `scripts/fixtures/vm_bytecode_cases.mjs`，构造字节不执行目标。

`vm_bytecode.js` 为固定虚拟机定义整个虚拟状态：accumulator、明确初始化的输出字节、PC 和 decoder key。支持显式返回、add/xor、store/load、parity branch、jump；未知 opcode/目标、缺失内存、状态和步数预算不得补值或伪造返回。节点身份包含模型实例、位置、代码/内存版本和完整解码 key。xor-key-v1 的同地址不同 key 不合并；当前三份公开 source profile 为 plain。每个操作保留原字节与全部虚拟状态效果；它们不是完整 native CPU flags/GPR 证明。

图的 memoryVersion 只标识不可变解码映像；输出 RAM 始终是每次求值的独立字节状态，不按该解码键合并。未穷举的有限样本即使全部匹配，顶层 status 也为 partial；未提供原录制时 recordedFunctionEvidence.status 为 not-supplied，不能显示为原生通过。

`function_check={program_ref,sample_inputs?,recording_runs?:[{recordings:[{id,sha256}]}]}` 先重新派生程序再调用原数据 worker。独立 source-level oracle 不导入候选解码器；另有不导入 JS 的 Python 解释器重算全部有限输入及 transcript 摘要。输入域 ≤4096 逐个穷举；更大域只做端点和最多 64 个显式样本。记录返回、全部声明输出字节、观察/未覆盖模型边、反例、测试/穷举/全域证明不同状态。`modelContractAccepted=true` 仅接受固定虚拟模型的明确有限域，`universalProof`、`nativeCpuEquivalenceProved`、`businessAccepted` 和 `wholeVmRecovered` 保持 false。

可选原生录制支持上述两份固定自产 PE：重验执行字节、入口 RCX、返回栈读/RET、全部解码 STORE 观察、fetch/指针递增与模型输出；超合同输入单独保留，不扩大合同。不同 run/输入、来源绑定的单 VM 调用和观察点代码字节分别记录。它是旧采集的有限路径证据，不证明 CPU 完整写 footprint 或观察间字节稳定，不启动新进程或继承清理权限。

每个分支返回不可变报告 UUID、SHA、路径和有界计数。完整关系、状态和图只在完整报告中，不能从预览补全。调用者不能提供 VIP/VSP、opcode 标签、阶段、任意表达式或验证成功结果。下游会重新派生上游；即使篡改结果另存成合法新报告，仍会拒绝不一致内容。

## 证据边界与未完成工作

| PR | 本批新增 | 尚未验收/实现 |
|---|---|---|
| 11 | 原始闭包重绑、入口输入、观察点代码、留出 fetch/dispatch/stack 关系；固定自产来源的跨 run/输入/调用检查 | 旧 VMP 仍缺不同输入/实例和 key 状态证据；运行/源码合同假设不能冒充通用 VM 角色证明 |
| 12 | 原候选图保留；固定自产来源已有可执行虚拟状态、分支、写后读和 key 状态区别 | 未实现任意保护器的自动 decoder/ISA 归纳、动态别名和未知路径的通用恢复 |
| 13 | 固定自产来源的独立 oracle、Python 复算、有限域穷举、有限测试与原录制重验 | 原生 CPU 全域等价、全宽符号覆盖以及现代保护样本完整业务合同仍未验收 |
| 14 | 五块只读调查视图、当前数据库与任务修订检查、插入前重读研究快照、原会话草稿接口 | 真正桌面渲染验收与进一步宿主拆分按各次报告记录，不由 renderer fixture 代替 |

`distinctObservedRuns` 仅统计已提交 selection 源 manifest 中的不同 runId；`identityAssurance=committed-source-manifest-only`，`rawCaptureRevalidated=false`。缺失 manifest 时保留 unknown。函数入口及输入域仅是合同声明，`contractBinding.functionEntryVerified=false`。地址不自动按 ASLR 平移，数据常量、寄存器值不重定位。

上一段描述轻量 `role_compare`；只有显式 `role_validate` 或固定来源的 recordedFunctionEvidence 才新增原始重绑结果，两者不可混用。

图节点身份包含 context/selection 摘要、run/thread/base、候选字节码位置、全部观察入口 GPR、观察 handler 入口及出现位置。代码 epoch、内存 epoch、VM 实例和解码内存仍未知，所以禁止跨观察合并，即使地址与寄存器相同也不把未知状态当相等。不会把未知后继填成 RET，也不会把源值直接叫 opcode 语义。

## 调查工作台

`GET /ig5-data?type=investigation` 只接受 `action=list|brief`。brief 要求任务 UUID 和列表中的 `task_revision`；仍通过原静态会话队列读取 brief。数据库预期身份及返回 `_ig5` 与原数据路由相同。不得将 URL 参数转成任意 workspace action。

页面展示问题/验收范围、事实/假设/未知、证据及完整引用、下一实验、工作/验收/资源三个状态。正文以文本呈现；同目标重开或修订变化在 render 阶段隐藏旧内容。选实验只生成本地草稿；插入前再读取 brief 并核对任务、研究、数据库及规划摘要，然后使用宿主 captureInsertion/insertText/persistDraft，不提交、不直接执行、不覆盖整个编辑器。

## 验证与回退

`npm run test:vm-progression` 覆盖重复运行、普通 switch 竞争解释、不同 fetch 增量、同地址不同观察、未知边、保留 STORE、伪造比较/图、错误 SHA/合同范围、只读路由、身份重开、乱序响应和草稿插入。合成 fixture 不是新原生执行。

`npm run test:vm-function` 加测分支/写后读、同地址不同 key、未知目标、数据 worker 取消与无报告、两个独立穷举 transcript、全宽域不升级证明、fresh SHA 伪造模型/证明升级、原始 handler 篡改。`scripts/accept_vm_function.mjs --evidence <新目录> --native-root <既有PR10目录>` 只重验旧捕获；`scripts/replay_vm_role_validation.mjs --artifact-dir <原artifacts> --evidence <新目录>` 重读旧单次 VMP 闭包，入口未绑定、输入独立性与 VM 角色仍保持未验收。

停用时回退新增 recovery 分支和调查页入口；保留新 kind/schema 的历史报告。旧 context、任务、research sidecar 和 CAS 不迁移、不覆盖，不修改旧 completed 含义。不支持的新报告版本拒绝，不猜测转换。

调查卡片默认显示问题、当前观察/未知计数、证据过期状态、下一实验及三个独立状态；完整身份、报告引用和反馈仍在原卡片的“完整状态与来源”折叠区。草稿插入继续重读原 brief，不因折叠改变验收或执行权限。

分支原生参考的录制验证按实际候选路径逐项匹配 opcode 与操作数字节读取、指针递增/跳转、完整有序 STORE 和 LOAD。跳过的分支不被列作已观察，模型有限域覆盖与原生录制覆盖分开。固定源 oracle 与独立 Python 同时识别这份精确来源，其他 PE 继续拒绝。

分支原生验收已在原客体完成输入0、1及uint64最大值的三次执行，两条分支均有实际录制；具体输入/返回/内存副作用与清理见2026-10-23分支原生验收记录。录制只覆盖这三条路径，256例是独立有限虚拟模型穷举，不是256次原生执行。独立原生审计保留TEST/XOR架构未定义AF，未观察区间稳定性和完整CPU写footprint仍未知。


## 可复现的固定来源验收入口（2026-10-23）

`accept_vm_function.mjs` 现在统一验证三份精确 SHA 来源，并可离线重读直线或分支自产 PE 的单批三份原生录制：

```powershell
node scripts/accept_vm_function.mjs --plugin-root <实际插件目录> --evidence <全新输出目录> --native-root <原采集根目录> --native-run <该目录下原生批次文件夹名>
```

`--native-run` 必须是直接子目录名；省略时仅在恰好存在一个原生批次时自动选择。同根目录含失败、历史或重新采集批次时，必须显式选择，不能静默跳过失败或合并不同批次。回执保存被选 acceptance 原字节 SHA、选择方式及每份原报告/blob 的来源 SHA。原录制只附加到相同目标 SHA 的模型，其他模型保持未提供原生证据。重复报告、目标不符、越界路径、修改的 blob 拒绝；共享相同 blob 允许。

每份模型仍为256例有限域和独立 Python 复算；重验三份录制不构成三次新执行，也不升级通用 CPU、全域、业务或整 VM 结论。公开脚本只读旧录制、生成新派生报告，沿用原数据 worker 及清理协议。


2026-10-23代码审查修复：VSP访问聚合兼容旧数组和当前`memoryWrites.stores`，STORE地址仅提供内存邻近观察，未知写后值不补成已知值。JS独立审计与Python分别复算；Python校验完整VSP字段、排序、类型和嵌套证明边界。旧不可变context或审计因派生规则变化而不再匹配时，应从原handler/selection另存新context和审计回执；不改写旧报告、不升级旧义务。`npm run test:review-fixes`覆盖本批定向负例。
