# 固定路径状态投影

寄存器源 CMOV 的完整固定解码形状可用于死目的 frame 省略：支持16/32/64位与全部16个条件编码，逐项绑定条件计算、源寄存器快照、确切下一地址条件跳转和目的写入。32位形式先将目的高32清零，即使条件为假也有这个效果，因此必须检查整个64位目的 frame。原条件标志保持；本功能不提供活 CMOV 结果，也不创造初始 flags。所有所选末态 GPR、有序 STORE 的地址和值、末控制以及中途 side exit 都参与同一次反向活性检查。内存源、额外效果、未知或非规范前缀拒绝；原始 p-code、摘要和指令/内存/进程预算不减少。

`test:cmov-dead-frame` 覆盖完整形状与反例；`scripts/test_projection_cmov_runtime.mjs` 通过固定 Java 车道检查实际解码的48个条件/位宽形状和拒绝项。独立解释器枚举六个 Boolean 标志组合，保留所有16 GPR及未修改的内存根；这属于普通 raw-pcode 数值核验，不能外推为完整CPU、VM角色或业务恢复。架构依据为 [Intel CMOVcc 手册](https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-vol-2a-manual.pdf) 和随包固定 Ghidra `ia.sinc` 的 CMOV/cc/check_Reg32_dest 定义；上游 [Ghidra 源码](https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Processors/x86/data/languages/ia.sinc) 仅供对照，本地固定解码和原字节仍是报告来源。

槽208与137的条件连接见docs/CONTEXT208_JOIN.md：78保存原入口RBP到F+208，137从旧槽144读取原入口RSI，不能混淆当前VIP寄存器。四份完整核心相等后复用旧6项未切割局部查询，本轮22查询16UNSAT6SAT另证3层54绑定/4写/2出口与84→86→88事实、21槽和原671窗口/映像保持；复用不是新增覆盖，非CPU/原生/整VM/精确3.8业务证明。

槽200与处理器0条件连接见docs/CONTEXT200_JOIN.md：136保存原RSP S到F+200，0从旧槽120读取原始入口RBP经R9压栈，不能混淆当前RBP=S。全16GPR/整内存/6写/4出口及20槽保持，76→82→84事实，表项78四字节复用。30查询23UNSAT7SAT是局部方程和明确归纳；源字cut另有原LOAD证明，SAT派发cut恢复原STORE。初版2秒unknown保留，非整VM/CPU/精确3.8业务通过。

规范CALL rel0另接受固定解码器完整RSP-8/STORE返回地址/BRANCH nextEA形状，原BRANCH和raw计数保持，终端仍带call/returnAddress；其余调用与flags规则保持。见[CALL_REL0](CALL_REL0.md)。

另可显式选择`projection_mode="opaque-status"`，使用独立schema将同路径已定义且已建模的状态位覆盖到PUSHFQ的未知映像。AF、初始状态及未建模/未定义位不补值，不能与guarded-path或compose叠加；范围、元数据和验收见[OPAQUE_STATUS_PROJECTION](OPAQUE_STATUS_PROJECTION.md)。

公开 project/compose 预览返回 `dagReferences`，对应完整报告的 `dag.references`。project 宿主重新统计全部有序参数边及初态、末态、内存、写入、控制和可选 guarded/opaque 根引用，逐项检查原 2048 节点、8192 引用与 128 深度预算；计数不符在保存报告前拒绝。compose 使用原完整状态绑定来源及分层根校验。重复边按出现次数计算；这个数仅是经过核对的结构元数据，不构成语义等价或原生业务证明。

显式 `projection_mode=opaque-effects` 使用独立保守表示与新未知值，完整范围见 [OPAQUE_PROJECTION](OPAQUE_PROJECTION.md)。以下 strict/guarded-path 的精确翻译、初始flags和拒绝规则保持原样；未知模式不能等同于精确指令恢复。

`ig5_ir level=project` 将原始 AMD64 PE32+ 文件中的一条明确指令路径，转换为寄存器、普通字节内存和末尾控制转移的共享表达式 DAG。它使用随包 Ghidra SLEIGH 解码，不启动目标、不打开数据库，也不改写文件。它是局部语义研究入口，结果始终 `partial / unverified`，不是去虚拟化成功证书。

```json
{
  "target": "C:\\research\\owned-fixture.exe",
  "level": "project",
  "projection_path": ["0x140001000", "0x140001004"],
  "projection_registers": ["rax", "rsp"]
}
```

地址必须是该文件的首选虚拟地址，且精确对应每条指令；示例地址不适用于任意文件。连续指令的 fallthrough 或直接跳转/受支持近调用目标必须与下一项一致。条件分支、间接转移及 RETURN 只允许在路径末尾；条件分支保留条件和两个后继。重复地址、未知调用、系统调用、未知副作用及依赖初始未知 flags 的路径均拒绝。内部 p-code 控制流仅有下述严格的 BSR/BSF 例外。此入口不接受录制映像、运行时地址、初始观测值或用户自定义表达式。

近直接调用只接受无前缀的5字节`E8 rel32`，根据不可变指令字节计算有符号位移目标及首选返回地址，并逐项匹配完整固定SLEIGH结构：`RSP-=8; STORE(RSP,nextEA,8); CALL target`。没有完整压栈/正确地址/控制的解码、额外操作、前缀、间接及远调用拒绝；调用方不能提供摘要替代它。后续地址须是实际callee入口，不能把CALL后的fallthrough当作“函数已返回”。终点为CALL时`control.kind=direct`并带`transfer=call`及十六进制字符串`returnAddress`；`path[].directCall`保存字节/语义摘要与栈效应，返回地址也保留在真实STORE值中。无CALL的既有报告字段保持原样。

该转移保留六个状态flags，但不改变活初始flags拒绝规则。被调函数只分析显式给出的后续指令，不推断ABI、返回值、库函数摘要、间接目标或执行callee。`compose`同样可连接这些受支持转移；CALL/RET返回地址可用精确写后读规则传播，压栈副作用不能因RSP恢复而删除。普通字节内存与首选地址模型仍不包括CET/shadow stack、访问故障、异常或原生可达性。近调用基础语义来源为[Intel官方指令手册](https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-vol-2a-manual.pdf)；当前匹配范围由实际固定解码与回归共同限定。

上述为默认 `projection_mode="strict"` 行为。显式 `projection_mode="guarded-path"` 可在一份请求内沿给定路径继续经过中途条件分支；下一项地址必须精确匹配 taken 或 fallthrough 中的一项。两侧同目标的退化分支暂不支持，中途间接转移/RETURN、重复地址与内部 p-code 限制保持。没有提供初始观察值或记录分支方向作为真值。

带守卫模式使用独立 schema `ig5-pcode-guarded-projection-v1`。`pathGuard` 是所给续程的累积条件；终点 `registers/currentMemory/control` 只在它非零时有效。每个 `branchPoints` 保存本条件、进入分叉的 `prefixGuard`、继续所选一侧的 `continuedGuard/continuedTarget` 与另一侧出口索引。`sideExits` 保存各自 guard、目标及分叉时的所选 GPR 和内存状态，续程明确 `not-analyzed`；不能用终点状态替代出口状态。

每个 STORE 的 `guard` 是进入该指令的条件。中途分叉前已经发生的写入，在另一侧出口仍然存在；不能用最终路径条件过滤全部 STORE。一个 planner 和 DAG 连续处理整条路径，flags 可跨中途条件边供后继使用，但出口不导出 flags，不能据此任意拼接另一个依赖初始 flags 的独立报告。向后切片在每个分叉时点加入出口所需寄存器与本条件，因此后面覆盖的寄存器不代表在更早的出口也已无用。

公开预览返回 `pathGuard`、分叉/出口总数及最多8个出口节点引用，`sideExitPreviewComplete=false` 表示须读取完整报告。条件、出口与状态引用都计入原来的 DAG 节点/引用/深度限制。输出仍是 `partial/unverified`；未证明条件可满足、原生可达性、未选中续程正文或全输入业务覆盖。默认 strict 的 schema、报告结构及限制保持原样。

初始 16 个 GPR 是独立自由 uint64 变量；`projection_registers` 选择保留的末态，不固定输入。内存是一份自由的、地址宽度 64 位、元素宽度 8 位的总数组，读写为小端并按指令顺序发生。所有 STORE 均保留，包括 RSP 恢复后的 PUSH/RET 遗留写入；数据读取不从文件填充常量。子寄存器按实际 p-code 字节覆盖，32 位清高位依赖解码中的显式扩展。未影响投影、存储和末控制的纯计算可省略。

返回的 `reportPath/reportSha256` 指向完整不可变报告，以多行 JSON 保存，支持宿主读取工具分页。其 `result.dag.nodes` 是拓扑排序节点，`registers`、`currentMemory`、`stores` 与 `control` 引用节点 id。工具预览只提供这些引用和数量，须读取完整报告才能解释表达式。`load_le/store_le` 共用内存链；整数运算按节点位宽取模；比较和 Boolean 运算生成 8 位 0/1；`extract.offset` 按最低有效位计数，`concat` 从高位到低位排列。完整报告同时保存原始字节、解码、输入摘要与解码器资产摘要。

`INT_REM` 仅支持等宽无符号操作数且除数为非零立即常量，DAG 表示无符号余数。零或符号除数在切片前拒绝，即使结果不保留；不借观察值假定非零，也不提供带除零语义的模型。该操作用于真实解码中的计数归一化等数据流，不放宽其所在机器指令的 flags 检查。[Ghidra p-code 说明](https://ghidra.re/ghidra_docs/languages/html/pcodedescription.html)与固定解码器的实际结构分别作为语义和来源依据。

状态标志位有额外的保守检查。分类只使用同一不可变输入的真实指令字节和解码结果，区分已定义、保持、架构未定义、解码器未建模及未知指令。若某个未定义或未建模标志会影响保留的寄存器、内存写入或末控制，整条请求拒绝；检查包括机器指令内部有效 p-code 的依赖。例如，不能沿用 MUL 前的 ZF 来解释后面的 JZ，也不能把固定解码器未更新的 AF 当作 ADD/CMP 的真实结果。移位和旋转依据编码计数及具体解码器限制处理，未知分类只要涉及有效标志位依赖就拒绝。后继重新定义相关标志，或这些标志确实不影响任何保留输出时，原寄存器及内存数据流仍可分析。完整报告保留 `flagPolicies`，有限分类并不等于完整 flags 架构证明。

BSWAP 另有编码检查。16 位 BSWAP 的结果在架构上未定义，但固定 SLEIGH 解码器可能产生确定的 32 位字节交换公式，因此该形式在切片前整条拒绝，即使目的结果随后被覆盖或未被选择。支持的形式为可选 `66`、随后可选一个紧邻 opcode 的 REX、`0F C8–CF`；`66` 必须同时具有有效 REX.W 才能通过。正常 32、64 位及 `66 + REX.W` 保留；重复、错序或额外前缀保守拒绝，不将更早且已失效的 REX.W 误判为有效。此限制没有宣称所有其他前缀都是 CPU 非法编码，也没有实现通用未定义 GPR 分析。

限制：最多 128 条不同地址的指令、每条 128 个/总计 8192 个 p-code 操作；2048 个 DAG 节点、8192 个引用、128 层深度；读写合计 256 字节。输出最多 4 MiB。与 Mergen 共用最多两个请求槽；计算在创建时绑定的 Windows Job 内，单子进程、2 GiB、最多 50 秒及 5 秒清理，宿主总预算最多 60 秒。只有同 nonce 清理确认及父 worker 真正退出后才释放槽位。

BSR/BSF 例外只处理 16、32、64 位寄存器源指令。BSR 匹配全部 10/11 条 raw p-code 和三条内部边：非零输入的计数从位宽减一向下，零输入直接退出，执行步数上界分别为 83、164、323。BSF 独立匹配全部 11/12 条操作及三条内部边：计数从零向上，移位后必须取最低位，零输入直接退出，上界分别为 99、196、387；不能把 BSR 结构或 TZCNT 前缀套用到 BSF。两者都只接受可选66、随后可选单个REX的明确寄存器编码；冗余66+REX.W、额外/错序/重复前缀保守拒绝。

只有该指令写入的全部目的寄存器字节及六个状态 flags 对后续投影、全部 STORE 地址/值、末控制和中途 side exit 均无影响时，才可省略局部计算。16 位写入只影响低 16 位；32 位结构含显式清高位，须检查完整 64 位。即使只是 ZF 仍被使用，也会拒绝。内存源、活输出或任何不同的内部控制结构不适用。[Intel 指令手册](https://cdrdv2-public.intel.com/812383/253666-sdm-vol-2a.pdf)规定 BSF 零源的目的结果未定义；固定解码器的零结果只用于检查其内部控制终止，不能当作架构结果。

每次请求在同一个 planner 中重新匹配结构并计算实际反向依赖，不接受外部证书作为省略依据。完整报告的 `internalElisions` 保存指令地址、字节、规范化 raw p-code 摘要、完整写入范围、出口活字节集合和省略理由，kind 区分 BSR/BSF。原始解码保留，原始操作仍计入预算；`omittedPureOperations` 与 `omittedInternalControlOperations` 分开，`internalElidedRawOperations` 是相同指令范围的交叉统计，不能再与前两者相加。结构终止论证和数值回归不证明未定义输出的架构语义。

此版本没有独立 SMT 等价证明、全路径可达性证明或全输入业务覆盖。固定解码与数据内存分开，不建模自修改代码、OS、MMIO、访问异常、并发或完整架构 flags。具有活输出的 BSR、BSF 及通用内部循环仍未支持。`businessAccepted` 与 `wholeBinaryVerified` 始终为 false。

回归入口：`npm run test:projection` 检查纯语义与宿主契约；`node scripts/test_projection_runtime.mjs <新的绝对产物目录>` 单独检查真实随包解码及受限分析进程。前者不替代实际 DSH 模型工具调用验收，后者不执行 PE 样本。

`npm run test:direct-calls`单独检查CALL匹配、flag边界、压栈与宿主字节绑定。`node scripts/test_projection_call_runtime.mjs <新的绝对目录> [插件根]`生成只读PE夹具并执行9项原生案例（6接受、3预期拒绝），用384组独立公式核对全部GPR/内存/控制；显式再传入已冻结的自产Ultra原请求JSON与合并地址图，可扩为15项/512组，分别保留原project全入口与文件引用compose全入口的拒绝。本地数据缺失时不生成或下载该保护样本；实际入口仍有PUSHFQ、RDTSC及未定义BSWAP等独立缺口，不以CALL转移通过算完整入口或业务通过。

标志位回归：`node scripts/test_projection_flags_runtime.mjs <新的绝对产物目录>` 通过公开工具入口检查真实解码、错误拒绝、正常数据流及进程清理。可选的旧安装副本 baseline 模式用于保留缺陷复现，不能把旧版接受不可靠表达式算成测试成功或架构支持。

BSR 回归：`node scripts/test_projection_bsr_runtime.mjs <新的绝对产物目录>` 检查真实解码、全部死写入范围与活输出拒绝。原 `test_projection_runtime.mjs` 的 context0 案例默认验证 BSR 例外后的真实路径；旧安装副本的拒绝基线须显式选择 `reject` 模式。这些源码测试不等于当前安装副本已更新，也不替代 DSH 模型验收。

BSF 回归：`node scripts/test_projection_bsf_runtime.mjs <新的绝对产物目录>` 检查真实解码、帧与前缀绑定、全部死值、活输出/flags/存储依赖和中途出口拒绝。独立 raw-pcode 数值检查穷尽16位源域，并覆盖32/64位零、每个单比特及随机源，核验固定解码结构的终止上界；它不是 CPU 架构或全业务证明。

BSWAP 回归由 `scripts/test_projection_bswap_runtime.mjs` 检查真实解码与前缀边界，独立字节交换公式只用于合法正例；未定义形式只核验拒绝，不编造数值期望。带来源绑定的原保护样本单条指令及完整路径作为单独负例保留。

带守卫回归：`npm run test:projection` 同时检查默认模式、条件出口反例与宿主参数/报告边界；`node scripts/test_projection_guarded_runtime.mjs <新的绝对产物目录>` 用真实解码检查中途 flags、时点状态、顺序存储及原样本路径，目标作为数据读取。数值公式比较与真实 DSH 模型验收分开记录。

另有[闭合状态组合入口level=compose](STATE_COMPOSITION.md)，对地址计划重新解码，连续代入全部GPR与写后内存，并按确定常量条件推导有限重复，或显式保留间接目标条件。它有独立schema和展开工作预算；本入口的重复地址/超限/中途间接控制拒绝保持，不能将另一请求改记为原请求通过。纯核心接口见[内部组合器](INTERNAL_COMPOSITION.md)。
