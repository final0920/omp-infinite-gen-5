# VMP 离线业务逻辑恢复（v1.1.0）

`ig5_ir level=trace` 接收已经采集的 x86-64 指令、寄存器和内存读取记录，在独立 Triton 子进程中建立输入输出表达式。不启动样本、不打开数据库、不启动 JVM。Core8 / Full40 与执行审批门保持不变；先用 `ig5_profile toolset=full` 展开入口。

当前实现处理 SysV 的 `dil/sil`、`di/si`、`edi/esi`、`rdi/rsi`，以及 Win64 的 `cl/dl`、`cx/dx`、`ecx/edx`、`rcx/rdx` 同宽输入；返回值为 `al/ax/eax/rax`。混合寄存器组拒绝。原生采集通过下述既有审批调试入口执行；离线恢复本身不执行目标。OS/import 语义仍无通用模型。依赖为单独固定的 Windows x64 CPython 3.12 Triton 1.0.0rc4 wheel，保留原始布局、RECORD、逐文件 hash 和许可；普通调用不下载依赖、不改全局 Python/PATH。

```json
{
  "target": "C:/path/sample.vmp.bin",
  "level": "trace",
  "traces": [{"path": "C:/path/sample.trace", "sha256": "64位小写SHA256"}],
  "trace_entry": "0x4011c0",
  "trace_exit": "0x4011ef",
  "trace_inputs": ["edi", "esi"],
  "trace_output": "eax",
  "initial_flags": "0x202",
  "max_instructions": 50000
}
```

省略 `action`、数据库/内核专用参数。entry/exit 指第一条/最后一条记录的地址，必须显式核对是否包括 RET；只声明边界不会证明轨迹涵盖了整个函数。initial_flags 为记录环境的 EFLAGS 假设，未记录的初始寄存器高位和初始内存也属于固定环境。

支持作者发布的三种 ASCII 记录：`r:` 后为 RAX/RBX/RCX/RDX/RDI/RSI/RBP/RSP/R8..R15 的 16 个 64 位十六进制数；`mr:地址:字节数:小端整数值`；`i:地址:字节数:机器码hex`。每条指令必须有前置寄存器快照，输入按原始文件 SHA 绑定；文件最多 4 MiB，最多两份/合计 8 MiB，各最多 50,000 指令，内存记录最多 1 MiB，128 次求解、每次 2 秒/512 MiB、子进程请求硬期限 60 秒。超限/取消/不支持/状态冲突不发布恢复证明。取消只终止所属子进程。

`recoveredExpression` 是结构化位向量表达式，8 位输出按模 256 回绕；不将 EAX 的高位冒认为 char 返回值。候选合成、低位投影都经独立 SMT 反例查询，只有 `unsat` 发布等价。地址选择与原生控制流约束决定路径；两份互补路径经互斥/覆盖查询才能合并 select。除有限 x/y signed/unsigned 比较外，还从记录条件的 AST 提取小型 add/sub/xor/and/or 候选及常量（包括相邻值和二补码），最多 2,048 个遍历节点、3 个种子、4 个常量和 42 个谓词；每个发布条件都须证明等价。达到候选求解预算时保留未知约束，不升级为完整模型。`guard.conditionExpression` / `select.conditionExpression` 为结构化谓词，旧 `condition` 文本仍保留。

未定义标志位、零输入 BSF/BSR 目标和 CPUID/RDTSC 观测保留为独立未知量；仅根据快照求取其记录值，禁止覆盖输入依赖。普通状态冲突、缺失初始内存、syscall/interrupt 或输入相关 CPUID 明确拒绝。返回表达式与未知量无关仍须证明。最大值样本的路径归约依赖记录中的两个 AF=0 环境观察，报告逐项列出。

返回值仍依赖硬件／未定义环境量时，结构化表达式用 `op=environment` 保留变量及是否有明确观察，不伪装为 x/y 参数，也不固定成普通常量。表达式等价证明与输入域恢复分开：这类路径仍为 partial，`recoveredExpression=null`；有快照也不等于跨环境业务恢复。

ELF 轨迹字节绑定按 PT_LOAD，仍核验范围/对齐/重叠/初始化字节，不依赖壳修改后的 section 语义；静态 kernel 原有严格 section 检查保持默认。报告包含每条轨迹的 SHA、指令数、字节匹配统计、环境读取、快照协调、路径条件、证明和独立保存报告 ID/hash/path。产物保存在 `artifactDir/trace-recovery`，不改数据库修订。

`coverage=trace-model-input-domain` 仅表示所供轨迹模型在已声明输入域及记录环境下覆盖；`wholeBinaryVerified=false` 始终保留。指令字节相符也不能证明所有真实运行路径、外部副作用、不同硬件环境或隐藏服务器实现均已恢复。只读静态 SSA、轨迹恢复、原生采集/执行的证据分别报告。

## 三份实际样本

固定来源为 [作者研究仓库](https://github.com/JonathanSalwan/VMProtect-devirtualization/tree/d2b26d66db59e341f179c7e326246d28c4d25491)。外部样本及轨迹只保存在 artifacts，不分发、不启动；没有运行上游 attack 脚本，也没有向恢复器提供参考业务公式。

| 样本 | 记录指令数 | 恢复返回值 | 独立验证 |
| --- | ---: | --- | --- |
| sample2.vmp.bin | 12,462 | x XOR y（32 位） | SMT + 边界/固定随机对 |
| sample3.vmp.bin | 25,085 | ((x XOR 0x5c) + y) mod 256 | SMT + 原 MBA 的全部 65,536 个输入对 |
| sample4.vmp.bin | 17,986 / 18,068 | signed(x)<signed(y) ? y : x | 路径条件、互斥/覆盖 SMT + 有符号边界/随机对 |

回归：`npm run test:trace`（真实语义/冲突/边界与路由），`npm run test:vmp-recovery`（实际固定样本与轨迹 + 独立参考语义），并运行原 kernel loader/jobs、引擎集成、审批门、工具目录及 DSH SDK 回归。真实 DSH 模型调用和宿主重载证据须另外保存。

## 新增三份实际样本

同一固定作者版本另有 sample1/5/6，均为 32 位输入／输出的 x86-64 ELF。

| 样本 | 记录指令数 | 恢复轨迹模型 |
| --- | ---: | --- |
| sample1 | 10,815 | `(x+y) mod 2^32` |
| sample5 | 16,164 / 15,758 | `(x+y) mod 2^32 == 1001 ? x+1 : y-1` |
| sample6 | 14,172 / 14,560 | `unsigned32(x+y) < 1234 ? x+1 : y-1` |

`npm run test:expanded-trace` 通过公开工具包装器恢复后，分别核对 1,184 个独立参考输入对，含分支边界、负值的机器表示及加法溢出。sample1/5 的 signed C 源码有溢出未定义行为，验证口径为记录机器码的 32 位回绕语义。参考公式不传给恢复器。两个条件分支同时核验路径互斥／覆盖 SMT。

sample5 的第二份作者原始记录夹有三行程序提示。准备工具仅删除精确匹配的前导／尾随三行，保持全部 r/mr/i 记录逐字节不变；原始／派生 hash、被删行号和内容均保留。公开解析器仍严格拒绝非轨迹行。扩大样本的来源和证据见 [PROTECTION_CORPUS](PROTECTION_CORPUS.md)。

## 原生记录与长轨迹

`ig5_dbg backend=x64dbg op=trace record_trace=true max_steps=1..512` 使用既有一次执行审批，记录真实单步、GPR、EFLAGS、指令字节和所有已识别内存读；可提供 `trace_inputs` / `trace_output`。`until` 是显式主模块运行地址；VM 内部 RET 不作为函数返回，离开主模块的 RET 或指定 until 才结束窗口。每窗口最多 1 MiB／40 秒软期限，单步事件等待另有 2 秒软期限。事件、线程、运行或读取不确定时保留可确认的前缀，明确停止原因；接受命令不作为执行证明。调用失败／硬超时／取消仍按所属进程清理规则处理。

新版原生格式以 `h:ig5-native-x64-v1` 开始，每条 r 后有 `e:EFLAGS`，最后有 `f:`（16 个 GPR、RIP、EFLAGS）。可有前导 `s:gs:基址`，作为显式环境假设；Windows x64 recorder 从对应线程的 native TEB 地址推导用户 ABI 的 GS 基址，报告来源，不宣称直接测量了硬件 GS。未声明 GS、FS、选择子、未采集向量／x87 状态拒绝，不假设为零；原生 segment 写入停止记录。CS/DS/ES/SS 内存覆盖只按 x64 长模式基址为零解释。分段合并还核对同一 segment 基址。

重放逐步核对 flags，保留输入依赖；Triton 的独立标志位组合成完整状态，未定义 AF 仅按明确快照协调。调试器在单步边界设置／清除的 TF 是单独环境变量，输入相关 TF 不覆盖。PUSHF 栈镜像保留架构固定 bit 1，清除 RF/VM；旧作者 r/mr/i 格式保持原语义。原生 RESUME 回调可能晚于 PAUSE+STEPPED，按同一确定暂停序号和两个停止回调确认，晚到的通知不能伪装成另一次执行。

记录保存在 `artifactDir/debug-traces`，返回 report UUID、blob path／SHA 和 `recoveryArgs`。多窗口恢复用 `ig5_ir level=trace trace_chunk_reports=[UUID,...]`，与 `traces` 互斥；最多 256 段，合计仍为 4 MiB／50,000 指令。合并检查所有报告／blob hash、同一目标／进程／线程、暂停计数、前后 GPR/EFLAGS/RIP 连续性，保留原始各段。返回 `joinedRecording` 可作为后续两路径输入；合并不执行目标，也不证明整个函数覆盖。

`trace_runtime_base` 显式声明主模块加载基址，按 RVA 映射回原文件。AMD64 PE 的 ABSOLUTE 填充／DIR64 relocation 按固定原文件的目录和加载偏移重建，仅用于字节绑定，不改文件／普通 kernel 首选地址视图。目录最多 1 MiB／65,536 fixups，未知类型、重叠、非法块拒绝。`allOriginalFileInstructionBytesMatch` 与 loaded image 的 `allInstructionBytesMatch` 分开，逐项保存 original／relocated 字节与目录依据；未知自修改、无目录依据的差异仍未证明。

表达式投影另支持 ITE/条件选择、扩展／提取／拼接及左右移位，仍受 256 节点／32 层预算限制，并对重建 AST 做独立等价查询。右移先保留原机器宽度，再截取输出低位。仅含已固定环境变量的条件单独记录为精确观察值检查，不冒称 SMT 证明；参数相关条件与最终表达式仍须 SMT。

完整恢复报告在缩略前保存。FC 响应的证据数组最多预览32项，并按整个格式化JSON的16 KiB预算逐级收缩，另给 `evidenceCounts`／`previewTruncated`／`previewEvidenceLimit`；表达式、证明、两条路径的记录环境和报告ID／路径／SHA保留，核心结论与报告引用优先输出。极大的核心表达式不能为预览限额而截断，用 `previewBudgetExceeded` 明确报告。缩略预览不能代替完整观察证据；普通模型结论无需重新读取数十万字符的完整观察表。

`ig5_dbg op=suspend interrupt_method=break-process` 可用 Windows DebugBreakProcess 中断被调试且属于本实例 cleanup job 的运行进程，没有任意 PID／附加入口；仍走公共审批，必须收到新停止事件。它可能切换到系统的中断线程，随后用 `op=regs thread_id=已有线程ID` 只读查看原线程。返回 `selectedThreadRegs`，不更改当前调试线程或其缓存。选定线程上下文当前仅支持 native x64，仍要求暂停、线程归属和稳定运行／暂停身份。

`npm run test:debug-trace` 使用自产 PE，真实验证 ASLR、栈写读、128 步循环、中断与指定线程快照。2026-10-14 的 128 步单独窗口约 1.6 秒；这是一份受控循环的实测，不能当成所有 VMP 工作负载的性能保证。公开包装器、审批门、算法和真实 DSH 模型分别验收。

新增 v2 保留 v1 读取兼容。`d:16位寄存器mask:改动值...` 是上一份实际 GPR 快照的无损差量，不能以预测寄存器填缺项；规范化先逐字节展开核对原文件。宿主最多读取每份 16 MiB 原始 native 数据，合并原始段最多 16 MiB；传给语义 worker 的每份规范化轨迹仍最多 4 MiB／两份合计 8 MiB／50k 指令。原始 hash、规范化 hash、字节数和派生 blob 单独保留。

部分虚拟化 Windows 平台的 CPUID 单步会在紧随的指令后才停下。v2 用 `c:` 明确表示这种无中间寄存器／flags 快照的连续指令，只允许 CPUID 后紧邻的 STC/CLC/CMC/NOP，或64位非 CPUID 输出 GPR 的 ADD/SUB immediate。后者必须是 REX.W + 81/83 的纯寄存器形式，禁止改 RAX/RBX/RCX/RDX、内存访问、分支及多个隐藏指令。记录器核对实际步前代码与最终全部 GPR／RIP／已定义 flags，统计 `unobservedContinuationInstructions`，不假造中间快照；其余跳跃停止并保留原始证据。单步 stop 计数与解码指令计数分开。未观察到非自跳 JMP 的状态转移时不把它记录成已执行指令，初始窗口可从新的明确暂停状态重试。

固定 Triton rc4 的 high-byte PF 使用了父寄存器保留低字节；五代对 AH/BH/CH/DH 的已定义结果 PF 重建真实结果字节的偶校验 AST，保留全部输入依赖。ROL/ROR 按 masked count 保留零计数 flags，从实际结果求 CF；仅一位旋转定义 OF，其余为独立未知。CPUID 的固定非索引 leaf 0/1/0x80000000 不以 ECX 为 subleaf，EAX 固定性仍经证明。索引 leaf 的输入依赖继续拒绝；改模型不改 vendor 二进制或根据样本强制赋值。

rc4 的变量 ROL/ROR 与 SHLD/SHRD 会固化记录时的 CL 计数。五代用完整位宽的 shift／concat AST 重建寄存器与内存结果，保留 count 输入、部分寄存器和32位零扩展；双移位的零计数保留 flags、16位超范围结果／flags 为显式独立未知。64位所有64种有效计数以常量旋转 oracle 做 SMT 检验；原生3.11自产旋转混合另以独立源码参考验证。合成候选若不等价，`synthesisAttempts` 保存反例，尝试另一份已证明简化／原始 AST，最终结构化表达式仍必须有自己的等价证明。

RCL/RCR 用目标位宽加一的 CF／目标位向量重建旋转，保留 masked count、8／16位的 modulo 9／17，以及部分寄存器未写位。OF 只在 masked count 为一时定义；例如 RCL DL,28 的有效旋转虽为一，OF 仍是独立未定义量，须由实际快照协调。零计数保留旧 flags。候选比较补齐 signed／unsigned 的小于等于和大于，仍需逐条 SMT 证明。

RDTSC／RDTSCP 输出属于显式外部环境观察，不能从 Triton 的虚拟 TSC 默认值预测。固定 decoder 不支持 RDTSCP 时，仅对精确机器码 0f01f9 建模其架构输出寄存器与 RIP；输出随后符号化并由实际后续快照绑定，flags 不变。没有观测、输入相关硬件状态或时间值最终影响业务输出时，保留 partial／拒绝。自产原生夹具核验本机 RDTSCP 特征位，真实采集两种指令及末态。

重复的 SAT／UNSAT 查询按 AST 结构及全部环境假设复用，哈希相同后还核对结构相等；未知／超时不缓存，不跨请求复用。`solverQueries` 计实际求解，`solverCacheHits` 计复用，原有128次实际查询和请求期限不扩大。

两条来自独立 ASLR 运行的轨迹可分别提供 `traces[i].recording={entry,exit,runtimeBase,initialFlags}`，四项均为显式十六进制字符串。省略时沿用顶层默认值；给定时分别检查记录边界、初始 EFLAGS 和映像字节，函数入口 RVA 必须一致，共用 x／y 符号后才证明条件互斥和覆盖。返回的每条 `paths[i].recording` 保留实际采用的环境；不同运行的寄存器和线程历史不能拼成单条连续轨迹。

长轨迹另可显式选择 `max_instructions`，默认仍50,000，各路径硬上限100,000；原生录制窗口仍最多512步，拼接仍最多256段。独立未定义／硬件／调试状态变量的默认路径预算20,000，显式超过50k时最多40,000，所有生成入口统一核验；独立运行之间释放上一条观察表，不串用状态。4 MiB规范化输入、8 MiB总输入、16 MiB原始拼接、128次实际SMT、每次2秒／512 MiB及50秒软／60秒硬期限均不扩大，结果的 `budgets` 明确记录采用值。原生夹具环境变量 `IG5_MODERN_MAX_INSTRUCTIONS` 指定同样的有限预算；未达到出口仍只能作为前缀证据。

结构化表达式还有独立的通用简化：位向量 De Morgan／双重补、互斥并集→XOR、模环常数提取、相邻宽度投影、零前缀扩展，以及同一表达式连续位片的选择性取反→常量XOR。位片合并最多64片，核对来源、宽度和连续偏移，最低片可使用同宽的模运算投影；错序、缺口或不同来源保留原式。每次局部改写都使用SMT反例查询，只有UNSAT才接受，父节点重建依据等式同余；不是依赖记录输入猜公式。最多512个访问节点、32层、64次候选尝试，仍共享原128次实际SMT和期限。SAT／超时保留原节点，期限／预算错误继续向外传播。改写后 `outputProof.method=SMT-projection-and-local-equality-congruence` 明确区分原输出到结构投影的直接证明与局部证明链；完整 `expressionNormalization` 证书先保存，预览只缩略证据数组。未知环境量不改成普通常量。

动态解包／解密代码可以在 `ig5_dbg op=trace record_trace=true record_image=true` 时捕获主映像。该操作仍经过公共审批；主映像最多8MiB，每页读取4096字节，共享录制40秒期限，核对捕获前后的暂停身份。不可读页成为显式空洞。字节是调试器观察值，可能受其断点内存读取策略影响；不重建导入表，不输出可运行脱壳文件，不修改原始目标。

录制结果返回 `recoveryArgs.trace_image={report_path,report_sha256}`。只读 `ig5_ir level=trace` 核验报告和blob摘要，并绑定目标／run／thread／stop、入口、flags与运行基址；可省略运行基址，由已经校验的快照给出。独立运行分别提供 `traces[i].trace_image` 与 `recording`，不能把一份共享快照套在不同ASLR运行上。`binaryBinding` 分别统计原文件与捕获映像匹配数，缺页或指令字节不一致拒绝恢复；报告保留 `capturedImageEvidence`。此证明只覆盖已记录代码和环境，未来代码变动与整个二进制仍未验证。

当42个启发式条件候选没有匹配时，还可直接投影实际记录的 input-only 谓词：全部自由变量必须属于声明的 x／y，最多256个投影节点／32层，并对原谓词和投影的逻辑差异做UNSAT检查；成功标记 `guard.method=input-only-recorded-predicate-projection`。含未解决环境变量、投影超限或未证明的条件仍保留 partial。低位掩码分支与零输入BSF路径可因此给出明确守卫；单条受约束路径不会升级为完整输入覆盖。

`proofScope` 在公共工具预览中优先展示声明的 x/y 位宽和 `allInputPairsProved`。具体 `observedInputs` 用于快照一致性核对，不限制符号化输入域；低位守卫划分全宽输入，不把64位变量变成1位变量。全部输入对成立仅在已有 `coverage=trace-model-input-domain` 的证明成功时标记，环境仍限定各轨迹的显式观察和记录内存位置，原程序完整恢复始终未证明。DSH独立核对器同时绑定源码参考证明的验收摘要，保留原文件字节匹配的实际值，不要求所有保护器都改变运行字节。

守卫候选的低位宽度除实际EXTRACT，还可来自AST中的AND连续低位掩码或OR补掩码。例如8位OR 0xfe只留下最低1位参与比较；推导只看字面掩码结构，不看记录输入或源码。仍最多扫描2048节点、共享42候选，原始全部约束与候选须SMT等价。原生CPUID续指令另支持精确 `66 81 F8–FF imm16` 的寄存器CMP，GPR不改写，CF／PF／AF／ZF／SF／OF均验证；仍没有中间快照，内存操作、其它前缀和复合尾部拒绝。

展示前的 `worker/trace_ast_normalization.py` 可对共享AST进行前序结构简化：NAND补集组合恢复XOR、双补／异或双补消除，以及从重复拼接字的固定宽移位／提取恢复ROL／ROR。最多512次节点遍历、32层、64规则尝试，每节点最多4次改写；所有规则须独立SMT UNSAT，不修改原AST，仍共享原求解与期限。`astNormalization` 保存完整证书；输出证明链明确绑定原合成证明、AST局部等价同余与最终宽度投影，再接表达式简化。原始119节点／72层的八轮虚拟化结构可因此在原展示预算中恢复，未提高256投影节点／32层限制。

标志位快照仍逐条检查。`flags_ast` 把已经无符号依赖的位合并为常量，仅对仍符号化的位构造组合AST；输入和独立环境变量均不替换。自产69,119条指令在相同cProfile入口的本机测量为29.09→22.11秒，数据与旧安装副本源码摘要在 `native-image-verification/compact-flags-performance.json`。测量含探针开销、后台负载未固定，不是普遍性能保证；原来双路径50秒期限失败另存，修复后两路径证明在原期限内完成。

独立常量计数的 ROL／ROR 使用精确旋转 AST，使每轮共享源表达式只保留一次；符号计数仍使用完整位宽移位模型，CF／OF规则不变。八轮自产程序原先在展开相同子表达式时触及256节点显示预算，现在可在相同预算下恢复96条原生记录；投影和独立源码参考仍需UNSAT证明。

启动等待另由 `source/debug_timeout.js` 统一界定：显式 `backend=x64dbg op=cont timeout=120` 可以最多等待120秒，RPC另留有界清理余量；其余调试操作保持60秒上限，宿主配置不足则前置拒绝。默认继续等待30秒、普通操作15秒、录制45秒；录制器自身512步／40秒和离线求解预算不变。测试脚本在每次公共调用前后保存UTC时间和 pendingCall，不能把尚在静态装载阶段出现的旧通知认作当前进程提示。

`selectedThreadRegs` 增加Windows AMD64 CONTEXT中的 DR0–3／DR6／DR7 精确十六进制观察；仍只读取已经暂停、属于当前调试job的现有线程，核对前后暂停身份，不设置寄存器或改变当前线程。布局核对使用安装的 Windows SDK；独立测试覆盖大于2^53的字段和值区间。

新增自产 VMP 3.11 分支案例中观察到 CPUID 与紧随的 `TEST DH,2` 合并为一次原生停止。只允许精确机器码 `F6 C0–C7 imm8`：纯8位寄存器读与标志位测试，不改GPR，没有内存、分支或额外硬件读取。记录器用最终未改写的CPUID输出核对完整GPR／RIP／已定义flags，高字节PF按实际结果字节重建，AF作为架构未定义观察保留。离线解释仍对符号依赖和输出做独立SMT证明；`c`格式与 `unobservedContinuationInstructions` 明确保留缺少中间快照。非白名单、冲突末态或更长跳跃仍停止。

条件候选另从实际AST中的低位EXTRACT提取最多4种宽度，为同宽x／y提供相等／不等候选；与原有候选共同受42个上限约束，每个发布条件仍需与全部原始约束的合取作等价UNSAT检查，不使用样本名、观测输入或源码参考猜条件。原生VMP分支的141条输入相关条件可因此证明等价于 `low1(x)!=low1(y)`，没有提高256节点／32层显示或128次求解预算。尚不能证明的条件保留 `guardProjectionFailure` 和未决计数。
# 共享AST与SMT优化（2026-10-15）

2026-10-15 增加综合前的有证书AST结构处理。同一位向量的互补常量左／右移位OR可恢复旋转，两级匹配可以合并计数；宽度、源结构及计数必须全部匹配。任意全宽新主体上的局部SMT UNSAT模板才允许对真实主体实例化，不使用记录输入或参考公式。综合前／后共享原512节点预算，处理后投影仍超限则回到原AST综合。引用按完整定义展开；同宽ADD可在原节点限额中扁平化，最终投影独立查询。256节点／32层展示限制不变。

`worker/trace_smt_dag.py` 用完整等式定义保留共享SMT结构：每个复合位向量项有新变量等式，每个Boolean项有双向等价，全部定义与原查询合取，原输入和环境变量仍自由。哈希复用须结构相等，规范键包含操作、宽度和子项身份。最多2048个不同节点、8192次引用／遍历和128层，超限／未知操作返回unknown而不是UNSAT。未定义状态协调可回退之前的完整原查询，所有非未知变量仍固定；计入相同2秒／512MiB／128次查询及请求期限。原AST／具体输入不改，求解专用变量不进入输出或用户输入反例。

本轮64项真实Triton回归、三份固定VMP样本与既有12个自产原生业务模型重放通过。12个模型各自仍核验2409组独立参考与全宽源码参考UNSAT；初次优化导致状态协调拒绝的回归已保留失败并修复。Enigma八轮66614条轨迹可在原期限生成8处局部UNSAT证书和输出投影证明，独立2409组参考比较通过；独立原查询与DAG源码参考查询均在2秒处超时。输入相关的640条守卫及路径覆盖未证明，`recoveredExpression=null`／`coverage=single-recorded-path`，不能升级完整业务通过。真实DSH验收单独记证据。

后续新增表达式层的互补移位旋转、同方向常量旋转合并，以及同宽 ADD/MUL/AND/OR/XOR 的结合交换与字面常量合并。每个未知复合主体都用精确结构匹配替换为任意全宽模板变量，完整局部等价必须SMT UNSAT；新主体/错误位宽拒绝，不代入观察输入。最多64项，沿用512节点／32层／64尝试和原求解预算。交换/扁平化不引入新非恒定子项，因此已证明的子项不重复遍历；这减少预算浪费，没有扩大预算。

最终68项轨迹回归通过。Enigma八轮报告 `3f16dc3d-7d40-4de9-b450-f7c4d84d5b19`／SHA `daa74284fb7c80af36ebce45e1a935d48aebc553eb37117a1c84c6eef154559e` 有19处表达式证书，输出与独立源码的全uint64等价由原生原查询及精确DAG分别UNSAT（本机该次均报告0ms）。旧超时保留。对完整原守卫的只读分组诊断找到 SAT 反例，说明这条路径不覆盖所有输入，不能删除守卫以升级业务验收。诊断报告与新原生采集仍分别保存，尚未据该反例执行目标。

# 守卫域诊断（2026-10-15）

`trace_image_only=true` 是显式的录制映像离线入口，同时必须提供 `trace_target_sha256`。`target` 在此模式仅作为录制时的绝对路径标签，须与每份不可变映像报告匹配；宿主和worker均不打开该原文件，也不重建或恢复PE文件。每条路径必须带自己的 `trace_image`，或使用已允许的共享映像；摘要、原目标身份、入口、flags、runtimeBase及录制run/thread/stop继续核对。支持由连续录制报告合并的数据，原始文件模式和其他引擎入口保持原校验。不能悄悄在默认模式失败后回退。

录制模式仍校验稀疏映像blob的大小／SHA和映射，并要求可读的AMD64 PE32+头及与模块一致的SizeOfImage；内存空洞不补零。输出 `targetVerification.source=hash-bound-native-recording`／`originalFileRead=false`；`originalFileMatchedInstructions`、`allOriginalFileInstructionBytesMatch`、`preferredImageBase` 为null，记录头观察单列，不能把录制身份说成重新验证了原文件。所有预算和审批保持原值。此入口只解释记录窗口，前缀的RAX输出证明不代表函数已返回，亦不升级完整业务／全程序覆盖。

守卫尚未恢复为紧凑条件时，`guardDomainDiagnostic` 提供有界的输入探索证据。原合取超过精确DAG限额后，才可分组查询“该组中是否至少有一个条件为假”；每组仍带全部原固定环境约束。任一真实SAT可证明记录路径不是全输入通路，并保留反例及来源范围；只有每组UNSAT且完整无重叠地覆盖全部原条件，才返回 `universal-under-fixed-environment`。最多16次尝试，共享原128查询、2秒／512MiB与请求期限；超时、单条件拒绝、未完成分组都保持unknown。诊断不删除守卫、不直接升级coverage，也不自动执行反例。完整证书保存到报告，预览保留计数和SAT witness。71项真实Triton回归含实际超过2048节点的合取、完整分组、固定环境约束和拒绝路径。

`guardCandidateSearch` 保存候选等价查询及SAT反例复用的拒绝链。若完整原守卫XOR候选为SAT，在该模型上求得小候选的常量真值，就能推出该反例处原守卫的相反真值；其他候选若也与之不同，可据同一真实反例拒绝。最多16个witness、42候选，模型缺输入／含环境／超出256节点32层时不复用；原输入符号、原AST、观察状态均不修改。它只减少错误候选的查询，发布守卫仍须对全部原约束和固定环境做等价UNSAT。Enigma原路径与反例前缀合并曾触及50秒期限；反例复用后前缀31候选被拒绝，原128查询和50软／60硬期限不变。

大型证明链在outputProof／synthesisProof／synthesisAttempts中重复时，FC预览可显式返回 `proofPreviewMode=summaries-with-immutable-report-references`。每个摘要保留真实status/method/scope并标记previewSummary及fullProofRef（报告UUID/SHA与精确JSON pointer）；完整报告和输出表达式均不修改。不能把摘要称为完整证书，也不丢弃未知／失败状态。实际核心表达式仍超限时保留previewBudgetExceeded，不伪装符合预算。

若仅JSON缩进已使表达式超过预览预算，可标记 `previewCompactJSON=true`，仅trace renderer用同一严格JSON校验器输出无缩进JSON。表达式树、字段与null原样保留，不把算式转成截断字符串；预算按实际序列化字节计算。

# 线程可见性诊断（2026-10-14）

`ig5_dbg backend=x64dbg op=regs thread_id=<已存在自有线程>` 继续使用公共审批，新增只读 `selectedThreadDebuggerVisibility`。它通过 Windows `NtQueryInformationThread` 的 ThreadHideFromDebugger 类观察；成功给出 True/False，失败给出 null、NTSTATUS／Windows错误，不能把权限不足当作未隐藏。读取不调用隐藏／恢复线程API，不切换调试器当前线程。`selectedThreadRegisterObservationScope` 明确：稳定调试暂停 epoch 不等于独立证明隐藏线程已暂停或所有寄存器具有一致性。

原生验收入口为 `scripts/test_thread_visibility_runtime.mjs <自产编译证明目录> <全新证据目录>`，仅使用 `scripts/fixtures/debug_hidden_thread.c` 的编译证明。主线程先可见，再自设隐藏；可见辅助线程制造可观测暂停。须验证 False→True、辅助线程 False、当前线程与GPR/暂停序号不变、目标SHA不变。该验收证明诊断能力，不证明隐藏线程可正常单步，也不证明 Enigma 或其他壳的业务逻辑已经恢复。

