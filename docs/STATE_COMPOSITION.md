# 闭合路径与有限循环组合

处理器208与256字节搬栈循环固定样本证书见docs/HANDLER208_RELOCATION.md；12/24/41条路径、自动32次复制和34层组合保持全16GPR/整内存/有序STORE/互补出口。84查询79UNSAT5SAT为局部方程与明确内存/绑定归纳，不是未切割整VM或精确3.8业务通过；75→76仅加一字节、复用四表项，原671窗口和19槽保持不可省略。

显式sequence/transition-chain另可选择[template_mode=opaque-status](OPAQUE_STATUS_COMPOSITION.md)，逐应用保留同模板已定义状态位与PUSHFQ保存映像的关系，随后通过普通内存/GPR传递。默认strict和旧opaque-effects保持；不提供CPU初始flags跨模板传递、外部摘要或更大预算。

`ig5_ir level=compose`在原始AMD64 PE32+文件上只读解码明确地址计划，将严格路径模板的全部16个GPR和写后普通字节内存连续代入。它复用现有40工具中的`ig5_ir`及lift/project共享进程池，不执行目标、不打开数据库，也不接受初始观测值、自定义表达式或外部摘要/证书。结果始终`partial / unverified`，`businessAccepted/wholeBinaryVerified=false`。

顺序组合只传`target`、`level`与`composition_plan`：

```json
{
  "target": "C:\\samples\\owned-fixture.exe",
  "level": "compose",
  "composition_plan": {
    "strategy": "sequence",
    "paths": [["0x140001000"], ["0x14000100a"]]
  }
}
```

示例地址只对应测试夹具中的`MOV RAX,42; MOV RCX,RAX`，不适用于任意文件。每个数组是一条严格路径：内部fallthrough/直接边须连续，条件或间接控制只能在模板末尾。单模板内地址唯一，模板之间可以重复；所有模板从原文件重新解码和投影，不接受调用者给出的raw p-code。每个模板须自行定义它读取的有效flags，模板之间不转移或导出flags。全部16个GPR都是每次模板出口的活值，不能因下一模板覆盖scratch而跨模板省略其无法建模的写入。

严格模板可包含与原字节及完整3操作解码匹配的无前缀`E8 rel32`近直接调用，下一明确地址必须是callee入口。终点CALL的`control`仍为direct，额外`transfer=call`和首选返回地址字符串保留调用身份；该值不是DAG节点id。压栈STORE照常保留、计原始访问预算并衔接到下一模板；CALL/RET的同址转发不删除该写入。不能直接跳到调用方fallthrough冒充callee摘要；间接/远/前缀调用、ABI与未提供callee正文仍未支持。完整边界见[STATE_PROJECTION](STATE_PROJECTION.md)。

较长或重复数组优先使用`composition_plan_ref: {"path":"C:\\plans\\owned-plan.json","sha256":"<文件原始字节的64位小写SHA-256>"}`，与`composition_plan`严格互斥。文件内容就是上述地址计划对象，最多65536字节、UTF-8 JSON且无BOM；只能读取稳定普通非链接文件。摘要不符、超限或未知字段在目标读取和进程提交前拒绝。文件入口不接受脚本、raw p-code、次数、观察状态或证书，也不放宽任何计划与计算预算。

工具将原文件保存为SHA blob，回应及完整报告的`compositionInput`绑定路径、原始字节摘要/长度、规范化计划摘要和实际显式模板/地址数。子进程只收到重新验证的规范化地址计划。提交后的原文件变化不能改变此次快照；子进程拒绝时错误仍附带已验证摘要与显式计数，不生成成功报告。调用者应核对这些回执，不以模型声称“完整复制”代替实际参数。改用文件引用是新的请求，不能追认此前漏项的内联调用为通过。

自动有限重复使用`strategy="constant-loop"`，同时且仅提供`prefix`、`body`和`suffix`，不提供次数：

```json
{
  "target": "C:\\samples\\owned-fixture.exe",
  "level": "compose",
  "composition_plan": {
    "strategy": "constant-loop",
    "prefix": ["0x140001040", "0x140001045", "0x140001049"],
    "body": ["0x140001045", "0x140001049"],
    "suffix": [["0x14000104b"]]
  }
}
```

此夹具为`MOV EBX,3; SUB RBX,1; JNZ body; MOV RAX,RBX`。prefix包括首次正文后，在完全自由初态DAG中的精确常量条件推导出额外2次正文。prefix/body必须在同一条件边界选择正文入口或首个suffix入口；支持taken或fallthrough回到正文。非确定条件、预算内未能退出或缺失flags拒绝，不把某次记录走过的方向代入模型。`inferredRepeat.bodyApplicationsAfterPrefix`不含prefix内的首次正文；完整trace和推导尝试统计保留在报告中。这不是一般符号循环不变量或任意多出口循环恢复。

默认`indirect_mode="reject"`拒绝中途间接跳转和RET。可在计划中显式设`indirect_mode="guarded-target"`，用实际目标表达式等于下一模板入口作为续接条件；不等的一侧保留原动态目标、控制执行后的16GPR和内存，包括RET已弹栈的RSP。入口值不写回寄存器或内存。常量不匹配时最终pathGuard为false，另侧出口仍有效，不能称路径已到达。它不自动发现或穷举目标，也不证明条件可满足或原生可达。

每条STORE使用自己进入模板时的guard；不能用最终pathGuard抹去此前的写入。`sideExits`保存分叉时点的状态，其续程标为`not-analyzed`。最终registers/currentMemory/control只在pathGuard非零时有效。内存是任意一致的总字节数组，保留小端、写入顺序、别名和uint64回绕，不用文件数据或观察值替代自由读取。

组合DAG对写后读使用精确字节转发：只有地址为同一个不透明uint64主体加模常量偏移（或均为绝对常量）时才确定相对位置。读取字节按最新STORE优先；部分重叠从新值和旧内存逐字节拼接，跨`2^64`回绕仍按模地址处理。已证不相交的写入可跳过；主体不同表示别名未知，必须保留读取当前完整内存，不能越过未知写入沿用更早值。典型`PUSH V; RET`能把同址读回的目标化简为V，但PUSH的存储、RET后的RSP和未分析动态出口都保留。

此优化每个组合DAG最多访问4096个STORE；预算耗尽保留原LOAD，不按观察值猜别名或升高原工作/DAG限制。`memoryNormalization`记录真实访问、转发、未知/预算回退与缓存计数，`independentSMTProof=false`表示本次工具没有调用证明器。离线局部公式验证与原生/模型回归单独存证，不能把数学内存模型的等式推广为OS、代码取指一致性或保护业务证明。原raw指令、全部STORE和原LOAD/STORE访问字节仍全额计数。

| 项目 | 固定限制 |
| --- | --- |
| 计划地址 | 最多128个不同首选地址、1024次显式出现；单模板1..128个且不重复 |
| 路径应用 | 最多64次；sequence显式给定，constant-loop由常量条件决定 |
| 展开工作 | 最多1024次逻辑指令、65536个raw p-code操作、1024字节累计LOAD/STORE |
| 单模板 | 继续使用strict projector的128指令、8192操作、256访问字节限制 |
| 推导尝试 | 尝试中的逻辑指令、访问字节分别累计不超过65536；最终翻译另外计数 |
| 共享DAG | 2048节点、8192引用（含根）、128深度 |
| 报告 | 原始分析输出和最终可分页JSON各不超过4MiB，格式化展开也计入 |
| 执行资源 | 与lift/project合计最多2请求；单进程2GiB/50秒Job在创建时绑定，总请求最多60秒及5秒清理余量 |

协议根进程和计算子进程分别验证规范化地址计划；原文件快照、Python、解码器及运行时清单锁定并核验SHA。宿主导入时核对计划、原解码与模板、实际应用的指令/操作/访问统计、DAG根引用和深度。取消只作用于所属请求；同nonce清理ACK和根进程真实退出均确认后才能释放容量，缺确认保留owner。返回预览最多8个出口，`sideExitPreviewComplete=false`时其余出口在完整报告中；预览节点id不等于公式或证明。

公开报告schema为`ig5-pcode-composition-v1`，`representationSchema`区分闭合核心和guarded-target核心；原始字节与解码、模板、全部应用边界、STORE、出口、DAG和尝试记录均留在`reportPath`，摘要为原响应`reportSha256`。查看所需依赖时每次最多200行并记录范围，不能从预览猜完整语义。`fitsPublicFixedPathLimits`仅比较旧`level=project`的边界，不是本请求成功或覆盖证书。

旧`level=project`的重复地址、中途间接控制及128指令/256访问字节等限制保持。不要将compose参数传入project，或把新入口通过改记为旧超限请求通过。两种入口均不证明CPU未定义结果、完整架构flags、访问故障、OS/MMIO、并发、代码写入与取指一致性、函数返回、全输入路径覆盖或保护业务恢复。BSR/BSF仅沿用完整字节绑定且全部目的/flags已死的有限结构例外；活输出仍拒绝。

`npm run test:composition`检查纯核心、计划边界和宿主契约，不启动原生引擎。`node scripts/test_composition_runtime.mjs <新的绝对产物目录>`通过真实公开工具/固定协议/受限解码子进程验证6个正例与7个拒绝例，随后用独立数值公式核验状态、别名内存和guard，生成的PE始终仅作为数据。1024访问字节的正例使用重复读取，另保留顺序LOAD/STORE在相同字节数下因DAG深度超限而拒绝的案例；各预算同时生效，不能只满足一项。这些检查不等于当前DSH安装已同步、模型已实际调用或VMP3.8业务已恢复；部署、重载、启动日志和已配置模型的DSH验收单独记录。

在上述命令显式提供`<插件绝对根目录> --plan-references`可用同一13项原生案例验收文件引用，额外断言原blob/规范化摘要/实际64段参数与子进程请求吻合。默认内联模式和独立384组数值状态核验保持；文件引用、内联与真实模型验收分别保存证据。

`npm run test:composition-memory`覆盖全部1..16字节读写宽度、35个相对偏移、5个边界/随机基址，共44800组独立数值核对，以及未知别名、最新窄写、优化工作耗尽和取消。`node scripts/test_composition_memory_runtime.mjs <新的绝对目录> [插件绝对根]`执行11项真实只读解码案例（9个接受、2个预期拒绝）及576组独立原生指令公式核对，含以内存计数的3轮循环与PUSH/RET守卫续接。

`npm run test:composition-memory-smt -- <新的绝对目录>`是独立的有界局部SMT检查，使用已固定的Triton依赖，不属于无原生依赖的纯测试。Triton的`ast.array`在当前安装中初始为零，不能直接冒称任意内存；检查器在每个实际初始读取地址放自由字节，使用SMT stores保持别名一致性，未读取的其余地址才保留零。任意总字节映射在这些有限位置均可由相应自由字节表示，包含地址相等的情况。前置SAT检查必须发现非零和非均匀读取，避免“全零初态”伪证明。公式、查询期限、失败、正例和负例都单独保存；API来源为[Triton官方AstContext文档](https://triton-library.github.io/documentation/doxygen/py_AstContext_page.html)。
# Explicit transition-chain representation

Long explicit sequences can select `composition_plan.representation="transition-chain"`.
See [TRANSITION_CHAIN.md](TRANSITION_CHAIN.md) for exact binding semantics, separate
retained/expanded depth, unchanged budgets and validation boundaries. The default
flat composition and constant-loop inference retain their original behavior.

