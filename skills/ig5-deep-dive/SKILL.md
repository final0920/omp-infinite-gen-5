---
name: ig5-deep-dive
description: "使用 IG5 深入解释函数或输入处理路径，结合调用关系、栈帧、跳转表、虚表、微码和变量切片验证假设，按授权进行函数仿真或审批修改。"
---

默认静态后端为 `engine=reverse`、`reverseProvider=bundled`，随包服务的实际 `provider=ghidra`，无需本机商业安装；显式 `engine=ghidra` 使用独立车道，商业扩展仅在显式配置 `reverseProvider=commercial` 时使用。先从 `ig5_status` 核对路径、engine、provider、capabilities、projectId/artifactId 与 dbRevision；结果保留来源，不能把两引擎数据库当成一致内存。路径相同不保证内容相同，地址用十六进制字符串并区分静态 VA、RVA、文件偏移和运行时 VA。Ghidra 分析预算到期的 partial 结果只能作为部分证据，不称完整分析。

确认目标与函数地址，用 `ig5_workspace target=... workspace={action:create,goal:...}` 建立调查任务，或用 `workspace={action:get,id:...}` 恢复。以本次返回的 `taskRevision` 作为 `expected_task_revision` 更新 hypothesis/next_step/conclusion，冲突后重新读取。任务只持久分析元数据，不写 IDB、不授权执行；status 是调用者进度声明，假设与结论不因保存自动成为事实。重开或数据库修订变化后旧系统快照标 stale，须重新取证。

优先使用 `ig5_decompile style=dossier task_id=...` 聚合单函数反编译、CFG、调用者/被调函数和栈帧，建立输入、输出、全局状态和关键分支的初步解释。检查各章节的 ok/truncated/unsupported/error、provenance 与分析 partial；只对影响判断的缺项补查，不把章节成功当作全程序分析完整。dossier 正文响应预算不等于全部后端计算预算，按问题选择少量函数。沿 `ig5_calls`、`ig5_xrefs` 追踪影响结论的调用者或被调函数；用 `ig5_cfg` 核验分支与循环结构，用 `ig5_bytes` 核验影响结论的常量或指令。若所需高级工具未启用，先调用 `ig5_profile toolset=full`，也保留用户 `/ig5 toolset full` 入口。按返回的 `toolsetScope` 判断作用域：支持作用域的宿主仅切换当前 agent；旧宿主明确返回 `plugin-instance` 时才影响插件实例。两种切换均不持久化，不构成执行授权或审批豁免。

`ig5_slice` 返回局部变量信息及按变量匹配的代码行，不能把文本命中当成完备的定义使用链或微代码污点证明。用局部赋值、别名、参数传递和调用上下文交叉核验。结构体偏移解释先用 `ig5_struct action=list|get` 检查已有类型；类型假设与已验证布局分别陈述。

按问题使用 `ig5_stack` 核对帧偏移，`ig5_switches` 检查 case/default，`ig5_vtables` 读取 RTTI/虚槽；显式表地址加偏移的解析不能代替寄存器来源证明。`ig5_microcode` 在实际能力支持时可读取分阶段真实 IR，或优化临时 IR；检查返回的 provider、实际 stage 与 maturity 映射，不把兼容映射当成专属微码等价。受限 `xor-self/sub-self` 规则必须检查实际 `rule_hits` 与前后 IR，命中为零时不声称改写，不宣传通用去平坦化。`ig5_switch_repair` 先 preview，应用必须审批且不在 Undo 范围内。

需要单函数去混淆证据时，在 Ghidra provider 使用 `ig5_microcode action=deobfuscate target=... ea=...`，默认 generated/firstpass。它在真实 SSA 上做有界 SCCP、受支持的 1..8 字节位向量常量传播、精确位片、同 SSA 恒等式及相邻整数乘积奇偶证明；检查 deobfuscation.constants、simplifications、branchDecisions、unreachableBlocks 与 dispatcherRoutes。后者是指定入边条件下、保留状态赋值的路径证据，不是已经改写的 CFG。LOAD/CALL 没有内存/函数模型，间接控制流、图 partial 或定点预算未完成时不发布确定性剪枝证明；未命中不等于没有混淆。

默认 max_steps=100000、max_evidence=128，上限 250000/512，原生图另有实际块/指令/边预算。按返回 limits、partial、evidenceTruncated 和 budget 报告范围。此覆盖层 rewritten=false/idb_modified=false/executed=false，不改 SSA、机器码或数据库，不重新生成去混淆 C，不承诺任意 VM 去虚拟化或通用去壳。用户可直接 `/ig5 deobfuscate [--engine reverse|ghidra] <十六进制函数地址> [样本路径]`，多目标须明确路径。观察协议状态按 ig5-protocol 技能另建显式会话轨迹并用 holdout 检验，不将客户端函数或网络观察当成隐藏服务器源码。使用例子见 [状态与去混淆指南](../../docs/DEOBFUSCATION_STATE.md)，工具总数仍为 Full 43。

VMP 等虚拟化样本须区分包装函数、观察到的原生调用入口、派发器和被保护计算体。沿本次实际 CALL/JMP 及调用元数据定位，不能把已知函数名或论文里的地址直接当成全部虚拟机。`expressionSimplifications` 的位运算真值表或线性 MBA 恒等式只证明指定 SSA 表达式；即使控制流未知，也不等于整个函数被恢复。`indirectTransfers` 只展示目标的向后依赖，`targetsResolved:false` 时禁止命名为已恢复 handler 表、VIP 或滚动密钥。部分图/预算耗尽不发布局部等价证明；局部限制为 32 节点、12 层、6 输入，切片为 32 节点。

`ig5_funcs.filter` 是名称子串，传入十六进制地址字符串返回空不能推断筛选器损坏或偏移游标行为。机器字节与高级伪代码形式不同是正常现象；若影响结论，补取 `ig5_ir level=raw` 与同地址 `ig5_bytes`，核验指令语义后再判断。不能用未经验证的手工反汇编描述证明代码/数据冲突。模型文字和作者源码仅供假设或真值对照，不替代本次目标、来源 hash、原生结果与独立验证。

原始 p-code 的调用示例是 `{target,ea,level:"raw",max_instructions:256}`，必须省略 `action`。`action=analyze` 等参数仅供 `level=kernel`；错误会列出具体不兼容参数，不能将失败误归因于 `max_instructions`。内核装载器拒绝某 ELF 不代表随包 Ghidra 的 raw/high 车道不可读。

只有用户已授权该目标的仿真或动态验证，才通过审批调用 `ig5_emulate` 验证实际 provider 与 capabilities 支持的架构、明确 ABI、整数参数与内存缓冲区；不能仅凭 engine 名称推断 x86/x64/ARM64 支持。ARM64 使用 AAPCS64，已有 Windows CPU 仿真证据不代表手机原生移植。它没有 OS/import/TLS 环境，fault、系统指令中止或超时不能单独证明真实程序行为。没有执行授权时继续完成上述只读证据，不扩大到任意程序执行。涉及解密/配置或报文解析时，按 `ig5-crypto` / `ig5-protocol` 建立显式参数、数据变换与独立验证证据；扫描命中不是算法确认。

当用户需要沉淀理解时，通过正常工具调用提交 `ig5_rename`、`ig5_comment`、`ig5_set_type` 或 `ig5_struct action=define|apply`，每个写操作必须通过宿主审批。不可通过工作台 HTTP、直接 Worker RPC 或任意 Python 绕过审批。给出地址、证据、尚未确认的别名或类型，以及修改后的重新反编译结果。商业引擎称 Reverse，开源结果保留 Ghidra/x64dbg 来源。

按实际 provider 与 capabilities 读取低层证据：`provider=ghidra` 的内置 Reverse 与显式 Ghidra 均可在能力支持时用 `ig5_ir level=raw|high`；微码入口的实际 stage 与兼容 maturity 映射不等于商业扩展的 IR 层级，p-code 也不构成去混淆证明。不支持的栈帧/虚表/修复能力先报告实际 capabilities；仅在用户需要且允许另一静态来源时显式打开，分别引用结果。写操作优先带本次证据的 `expected_revision`。需跨引擎保存选中名称/注释/字节时用 `ig5_sync` preview→审阅 digest→apply，两步仍审批；仅同 hash、显式 RVA，部分失败不声称原子回滚。
