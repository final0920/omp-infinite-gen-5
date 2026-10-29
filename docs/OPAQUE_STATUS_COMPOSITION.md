# 保存标志映像的多段状态组合

原文件明确地址计划可显式选择`strategy="sequence"`、`representation="transition-chain"`、`template_mode="opaque-status"`。公开schema为`ig5-pcode-opaque-status-transition-chain-v1`，内部表示为`ig5-internal-opaque-status-transition-chain-v1`。中途RET/间接出口另需`indirect_mode="guarded-target"`。内联计划与SHA绑定的计划文件沿用同一验证器；不接收未知值、初始flags、p-code、观察状态或外部摘要。

每个模板从固定原字节完整重译，保留全部16GPR、顺序字节内存与出口。PUSHFQ只将同模板已经定义、已建模、依赖闭合的状态位覆盖到该应用新生成的64位未知输入；ADD64实例保留CF/PF/ZF/SF/OF，已知mask0x8c5、有效未知59位，AF仍未知。前一模板定义CF，不允许后一模板直接读取CPU初始CF；存入普通内存/GPR的flag映像数据可以通过精确状态等式传递。

模板只保存原效果与来源策略，其`flagImageRefinement`不含全局valueNode。每个`layers[].flagImages`项用instructionIndex和值根绑定该应用实际PUSHFQ的STORE.value；同一缓存模板重复应用，未知输入及值根也须按应用独立。规范mask/布尔化/扩宽/位放置/OR节点保留，并带statusOverlayStep；每段只复用字面常量，不能以常量标志计算同值为理由复用上一段非恒定节点ID。该限制保持精确边界，而不是允许越过source边。

宿主核对每段原始解码、flagPolicies、mask/未知位数、逐位定义来源、规范位树、STORE索引和值、节点范围及新鲜身份。18个state_binding仍是原完整GPR/内存/guard的来源等式。每处flagImages值根与nondeterministicInputs都计入原引用预算；模板原raw操作和每次应用的读写按全额统计。所有STORE保留进入guard，未选中的动态出口保留实际目标及执行控制后的全部状态；最终状态仅在pathGuard成立时有效。

公开预览将schema、实际节点/引用/STORE/出口计数及partial/unverified/false范围放在响应开头，避免长元数据中段被裁剪后漏读。statusFlagImageCount和representationValidation.statusFlagImagesChecked表示宿主检查过的值根数，statusFlagsExported=false。它们是结构/来源核验，不能当成CPU、SMT或业务恢复证明。

原64应用/128不同地址/1024逻辑指令及访问字节/65536逻辑操作/2048节点/8192引用/段内128深度/4MiB限制保持。模板与组合共享4096次STORE访问优化额度。创建时单进程2GiB/50秒Job、5秒清理、两请求槽及同nonce ACK和协议根实际退出要求不变。默认strict/opaque-effects、flat和constant-loop原规则保持；opaque-status不适用于flat或循环推断，不增加公开跨报告连接。

维护回归包括：同模板重复时的新鲜未知、常量运算边界、经完整内存传递的状态字、CPU flags不得跨段、AF自由、未知别名、回绕、原始存储索引、全部状态/出口和原预算。固定官方3.11 Demo自产样本另检查250→136、分开250正文与派发器、137→250→136和重复250；翻译成功与对应路径真实可达分别记录。

`prove_status_chain_semantics.py`对当前公共两段链验证：原始操作数地址、独立ADD64完整状态映像公式、250的全16GPR/整内存/四次写入/guard/控制、136原22指令全状态/整内存/两次写入/控制，以及以先前18个精确绑定为输入的136状态和完整互补出口。10查询为6UNSAT/4SAT；SAT保留AF两值、旧完整未知映像精度丢失和“后继读取原M0而非250写后内存”的反例。后一个SAT恢复每项cut定义；自由cut不能单独当作实际反例。

结论由局部全称证书和明确两步绑定归纳组成，不声称单项未切割整链SMT。2560组独立普通状态公式检查覆盖5计划各512组，其中每计划256组别名/回绕，128组guard真、384组假；guard假后的后续编码状态只是条件性假设。各部署复用同一批输入，不能累计成更多覆盖。独立读取器只核对证书、来源、完整DAG、类型和限制，不重跑求解器/CPU。本页两层证书本身未证明入口字节接点。后续67→69→75字节的136/78条件归纳另见[CONTEXT_WRITE_JOIN](CONTEXT_WRITE_JOIN.md)，仍未证明原生栈/加载字节/CPU/故障、全路径业务或精确VMP3.8。

回归：`npm run test:status-chain`。真实解码：`npm run test:status-chain-runtime -- --plugin-root <插件绝对目录> --out <新绝对目录> --cases <固定自产目标的计划JSON> --cases-sha <SHA256>`。证明：`test:status-chain-proof`需`--receipt/--receipt-sha/--handler136/--handler136-sha/--out`；读取器：`test:status-chain-audit -- --proof <verified.json> --out <新audit.json>`。输出与失败分别保留，未知或预期状态不符必须失败，不提高预算换结论。
