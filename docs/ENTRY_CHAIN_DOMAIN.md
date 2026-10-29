# 入口与初始化状态链的条件域证明

维护脚本 `scripts/prove_entry_chain_domain.py` 读取已封存的真实 Java 解码及公开 compose 报告，为自产 VMP **3.11 Demo 2835** Ultra 入口加 16 段初始化链生成有界 SMT 查询。v2 还接受明确的 `--case-id entry-plus17`，其维护证明输出 schema 为 `ig5-entry-chain-conditional-domain-proof-v2`，数组／计数改用通用字段名。默认仍选 entry-plus16。它没有新增公开求解工具，不自动执行目标，也不是 VMP 3.8 的版本证据或完整去虚拟化结果。

该固定研究夹具包含 17 次应用、53 个有序八字节 STORE、17 个完整内存绑定及 16 个互补出口。所有 GPR、初始字节内存和活未知 PUSHFQ 值保持自由；`state_binding` 保留完整来源等式。编码前检查整个 DAG 的索引、顺序、类型、操作形状、宽度和预算，证明中的截断点不能隐藏损坏定义。地址查询可把 LOAD 放宽成独立自由值，只有其 UNSAT 结论能够用于原来的连贯内存；派发目标查询不使用这种放宽。

令 `S=初始RSP`、`L=S−671 mod 2^64`。在 DAG 的普通字节内存模型中，无条件证明全部 53 次写入的起始偏移 `unsigned(address−L)≤663`。单独验证全部 17 个边界的 RSP、RBP、RSI 和 R11 恒等式；即使整体地址查询返回 unknown，也保留原状态，只有精确地址分解和独立位向量引理均 UNSAT 时才取得组合结论。

条件性路径结论需要两个明确前提：

- 25 个具体的初始数据内存字节与固定 PE 中的选择器及派发表字节相同。其他内存没有填零或替换成文件内容。
- `unsigned(L−imageBase)≥imageSize` 且 `unsigned(imageBase−L)≥671`，即循环地址空间中的栈窗口与整个映像分离。

显式 64 位到 10 位偏移桥接引理、任意窗口写字节保留外部字节引理和映像分离引理，连同逐条核对的 53 个 STORE 与 17 个内存来源绑定，证明每个写入前缀都保留映像字节。每段派发器先在任意当前内存上证明完整目标恒等式，再由已推导的字节事实证明目标值；这些局部证书才可作为守卫查询的显式等式截断点。结果是 16 个所选续接为真、16 个互补出口为假，以及终点目标的条件值。原报告中的全部写入、guard 和出口均保留。

原预算为每项 ≤2 秒、512 MiB，合计 ≤128 查询、45 秒，创建时绑定单进程／2 GiB／50 秒 Job；每查询 ≤1 MiB／2048 个编码 S 表达式／8192 个原子 token／128 层。分段 DAG 的展开依赖深度和查询编码深度分开记录。所有查询原文、hash、实际状态、时限与进程退出证据独立保存。unknown 不计 UNSAT；只有确认子进程退出后才有界读取日志。

回归入口：

```powershell
& .\runtimes\ghidra\python\python.exe -I -B -X utf8 scripts/test_composition_domain_smt.py
& .\runtimes\ghidra\python\python.exe -I -B -X utf8 scripts/test_composition_domain_smt.py --smt --out <新绝对目录>
& .\runtimes\ghidra\python\python.exe -I -B -X utf8 scripts/prove_entry_chain_domain.py --receipt <已封存真实验收JSON> --receipt-sha <SHA256> --out <新绝对目录>
& .\runtimes\ghidra\python\python.exe -I -B -X utf8 scripts/verify_entry_chain_domain.py --proof <上述目录/verified.json> --out <新的审计JSON绝对路径>
```

固定研究夹具的生产器、二进制及私有报告不分发。脚本拒绝非匹配目标或报告；它不是任意输入自动证明接口。审计重新核对所有查询和证书引用、来源字节、存储顺序及绑定，并用 1,555 组不同状态检查数值性质。数值内存只固定上述 25 字节，其余为变化的确定性全域函数。分离的 1,240 组全部满足结论；重叠的 315 组中 260 组仍续接、55 组不续接，说明分离是充分条件，不能被描述为必要条件。数值回归不是全域证明或独立 CPU 解释器。

缺少字节事实及缺少区域分离各有 SAT 反例。实际栈分配、装载后数据与首选文件／重定位的对应、CPU／故障／flags 语义、其余 VM 初始化及 ISA、完整业务与跨输入路径覆盖尚未验证。`businessAccepted`、`wholeBinaryVerified` 继续为 false。

## 第17次上下文搬运与立即数处理器

entry-plus17 包含入口加17次上下文搬运：18应用／55写／18内存绑定／17互补出口／30个初始字节事实。相同671字节窗口引理逐条核对全部55写。整体查询若在原2秒内 unknown，保留该结果，以精确地址分解、对齐及范围引理取得窗口结论；不能声称所有查询均 UNSAT。旧 entry-plus16 范围另跑47查询与1555状态，作为维护器参数化的回归。

`scripts/test_handler17_runtime.mjs` 从已绑定的静态发现文件取得地址，再由公开 Java project/compose 全量重新解码。它验证 entry-plus17、立即数压栈6指令、带栈检查10指令、显式快路22指令与组合133个不同地址的原预算拒绝。最后一项在前置验证拒绝、没有创建分析根；不伪造失败报告或进程清理回执。命令需要 `--plugin-root`、新的 `--out`、`--discovery` 与 `--discovery-sha`；学习夹具与静态发现文件不分发。

`scripts/prove_handler17_semantics.py --receipt <真实验收JSON> --receipt-sha <SHA256> --domain-proof <entry-plus17域证明JSON> --domain-sha <SHA256> --out <新绝对目录>` 在相同有界 Job／SMT 限制下核验三份局部报告：全部16 GPR、整个字节数组内存、按顺序的写入和完整控制。快路的第二次写只在当时guard下发生，栈检查之前的立即数写不能被后继guard抹掉；搬栈分支保留写后状态与未分析续程。

处理器从 incoming RSI 读8字节，RSI+=8、RBP-=8并写虚拟栈；检查 `unsigned(RBP)>unsigned(RSP+384)`。在已证明的入口加17边界上，快路条件为 false 当且仅当无符号初始RSP在 `[8,264)`。映像分离本身不能保证快路；不回绕的671字节初始栈窗口是充分条件。另加13个明确初始字节事实后（总计43），当前夹具压入零，并条件性转移到opcode137／`0x1400545e7`。这里的零来自八个明确字节前提，不作为一般内存默认值。

新局部证明14查询（11 UNSAT、3 SAT）与1268组自由状态的3804次局部数值求值分别记录；覆盖字节重叠、地址回绕以及全部672个小初始RSP。它们不是独立 CPU 解释器或业务覆盖证明。133地址整体计划继续拒绝；维护研究使用完整局部摘要和已认证接点关系，尚无公开跨报告组合接口。搬栈续程、其余ISA／业务及原生前提仍未完成。

## 17槽上下文映射

`scripts/prove_context_mapping.py --receipt <真实验收JSON> --receipt-sha <SHA256> --domain-proof <entry-plus17域证明JSON> --domain-sha <SHA256> --out <新绝对目录>` 读取匹配的域证明与相邻独立审计，重验完整55写、18内存绑定及查询摘要。47个明确初始字节与相同映像／栈窗口分离前提下，27项查询得到24 UNSAT、3 SAT，结合逐字节内存归纳得到17个上下文槽：15个原始GPR、一个自由64位flag映像和一个后写零；不声称包含初始RSP。入口对 S-72 的后写零、S-16 的 r12 与 S-8 的 rdi 覆盖必须保留。

非别名依据是具体槽偏移、通用8字节写入／字节保持引理以及全部先后写索引，不能由不同DAG节点ID推出。该结论由局部全称SMT证书和明确的有限内存归纳组合而成，不声称存在单项整体SMT查询。1264组数值状态中1200组分离状态全部符合，重叠状态43符合、21不符合；它们不是CPU执行或业务路径覆盖。flag映像保持自由值，不默认为零，不补造架构flags关系。

真实Java回归可额外指定 `--next-discovery <绑定的16指令发现JSON> --next-discovery-sha <SHA256>`，加入opcode137的16指令栈检查和28指令快路翻译。两个路径均全量翻译，不是“仅翻译16/28”。该回归验证原始字节、完整寄存器／有序内存／互补出口和宿主预览计数；另行证明见下节。分析与求解的原Job、时间、内存和请求预算不变，所有失败及unknown保留。

## opcode137全状态及条件接点

`scripts/prove_handler137_semantics.py --receipt <同一真实验收JSON> --receipt-sha <SHA256> --context-proof <17槽证明JSON> --context-sha <SHA256> --literal-proof <立即数处理器证明JSON> --literal-sha <SHA256> --out <新绝对目录>` 绑定同一入口报告、域审计及实际16指令／28指令字节。`scripts/verify_handler137_semantics.py --proof <新证明JSON> --out <新审计JSON绝对路径>` 独立核对证书、原报告、全部查询字节与预算、cut对应的实际写后内存和66个原始映像字节；读取器没有重跑求解器或CPU。

读取器按物理绝对路径及SHA绑定源回执，接受同一Windows文件的斜杠／大小写拼写差异，不把字符串写法不同当作证据失配；同内容的其他文件、缺失、相对或非规范路径仍拒绝。该兼容问题由真实DSH模型验收触发，原失败保留；回归 `scripts/test_handler137_receipt_paths.py` 验证这两侧边界。

局部全称摘要先读 `index=load8(M0,RSI)`、`value=load64(M0,RSP+index)`，再写 `store64(M0,RBP-8,value)`；RBX=value、RDX=零扩展index、RSI+=1、RBP-=8，栈检查R8=RSP+384。快路随后从第一次写后的内存取下一selector及表项，RSI再加1、RAX=selector、R8=目标并在RSP-8压入目标，RSP恢复；第一个写入不能被后继guard抹掉。全部16GPR、整个普通字节数组、原写入顺序、两侧控制和侧出口状态分别证明，无局部内存不别名假设。将上下文读取移到写入后会改变结果的重叠SAT反例必须保留。

当前19项查询为11 UNSAT、7 SAT、1 unknown：整体17槽数组保持查询2秒超时原样保留；对应结论由新的全称逐字节不相交UNSAT、前驱单字节保持UNSAT及明确17槽×8读取字节×4次8字节写入的有限内存归纳支持，不拿unknown当证明。所有新写地址仍在原671窗口，每个写前缀沿用已认证的映像保持引理。前驱47字节与立即数13字节再加本处理器6字节，共66个明确初态字节；缺槽值、操作数字节或后继selector／表项分别有SAT反例。

认证接点上137快路false恰为初始RSP在 `[16,264)`；上一立即数处理器快路成立时，137快路必成立。上下文槽48来自入口第17号有序写的后写零，跨两处理器保持，因而137条件性压入零并转移到opcode250／`0x140055f66`。最终内存cut是137第一次真实STORE之后的完整数组，来源及先后链接核验；不能当作任意新初态。

局部1920组状态对两份报告做3840次全状态数值求值，含720组字节重叠及全部672个小接点RSP。另1264组组合输入中，1200组满足区域分离，64组重叠跳过；256组在前驱立即数处走另一侧，余944组到达137快路。guard为false的编码末态不传给后继。两批测试不算业务路径覆盖或独立CPU解释器，部署间复用同一批输入不累加。原128不同地址整体计划限制、全部预算和未验证的原生／搬栈／其余ISA／完整业务前提不变。
