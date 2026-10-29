# 固定路径的未知效果投影

本页保留`opaque-effects`的完整未知标志映像契约。需要保留同一路径已定义状态位与保存标志字的关系时，另显式选择[opaque-status](OPAQUE_STATUS_PROJECTION.md)及其独立schema；不会静默改变本页旧模式。

`ig5_ir level=project projection_mode=opaque-effects` 显式选择保守数据效果模型，使用独立 `ig5-pcode-opaque-projection-v1` 表示。它保留不知道的值，不声称逐条指令精确恢复。默认 `strict`、`guarded-path` 和 `compose` 的拒绝规则不变，模式不能叠加。

只支持完整字节与固定 SLEIGH 输出同时匹配的三类指令：

| 编码 | 数据效果 | 保留的未知 |
| --- | --- | --- |
| 无前缀 `9C` / PUSHFQ | RSP 减 8；顺序写入一个新的任意 uint64 | 完整标志字的位约束及与状态标志的关联不建模 |
| 无前缀 `0F 31` / RDTSC | 新的任意 uint64 分给 EDX:EAX；RAX/RDX 高 32 位清零 | 不代入录制时间，不建立多次读取的时序关系 |
| 单 `66`、可选单 REX 且无 W、`0F C8–CF` / 未定义 16 位 BSWAP | 整个目的 GPR 改为新的任意 uint64 | 不采用解码器的确定 32 位 BSWAP 公式，不假定高位保留 |

PUSHFQ/RDTSC 的全部原始 p-code 使用固定语义摘要匹配；BSWAP 还按原字节确定目的寄存器，统一寄存器后匹配全部 12 条操作。缺失、附加、错误副作用和未知前缀拒绝。公开参数不能提供未知值、原始 p-code 或效果证明。内部 `IG5_OPAQUE` 只允许匹配器当次生成，原始输入出现它仍拒绝。

替代表示包含普通无故障执行的数据结果，是刻意放宽的集合。它不模拟异常、特权检查、VM exit、设备、CET、自修改取指或完整 CPU。其余指令继续使用原始 p-code 和既有 flags 屏障，活初始 flags、活未建模/未定义 flags、一般内部 CFG 仍拒绝；这不是接受任意未知指令的兜底。

`opaqueEffects` 保留每处原字节、完整原始 p-code SHA、原/替代操作数和范围。实际影响输出或 STORE 的新值写为 DAG `nondeterministic` 节点，引用列在 `nondeterministicInputs`。即使新值最终不再被观察，其指令的抽象记录仍保留。不同位置的新值互不合并，也不替换自由 GPR 或初始一致字节内存。

所有 STORE 按顺序保留。PUSHFQ 的 `pcodeIndex=56` 指向原始解码操作，`replacementPcodeIndex=2` 指向内部替代表示。预算仍计原始 57 条操作。`pcodeOperations` 统计原始工作；`selectedOperations/omittedPureOperations` 描述替代表示的切片，`abstractedRawOperations/replacementOperations` 单独公开差异。

未知模式复用组合器的精确写后读归一化。只在同一不透明 uint64 主体加模常量偏移时推导别名；不同主体、未知写入或 4096 次 STORE 访问优化额度耗尽均保留 LOAD。栈回绕、部分重叠和全部写入不省略。常量运算按 p-code 位宽求值，不从样本输出取值。

原 project 的 128 指令、每指令 128 p-code、8192 总操作、256 访问字节、2048 DAG 节点、8192 引用、128 深度和 4 MiB 报告不增加。复用两个请求、60 秒总期限、创建时绑定的单子进程 2 GiB/50 秒 Job；清理 ACK、nonce 和真实退出要求不变。Core8/Full40 和 13 个执行/修改审批门不变。

原生解码、独立数值检查、局部 SMT、安装副本、宿主模型和完整保护业务分别记录。业务、整程序标志仍为 false。首选原文件视图不隐式接受 ASLR、录制映像或文件数据替换。接口说明不能代替部署证据。

回归入口：`scripts/test_pcode_opaque.py`、`scripts/test_projection_opaque_host.mjs`。真实原生入口及 DSH 验收另行记录。

真实原生回归：`node scripts/test_projection_opaque_runtime.mjs <新的绝对产物目录> [插件绝对目录] [已绑定98地址入口图JSON]`。默认仅生成并读取自产 PE 字节；可选入口图须同时绑定目标大小/SHA和明确地址，不执行目标。保存的报告由 `scripts/test_projection_opaque_runtime_verify.py` 对未切片原始 p-code及独立未知数据公式逐项核对全部16GPR、顺序STORE、总字节内存和末控制。其数值边界/随机/别名场景不等于全输入或CPU证明。

架构数据效果参考 Intel 官方 [BSWAP 说明](https://cdrdv2-public.intel.com/812383/253666-sdm-vol-2a.pdf)及 [PUSHFQ/RDTSC 说明](https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-vol-2b-manual.pdf)。厂商说明、固定解码匹配和有限回归不构成完整架构证明。
