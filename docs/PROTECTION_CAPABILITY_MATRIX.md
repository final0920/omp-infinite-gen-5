# 保护器与逆向能力矩阵（VMP 3.8 / 3.11 / UPX / Enigma / Themida）

本文档维护无限五代工作台在各受保护程序、版本、配置及反混淆/逆向引擎上的**真实能力与证据矩阵**。

> [!WARNING]
> **时效声明（2026-10-24 补充）：本表是历史记录，不代表当前环境可复现。**
> - 下文所有 VMP 3.11 的 `verified` 行，依据的是此前已录制的数据和当时的运行环境。2026-10-24 在当前开发机上重新采集 VMP 3.11 时，先出现 Java 堆内存溢出，随后因 Demo 版跨机器许可限制而**未能运行**，因此这些结论**没有被本次重新验证**。
> - 每一行的结论只对**该具体样本、该具体函数合同**成立（见各行"范围与边界"列），不得外推到其他样本、其他编译结果、其他版本或"现代 VMP 已被恢复"。
> - 本地开发机上 Ghidra 原生 SLEIGH 通道被 Windows 策略 4551 阻断，只能走 Java 通道；"文件存在"不等于"引擎可用"。
> - 当前有效的能力清单、证据层级和不得宣称事项，以 [`CAPABILITIES.md`](CAPABILITIES.md) 和 [`LIMITATIONS.md`](LIMITATIONS.md) 为准；二者与本表冲突时，以它们为准。

> [!IMPORTANT]
> 严格区分“局部投影/解码退出码0”、“单个输入通过”、“局部 SMT UNSAT 证书”、“模型自述文字”与**真实完整函数业务恢复**。未在对应版本、全输入域、跨路径、稳定部署和无预答案环境下验证的项，均不得宣称为已攻克。

---

## 1. 核心边界与定义

- **`verified`（已验证业务通过）**：在明确函数合同下，到达真实返回点，通过 1,000+ 独立输入核验、全输入域 SMT UNSAT 证明、跨分支覆盖与部署重现。
- **`partial`（部分验证）**：完成了特定 handler 算式求解、局部死帧消除、单条执行路径或特定片段投影；未建立完整 VM ISA 或未解决输入守卫。
- **`blocked`（安全/策略阻断）**：受宿主安全策略（如 WinError 4551 阻止 native SLEIGH 执行）或防病毒隔离（如 Themida 输出被 Defender 隔离）保护，按原则**绝不绕过、不换目录、不修改系统安全设置**。
- **`unverified`（未验证/未知）**：缺乏权威版本样本（如 VMP 3.8 qualified sample = 0）、长预算前缀耗尽（如 Ultra 8轮在 100,000 指令未返回）或反例尚未解决。

---

## 2. 保护器能力与样本矩阵

| 目标保护器 | 版本凭证与来源 | 保护配置 | 状态 | 实测指令数 | 业务恢复结论 | 输入与路径覆盖 | 限制与未决边界 |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **VMProtect 3.8.x** | 无合格样本（0 qualified）；论坛线索 3.8.1 未获授权交付；研究参考 REcon 2024 / VMPLift / titan | 任意 | **`unverified`** | 0 | **未恢复** (false) | 0 | 样本合格数为 0；动态 rolling-key 与 per-handler 寄存器轮换正在建构模型，严禁宣称已兼容 3.8。 |
| **VMProtect 3.11 Demo** | 官方 Demo 3.11.0.2835，Authenticode 签名验证有效，SHA256: `52e23d2f...` | Virtualization (add64) | **`verified`** | 25,241 | **`uint64(x + y)`** | 1,124 组独立输入对，SMT UNSAT | 仅限该记录函数的业务合同；`wholeBinaryVerified=false`。 |
| **VMProtect 3.11 Demo** | 同上 | Virtualization (signed-select64) | **`verified`** | 51,465 (双路径) | **`signed(x) <= signed(y) ? y : x`** | 2,409 组独立参考，双路径覆盖互斥 UNSAT | 完整双路径覆盖；`wholeBinaryVerified=false`。 |
| **VMProtect 3.11 Demo** | 同上 | Virtualization (branch-mix64) | **`verified`** | 47,365 (双路径) | **`low1(x) != low1(y)`** | 2,409 组独立参考，双路径互斥 UNSAT | 双路径到达调用者返回；`wholeBinaryVerified=false`。 |
| **VMProtect 3.11 Demo** | 同上 | Mutation | **`verified`** | 205 | 位运算归一化恢复 | 2,409 组独立参考，SMT UNSAT | 针对 mutation 展开与规范化。 |
| **VMProtect 3.11 Demo** | 同上 | Ultra (mul-mix32) | **`verified`** | 59,167 | **`uint64(((x ^ y) + 99) * 143)`** | 2,409 组独立参考，MBA 局部简化后 SMT UNSAT | 超长单路径求解通过。 |
| **VMProtect 3.11 Demo** | 同上 | Ultra (round-mix64 8轮) | **`unverified`** | 100,000 (预算耗尽) | **未返回** (false) | 0 (前缀截断) | 196 段 / 18,166,919 字节后未到达函数返回点；严格保留为硬失败，不扩大预算掩盖。 |
| **VMProtect 3.11 Demo** | 历史采样录制（Page 0 & Page 8） | Virtualization / Ultra 采样主体 | **`partial`** | 16 个采样 handler 主体 | 10 个 ordinary-consistent，6 个 partial (保留未知)，0 unverified | 15 个语义核心字段完全对等，0x39 RIP-relative 经 runtime-PC 坐标投影保留为 partial | 仅证明单个 handler 主体的方程与 dead-frame 消除，不构成全 ISA 或通用字节码解释。 |
| **UPX 5.2.1** | 官方 release 5.2.1，ZIP SHA256: `eabc6792...` | NRV (method=2) / LZMA (method=14) | **`verified`** | 130 | 5 组编译案例（分支、8轮旋转混合、选择、乘混合）全部恢复 | 每例 2,409 组参考输入，全输入域 SMT UNSAT | 在运行期快照中重现；原文件压缩字节不匹配保留为 false；`wholeBinaryVerified=false`。 |
| **Enigma 7.80 Demo** | 官方 Demo 7.80，CLI SHA256: `c393a08a...`，签名有效 | Classic VM (`vm_begin` / `vm_end`) | **`partial`** | 66,614 (131 段) | **未完成业务验收** (0 accepted) | 输出在 2,409 组上匹配参考，但存在 640 个全窗口守卫与 320 个前缀守卫未解 | 发现真实反例输入 (`x=0xbf8e3c24947ce2a2, y=0xfffbf3f707ab2019`)；单路径不能冒充全输入域去虚拟化。 |
| **Themida 3.2.4.34 Demo** | 官方 Demo 3.2.4.34，有效签名 | Demo (Tiger -> Falcon Tiny) | **`blocked`** | 0 | **未恢复** (0 accepted) | 0 | 产物被宿主 Windows Defender 隔离；严格遵守安全规范，不关闭防护或规避隔离，通过数保持为 0。 |

---

## 3. 底层 p-code 状态投影与死帧消除能力

| 引擎能力 | 适用范围与数学边界 | 验证方式 | 回归套件 |
| :--- | :--- | :--- | :--- |
| **BSR 完整死帧消除** | 16/32/64 位寄存器源 BSR，3条内部跳转边 `[3,9]`, `[6,9]`, `[8,4]`，最大步数 83/164/323；要求目的寄存器及 6 个标志位（CF, PF, AF, ZF, SF, OF）全死 | 纯 Python 逻辑 + Java 解码运行时双重核验 | `scripts/test_pcode_bsr.py`<br>`scripts/test_projection_bsr_runtime.mjs` (20 案例) |
| **BSF 完整死帧消除** | 16/32/64 位寄存器源 BSF，3条内部跳转边 `[3,10]`, `[7,10]`, `[9,4]`，最大步数 99/196/387；要求目的寄存器及全部 6 个标志位全死 | 纯 Python 逻辑 + Java 解码运行时双重核验 | `scripts/test_pcode_bsf.py`<br>`scripts/test_projection_bsf_runtime.mjs` (22 案例) |
| **CMOVcc 48 种形状死帧消除** | 16/32/64 位全部 16 种条件编码，32 位显式高 32 位清零约束，标志位保持 | 48 种完整形状全覆盖，独立布尔代数枚举 | `scripts/test_pcode_cmov.py`<br>`scripts/test_projection_cmov_runtime.mjs` |
| **Runtime-PC 坐标投影** | 针对含 RIP-relative 数据访问的 handler（如 0x39），按原 PE 可执行节逐字节映射切换解码 PC，保留数据常量语义，禁止盲目重定位 | 8 项坐标契约 + 3 runtime 基址投影 + 16 handler 对等审计 | `scripts/test_recorded_coordinates.py`<br>`scripts/test_recorded_coordinates.mjs` |
| **未定义标志位流转阻断** | MUL/IMUL ZF undefined, ADD/CMP AF unmodeled, SHL/ROL OF undefined 等严密阻断；若后续存活指令消费未定义位，严格拒绝 | 19 项标志位真实边界测试，Java 解码管线通过 | `scripts/test_projection_flags_runtime.mjs` |
| **Direct CALL rel0 压栈返回绑定** | 严格识别无前缀 5 字节 `E8 rel32`，绑定 `RSP-=8; STORE(RSP, nextEA); CALL target` | 形式语义与写后读传递证明 | `scripts/test_pcode_calls.py`<br>`scripts/test_call_zero_runtime.mjs` |

---

## 4. 研发纪律与准入准出规范

1. **零虚标原则**：单次测试退出码 0、局部 SMT 证明通过或模型文字表述，仅代表该局部算式自洽，**绝不冒充完整去虚拟化成功**。
2. **反例与未知完整保留**：如 Enigma 的 640 未解守卫与 SAT 反例、Ultra 8 轮的 100k 超限、0x39 的 partial 状态，一律如实记录在权威状态中。
3. **安全与许可红线**：
   - 宿主应用控制策略阻断 4551 严格遵守，全程走 Java SLEIGH 解码通道，严禁通过重试/改名规避；
   - 隔离文件（Themida / mutation）严禁恢复或修改安全策略；
   - 外部参考（VMPBypass / apk-reverse-main）严格遵守许可边界，仅吸收思路与方法，不分发未授权代码。
