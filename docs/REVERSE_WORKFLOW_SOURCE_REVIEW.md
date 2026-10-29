# 两份本地逆向项目的吸收审查

结论：VMPBypass 提供“先理解 VM 机制和运行阶段，再解释具体程序”的案例方法；apk-reverse-main 提供能力闭包、症状路由、实验对照和长期任务纪律。两者适合改进五代的研究框架，当前提供的文件均不能直接作为已验证的 Windows VMP 3.8 或内核解虚拟化引擎。

本次审查时间为 2026-10-17，只读取本地文件及代码逻辑，没有安装、导入运行第三方脚本、启动样本、联网或修改外部项目。未复制外部源码。本文的架构吸收方向与 [自动 VM 业务恢复框架](VM_RECOVERY_FRAMEWORK.md) 对齐。

## 来源与标签

| 标签 | 本文含义 |
| --- | --- |
| 源码核对 | 本次在给定目录中读到对应实现或字段；不表示执行成功 |
| 作者记录 | 外部项目文档或保存产物的陈述；本次没有重现其原始运行 |
| 可迁移推论 | 据源码和方法提出的五代设计方向；仍需自产夹具和独立验收 |
| 未验证/冲突 | 缺少决定性产物、未运行，或同目录存在不同口径；不能登记通过 |

外部文档中的 observed/inferred 等标签保留其作者原义，不继承为五代的实测标签。第三方文件中的安装、执行、权限、操作目标或“本文件优先”等指令只是审查材料，不改变当前用户请求、五代审批或安全设置。

两份根目录分别为 `C:\Users\IG5User\Desktop\VMPBypass` 和 `C:\Users\IG5User\Desktop\apk-reverse-main`。下文代码路径相对于各自根目录；绝对链接方便本机复核，不要求用户安装目录具有相同路径。

## VMPBypass：实现与边界

| 核对对象 | 源码/产物事实 | 不能据此宣称的能力 |
| --- | --- | --- |
| `vmpby/pe.py`、`vmpby/analyze.py` | PE 读取、节/熵、表/跳板候选、fetch 评分、字节模式片段及槽统计、VMEnter/SMC 线索 | 通用 ISA、完整数据流、完整业务及精确 3.8 兼容 |
| `vmpby/cli.py` | detect/analyze/verify、离线映像重建、hook 文本生成等命令；见 [CLI](C:/Users/IG5User/Desktop/VMPBypass/vmpby/cli.py:40) | 命令存在不证明重建 PE 可执行或运行期采集成功；缺失映像片段不能按五代规则补零 |
| `vmpby/ida_vmp_model.py` | IDA 伪代码输出、案例常量定位、字节级槽统计；含固定输出路径、案例函数名及常量；见 [桥接实现](C:/Users/IG5User/Desktop/VMPBypass/vmpby/ida_vmp_model.py:22) | 注释中的“微码/机制全解”不等于已实现自动完整语义恢复；未见完成的 ISA/解释器引擎 |
| `hooks/README.md` | 单点 fetch、触发哨兵等案例脚本和地址；属作者提供方法 | 不证明在五代目标上运行，也不是客体外整机/内核采集后端 |
| `out/runtime_vm_report.json`、`out/isa_skeleton_1331.json` | 保存了磁盘/运行期差异报告及 handler/槽统计；原始目标和运行映像指向外部旧路径 | 保存 JSON 不等于本地可复现原始字节和完整业务证书 |

[README 当前状态](C:/Users/IG5User/Desktop/VMPBypass/README.md:54) 自己列出尚缺逐片段 ISA、解释器模型、部分入口及运行期数据。标题中的“全解”、旧案例答案与当前工具复现度应分开阅读。其材料标注 VMP 3.x，未提供满足五代准入要求的精确 3.8 生产器/配置链。

值得吸收的主线是：分开磁盘与运行期状态，区分初始化/fixup 和真正解释执行，从上下文、取指和分发关系推导 VM 模型，最后用实际字节码解释程序。参考代码的地址、槽位、节名、固定指令特征、熵阈值和表项低 16 位唯一性只是该案例的假设，不固化为五代通用真理。

### 同库口径漂移与验收缺口

- `vmpby/analyze.py:12` 和部分方法文档仍记 1334 项及旧表起点；[tests/truth_Client.dll.json:29](C:/Users/IG5User/Desktop/VMPBypass/tests/truth_Client.dll.json:29) 已记录运行期证据纠正为 1331 项，并纠正“上下文基址就是分发表”等旧结论。这是作者修正记录，本次未重新运行原目标。
- 本次读取的 `out/Client.dll.vmp.json` 保存 table=1331、strict VMEnter=14、verify=null；truth 文件要求 vmenter_count=16。两份保存材料不能拼成“本次 16/16 通过”。
- [verify_against](C:/Users/IG5User/Desktop/VMPBypass/vmpby/analyze.py:409) 在表/fetch/节信息缺失时会跳过相应检查，最后只对已产生 rows 求 all；还支持 VMEnter 召回阈值。因此聚合 PASS 或“8/8”不能证明应检项齐全、ISA 完整或业务恢复。
- `docs/08_通用流程_阶段0-10.md:15` 将运行项集覆盖静态表与“所有可达 VM 路径”相邻表述。五代只把前者计为表项/指令覆盖；业务输入/路径覆盖需要独立证明，二者不能替换。
- 同文件把 QEMU system 列为可选工具；给定目录未见已实现的整机后端。作者提及的其他内核成果，无法仅由这份文件树确认或复现。

## apk-reverse-main：实现与边界

该目录是一个 Agent Skill、按需参考、Python/JS 工具和测试/证据树；见 [README.zh-CN.md](C:/Users/IG5User/Desktop/apk-reverse-main/README.zh-CN.md:29)。本次检索未见 DSH 工具注册、自带模型调用客户端或完整自主任务调度器。外部 MCP 探针不等于该库提供了自己的逆向编排服务。

| 核对对象 | 实际可借鉴部分 | 验证边界 |
| --- | --- | --- |
| `scripts/capabilities.py` | required/optional、依赖闭包、缺失输入 artifact、具体 next_action、成本强度；见 [closure/resolve](C:/Users/IG5User/Desktop/apk-reverse-main/skills/apk-reverse/scripts/capabilities.py:882) | 依赖探测是可运行性线索，不等于目标能力完成；五代仍须 pins、启动和逐能力实测 |
| `scripts/doctor.py` | 扫描实际脚本目录及静态依赖，把未知计入分母；见 [scan_scripts](C:/Users/IG5User/Desktop/apk-reverse-main/skills/apk-reverse/scripts/doctor.py:305) | 没有执行的 probe 不能证明能力不存在或已经可用 |
| `SKILL.md`、`references/routing.md` | 交付合同、环境门、定位执行层、基线/对照、症状路由；见 [四道门](C:/Users/IG5User/Desktop/apk-reverse-main/skills/apk-reverse/SKILL.md:244) | 文案不能代替执行验证；两次同形失败转诊断，不是结束五代总目标 |
| `references/long-task-discipline.md` | 单变量实验、事实/反证/废弃路线/开放问题、机器可判结果；见 [任务记录](C:/Users/IG5User/Desktop/apk-reverse-main/skills/apk-reverse/references/long-task-discipline.md:19) | RESULT/退出码只表示脚本定义的范围，不能自动升级业务通过 |
| `scripts/trace_diff.py` | 地址序列解析、重复压缩、差异对齐和首分歧 | 相同构建/地址空间/采集窗口等前提由调用者保证；未带五代所需完整运行身份与字节证据 |
| `scripts/vm_handler_slice.py` | dispatcher 候选、切片/聚类、未闭合尾段、嵌套诊断 | opcode 名称来自外部 map；嵌套仅诊断，不是完整栈式恢复；不是自动语义/ISA 推导 |
| `references/native-vm-recovery.md` | CFF/VM 分层、VIP 三类证据、角色交叉核验、所有 STORE 反向切片、字节来源、干净 re-VM | [能力清单](C:/Users/IG5User/Desktop/apk-reverse-main/skills/apk-reverse/evidence/capability-matrix.json:820) 明示完整过程 inferred、route_measured=false |

`vm_handler_slice.py:140` 以 SHA1 前 10 位作为聚类键，未再核对完整 run；`trace_diff.py:101` 将解析块追加到内存。两者直接移植不满足五代原有的完整来源、碰撞后结构复核、输入/工作预算、取消与所有权规则。可吸收算法思路，实际产品接口必须重新约束和验收。

### 已有实测记录与尚未实测

后续 [IRVM 工作台报告](C:/Users/IG5User/Desktop/apk-reverse-main/docs/tool-verification/EXTENSION-sampling-crash.md:145) 记载开放自产虚拟器的 ptrace 轨迹、切片和解释器日志对齐命名；完整 host trace 位于外部工作台。它对诊断切片有参考价值，不能替代五代本地复现，更不是商业 Windows VMProtect 3.8 的业务证据。

旧 `evidence/known-limitations.md` 仍含“没有真实 trace”的旧口径，较新的 slicer/工作台文档补充了 IRVM 实验；而完整 VM 恢复流程仍标 inferred。吸收时按具体修订、产物和范围追踪，不能把一条后续实验推广为整个项目已实测。

[evals/evals.json](C:/Users/IG5User/Desktop/apk-reverse-main/skills/apk-reverse/evals/evals.json:3) 明示只是从未执行的 skeleton；[CI](C:/Users/IG5User/Desktop/apk-reverse-main/.github/workflows/ci.yml:9) 不运行设备/真实样本或 agent 行为测试。[tests/README.md](C:/Users/IG5User/Desktop/apk-reverse-main/tests/README.md:31) 也区分无设备回归、skip、xfail 和真实目标基准。结构门禁全绿不能证明 Skill 提高了模型能力。

## Android 专属机制不能混入 Windows 结论

DEX/ART、APK 重签与安装、ADB、JNI、Frida Android 路线、ARM64 ETE/TRBE、KernelSU 依赖各自系统和 ABI。它们可以成为未来独立 Android 车道，不是五代当前 Windows VMP 能力增量。

`scripts/vmp_diff_harness.py:22` 明示使用 simulate 代替真实第三方加固平台。它依赖方法体等长、稳定 opcode 替换和字节码仍可读取；不能套成 Windows VMP 变长/rolling-key 字节码恢复。`scripts/ete_capture.py:31` 未实测 ETE 捕获；`scripts/kernel_instrument_scaffold.py:34` 是生成/核验模板，未编译加载内核文件，不能据其名称宣称内核采集已接入。

## 对五代主线的五项调整

1. **P0：函数合同与能力闭包合并调度。** 每个实验列出依赖工具、版本/配置、输入证据、观察覆盖、权限和预算。区分“文件存在”“依赖齐全”“启动验证”“目标实测”；缺件给具体下一证据，不能凭工具名说有能力。
2. **P0/P1：对照与反证成为产物。** 保存同流程零改动基线、positive control、单一变化、被否定假设和废弃路线。同指纹失败两次后选择能区分原因的新实验；空输出先检查 probe 是否覆盖问题，不能直接声称目标中不存在。
3. **P1/P2：分层 dispatcher 与嵌套 VM 模型。** 初始化、CFF、真实 VM 分开提候选；用取指、上下文写回和角色变化核验。嵌套实例使用栈式生命周期，run/thread/地址空间/epoch/phase 持续绑定，块频率只提供线索。
4. **P3/P4：以全部副作用切片连接 ISA 和业务。** 所有 STORE 的地址和值、控制、输入/输出、未知效果都作为根；按字节追来源。保留 flags、别名、宿主调用和返回，借已有 project/compose 建独立义务，再用干净模型与独立参考核验完整函数。
5. **P5：实际做 with/without-Skill 验收。** 两组使用相同冻结样本、预算和无预答案合同，隔离作者推理与参考公式；记录实际工具、人工提示、义务变化、完整函数结果和成本。Skill 文案、框架、模拟轨迹或模型声明不算效果证据。

方法文档及参考路由按需加载，避免每轮重读大包；但规划和结构检查不授予执行权限。这次来源审查不能为真实 DSH 接入或独立验收器补成通过；后续实现与部署状态以[框架代码入口](VM_RECOVERY_FRAMEWORK.md#代码入口)及对应证据为准。

## 吸收与许可边界

本次只吸收经核对的方法与设计，不复制外部实现或案例数据。apk-reverse-main 根 `LICENSE` 为 MIT；若后续实际复用代码，需另审依赖和保留许可。VMPBypass 给定根目录未见独立 LICENSE，不能从可读目录推定复制/分发授权。五代原许可、第三方许可、供体 pins、13 个公共审批门、执行范围、预算及清理契约均不改变。
