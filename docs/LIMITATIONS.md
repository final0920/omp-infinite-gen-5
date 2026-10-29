# 已知限制与不得做的声明(2026-10-25)

给交付方、评审与使用者。每条都有对应的实测或设计边界,详细依据见 `CAPABILITIES.md` 与 `archive/history/AGENTS_FULL_20261024.md`。

## 不能宣称的
1. **不能宣称通用去混淆/去虚拟化/去壳。** 已验证的是自产样本与有界局部恒等式;`wholeBinaryVerified` 始终为 false。
2. **不能宣称现代 VMP 已恢复。** VMP 3.11 新采集因 OOM 与 Demo 许可限制未成功,仅有历史录制数据。
3. **不能宣称辅助模型(assist)带来收益。** 同预算配对评测未做,默认关闭。
4. **不能把"夹具/覆盖层/局部证明通过"说成"真实目标成功"。** CFF、BV 候选目前都停留在夹具层。
5. **不能把启发式评分当作语义等价或漏洞确认证据。**
6. **不能把一个样本、一个架构、一个后端的结果外推**到其他样本、ARM/手机、Bochs 或现代保护器。
7. **`scripts/` 中 15 个名字带 `handler<编号>` / `context<编号>` 的脚本是针对某个录制样本的证明**，换样本或重新编译就不再成立，不是通用能力，清单见 `tools/ci/sample-specific.json`（CI 强制登记，且不进入默认门禁）。它们目前仍随 `scripts/` 一起打包。
8. **`docs/PROTECTION_CAPABILITY_MATRIX.md` 是历史记录**，其中 VMP 3.11 的 `verified` 行没有在 2026-10-24 重新验证，以本目录的 `CAPABILITIES.md` 为准。

## 环境与运行限制
- Windows 策略 4551:2026-10-16/19 阻断过 x64dbg 的 `headless.exe` 与 Ghidra 的 SLEIGH 组件,来源是智能应用控制(代码完整性策略 `VerifiedAndReputableDesktop`)。该控制已于 2026-10-19 关闭,阻断记录归档。**x64dbg 已在 2026-10-24 通过显式实机验收(64/32 位,源码与安装两条 runtime 路径);SLEIGH 尚未重测。** 本项目仍然**不为绕过策略而改名、复制或换目录**;若再次出现 4551,按原规则记录并停止。
- 完整 Windows 发行包依赖随包 runtimes(Ghidra、x64dbg);GitHub 自动 Source ZIP / `git clone` 不含这些,**不是可安装发行物**。
- 原生后端依赖 Windows;macOS/Linux/手机宿主未验证。
- 若目标被审批门拦截,调用会被拒绝,不是故障。

## 测试状态（2026-10-25 实测）
- `npm run ci`：JS 语法 487 个、模块分层/审查台账、单样本脚本登记，加默认门禁 **119/119 通过**；含 extended 的 `npm run test:all`（即 `node tools/ci/run-gate.mjs --tier all`）为 **135/135 通过，失败 0、超时 0、缺失 0**（2026-10-25，P1/P3/P4/P5/P6/P7 完成后实测；其中 DEX/AXML 与独立实现的对照测试依赖随包 JDK，缺失时会明确跳过而不是静默通过）。
- `scripts/` 下约 122 个纯 Node 测试实测：115 个通过，7 个未通过，均**未纳入门禁**：
  - `test_emulation_permissions`、`test_host_reliability`、`test_host`、`test_worker`：本机检测到商业版 IDA 安装但其 DLL 无法加载（`ImportError: DLL load failed while importing _ida_auto`），属环境问题。
  - `test_debug_host_queue`：**测试自身已过期**——它用正则从 `index.js` 切出 `WorkerManager` 类源码，而该类已拆到 `source/worker_manager.js`。需要重写注入方式，目前该测试覆盖的行为没有有效的自动回归。
  - `test_progress`：需要命令行参数，不是自动测试。`test_new_tools`：90 秒超时，原因未查。
- 另有约 58 个原生/运行态测试（Ghidra、x64dbg、VM guest、macOS、安装包）未在本轮运行。
- Python：243 个文件仅做语法检查（`IG5_PYTHON` 指向随包 Python 时通过），没有进入门禁的单元测试；P1/P4/P5/P7 的 Python 单测由各自的 `scripts/test_*.mjs` 显式驱动（extended 门禁内）。

## APK 前端(`ig5_package`)限制
- 只做静态分析,不执行样本,不联网。**不验证 APK 签名**:v1/v2/v3 只用于识别证书(指纹、主体、有效期),`signatures.verified` 恒为 false;"是否被改过"要靠 apksigner 等工具。
- 验证:自造 APK + 14 个真实 APK(保护语料里的公开挑战题,不含恶意样本和商业加固壳)与独立实现(AXMLPrinter2、dexlib2、Node X509Certificate)对照。**恶意 APK、商业加固壳、畸形包的表现未知。**
- 被 R8 混淆的第三方库没有包名可识别,其 API 调用会计入应用代码,"应用代码"一栏因此偏多。
- 不解码 `resources.arsc`(标签、字符串资源取不到);不处理 AAB/XAPK 容器(内含的 APK 需先取出);不读 Compact DEX。
- 能力规则只表示"代码里出现过这个 API",不是意图判断;知名库前缀表是启发式,被混淆的库会被算作应用代码。
- 规则表里的 Android 类名按 SDK 文档手写,无 SDK 副本可机器核对;写错的规则对真实包不会触发,且没有告警。
- 单次分析有 45 秒截止和各类条目预算,命中会写入 `limitsHit`,报告的其余部分仍可用。

## 固件前端(`ig5_package` firmware/unpack)限制
- 只做静态解析与解包,不执行任何内容;`unpack` 写出的是清洗过名字的普通文件,解包后的 ELF/脚本仍须按样本对待(只在隔离环境里动它们)。
- 验证只用自造镜像(+ 7-Zip 对 SquashFS/ext 的名字与大小对照),**没有在真实设备固件上跑过**;厂商私有封装、加密固件、分段更新包识别不了。
- 不支持 LZO / zstd / LZ4 压缩的 SquashFS 与 zstd/LZ4 流(只识别);JFFS2、UBIFS、CramFS、ROMFS 只识别不展开;无签名/安全启动校验。
- 文件内容整体读入内存(单文件上限 256 MiB),总解包 1 GiB、5 万文件、深度 4、单次 5 分钟;命中会写入 `limitsHit`。
- 偶然通过头部校验的短签名仍可能产生假组件(gzip/zlib/LZMA 类已要求实际解压成功);报告里每个组件都带偏移,务必回头核对。

## 加壳识别(`ig5_scan` 的 `packing`)限制
- 只做静态判断,**不脱壳、不执行样本**;`unpack.status` 永远不会是"已还原"。
- 节名/字符串标记可以被作者改掉,只算 `name-only`/`marker` 线索;改过节名的 UPX 靠结构识别(空的可执行首节 + 高熵入口节)。
- 阈值(熵 7.0/7.5、导入函数数 12/30、状态 30/60)是在保护语料和 Windows 系统文件上校准的,新壳型的误报漏报率未知。微软自己加密的授权/DRM 组件(如 WMVDECOD.DLL、ClipUp.exe)会被判为 suspected,这是有意保留的。
- 不处理 .NET 保护器、Mach-O、安卓 DEX 壳(DEX 壳走 `ig5_package` 的 `code.stub-like`/`payload.*` 线索)。

## 签名规则匹配(`ig5_scan` 的 `ruleMatches`)限制
- 命中只表示"这些字节出现在已扫描的范围内",是**证据等级 E0 的线索**,不证明加壳、行为、意图或身份;内置规则表不是恶意判定,签名可以被伪造。
- 只匹配扫描器实际读到的字节(默认每段 1 MiB、全局 8 MiB 采样);未读区间没有结论。`coverage.bytesScanned` 与 `truncated` 必须一起读。
- 只支持受限子集:文本(ascii/wide/nocase)、十六进制(`??`/`?A`/`4?`)、布尔条件与 `of them`。**没有**正则、跳转、选择、`fullword`、`xor`、计数、`at`/`in`、`for`、模块、节级作用域;拼错或越界的构造在编译期报错,不会被忽略。
- 自定义 `rules` **整体替换**内置表,不会合并;调用方需自行保证规则精度。单次上限:64 条规则、256 个字符串、单模式 256 字节、源 65,536 字节;每个模式最多统计 1024 次出现,证据最多记录 `max_rule_matches`(默认 256)。
- 精度只在保护语料、300 个 System32 抽样和 .NET Framework 程序集上校准过;**真实恶意样本、加壳后再加密的数据、其他 Windows 版本上的误报/漏报率未知**。`dotnet_managed` 依赖 CLR 元数据被扫描到:元数据在采样预算之外时会漏报(报告不会说成"不是 .NET")。
- `wide` 只支持 ASCII 文本;非 ASCII 宽字符串会在编译期被拒绝。

## 动态 API 轨迹(`ig5_dbg` 的 `op=apitrace`)限制
- 只记录**静态导入表里、暂停时 IAT 已解析**的 API 入口。字符串 + `GetProcAddress` 的动态解析、延迟导入、直接 `call` 进 DLL 代码、系统调用、未插桩模块里的调用都不会出现;报告里没有某个 API,不等于进程没调用它。
- 调用列表是 **E1**(这一轮确实命中了断点);行为类别与行为链是 **E0** 线索,不证明意图、调用成功或覆盖完整。参数是入口那一刻的原始寄存器/栈值:宽度、类型、指针目标、返回值、`GetLastError` 都没有观察。x86 只取返回地址与栈上 4 个 DWORD(`arguments.complete` 标明是否读满)。
- 设置的是**软件断点**:会改写被调试进程里 API 代码页的首字节,可能被反调试发现;不修改磁盘样本。命中预算耗尽后进程停在最后一个 API 入口,需要显式 `cont`/`stop`,不要当成"已恢复运行"。
- 运行态只在宿主 x64dbg(headless)上验收;**guest(VMCI) 路径、x86 运行态、ARM64 PE、.NET 托管入口未验收**。反调试样本可能直接看到 INT3 或改变行为,轨迹随之失真。
- IAT 槽为 0 或越界时记进 `coverage.unresolved`,不猜地址、不设断点;这类 API 的"未出现"没有意义。
- 断点清理失败会如实给 `cleared=false` 与 `failures`。进程在本轮退出时 `attempted=false`(没有断点可清),这不代表清理被验证过。

## 流量↔样本对应(`ig5_capture` 的 `action=correlate`)限制
- 只做**字面量**搜索:ASCII/UTF-16LE 原样与 ASCII 大小写不敏感,不支持正则、通配、其他编码、压缩或加密内容。加壳/压缩/加密的字节看不到原始字符串。
- **正文哈希相同 = E1**:只证明捕获的正文字节与样本文件完全相同,不证明客户端执行、加载或写盘了它,也不证明服务端如何生成。加密隧道与 WebSocket 单帧另有口径(隧道不做应用层正文同一性;WS 只对照单帧,不重组消息)。
- **字面量出现 = E0**:可能是程序字符串、导入名或无关数据;`unmatched` 只表示"没找到",样本可能动态拼接、编码存放或根本不用。**缺失不是证明**。
- 每次调用只对照**一条**交换记录;不自动把一批流量归给同一个样本,也不自动建立时间/进程归属。
- 偏移是**文件偏移**,不是 RVA/VA;工具不打开静态数据库、不映射函数,需要用户自行换算并 `ig5_open`/`ig5_search`。
- 样本上限 32 MiB,超限直接失败(不做部分扫描);只读取 `user-agent`/`referer`/`origin`/`accept`/`content-type` 五个头值,不读 cookie/authorization,不读查询串。
- 网络 API 清单来自 `worker/behavior_rules.py` 的 network 分类;短名(`socket`/`connect`/`send`/`recv`)带 `ambiguous` 标记,字面量命中不等于调用。
- 未在真实业务流量、真实恶意样本或真实客户端上评测误报/漏报;不覆盖 HTTP/2、QUIC、未解密隧道内层。

## 数据与审计限制
- 审计只记录**执行后**流水,审批拒绝/取消不入该流水,不能当作全部审批历史。
- Ghidra 部分类型/结构体/分析为 session-only 原生 Undo,强杀/硬超时可能丢失未保存修改。
- 同步(sync)部分失败时 `atomic=false`,需检查证据并重新 preview,不得盲目重试。

## 使用提示
- 找来源文档用 `ig5_profile knowledge={action:"documents"}`;`search` 搜的是方法卡。`search` 无方法卡命中但文档命中时,返回会带 `hint: TRY_DOCUMENTS`。

## 许可
- 项目自有代码为 CC BY-NC-SA 4.0(**非商业**);第三方组件按各自许可,不受 NC 条款覆盖,详见 `THIRD_PARTY_NOTICES.txt`。
- 许可证本次不变更(公司决定)。该许可证本身不授予商业使用权;商业交付需权利人另行书面授权,见 `docs/DELIVERY_NOTE.md` 第 5 节。
