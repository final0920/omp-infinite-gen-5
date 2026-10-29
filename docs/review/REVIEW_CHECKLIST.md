# 安全关键代码：审查清单与风险要点

编制日期：2026-10-24。对应台账：`docs/review/ledger.json`（36 个文件，约 10165 行，签字状态：全部未审查）。

> **本文件是给人工审查者的阅读指引，不是审查结论。** 它由 AI 代理编写，任何一条"已确认"都只表示"代理读过那段代码并能指出行号"，不代替真人审查。
> 审查者读完某个文件后，用 `node tools/ci/module-audit.mjs --sign <文件> --by <姓名>` 签字；文件之后一旦修改，签字自动失效。

## 0. 阅读覆盖情况（先看这个）

| 状态 | 文件 |
| :--- | :--- |
| **已完整读过**（下文风险点据此得出） | `source/approval_gate.js`、`attachment_lease.js`、`audit_history.js`、`patch_export.js`、`capture_ca.js`、`capture_proxy.js` |
| **只读了片段** | `source/worker_transport.js`（前 40 行）、`worker/ig5_worker.py`（`m_idapython`，约 20 行）、`adapters/ghidra/script_api.py`（`exec` 附近）、`index.js`（`ig5_run_idapython` 定义） |
| **未读**（下文只给出"按职责应检查什么"，不含任何发现） | 其余 26 个文件，包括 `worker_manager.js`、`project_store.js`、`remote_execution_store.js`、`engine_runtime.js`、`x64dbg/adapter.py`、`vmci/adapter.py`、`cpu_emulator.py`、`lift_process.py` 等 |

## 1. 建议阅读顺序

按"一旦出错后果最严重 × 篇幅小"排序。前 8 项合计约 1100 行，一个人半天可读完。

| # | 文件 | 行数 | 为什么先看 |
| :-: | :--- | -: | :--- |
| 1 | `source/approval_gate.js` | 70 | 所有"修改或执行"类操作唯一的人工闸门 |
| 2 | `index.js`（审批接线、`ig5_run_idapython` 等工具定义） | 1317 | 工具是否都挂上闸门、弹窗展示什么 |
| 3 | `source/attachment_lease.js` | 64 | 数据库租约，判错会导致两个进程同时写同一库 |
| 4 | `source/capture_ca.js` | 76 | 手写 X.509 与本地 CA 私钥 |
| 5 | `source/patch_export.js` | 128 | 向外交付"补丁后二进制"，是对外产物 |
| 6 | `source/audit_history.js` | 129 | 审计读取与分页，补丁导出依赖它 |
| 7 | `source/worker_transport.js` | 274 | 启动 Python worker 的唯一入口之一，决定子进程环境 |
| 8 | `adapters/ghidra/script_api.py`、`worker/ig5_worker.py` 中 `exec` 所在函数 | 483 / 1497 | 真正执行用户脚本的位置 |
| 9 | `source/capture_proxy.js` | 530 | 网络监听、TLS 解密、转发 |
| 10 | `source/worker_manager.js`、`project_store.js`、`remote_execution_store.js` | 773 / 427 / 245 | 调度、存储、写入路径 |
| 11 | `adapters/x64dbg/adapter.py`、`adapters/vmci/adapter.py`、`worker/cpu_emulator.py`、`worker/lift_process.py` | 1292 / 179 / 183 / 217 | 调试器、客体虚拟机、仿真、子进程 |
| 12 | 其余 | — | 小型契约与工具模块 |

## 2. 已发现的风险要点

标注含义：**[已确认]** 代理读到了对应代码；**[待验证]** 取决于代码之外的条件，需要人去核实。

### R1　审批弹窗可能没有展示将要执行的脚本　**高 · [源码已修复；独立核验未通过：主力宿主未部署、且未出现人工弹窗]**
- **独立核验结论（2026-10-24，记录在 `_research/approval-r1-r4-verification-20261024-v1/核验结论.txt`）：不予验收通过。**
  1. 第一版修复把长脚本截断（单字段 4000、总计 8000 字符），审批人看不到被截去的代码；SHA-256 只能标识载荷，不能让人审阅。我当时的测试还把"末尾不可见"当成期望。**这是缺陷，已纠正（见下）。**
  2. 主力安装副本 `~/.dsh/plugins/dsh-infinite-gen-5` 里**没有** `source/approval_gate.js`，仍是只展示工具名与 target 的旧门，审批请求不含脚本。**修复尚未部署到主力 DSH。**
  3. 真实 DSH（0.2.1-alpha.1）会话中，3 次审批请求的决定均为 `allowed-once`、间隔 0ms，界面**没有出现人工审批弹窗**；会话初始 `policy=never`。因此"在真实宿主里点一次弹窗、看到全文"**没有完成**，自动批准后执行成功不算通过。
- **已纠正（源码）**：`approval_gate.js` 的 `describeOperation` 现在**不截断任何字段**；展示内容超过 `APPROVAL_DISPLAY_LIMIT`（131072 字符）时，闸门直接 `deny`，**不向审批人发起请求，也不分发执行**。`ig5_run_idapython` 的 64 KiB 脚本首尾完整出现在 `reason` 与 `displayReason`（中英文）。`ig5_capture_control` 只展示脱敏摘要。回归测试：`scripts/test_approval_gate.mjs`（53 条），含 7613 与 65536 字符脚本全文、超限拒绝。
- **仍需完成**：①按工程流程把源码部署/重载到主力 DSH；②在**逐次询问**的审批策略下实测：首尾完整、可滚动、拒绝后不执行。代码与测试无法替代这两步。
- 以下为修复前的原始发现：
- 证据：`source/approval_gate.js:19` 弹窗摘要为 `plan_id ?? ea ?? name ?? target`。`ig5_run_idapython`（`index.js:942`）的参数只有 `target` 和 `code`，因此摘要只显示目标路径，**不含最长 64 KiB 的 `code`**。
- 后果：审批人看到的是"对某文件执行写操作"，而实际批准的是任意 Python。该脚本在 worker 进程内 `exec`（`worker/ig5_worker.py:650`、`adapters/ghidra/script_api.py:463`），代码自身声明 `securitySandbox: False`。脚本能做 worker 进程权限允许的一切事情。
- 需要核实：宿主（DSH）的通用审批界面是否另行展示工具参数。**若不展示，这是一个同意有效性缺陷。**
- 建议：弹窗里展示代码的 SHA-256 与完整内容（或可展开全文）；对 `ig5_dbg`、`ig5_emulate`、`ig5_patch_bytes` 同样检查弹窗是否展示真实载荷（字节、地址范围、命令）。

### R2　审批闸门是"危险工具名单"，不是默认拒绝　**高 · [对账已补，仍非默认拒绝]**
- **已补**：新增 `scripts/fixtures/tool_classification.mjs`（40 个工具，13 个需审批、27 个有意不设审批，并写明非纯只读者的理由）和 `scripts/test_tool_classification.mjs`（已入门禁）。它保证产品的 `IG5_WRITE_TOOLS` 与评审过的名单双向一致；`test_public_tool_catalog.mjs` 已改为引用同一份夹具，原先的"测试里另抄一份"已消除。新增/改名工具会让测试失败，迫使开发者明确分类。
- **仍存在**：闸门本身仍是名单制。如果有人同时改了夹具和名单，或者新工具没经过这些测试，就不会被拦。长期方案是给每个工具声明 `mutating` 元数据并改为默认拒绝。
- 以下为修复前的原始发现：
- 证据：`approval_gate.js:6-12` 硬编码 13 个工具名，`:16` 对不在名单内的工具直接 `next()` 放行。
- 后果：新增或改名的修改/执行类工具，只要漏加进名单就**无任何审批**。名单与工具目录之间是否有自动对账，**我没有核实**，需要查 `scripts/test_public_tool_catalog.mjs`（未读）。另外 `scripts/test_approval_gate.mjs:19-22` 是用字符串截取方式读取 `approval_gate.js` 源码、再放进 `vm.runInNewContext` 执行来测试，对源码格式改动较脆弱。
- 建议：给每个工具声明 `mutating` 或 `readOnly` 元数据；增加一条测试——"目录里所有非只读工具必须在名单内，否则失败"；以后改成默认拒绝。
- 另需确认这些入口是否有意不受审批：`ig5_export_diff`（向 `artifactDir` 写文件）、`source/kernel_jobs.js` 与 `source/lift_jobs.js`（启动子进程）。

### R3　审计留痕有缺口，且无完整性保护　**中 · [部分缓解 2026-10-24]**
- **已缓解**：审计行写入失败时，现在会在 `ig5-diag.log` 留下一条记录（含工具名与 callId），仍不影响结果返回（测试：`test_approval_gate.mjs` 末尾"a failed audit write…"）。如果 `artifactDir` 本身不可写，诊断同样写不进去，这种情况仍然是静默的。
- **未解决**：拒绝/取消不记录；仍无哈希链或签名；原始参数仍整体落盘。
- 以下为修复前的原始发现：
- 证据：`approval_gate.js:47-67`。只在执行**之后**写 `approvals.jsonl`；写入失败被 `catch {}` 吞掉（`:64`），操作已经执行但可能无任何记录；被拒绝或取消的请求不记录；无哈希链或签名。除 `ig5_capture_control` 外，原始参数整体落盘（脚本源码、补丁字节都会写进去）。
- 后果：不能把它当作取证级审计。进程在"执行后、写日志前"崩溃会丢记录。`AGENTS.md` 已声明审计只是"执行后流水"，对外材料不得夸大。
- 缓解事实：`patch_export.js` 导出补丁时，字节取自当前数据库（`mgr.rpc('bytes')`），审计行只用于选择范围，伪造审计行的影响有限（`:83-92`）。
- 建议：写失败时让操作结果带上"审计未落盘"的告警；对参数做脱敏策略；若要对外称"可追溯"，加哈希链并把头部哈希保存到日志之外。

### R11　宿主审批策略为 never 时，"13 个审批门"没有真人参与　**高 · [公司决定：DSH 保持自动批准——已知并接受，不是缺陷修复项]**
- **2026-10-24 决定**：公司要求 DSH 自动审批。因此 R1 的"弹窗是否显示全文"在本机不再是需要点击验证的项目；审批门在该配置下只是留痕，**不是人工把关**。所有对外文档须按此措辞（见 `DELIVERY_NOTE.md` 第 6 节）。若将来在含涉案数据的环境使用，必须重新评估并改为逐次询问。
- 证据：同上核验记录。真实 DSH 会话 `policy=never`，3 组 `approval/asked` → `approval/decided` 均为 `allowed-once`、0ms，无人工弹窗；其中两次 `ig5_run_idapython` 实际执行并产生会话事务修订。
- 含义：插件向宿主请求审批，但**是否有真人点击由宿主的审批策略决定**。在这种策略下，13 个门对"是否经人批准"没有任何约束力。该现象可能来自宿主配置、宿主版本行为，或旧门的接入方式，**目前不能确定是哪一种**。
- 建议：①先查清 DSH 的审批策略配置与默认值；②把"宿主必须使用逐次询问策略"写成部署前置条件；③评估插件能否通过 `ig5_doctor` 报告宿主当前审批策略并在 `never` 时给出明确警告（需要确认 DSH SDK 是否暴露该信息，**我没有核实**）；④在对外材料中不要写"所有修改均需人工审批"，而要写"插件会发起审批请求，是否有人工确认取决于宿主策略"。

### R4　子进程继承完整环境变量　**中 · [源码已修复；独立核验部分通过，主力宿主未部署]**
- **独立核验（同上记录）**：用最新源码的 `workerLaunch` 加主力安装里的 runtime，在**未设置** `workerEnvPassthrough` 时：Ghidra 的 Python worker 与 JVM 启动成功，`doctor ok=true`（Ghidra 12.1.4；这**不加载**被阻断的 `ig5_sleigh.dll`，也不证明 SLEIGH 通道可用）；x64dbg 适配器启动、doctor 成功，但 `launchVerified=false`、`nativeLaunchAttempted=false`，**原生 x64dbg 冷启动没有做**——同路径 `headless.exe` 有历史 4551 阻断记录，按项目约定不重试、不改名、不换目录，所以不能签成通过。两个 Python 可执行文件下的哨兵检查：非白名单变量不可见，白名单 `IG5_*` 可见。
- **部署（2026-10-24 已完成）**：源码已复制到 `~/.dsh/plugins/dsh-infinite-gen-5`（只复制、不删除，不碰 runtimes/third_party/.downloads）；原安装副本代码已备份到 `Desktop/无限五代/_backup_installed_plugin_20261024`。1058 个代码文件哈希零差异；在安装副本内运行审批测试与白名单测试均通过。**已运行的 DSH 进程仍在使用旧代码，须完全退出并重开。**
- **原生 x64dbg（已解决）**：此前的 4551 来自智能应用控制 `VerifiedAndReputableDesktop`，所有者已于 2026-10-19 关闭，旧记录归档于 `runtime-policy-blocks/archive`。2026-10-24 用 `scripts/test_x64dbg_runtime.mjs`（生成最小 PE、产品自身启动路径）在**源码目录与安装目录两条 runtime 路径**上各跑 64 位和 32 位 headless，均通过，活动目录无新增阻断记录，无残留进程。仅证明自造 PE，不外推到任意样本。
- **修复**：`worker_transport.js` 新增 `workerEnvironment`（白名单：系统启动必需变量、`LC_*`、`IG5_*`；其余丢弃），`workerLaunch` 与 `kernel_jobs.js` 均使用。需要额外变量时设置 `cfg.workerEnvPassthrough: ['NAME']`。`lift_jobs.js` 原本就只传 4 个变量，未改。测试：`scripts/test_worker_env.mjs`（已入门禁）。
- **已验证**：用白名单环境启动项目自带的 Python 3.12 成功，且看不到被丢弃的变量。
- **未验证**：真实 Ghidra/JVM、x64dbg 在白名单环境下是否都能正常启动（本机 SLEIGH 受 4551 阻断，无法在此验证）。**在主力环境上冷启动一次并运行 `ig5_doctor`，若缺变量就加入 `workerEnvPassthrough` 或白名单。**
- 以下为修复前的原始发现：
- 证据：`source/worker_transport.js:15` 以 `{ ...process.env, ... }` 启动 worker。
- 后果：宿主进程里的任何令牌、API Key 都会进入 Python worker，进而对 R1 的脚本可见。
- 建议：改成白名单环境变量。需核实 `kernel_jobs.js`、`lift_jobs.js`、`engine_runtime.js` 三处启动子进程时是否同样处理。

### R5　抓包 CA：私钥落盘与手写证书编码　**中 · [已确认 / 部分待验证]**
- 证据：`source/capture_ca.js`
  - CA 私钥以未加密 PEM 保存（`:57`），`mode: 0o600` 在 Windows 上基本不起作用，实际权限取决于目录 ACL **[待验证]**。
  - CA 有效期 365 天，无 NameConstraints，可签发任意主机名的证书（`:34`、`:61`）。
  - 手写 DER 编码器；所有日期一律用 `GeneralizedTime`（`:20`），而 RFC 5280 对 2049 年之前的日期要求 `UTCTime`。Node 能解析，别的客户端不一定。
  - 叶子证书有效期 7 天，缓存 64 个，私钥在内存中。
- 正面：不改系统信任、不内置私钥、拒绝符号链接与超大文件（`:39-42`）、校验 CA 与密钥匹配及未过期（`:61`）、`wx` 标志防覆盖。
- 建议：确认 Windows 下 CA 目录的 ACL 仅限当前用户；文档明确"不要把该 CA 装入系统信任库"；评估缩短有效期；密码学相关代码找有经验的人单独复核。

### R6　本地代理无认证，且抓取内容含敏感数据　**中 · [已确认 / 部分待验证]**
- 证据：`source/capture_proxy.js`
  - 只监听 `127.0.0.1` 且 `exclusive`（`:191`），但同机任何进程或用户都可使用该代理访问范围内的 origin。
  - 请求头（含 `Authorization`、`Cookie`）与最长 1 MiB 的正文原样交给 `onExchange`（`:254-261`）。解密 TLS 后这些就是明文。落盘位置、脱敏、保留期取决于下游接收方（如 `capture_service.js`，**未读**）。
  - 接收方出错只计数 `sinkErrors`（`:225-227`），捕获内容会静默丢失，需确认该计数是否被展示给用户。
  - 若把内网 origin 写入范围，代理会向其转发请求，范围由使用者负责。
- 对政府/警务场景：需要确定抓包数据的密级、保存期限、销毁方式和访问控制。
- 正面控制（审查时核对测试是否覆盖）：origin 白名单只允许协议+主机+端口（`:16-25`）；Host 头必须与请求 origin 一致（`:243-244`）；TLS 隧道内请求不得越过绑定的 origin（`:240`）；上游 TLS 始终校验（`:304`）；并发、头大小、超时有上限；嵌套 CONNECT 被拒绝（`:480`）。

### R7　脚本"预算"不是沙箱　**高 · [已确认]**
- 证据：`adapters/ghidra/script_api.py:450-466`。脚本通过 `sys.settrace` 做时间等预算，执行在同一进程内，来源标注 `securitySandbox: False`、`directNativeCallsAccounted: False`、`targetExecutionControlledByScript: True`。
- 含义：预算只能限制"跑多久"，不能限制"做什么"。脚本可以直接调用文件、网络、子进程。安全边界完全取决于 R1 的审批和 worker 进程自身的权限。
- 建议：对外材料不要称其"沙箱"；评估让 worker 以低权限用户或受限令牌运行。

### R8　台账范围此前只覆盖 JS，Python 执行器占比很大　**范围说明 · [已确认]**
- `worker/` 与 `adapters/`（不含 vendor）共约 1.7 万行 Python，217 个 Python 文件目前只有语法检查，没有门禁测试。本次已把 6 个直接执行/调试/仿真/子进程的 Python 文件纳入台账，其余 Python 文件仍**未纳入审查范围**。

### R9　租约：失败安全，但有已知精度边界　**低 · [已确认]**
- `attachment_lease.js`：无法确认进程已死亡时一律不放租约（`:51-63`），方向正确。
- macOS 用秒级时间戳哈希代替创建时刻（`:25-33`），同一秒内 PID 复用无法区分，代码注释已承认。
- 每次探测在 Windows 上要启动一次 PowerShell（`:15`），超时 5 秒；注意 `processId` 已先经过安全整数校验再拼进命令，注入风险低，但审查者应再确认所有调用者都不绕过 `pid()`。

### R10　补丁导出：防护细致，审查重点在边界　**低 · [已确认]**
- `patch_export.js`：目标文件的身份、大小、哈希在打开、读取、写出前后多次比对；输出目录逐级检查非符号链接且身份未被替换；有 8 MiB、16384 段、4 MiB 报告的上限；用临时文件加原子改名。
- 审查重点：`EXPORT_PARTIAL`（`:119`）出现时二进制已交付而报告缺失，调用方是否把它当作失败处理；`unbound` 历史会直接拒绝导出（`:69`），这是否符合预期。

## 3. 逐文件检查清单

### 已读文件（可对照上面的发现逐项勾选）
- [ ] `approval_gate.js`：R1、R2、R3；`outcome !== 'allowed-once'` 才放行（`:43`）和缺少 agent 或审批服务即拒绝（`:32-33`）是否真被测试覆盖；`exec.signal.aborted` 的取消路径。
- [ ] `attachment_lease.js`：R9；`probeAttachmentLease` 的 `releasable` 是否只在宿主与 worker 都确认已死亡时才为真（`:63`）。
- [ ] `audit_history.js`：游标是否绑定文件身份与快照边界（`:49-55`）；读取过程中文件被替换是否会失败（`verifyJournal`）；导出遇到半写入的末行是否拒绝（`:126`）。
- [ ] `patch_export.js`：R10；`targetIdentity` 在 Windows 大小写与路径规范化上是否一致使用。
- [ ] `capture_ca.js`：R5。
- [ ] `capture_proxy.js`：R6；WebSocket 帧解析器（`:52-109`）对畸形输入是否都走 `onInvalid`，`readBigUInt64BE` 的长度上限；`maxConnections` 与背压是否足以抵抗本机拒绝服务。

### 未读文件（以下仅为按职责应检查的问题，不代表发现）
- [ ] `worker_manager.js`：调用 worker 前是否核对 `expected_revision`；取消、超时、worker 崩溃后的状态清理；多会话是否可能共享同一个活动数据库。
- [ ] `worker_transport.js`：R4；消息大小上限是否在所有分支生效；子进程终止是否杀掉整棵进程树。
- [ ] `project_store.js`、`history_index.js`、`remote_execution_store.js`：写入是否原子；并发写保护；路径是否被限制在项目目录内；`partial_commit` 状态保留。
- [ ] `engine_runtime.js`：环境变量 `IG5_HOME`、`IG5_RUNTIME_ROOT` 能否把运行时指向攻击者控制的目录；对运行时文件的哈希校验是否在启动前完成。
- [ ] `function_dossier.js`、`function_batches.js`、`result_artifacts.js`、`analysis_artifacts.js`：落盘路径与文件名是否由外部输入拼接；大小与数量上限。
- [ ] `debug_trace.js`、`guest_debug_profile.js`、`guest_recovery.js`、`native_store_events.js`：调试与客体虚拟机的授权检查；样本是否只在审批后才执行。
- [ ] `address_ref.js`、`json_output.js`、`host_platform.js`、`engine_error.js`、`diag_log.js`、`implementation_info.js`：64 位地址是否用字符串或 BigInt 处理；输出 JSON 是否严格合法；诊断日志是否会写入密钥或敏感数据。
- [ ] `index.js`、`capture_tools.js`、`integration_tools.js`、`workflow.js`：每个工具的 `execute` 是否对参数做校验；审批、`expected_revision`、只读队列的接线是否一致；`ig5_sync` 为何被排除在 `expected_revision` 注入之外（`index.js:1226`）。
- [ ] `adapters/x64dbg/adapter.py`、`adapters/vmci/adapter.py`、`worker/cpu_emulator.py`、`worker/lift_process.py`：目标进程如何启动、权限与工作目录、超时和终止、Windows Job 对象的使用、命令行拼接（`lift_process.py` 使用 `list2cmdline`）。
- [ ] `worker/ig5_worker.py`：除 `m_idapython` 外，所有 `m_*` 入口是否能被任意参数触发文件写入或进程创建。

## 4. 通用提问（对每个文件都问一遍）

1. 这段代码的输入来自哪里？是否有外部可控的字符串被拼进路径、命令或正则？
2. 出错时是**放行**还是**拒绝**？`catch {}` 吞掉的是什么？
3. 它声称的保证（如"已审批""已绑定样本""已验证"）有没有对应的**测试断言返回值**，而不只是"没抛异常"？
4. 同一类检查是否在多个文件里各写了一份？它们是否一致？
5. 测试和被测代码是不是同一次生成的？测试是否只是把实现的形状复述了一遍？

## 5. 本清单的局限

- 编写者是生成这些代码的同类 AI，可能带有同源盲点。**请务必由没有参与编写的人审查。**
- 未覆盖：`source/` 中其余 128 个模块、217 个 Python 文件中除 6 个外的全部、`client.js`（2819 行前端）、打包与安装脚本、第三方运行时。
- 未做动态验证：没有实际运行宿主 UI 来确认 R1 的弹窗内容，也没有对代理做渗透测试。
