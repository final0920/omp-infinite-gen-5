# 无限五代 36 个关键文件代码审查

审查日期：2026-10-24。结论：**不予整体通过**。已逐文件阅读全部 36 个文件、共 10,185 行，确认 8 项 P2 问题，直接涉及 5 个文件。其余 31 个文件本轮未发现独立阻断项，但不能据此将其依赖的完整执行链标为通过。未确认 P0/P1，不代表不存在其他缺陷。

审查对象为 `C:/Users/IG5User/Desktop/无限五代/dsh-infinite-gen-5` 的当前工作区，包含既有未提交修改；Git HEAD 为 `2baed0fadba511a16bc695114e2f6ce1adaff067`，实际版本以每个文件的 SHA-256 为准。[源码快照](C:/Users/IG5User/Desktop/无限五代/dsh-infinite-gen-5/docs/review/review-20261024/source-snapshot.json)和[结束校验](C:/Users/IG5User/Desktop/无限五代/dsh-infinite-gen-5/docs/review/review-20261024/source-verification.json)确认 36 个文件在审查期间未改变。

## 已确认的问题

以下 R 编号对应复现脚本和 JSON 证据中的编号；按建议修复顺序排列。复现中的进程、引擎 API 和数据库写入均使用模拟对象或临时目录，没有启动样本、真实调试器或 JVM。

### R5 清理未确认却释放调试状态

**P2，不通过。** [adapters/x64dbg/adapter.py:1170](C:/Users/IG5User/Desktop/无限五代/dsh-infinite-gen-5/adapters/x64dbg/adapter.py:1170)

`cleanup()` 忽略终止命令和 `proc.wait(timeout=2)` 的异常，随后无条件清空 `self.proc`；`KillJob.close()` 也不检查 `CloseHandle` 的返回值。`error_result()` 随即给出 `cleanedUp=true`、`state=no-task`。如果 Job 关闭或进程终止未成功，这些标记并无退出证据。上层 `WorkerManager.performDebug()` 根据 `cleanedUp` 清除调试所有权，可能允许在旧执行尚未确认结束时再次启动。

复现令 Job 句柄关闭失败、taskkill 抛错、wait 超时，原进程的 `poll()` 仍为 `None`；结果却为 `cleanedUp=true`，且进程引用被清空。建议让清理返回明确的退出与 Job 关闭证据，失败时保留进程引用和所有权并返回 `cleanupConfirmed=false`。不能仅由本地状态清空推断进程退出。

### R2 商业 Reverse 调试写入忽略 expected

**P2，不通过。** [worker/ig5_worker.py:834](C:/Users/IG5User/Desktop/无限五代/dsh-infinite-gen-5/worker/ig5_worker.py:834)，同样影响 872 行的 `writemem`。

公共 `ig5_dbg` 将 `expected` 描述为写入前原值校验，并把它传给 worker；商业分支的 `setreg` 和 `writemem` 都没有检查此参数。调用者根据旧暂停状态批准的操作会覆盖已经变化的寄存器或内存，而不会像 x64dbg 分支那样拒绝。

复现：寄存器实际为 `0x11`，提交 `expected=0x99,value=0x22`，仍写入 `0x22` 且返回成功；内存写入也在提供不匹配的 expected 时被调用。建议在当前暂停上下文读取并比较原值，拒绝不匹配或无法完整读取的值，并验证写后结果。

### R8 修订提交失败覆盖原有部分提交凭据

**P2，不通过。** [source/worker_manager.js:245](C:/Users/IG5User/Desktop/无限五代/dsh-infinite-gen-5/source/worker_manager.js:245)，成功响应的 259 行也存在替换结果的问题。

worker 返回写入失败或部分提交后，宿主先 `invalidate()` 更新修订。如果此时项目元数据锁冲突或写盘失败，代码构造新的普通 Error，丢弃原响应中的 `committed/saved/partial_commit/recoveryRequired/journalId/revision`。后续 `rpcError()` 无法恢复已丢失的字段，调用方失去判断和恢复原事务的依据。

复现通过真实 `WorkerManager.open/rpc` 与模拟 JSONL 进程发送 `committed=true,saved=false,partial_commit=true,recoveryRequired=true,journalId=fixture-journal`，再令 `bumpRevision()` 抛出 `STORE_BUSY`；最终错误不再含上述字段。建议保留原执行凭据，另附元数据持久化失败信息；回收会话也不能删掉部分提交事实。

### R7 项目锁缺少主机身份而可能回收异主机活锁

**P2，不通过，触发条件是元数据根目录被多主机共享或迁移后携带锁。** [source/project_store.js:105](C:/Users/IG5User/Desktop/无限五代/dsh-infinite-gen-5/source/project_store.js:105)

新锁只记录 PID、进程创建标识和 nonce，`_lockOwner()` 不核对主机/平台，`_recoverLock()` 使用当前主机的 PID 状态判断原所有者是否死亡。另一主机的同 PID 有不同创建时间，或者该 PID 在本机不存在，都可能被解释为可回收，违反异主机所有者应保留的约定。

复现仅在临时目录构造带不同 `hostName`、本机当前 PID 和不同创建标识的锁，`_recoverLock()` 返回 true 并移走该锁。建议写入并验证主机与平台身份；缺失身份的旧锁、异主机锁都应保持未确认，不能用本机进程探测放行。

### R1 可重复注释 Undo 恢复了错误的注释通道

**P2，不通过，仅影响商业 Reverse 分支。** [worker/ig5_worker.py:901](C:/Users/IG5User/Desktop/无限五代/dsh-infinite-gen-5/worker/ig5_worker.py:901)及 [584 行](C:/Users/IG5User/Desktop/无限五代/dsh-infinite-gen-5/worker/ig5_worker.py:584)。

`m_comment(repeatable=true)` 写入可重复注释，却总用 `get_cmt(ea, False)` 记录旧的普通注释，日志没有保存 repeatable。Undo 又固定调用 `set_cmt(..., False)`，因此既没有恢复被修改的可重复注释，也没有保留对应的正确逆操作。

复现中可重复注释从 `repeatable-old` 改为 `repeatable-new` 后 Undo 返回 `ok=true`，但仍为 `repeatable-new`。建议日志保存注释通道和该通道原值，按原通道撤销并核对恢复结果。

### R3 显式分析吞掉 API 失败并返回成功

**P2，不通过，仅影响商业 Reverse 分支。** [worker/ig5_worker.py:1033](C:/Users/IG5User/Desktop/无限五代/dsh-infinite-gen-5/worker/ig5_worker.py:1033)

`mark_code/reanalyze` 对 `auto_mark_range` 和 `auto_wait` 的异常分别 `pass`，最后无条件返回 `ok=true`。这会把没有完成的分析操作当成成功，后续工作可能使用未更新的函数/代码信息。

复现让两个 API 均抛出异常，仍获得 `ok=true,action=reanalyze`。建议传播失败，或者在确实发生部分分析时返回明确的部分状态；同时处理 API 返回失败值的情况，不将没有抛异常等同完成。

### R4 商业导出查询仍将分析入口当作导出表

**P2，不通过，仅影响商业 Reverse 分支。** [worker/ig5_worker.py:538](C:/Users/IG5User/Desktop/无限五代/dsh-infinite-gen-5/worker/ig5_worker.py:538)

公共 `ig5_listing` 已区分 `exports` 和 `entries`，但商业 worker 的 `exports` 仍直接枚举 `ida_entry`，并没有 `entries` 分支。普通程序入口/TLS 等分析入口会被标为导出；显式请求 entries 则失败。

复现中只有一个普通分析入口，exports 仍返回该项，而 entries 抛出 `unknown kind`。建议将当前枚举归入 entries，exports 从实际导出来源读取；没有可靠导出来源时返回 unsupported/partial，并保留来源说明。

### R6 多实例保存会把不完整历史缓存标为完整

**P2，不通过，触发条件是同一历史目录有多个存储实例或写入者。** [source/history_index.js:26](C:/Users/IG5User/Desktop/无限五代/dsh-infinite-gen-5/source/history_index.js:26)

`saved()` 直接向本实例旧缓存插入自己的新记录，再将缓存 stamp 更新为目录的最新时间，没有确认旧缓存是否已漏掉其他实例的提交。之后 `refresh()` 因 stamp 一致命中缓存，遗漏的报告不再被扫描，却返回 `partial=false`。

复现为两个 `AnalysisArtifacts` 同时打开空目录，A 保存第一份报告，B 保存第二份报告，B.list 返回 `total=1,partial=false`；第一份报告仍可通过 ID 正常读取。建议保存时使索引失效，或采用能够验证旧目录代次的合并机制；无法证明完整时重新扫描。

## 验证结果与边界

| 检查 | 本轮结果 | 证据层级 |
| --- | --- | --- |
| 36 个指定文件阅读与语法 | 36/36；30 JS 使用 node --check，6 Python 使用 AST parse | 源码 |
| 审查前后文件 SHA-256 | 36/36 相同 | 源码版本绑定 |
| 默认门禁 | 109/109 通过，退出码 0 | 既有 Node 门禁，不等同原生验收 |
| Ghidra 脚本 API 测试 | 35/35 通过 | 模拟 Ghidra API |
| 商业调试 API 测试 | 15/15 通过 | 模拟商业 API |
| 本轮定向复现 | 8 项均复现 | 模拟进程/API、真实临时文件存储 |

运行环境为 Windows，Node v24.19.0、随包 Python 3.12.10。没有启动真实 DSH 宿主，没有为本轮出具 DSH 部署版本或弹窗验收结论。Ghidra/JVM、商业 DLL、x64dbg、VM 客体、Unicorn 和 Windows Job 原生运行效果未在本轮重新验收；跨平台运行和打包安装也不在这份代码审查的通过范围内。

现有测试通过与本轮问题复现并不矛盾：新增探针覆盖了原测试未断言的失败和多实例路径。复现脚本的退出码 0 表示“缺陷现象与断言一致”，不能计入产品通过数。

证据文件：

- [门禁日志](C:/Users/IG5User/Desktop/无限五代/dsh-infinite-gen-5/docs/review/review-20261024/gate.log)
- [35 项 Ghidra 模拟测试日志](C:/Users/IG5User/Desktop/无限五代/dsh-infinite-gen-5/docs/review/review-20261024/test_ghidra_script_api.log)
- [15 项商业调试模拟测试日志](C:/Users/IG5User/Desktop/无限五代/dsh-infinite-gen-5/docs/review/review-20261024/test_debug_api.log)
- [Python 复现脚本](C:/Users/IG5User/Desktop/无限五代/dsh-infinite-gen-5/docs/review/review-20261024/reproduce_python.py)与[结果](C:/Users/IG5User/Desktop/无限五代/dsh-infinite-gen-5/docs/review/review-20261024/python-evidence.json)
- [Node 复现脚本](C:/Users/IG5User/Desktop/无限五代/dsh-infinite-gen-5/docs/review/review-20261024/reproduce_node.mjs)与[结果](C:/Users/IG5User/Desktop/无限五代/dsh-infinite-gen-5/docs/review/review-20261024/node-evidence.json)

从源码根目录运行：

```powershell
node docs/review/review-20261024/reproduce_node.mjs
.\runtimes\ghidra\python\python.exe -I -B -X utf8 docs/review/review-20261024/reproduce_python.py
.\runtimes\ghidra\python\python.exe -I -B -X utf8 docs/review/review-20261024/verify_sources.py
```

本轮只新增审查报告与验证材料，没有修复产品源码、部署安装副本或修改人工签字台账。修复上述问题后，需要补充断言修复行为的回归测试，并按相应后端完成原生验证，才能重新判断整体是否通过。

## 逐文件结论

“未发现独立阻断项”表示已阅读该文件且本轮没有确认其中的独立缺陷，不是无缺陷证明，也不是人工签字或依赖链验收。

| 顺序 | 文件 | 行数 | 核对重点 | 本轮结论 |
| --- | --- | --- | --- | --- |
| 1 | [source/approval_gate.js](C:/Users/IG5User/Desktop/无限五代/dsh-infinite-gen-5/source/approval_gate.js) | 105 | 13 个工具、失败关闭、完整展示预算、取消与执行后审计 | 未发现独立阻断项 |
| 2 | [index.js](C:/Users/IG5User/Desktop/无限五代/dsh-infinite-gen-5/index.js) | 1317 | 工具参数、作用域、队列内修订检查、结果与错误包装 | 未发现独立阻断项 |
| 3 | [source/attachment_lease.js](C:/Users/IG5User/Desktop/无限五代/dsh-infinite-gen-5/source/attachment_lease.js) | 64 | PID 与创建身份、nonce、异主机与未知所有者保留 | 未发现独立阻断项 |
| 4 | [source/capture_ca.js](C:/Users/IG5User/Desktop/无限五代/dsh-infinite-gen-5/source/capture_ca.js) | 76 | 密钥与证书匹配、文件形态、签发范围与缓存 | 未发现独立阻断项 |
| 5 | [source/patch_export.js](C:/Users/IG5User/Desktop/无限五代/dsh-infinite-gen-5/source/patch_export.js) | 128 | 样本和数据库绑定、当前字节、完整文件映射、阶段提交 | 未发现独立阻断项 |
| 6 | [source/audit_history.js](C:/Users/IG5User/Desktop/无限五代/dsh-infinite-gen-5/source/audit_history.js) | 129 | 稳定文件、游标范围、扫描预算、损坏行和尾行 | 未发现独立阻断项 |
| 7 | [source/worker_transport.js](C:/Users/IG5User/Desktop/无限五代/dsh-infinite-gen-5/source/worker_transport.js) | 295 | 启动环境、JSONL 字节预算、超时与取消 | 未发现独立阻断项 |
| 8 | [adapters/ghidra/script_api.py](C:/Users/IG5User/Desktop/无限五代/dsh-infinite-gen-5/adapters/ghidra/script_api.py) | 483 | 外层事务契约、API 与输出预算、失败传播；非安全沙箱 | 未发现独立阻断项 |
| 9 | [worker/ig5_worker.py](C:/Users/IG5User/Desktop/无限五代/dsh-infinite-gen-5/worker/ig5_worker.py) | 1497 | 商业 API、修改与保存、Undo、调试、分析结果真实性 | 不通过：R1、R2、R3、R4 |
| 10 | [source/capture_proxy.js](C:/Users/IG5User/Desktop/无限五代/dsh-infinite-gen-5/source/capture_proxy.js) | 530 | 显式 origin、TLS 校验、连接预算、WS 分片和中断 | 未发现独立阻断项 |
| 11 | [source/worker_manager.js](C:/Users/IG5User/Desktop/无限五代/dsh-infinite-gen-5/source/worker_manager.js) | 773 | 会话排队、修订、部分提交、调试所有权和客体凭据 | 不通过：R8 |
| 12 | [source/project_store.js](C:/Users/IG5User/Desktop/无限五代/dsh-infinite-gen-5/source/project_store.js) | 427 | 原子元数据、文件锁、别名、租约恢复和修订 | 不通过：R7 |
| 13 | [source/remote_execution_store.js](C:/Users/IG5User/Desktop/无限五代/dsh-infinite-gen-5/source/remote_execution_store.js) | 245 | 不可变绑定、执行代次、清理回执与保留状态 | 未发现独立阻断项 |
| 14 | [adapters/x64dbg/adapter.py](C:/Users/IG5User/Desktop/无限五代/dsh-infinite-gen-5/adapters/x64dbg/adapter.py) | 1292 | 命令白名单、事件代次、控制队列、执行与清理 | 不通过：R5 |
| 15 | [adapters/vmci/adapter.py](C:/Users/IG5User/Desktop/无限五代/dsh-infinite-gen-5/adapters/vmci/adapter.py) | 179 | 目标目录、认证来源、取消映射和清理回执 | 未发现独立阻断项 |
| 16 | [worker/cpu_emulator.py](C:/Users/IG5User/Desktop/无限五代/dsh-infinite-gen-5/worker/cpu_emulator.py) | 183 | 内存页权限、ABI、指令与时间预算、终止原因 | 未发现独立阻断项 |
| 17 | [worker/lift_process.py](C:/Users/IG5User/Desktop/无限五代/dsh-infinite-gen-5/worker/lift_process.py) | 217 | 创建时 Job 绑定、句柄继承、资源和退出确认 | 未发现独立阻断项 |
| 18 | [capture_tools.js](C:/Users/IG5User/Desktop/无限五代/dsh-infinite-gen-5/capture_tools.js) | 48 | 只读与控制入口分离、参数和重放语义 | 未发现独立阻断项 |
| 19 | [engine_runtime.js](C:/Users/IG5User/Desktop/无限五代/dsh-infinite-gen-5/engine_runtime.js) | 284 | 运行时路径、平台与结构校验、进程树终止 | 未发现独立阻断项 |
| 20 | [integration_tools.js](C:/Users/IG5User/Desktop/无限五代/dsh-infinite-gen-5/integration_tools.js) | 233 | 同步摘要、修订与原值复核、双会话队列、部分失败 | 未发现独立阻断项 |
| 21 | [source/address_ref.js](C:/Users/IG5User/Desktop/无限五代/dsh-infinite-gen-5/source/address_ref.js) | 151 | 64 位整数、地址空间、映射歧义与运行时代次 | 未发现独立阻断项 |
| 22 | [source/analysis_artifacts.js](C:/Users/IG5User/Desktop/无限五代/dsh-infinite-gen-5/source/analysis_artifacts.js) | 168 | 稳定读取、内容散列、两阶段报告与元数据；索引受 R6 影响 | 未发现独立阻断项 |
| 23 | [source/debug_trace.js](C:/Users/IG5User/Desktop/无限五代/dsh-infinite-gen-5/source/debug_trace.js) | 89 | 轨迹与映像散列、暂停身份、来源与恢复参数 | 未发现独立阻断项 |
| 24 | [source/diag_log.js](C:/Users/IG5User/Desktop/无限五代/dsh-infinite-gen-5/source/diag_log.js) | 13 | 诊断失败不破坏主流程 | 未发现独立阻断项 |
| 25 | [source/engine_error.js](C:/Users/IG5User/Desktop/无限五代/dsh-infinite-gen-5/source/engine_error.js) | 20 | 错误文本归一化与运行时路径处理 | 未发现独立阻断项 |
| 26 | [source/function_batches.js](C:/Users/IG5User/Desktop/无限五代/dsh-infinite-gen-5/source/function_batches.js) | 91 | 持久任务、身份和修订、预算收费、取消和恢复 | 未发现独立阻断项 |
| 27 | [source/function_dossier.js](C:/Users/IG5User/Desktop/无限五代/dsh-infinite-gen-5/source/function_dossier.js) | 318 | 单修订聚合、来源核对、缓存与完整性标记 | 未发现独立阻断项 |
| 28 | [source/guest_debug_profile.js](C:/Users/IG5User/Desktop/无限五代/dsh-infinite-gen-5/source/guest_debug_profile.js) | 59 | 配置名称、稳定文件、目录和密钥摘要绑定 | 未发现独立阻断项 |
| 29 | [source/guest_recovery.js](C:/Users/IG5User/Desktop/无限五代/dsh-infinite-gen-5/source/guest_recovery.js) | 58 | 精确恢复参数、旧会话清理证明、桥退出确认 | 未发现独立阻断项 |
| 30 | [source/history_index.js](C:/Users/IG5User/Desktop/无限五代/dsh-infinite-gen-5/source/history_index.js) | 96 | 目录代次、增量保存、扫描上限与完整性 | 不通过：R6 |
| 31 | [source/host_platform.js](C:/Users/IG5User/Desktop/无限五代/dsh-infinite-gen-5/source/host_platform.js) | 43 | 宿主而非浏览器身份、平台与 libc 约束 | 未发现独立阻断项 |
| 32 | [source/implementation_info.js](C:/Users/IG5User/Desktop/无限五代/dsh-infinite-gen-5/source/implementation_info.js) | 3 | 实现版本和模块加载时间 | 未发现独立阻断项 |
| 33 | [source/json_output.js](C:/Users/IG5User/Desktop/无限五代/dsh-infinite-gen-5/source/json_output.js) | 50 | 严格 JSON、异常数值、循环与访问器拒绝 | 未发现独立阻断项 |
| 34 | [source/native_store_events.js](C:/Users/IG5User/Desktop/无限五代/dsh-infinite-gen-5/source/native_store_events.js) | 48 | 原始轨迹绑定、组数、暂停与写观察完整性 | 未发现独立阻断项 |
| 35 | [source/result_artifacts.js](C:/Users/IG5User/Desktop/无限五代/dsh-infinite-gen-5/source/result_artifacts.js) | 183 | 配额、过期、身份与提交验证、认证分页 | 未发现独立阻断项 |
| 36 | [workflow.js](C:/Users/IG5User/Desktop/无限五代/dsh-infinite-gen-5/workflow.js) | 290 | Core8 与 Full 作用域、只读命令入口、生命周期清理 | 未发现独立阻断项 |
