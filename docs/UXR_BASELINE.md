# UXR-00 真实使用反馈基线

2026-10-23；起始 HEAD `2baed0fadba511a16bc695114e2f6ce1adaff067`。当前未提交实现属于有效输入；完整状态、相关文件大小/SHA、Node/Python 路径见 [workspace.json](uxr/baseline/workspace.json)。未修改安装副本。

## 证据与复现

命令 `node scripts/uxr_baseline.mjs`，退出码 0。脚本使用真实源码注册与合成 provider，临时目录自动清理，不启动引擎、不运行原报告样本。工具 schema 见 [tools.json](uxr/baseline/tools.json)，四项复现数据见 [fixtures.json](uxr/baseline/fixtures.json)。后续重跑请传不同输出目录，保留本目录的改造前快照。

`node --test scripts/test_delegation_control.mjs scripts/test_function_dossier.mjs scripts/test_address_ref.mjs`：退出码 0，16 个 Node test 项通过（其中 dossier 脚本含 9 组断言）。这是源码夹具证据。

| 反馈 | 状态与实际结果 | 复现/代码入口 | 下一工作包 |
| --- | --- | --- | --- |
| 1 会话中断 | reproduced；缺失父对象抛 AGENT_LINEAGE_UNAVAILABLE。预算已持久化，历史报告“预算只在父内存”不符合当前代码 | DelegationControl.lineage/transaction；baseline 的 child→missing | 01 |
| 2 伪代码裁剪 | reproduced；80513B 合成代码在 14000B 请求下返回6668B dossier，剩余份额分配给其他段，没有完整结果引用 | collectFunctionDossier compact/projected；Ghidra m_decompile 本身返回完整 C | 02/03 |
| 3 缓存从不命中 | not-reproduced；首次5 RPC，第二次0新增RPC且hit=true；改展示预算miss | dossier key含身份/预算/能力；session.cache | 05 |
| 4 参数误判 | source-confirmed；interactive跳过Parameter ID，dossier只显示profile，无明确原型未知提示 | Ghidra分析metadata、dossier analysis | 05 |
| 5 xref缺失 | corrected；Full40已有ig5_xrefs，Core8不包含；真实后端本轮未验证 | index注册、Ghidra m_xrefs、Reverse m_xrefs | 05 |
| 6 72项批量 | source-confirmed；现有AnalysisJobs是隔离数据计算队列，不能直接当持久函数批任务 | analysis_jobs、profile/workspace | 06 |
| 7 CFG/stack裁剪 | reproduced/source-confirmed；CFG provider当前返回全图但dossier再裁剪；calls provider先按limit裁剪 | Ghidra m_cfg/m_calls；dossier providerOmissions | 02/03/05 |
| 8 错误诊断 | reproduced；lineage全部压成同一个code，普通doctor还会启动worker且先受charge阻断 | index公共包装器→coordination.charge→doctor；delegation_control | 01 |
| A 地址混乱 | source-confirmed；现有static/rva/va/file与runtime身份严格，但无独立elf_vaddr/ghidra_va和实际ELF加载映射公共合同 | address_ref、Ghidra open/memory | 04 |

## 请求链路

workflow注册Core8/Full40及agent scope → index公共execute绑定engine/signal/agent → coordination.charge验证真实session祖先并在ProjectStore锁内计费 → memory.activate →选择session/attachment → withSessions队列 → expected_revision →工具execute → WorkerManager.rpc → worker_transport（单行16MiB/未解析32MiB硬限额）→ Ghidra/Reverse adapter → dossier投影/按段裁剪/响应JSON字节限额 → jsonToolOutput →宿主展示（本轮未知）。失败的已分派调用计费，预算耗尽不执行。

缓存命中仍通过公共计费；缓存与预算账本独立。dossier遇section error不缓存；修订、attachment、能力、参数变化有不同key。普通反编译还有另一套session缓存与12000字符spill逻辑，字符阈值不能称UTF-8字节阈值。

## 后端能力矩阵

| 车道 | 声明 | 源码实现 | 本轮文件检测 | 本轮实际运行 |
| --- | --- | --- | --- | --- |
| Reverse bundled | decompile/xrefs/calls/cfg/stack | Ghidra METHODS与m_*；独立engine/attachment | 注册阶段读取runtime配置；不作启动断言 | unknown |
| Ghidra | 同上 | adapters/ghidra/worker.py | 同上 | unknown |
| Reverse commercial | 同上 | worker/ig5_worker.py 的m_decompile/m_xrefs/m_calls/m_cfg/m_stack | 未选商业运行时；unknown | unknown |
| x64dbg | 调试车道 | 不实现静态dossier | 已知4551约束保留，禁止重试受阻组件 | 未运行 |

声明不等于可用。`scripts/test_public_tool_catalog.mjs`默认会启动原生引擎和调试器，不能把它当只读schema导出。本轮以无原生注册脚本导出40工具schema；未声称安装SDK、真实宿主或原场景已通过。

## 冻结的第一批接口

- UXR-01：`ig5_doctor operation=session`仅读取执行者session元数据；允许该精确、独立操作在lineage失联时到达。默认doctor仍走计费和真实探测。保留旧lineage错误code，附加细分reason/phase/retryable/recoveryActions/observedAt，避免破坏旧调用者。
- UXR-02/03：沿用`ig5_decompile`，增量operation=`collect|read`；默认collect保持原行为；read须显式target、result_ref、section，可选cursor/page_max_bytes。产物绑定完整provenance、query、schema；当前修订严格失效。provider未知完整性不得写complete。
- 不新增公共工具，不改40工具/13审批门、原生预算或runtime pins。批处理的逐项计费必须在06接入前单独冻结。

## 缺失证据

没有原历史请求、宿主日志或已核对SHA的libjinverify.so，历史事故根因、原报告函数、宿主再次裁剪量全部unknown。可信祖先恢复接口尚未找到；仅原宿主重新索引真实父对象可继续既有关联，不接受用户传入parentId认领预算。
