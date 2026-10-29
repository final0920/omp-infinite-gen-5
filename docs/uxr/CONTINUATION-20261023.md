# UXR 顺序推进补充验收

## UXR-01：宿主恢复接口核查

实际安装宿主为 DSH 0.2.1-alpha.1。运行 `node scripts/audit_uxr_host.mjs docs/uxr/host-recovery-audit.json`，只读取 app.asar 中四个包的源码，记录版本、SHA 和关键行号；没有打开持久会话、修改配置或调用模型。

宿主有 `AgentLoop.resume(ownerCtx, options)`。它通过 `sessionPersistence.open(id, "write")` 取得写所有权，读取原记录，必要时 `handle.append(closers)`，使用 `structuredClone(handle.header)` 恢复原头，再 `setupAndPublish` 发布活动 agent。`SessionStore.prepare/fromRestore` 则只是构造会话，不等于恢复活动 agent。因而不能将 resume 自动接进只读 `ig5_doctor operation=session`。

结论修正：不是宿主没有恢复 API，而是该 API 是宿主拥有的写入及生命周期操作；当前 IG5 没有自动恢复入口。策略书 UXR-01 第 4 项允许交付诊断与显式重新接入流程，此处采用该分支。

### 显式重新接入流程

1. 在故障子会话单独调用 `ig5_doctor {"operation":"session"}`，保留 diagnosticId、observedAt、code。`PARENT_SESSION_UNAVAILABLE` 只说明当前索引缺少父对象，不证明原会话或账本丢失。
2. 由宿主会话管理恢复原持久父会话；多层祖先先恢复原根，再逐层恢复原父。使用原持久 session identity，不能创建一个新根替代。宿主集成方可使用上面核查到的 resume API，但必须由宿主拥有 ownerCtx、持久存储与生命周期，不由工具参数指定父 ID。
3. 父对象进入宿主 agents 索引后，再在原子会话调用同一 doctor。预期 code 为 `SESSION_LINEAGE_AVAILABLE`；有预算时核对原 used/limit。若仍缺失，保留 unavailable，不改子会话 header、不补造祖先对象。
4. 用原 `ig5_profile {"collaboration":{"action":"status"}}` 核对原根账本。不要再次 start；预算耗尽仍耗尽。损坏账本不自动重建，没有证据的原 used/limit 不能补零。
5. 再继续分析。数据库 attachment 或 revision 已变化时，旧分页/批任务仍应拒绝为 stale；会话恢复不覆盖数据身份检查。

已验证范围：安装宿主源码审计；原有公开包装器夹具验证重新索引后沿用原账本、耗尽后只读诊断、损坏拒绝。真实历史会话恢复未复现；不把上述流程写成已在事故会话执行。

## UXR-04：运行时地址证据核查

`source/address_ref.js` 校验 runId/moduleLoadEpoch/stopSeq，但它自身不观察进程，不能把调用者提供的 mapping 升级成实测证据。`source/project_store.js` 可记录运行模块事件；这不是 Android ELF 模块观测后端。现有 VM 录制观察在 `source/vm_observations.js` 等处明确保留 moduleLoadEpoch=null / addressSpaceAttested=false，不能给当前 ELF runtime_va 背书。

因此新 ELF 转换仍只接受静态四空间。要接通 runtime_va，下一步需要能产生并绑定同 SHA 模块、真实 run、加载 epoch 及 ELF load bias/实际映射范围的后端。不能用用户填写 base，或用最低 PT_LOAD vaddr 对应的 module_offset，替代该证据。本轮不改转换公式和 runtime pins。

## UXR-05/06：实际 ARM64 静态验收

新增 `scripts/fixtures/uxr_arm64.mjs`：自产 ELF64/AArch64、72 个具名函数、明确 BL 引用、非零 ELF vaddr。仅作为静态数据加载，从未执行目标。

运行 `node --test scripts/test_uxr_arm64_runtime.mjs`：1 项通过，约 14 秒。通过实际 Ghidra worker 和产品公共包装器验证：

- ARM64 BL 的交叉引用含 isCall=true，来源地址正确。
- ELF vaddr 0x401000 转成文件偏移 0x1000。
- 72 项分 9 次、每次 8 项保存，全部 completed、无 failed，72 个独立结果引用。
- 共享预算在 9 次 run 前后恰好增加 72；首尾结果可通过公开分页读取。
- 对已完成任务再次 run，不增加任何 item attempts。

completed 仅指保存采集结果，不代表完整调用图、正确原型或业务恢复。真实宿主 registry/模型调用不在该测试中；公共包装器使用隔离服务夹具，实际静态 worker 是随包 Ghidra。

保留两份测试编写失败日志：`arm64-runtime-initial-assertion.log` 把现有 xref 字段 other 错写为 from；`arm64-runtime-initial-budget-assertion.log` 忽略 profile 的 collaboration 包装。修正测试后独立重跑，最终日志 `arm64-runtime.log`；两次失败不计通过。

工作区与 Downloads 的限定文件名搜索未找到 libjinverify.so，原报告 SHA 样本仍未验证。自产 ARM64/72 函数结果不能替代原事故样本。

## 部署与下一步

本轮只新增维护脚本、静态夹具与验收文档，产品运行代码保持 `20261023-uxr-1`。部署和宿主重载结果另记本轮交接末尾。保留全部原预算、结果、批任务与数据库；回退不删除这些数据。

本轮验收与部署收尾：

- `continuation-syntax.json/log`：355 JavaScript、190 Python、33 PowerShell 全量语法通过；Python 使用随包解释器。
- `continuation-unit.log`：29 项 UXR 回归全部通过。
- `../../../_research/ig5-uxr-deployment-20261023-v4.json`：901 个源码/stage/安装文件 SHA 一致；原安装已备份至 `ig5-uxr-install-backup-20261023-v4`，未改运行时资产。
- `../../../_research/ig5-uxr-installed-arm64-v4.log`：安装副本实际 Ghidra 的 ARM64/72 函数测试通过。
- `../../../_research/ig5-uxr-installed-sdk-v4-20261023/host-sdk.json`：实际安装 DSH SDK 服务验收通过，包括共享预算、Core/Full 作用域和全部13门。
- `../../../_research/ig5-uxr-hot-reload-20261023-v4/hot-reload-receipt.json`：实际桌面于 2026-10-23T15:52:17.164Z（北京时间23:52:17）重载原实现；Core8/Full40，配置原 SHA 已恢复。本次启动日志确认原13个审批门挂载。
- 文档本段在冻结部署后补记；运行代码没有后续修改。真实模型交互与冷启动未执行。

下一项需要真实宿主中的模型工具调用验收，以及原 SHA 样本。缺少原样本时不补写原事故通过。Android runtime_va 需要上述可信观测后端后再实现。
