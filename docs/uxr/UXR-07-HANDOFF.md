# UXR-07 集成验收

起始HEAD `2baed0fadba511a16bc695114e2f6ce1adaff067`，有效未提交工作区基线见baseline/workspace.json。所有入口由本轮串行接入，未暂存、提交或清理其他修改。

实现标识 `20261023-uxr-1`，package版本仍1.1.0，runtime pins/40工具/13审批门不改。

当前证据：

- 基线：baseline/tools.json（实际源码注册schema）、fixtures.json、workspace.json。
- 自有全量语法：syntax.json/log，JS352、Python189、PowerShell31通过；最终增补后另存final-syntax日志。
- 相关回归：regression.log，104项通过，含真实安装DSH 0.2.1-alpha.1 SDK服务、Core/Full隔离及13门；不等于GUI实际模型调用。
- 真实静态worker：runtime.log，3项通过，Reverse内置/Ghidra的自产PE与ELF，不执行目标。
- 新增专项：unit.log、addresses.log（最终命令与退出码写在日志及验收索引）。

## 最终验收与部署

- `npm run test:uxr`：29项通过，退出0，final-unit.log。
- 随包Python执行`-I -B scripts/test_uxr_addresses.py`：4项通过，退出0，final-addresses.log；包含72个已生成调用关系独立于32行展示限制的捕获。
- 最终相关集成回归101项通过，退出0，final-regression.log（另保留此前104项回归记录，不把重叠项累加）。
- 最终自有全量语法352 JS、190 Python、33 PowerShell文件通过，release-syntax.json/log。执行Python与宿主随包路径一致。
- 安装副本实际DSH 0.2.1-alpha.1 SDK服务通过；[SDK报告](../../../_research/ig5-uxr-installed-sdk-v3-20261023/host-sdk.json)。
- 最终安装副本的自产PE/ELF真实静态验收3项通过，退出0；[原始日志](../../../_research/ig5-uxr-installed-runtime-v3.log)。不启动目标进程、不调用受阻x64dbg/SLEIGH路径。
- [v3部署冻结摘要](../../../_research/ig5-uxr-deployment-20261023-v3.json)：888个stage/install文件摘要一致。source-manifest.json再次核对11个产品代码文件源码/安装SHA一致；改造前基线中只有预期的7个现有代码文件变化，其余基线文件保持。文档验收报告在冻结后更新，未作为运行代码重新镜像。
- [实际桌面热重载回执](../../../_research/ig5-uxr-hot-reload-20261023-v3/hot-reload-receipt.json)：北京时间2026-10-23 23:39:08加载`20261023-uxr-1`；Core8/Full40，配置SHA恢复原值。冷启动未执行。
- 实际本次启动日志再次记录新实现及全部13门挂载；最终live-host.json保存当前loadedAt、工具数量、无活动session/job及本次日志行。没有调用真实会话中的模型发起新分析，因此实际模型交互和最终显示范围仍未验证。

保留两次部署前置失败：首次新脚本缺UTF-8 BOM，PowerShell5.1误读中文路径导致暂存失败，安装未改；已补BOM并保留失败备份（移回工作区），原目录其他内容未动。首次热重载用PowerShell5.1，因HashData API缺失在写配置前失败；后用PowerShell7执行成功。前置失败不计通过，日志/回执分别保留。`deploy_uxr.ps1`可用PowerShell5.1，`hot_reload_uxr.ps1`须用`pwsh`。

原功能整体回退备份为`_research/ig5-uxr-install-backup-20261023-v2`；v3备份只用于回退最后的调用列表捕获补充。回退通过受核对的stage/镜像流程恢复代码，仍须热重载和日志核验；不在安装目录手工拼文件。预算、结果和批任务全部保留。

仍未验证/未实现：历史报告精确SHA样本、原宿主事故、真实ARM64 xref、当前ASLR运行态映射、可信父会话自动恢复，以及宿主模型最终展示完整分页。静态转换对runtime_va明确拒绝；源partial仍partial。没有宣称VM、签名协议或业务恢复。

回退：按部署备份恢复代码；保留预算账本、数据库修订、function-results/function-batches和所有分析历史。旧代码不读取新增命名空间，不做破坏性反向迁移。

## 顺序推进后的补充验收

详见 CONTINUATION-20261023.md。新增实际 ARM64 ELF 交叉引用与72项完整批任务验收，源码和安装副本均通过；属于自产静态夹具，原SHA样本仍未验证。安装宿主恢复API已审计，完成显式重新接入流程；自动恢复不在只读doctor合同内。v4部署901个文件SHA一致，实际安装SDK通过，23:52:17桌面重载并恢复原配置；355 JS/190 Python/33 PowerShell语法及29项UXR回归通过。运行产品实现仍为20261023-uxr-1。本段替代此前“真实ARM64 xref未验证”的当前状态，其他原事故/运行时/模型验收缺口保留。v4仅是本轮维护文件部署备份，原功能整体回退仍使用v2备份。

## 2026-10-24 最后验收

见 FINAL-ACCEPTANCE-20261024.md：原样本由用户确认没有。新增自产实际ARM64大函数8页重组、真实DSH CLI模型连续2页读取及独立可见正文审计、本地浏览器长正文/ELF标签验收。模型首次180秒超时保留为失败；第二次223秒、6调用完成并确认清理。77客户端、29 UXR回归及360 JS/190 Python/33 PowerShell语法通过。产品代码仍未变化；真实桌面GUI模型及冷启动未验，不能把CLI与浏览器夹具合并称GUI端到端。v5维护部署与本次热重载证据见_research/ig5-uxr-deployment-20261024-v5.json及对应hot-reload回执。
