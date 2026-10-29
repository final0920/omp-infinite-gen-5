# 5 个关键文件复审与授权签署

日期：2026-10-24。实际审查执行者：Codex。授权者：bai。本轮依据本聊天中“代替我 bai 进行评审并对这 5 个文件复审并签字”的明确指令，记录用户授权的代理复审，不声明 bai 亲自阅读了代码。

## 复审结论

R1–R8 的原缺陷在本轮新哈希上通过源码与定向回归复核，接受这 5 个文件对应的修复。台账有效 5 项，过期 0 项，仍有 31 项未签署；严格审计继续因这 31 项失败，不能把本轮签署外推为全部 36 文件或整套产品发布通过。

| 文件 | 复核结论 |
|---|---|
| worker/ig5_worker.py | R1 保存并恢复正确注释通道且回读；R2 拒绝不匹配/不可完整读取的 expected；R3 分析 API 失败不再报告成功；R4 导出读取 PE 目录，入口另列。定向模拟 API 通过，商业 IDA 实机仍未验证。 |
| adapters/x64dbg/adapter.py | R5 同时检查 Job 关闭和进程退出，未确认时保留引用并拒绝新启动。失败路径模拟与 64/32 位原生正常清理通过。 |
| source/history_index.js | R6 增量缓存命中前校验记录数量，多实例漏项复现对应回归通过；保留既有不可变记录/摘要契约。 |
| source/project_store.js | R7 记录并核对主机、平台；旧锁和异主机锁保持拒绝自动回收。临时目录回归通过。 |
| source/worker_manager.js | R8 保留原始事务回执，元数据失败另附 metadataFailure；成功执行后的元数据失败保留 operationResult。模拟 JSONL 回归通过。 |

R7 的兼容处置新增 `scripts/recover_legacy_project_lock.mjs`，默认只预览，必须显式离线确认并匹配 owner 摘要后才移走旧锁，原证据保留。[操作说明](LEGACY_LOCK_RECOVERY.md)。实际项目根目录本轮检查没有旧锁，因此没有迁移用户锁。

## 验证证据与范围

- 完整 CI 初次运行 110/110 通过：[ci.log](recheck/ci.log)。R1–R5 定向模拟 API 15/15：[python.log](recheck/python.log)。R6–R8 定向 Node 8/8：[node.log](recheck/node.log)。
- 新增离线锁恢复负例及证据保留测试通过；源码打包完整性检查 `Assert-IG5PluginSource -CoreOnly` 通过。
- 真实 x64dbg 64 位与 32 位自产样本验证通过：打开/装载不执行、启动、断点、寄存器、内存 expected 拒绝、单步、异常、停止与关闭。[64 位日志](recheck/x64-native.log)、[32 位日志](recheck/x86-native.log)。这是原生适配器证据，真实 DSH 会话结果另记。
- 安装测试首次因既有夹具缺少 `source/knowledge_catalog.js` 失败：[package.log](recheck/package.log)。补齐夹具缺失的 33 个现有必需模块和新增恢复工具；后续重跑结果见最新 package 日志。没有降低安装源校验要求。
- DSH 已冷启动；实际桌面宿主 PID 42988，监听端口由旧的 55352 变为 55744，`/ig5-jobs` 返回插件修订 `20261024-fusion-ui-target-1`、加载时间 `2026-10-24T12:59:36.695Z`，初始会话与作业均为 0。[启动回执](recheck/desktop-start.json)。宿主 app-boot 为 `0.2.1-alpha.1`，见[安装版本证据](recheck/host-version.json)。
- 真实模型会话第一轮静态分析成功，但 Core 未暴露调试工具，整体失败；第二轮 Full 静态分析成功，模型省略 engine 后选择了未打开的默认 Reverse，整体失败。两轮均关闭静态目标并退出 CLI，保留日志，均不计为通过。

商业 IDA 的 R1–R4 只有模拟 API 验证；Ghidra/x64dbg 的真实执行不替代商业 IDA 验收。本次仅使用自产测试副本，不修改用户目标或工程原件。

## 最终实测结果

- 最终 `npm run ci` 退出 0，111/111 门禁通过，包含新增旧锁恢复测试：[ci-final.log](recheck/ci-final.log)。安装/打包测试退出 0，37/37 场景通过：[package-v3.log](recheck/package-v3.log)。原失败记录仍保留。
- 第三轮独立真实 DSH CLI 会话使用已安装插件、Full 工具集和真实模型 `experi/deepseek-v4.1-flash`，显式设置该测试会话的 defaultEngine=ghidra。没有修改桌面 profile 或全局默认引擎。测试 guard 限定自产样本和 20 次/5 分钟内的指定工具操作，13 个产品审批门未改动。
- 9 次工具调用全部成功：open → funcs → decompile → dbg load → start → regs → step → stop → close。分析完成，发现 16 个函数；反编译包含 `return param_1 + param_2`；load 返回 targetExecuted=false；启动后 suspended，读取 24 个寄存器；同一 runId 的暂停序号从 1 增至 2；stop 返回 no-task；close 返回 closed=true。
- 真实会话事件有 5 组 approval/asked、approval/decided，5 次均为 allowed-once。宿主使用既有会话审批策略，本轮没有验证 GUI 审批卡片的人工点击展示。
- 调试器 PID 19300 已由独立进程探测确认不存在，CLI 已退出；临时 provider 私密配置已移除。目标摘要在结束时重新核对一致。
- 模型最后输出在 JSON 后附加文本，最终回答 JSON 解析失败，此项单独记为格式失败。实机冒烟通过依据是独立校验的工具返回值、会话审批事件、目标摘要和进程退出。独立验证退出 0，见 [smoke-verification.json](recheck/smoke-verification.json)。

完整真实会话证据目录：`C:/Users/IG5User/Desktop/无限五代/_research/review-smoke-20261024-v3/`，包含 tools.jsonl、events.json、acceptance.json、independent-verification.json 和自产目标。v1/v2 失败试验分别保留在相邻目录，不计入通过数。桌面 DSH 保持运行。

## 签署绑定

以下哈希与已安装副本一致；完整记录在 [five-file-hashes.json](recheck/five-file-hashes.json)。台账记录 `reviewKind=user-authorized-agent-review`、实际执行者、授权者、授权来源、审查范围和本报告。文件以后变化会使签署失效。

| 文件 | SHA-256 |
|---|---|
| worker/ig5_worker.py | `7dd1f758e75a777839783af956c3993e4a718d359cb72cc86cec41a92c4e6c4e` |
| adapters/x64dbg/adapter.py | `12f7ea5ddb897ee5bddf7b61637db750d768bc8a5ba3aa57967aa4aa5c590738` |
| source/worker_manager.js | `8ddf16d1c0c34b49ac5620c009a4918c83ad9925e842d0acd5af9d19f024a01d` |
| source/project_store.js | `cab0ff77f00b9da43e7992896e1376960fd86ea234d43b7671a05f891ba81e73` |
| source/history_index.js | `7f329a40d7b24ebf3ef0f9ff9aeae2e965ee28d2c38162f776347d3942750e26` |
