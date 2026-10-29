# R8/R9 待授权执行单

本文件准备具体可审查的步骤，当前尚未执行。真实安装、重启与模型会话仍需要交接单要求的所有者明确同意；“推进审查”不作为代签或真实宿主变更许可。

## R8 安装与重载

1. 输入仅使用本轮修复后重新构建的 1.2.0 便携包，以 `_research/ig5-review-20261026/RESULTS.md` 中的最终 PORTABLE_ROOT 和 SHA-256 为准；旧 `_research/ig5-regression-20261026/` 包仍保留，但未含本轮修复，不拿它替代。
2. 先确认实际 DSH 进程与 profile；正常退出 DSH，保留既有会话。无法正常退出时停止并报告，不强行结束用户工作。
3. 将真实 `C:\Users\IG5User\.dsh\plugins\dsh-infinite-gen-5` 备份到本轮证据目录下的新空目录，保留文件内容与必要元数据，核对完整相对路径/大小/SHA-256 清单后才安装。原 profile 配置也只备份、核对，不改模型、自动批准、安全、PATH 或许可证配置。备份失败不继续。
4. 从新包运行 `powershell -NoProfile -ExecutionPolicy Bypass -File <PORTABLE_ROOT>\plugin\install.ps1 -DshRoot C:\Users\IG5User\.dsh`。保留安装器自身生成的恢复副本与 profile 备份，不自动卸载或删除用户数据。
5. 正常启动原 DSH 应用；记录新进程身份和插件加载时间，实际调用 ig5_doctor、ig5_status，核对插件版本 1.2.0、Full 注册数 43、引擎/会话状态。输出自动批准的实际行为，0ms 不解释为人工审阅。
6. 若安装/重载失败，先保存证据并报告；只有在已确认备份有效且操作范围清楚时回滚本插件。不得把失败重载记为成功。

## R9 真实模型会话（独立于 SDK 测试）

使用 DSH 真实模型路由和新安装的插件，保留实际工具定义、调用/返回、会话事件及独立断言。已确认的模型路由需在执行时再核对，不复制凭据到报告。新建隔离测试会话，测试 artifacts/project/state 都放在本轮证据目录。只生成和静态读取自产 PE，不执行目标、不调试启动、不抓取真实网络。

1. 初始 Core：取得模型实际可见工具定义，断言集合为 ig5_doctor/open/status/funcs/strings/decompile/close/profile 八项，不只读状态文本里的计数。
2. 通过真实模型调用 `ig5_profile {toolset:"full"}`；取得更新后的模型可见定义，断言 IG5 集合等于当前 Full 43 清单。
3. 用 `scripts/fixtures/pe64.mjs` 的自产构造器生成本轮临时 PE，保存初始哈希；真实模型调用 `ig5_open {path:<临时PE>,engine:"ghidra",background:false}`，建立静态会话。
4. 调用 `ig5_workspace {target:<临时PE>,workspace:{action:"list"},engine:"ghidra"}`，断言 `workspace.tasks` 是数组。此显式 target 是实际源码前置条件，交接单的缩写调用不能省略它。
5. 复制 `scripts/fixtures/vm_recovery_case.example.json` 到测试证据目录，固定 SHA-256。调用 `ig5_recovery {recovery:{case_ref:{path:<复制文件>,sha256:<固定值>}}}`；断言 `recovery.executionPerformed=false`、报告存在、哈希与返回一致、再次调用不改写旧报告。
6. 分别调用 `ig5_profile {workspace:{action:"list"}}` 和 `ig5_profile {recovery:{case_ref:...}}`，在实际模型工具调用层断言错误分别包含 `Use ig5_workspace` / `Use ig5_recovery`。若宿主 schema 在执行前拒绝，单独记录该结果，不能冒称已观察到执行层迁移文案。
7. 关闭临时静态目标，结束测试会话，确认自产 PE 哈希未变。每项根据返回值断言；模型最后说“完成”不作为通过证据。保留任何失败/超时/中断，SDK 或门禁不替代这一轮 L4。

范围不包含原生样本执行、调试启动、真实流量、系统代理/证书设置、全局 Python、PATH、第三方程序或许可变更。五项契约的确认和台账风险接受也不由本单代为决定。
