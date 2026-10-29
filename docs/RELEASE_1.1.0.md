# 无限五代 1.1.0

2026-10-20 更新；本次实现标识 `20261020-controlled-delegation-1`。

## 用户可见更新

- Core8 / Full40 工具面、八个原生技能及十三个修改/执行审批入口保持；新增独立 HTTP/HTTPS 采集、离线载荷和有界协议状态分析。采集不自动修改系统代理或证书信任，TLS/重放仍需显式范围及审批。
- 调查任务与 dossier 保留身份、数据库修订、完整报告摘要和过期证据；受控 handoff 绑定真实 DSH 父子会话，子代理 claim、读取 evidence、submit 并完成后，父代理才能正式 review。未携带 handoff_id 的旧 review 明确仅为完整性预检查。
- 可显式开启持久化根会话共享调用额度，父子及后代的 IG5 调用统一计账，已分发失败调用也计数；耗尽拒绝继续。额度不从提示词自动推断，未启用时不设限，不计非 IG5 工具或 token。
- 修复 Ghidra 后端 exports 错用分析入口的问题。真实 PE 导出目录与程序入口/TLS 回调分开，保留转发、无名项、partial 和诊断，不用猜测补齐异常数据。
- 纳入本地累计的有界录制观察、Java 状态投影、路径/主体研究与失败诊断。局部观察、结构核验和有限证明不能外推为完整 VM、VMP 3.8 或通用业务恢复。

## 安装

推荐下载本次 Release 的 `IG5-1.1.0-Windows-x64-full-20261020.zip`，核对同名 `.sha256`，完整解压后在 PowerShell 执行：

```powershell
& .\plugin\install.ps1
```

完整包包含所需 Ghidra/Java/Python、x64dbg 运行资产及上游许可/来源记录；不分发用户工程、私有调试配对配置、外部学习样本或实验缓存。可选商业兼容后端仍需用户已有合法安装与许可。

源码仓库及 GitHub 自动生成的 Source code ZIP 属于维护源码；安装器使用原固定、已认证的公开 1.0.0 供体补齐运行资产，不覆盖下载者的 1.1.0 代码。`scripts/distribution.json` 的原始 SHA、上游清单和运行时 pins 保持不变，不能改成指向包含自身的新包。

更新后冷启动 DeepSeek Harness，检查 `ig5_profile` 的 version=1.1.0 和上述 implementationRevision，再执行 ig5_doctor。插件开关可能复用旧模块，不能仅据磁盘文件或版本号判断新代码已加载。

## 本机验证范围

- 全项目 JS/MJS、Python 和 PowerShell 语法检查通过。
- 受控协作/调查 17 项、PE 导出解析 4 项测试通过；实际安装 DSH SDK 的 schema、分发、隔离、审批、卸载和父子共享预算拒绝路径通过。
- 40 工具在受控自产夹具上的原生回归通过；不代表任意外部目标全部可恢复。
- 实际 DSH 模型派工中，提前正式 review 被拒绝；子代理读取并提交证据、实际完成后复核成功。共享账本实际包含父子调用及失败调用，semanticAcceptanceVerified 始终 false。

受控协作依赖可核验的 DSH 会话身份和原生子代理生命周期，缺件时不伪称受控通过。文件完整性与运行结束证据不证明模型理解或自然语言结论正确；其他平台、provider 和宿主版本仍需独立验收。
