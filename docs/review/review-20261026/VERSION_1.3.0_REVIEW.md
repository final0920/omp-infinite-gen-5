# 1.3.0 版本绑定增量复审

2026-10-26，执行者 Codex，授权者 bai。依据本聊天用户“标改成1.3.0 并更新到我的本地deepseek harness”的明确指令以及此前逐项代理复审授权。

与已通过授权审查的便携包按完整文件字节比较，index.js 仅 PLUGIN_VERSION 从 1.2.0 改为 1.3.0，implementation_info.js 仅 IMPLEMENTATION_REVISION 改为 20261026-release-1.3.0；没有其他执行逻辑变化。两个关键文件按新 SHA-256 续签，前签署保留，具体摘要见 [version-1.3.0-coverage.json](version-1.3.0-coverage.json)。其他关键文件签署继续有效。

package.json 的两处版本与当前 README 同步。runtime_pack.ps1 在封闭的兼容集合中明确增加 1.3.0 对现有固定 1.0.0 供体的复用，并使 1.3.0 继续要求采集、trace 和 1.2.0 核心模块，另要求 RELEASE_1.3.0.md；没有放宽未知版本、预发布版本或供体摘要校验。distribution.json 和 runtimes/manifest.json 与前包逐字节一致。定向打包回归覆盖 1.3.0 正例、未知/预发布拒绝、缺件拒绝及原 pin 不变。

此记录只续签版本常量增量，不改写历史审查的原 SHA-256，也不将历史阅读/测试冒称本轮全新完整阅读/全部原生测试。五项功能契约仍承接 DELEGATED_ACCEPTANCE.md 中各项范围和限制。

本轮 CI、严格审计、安装回归、新包及真实安装/加载证据保存在工作区 `_research/ig5-release-1.3.0-20261026/`；安装是否完成以该目录最终报告为准。未执行公共发行发布。

工作台 client.js 的头部与显示 VERSION 同步为 1.3.0，按字节对比仅这两处文字变化；独立 client 回归通过。当前 HARNESS_PLUGIN 入口同步标记，并校正当前工具分类为 Full43/Core8、13 审批门（历史验收文档不改）。
