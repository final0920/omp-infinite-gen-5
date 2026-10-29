# UXR-00 交接

状态：verified（源码与合成夹具层）。起始HEAD、未提交修改摘要与工具路径见baseline/workspace.json。

交付：docs/UXR_BASELINE.md、baseline/tools.json、baseline/fixtures.json、baseline/workspace.json、scripts/uxr_baseline.mjs。未变更产品实现；未暂存或提交已有文件。

复现：`node scripts/uxr_baseline.mjs <新的输出目录>`；父失联、重复缓存、大代码裁剪与部分调用列表均含断言。xref源码与注册确认，实际引擎未运行。既有delegation/dossier/address回归16项通过，退出0。

01准确入口：delegation_control.lineage/charge和index公共包装器；仅session metadata doctor可精确豁免。02入口：dossier rawSections在compact前，analysis_artifacts稳定读/发布可复用；必须额外约束配额、身份和生命周期。04入口：address_ref转换及Ghidra加载映射；不可用报告数值替代实际映射。05入口：capability_catalog缺查询能力、dossier缓存key与analysis、Ghidra xrefs/calls。

部署：仅源码与报告；安装包、宿主加载、实际调用、历史样本均未验证。回退仅移除本包新增脚本与文档；不得删除预算账本、数据库或其他工作修改。
