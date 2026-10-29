# UXR-05 查询、缓存与质量

起始HEAD/摘要见baseline/workspace.json。状态：verified（源码、自产PE真实静态后端）；历史缓存miss原因unknown。

source/capability_catalog.js新增xrefs/calls/CFG能力维度，不增加公共工具。index.js增量queryState区分空、观察、截断、分析未完与错误；不支持使用UNSUPPORTED_CAPABILITY；引擎失败仍抛原异常。Ghidra xref保留原type，另加读/写/调用/数据/代码标记和来源。未解析间接调用始终unknown，不声称边完备。

function_dossier.js保留完整身份/视图/能力key，补分析状态及profile，缓存reason是可核验的本次miss依据；无历史上下文时只称cold_or_evicted。sessionLastAttempt仅一份元数据；缓存仍16份/1MiB。refresh只绕过响应缓存，照常计费，不重分析。分析quality保留partial与skippedAnalyzers，prototypeStatus=unknown，不校准置信度。

重复命中、修订/attachment/预算/能力/error与分析状态用既有dossier及新增result测试验证；真实reverse/ghidra的xref调用点、非空calls、CFG、刷新与Parameter ID警告见runtime.log。SDK目录仍8/40，全部13审批保持，regression.log。

README、docs/UXR_USAGE.md、ig5-reverse-agent技能说明更新；未提交内容不覆盖整文件。部署见07。回退代码即可，缓存删除不触碰共享账本、结果或批任务。缺失：原报告宿主版本、原请求序列和真实ARM64查询验收。
