# UXR 剩余验收收尾（2026-10-24）

## 本轮结果

用户已确认没有原 libjinverify.so。本轮使用自产 ARM64 ELF；原事故复现保持未验证，不再作为可独立工作的前置条件。运行产品代码仍为 `20261023-uxr-1`，没有改变工具数量、审批、原生 worker 预算或 runtime pins。

### 实际大函数与连续分页

`scripts/fixtures/uxr_large_arm64.mjs` 生成只用于静态分析的函数，包含256次有序内存更新，不执行目标。`node --test scripts/test_uxr_large_runtime.mjs` 在实际随包 Ghidra 上通过：伪代码15,349字节，4,000字节响应预算下连续8页；逐页offset连续、无超预算、末游标为空，全文重新计算SHA一致。

日志：`large-runtime.log`。摘要：`6b786533aa0160f2899b6dfb4dde5647ec05d0995db379893e9af0789b02d727`。

### 真实模型与宿主工具调用

`scripts/run_uxr_model.mjs` 运行实际安装的 DSH CLI、实际模型路由 experi/deepseek-v4.1-flash 和安装副本 IG5。既有隔离评测profile不修改；临时patch只配置本次独立进程，限制允许的工具为doctor/session、指定自产文件的open、dossier/read、close，其余工具拒绝。产物、配置与日志在工作区 `_research` 中，不分发私有provider配置。

- 首次试验：`../../../_research/ig5-uxr-model-live-20261023-v1/acceptance.json`。180秒内完成前三次调用后超时，0页，pass=false，原始记录保留，DSH进程退出已确认。
- 第二次试验：`../../../_research/ig5-uxr-model-live-20261024-v2/acceptance.json`。单次评测总时限300秒、分页响应12KB，223秒完成6次工具调用：doctor→open→dossier→read→read→close。两页9492+5857=15349字节，无拒绝，实际进程退出确认。增加的是这次评测的模型往返总时限，不改变产品RPC/worker或共享调用额度。
- 独立审计：`scripts/audit_uxr_model.mjs` 重新读取宿主事件与工具日志；`../../../_research/ig5-uxr-model-live-20261024-v2/independent-audit.json` 为pass。核验实际模型可见tool/result仍是完整可解析JSON、正文与结构化结果逐字相同、同一result_ref、cursor精确链接、offset与UTF-8字节一致、每页紧凑JSON预算、末页结束、拼接SHA及模型报告的字节/页数/摘要一致。不是只相信模型的最终文字。

模型正确保留了参数原型未知和摘要取自响应、未自行计算的限制。其限制说明中有一句将 `sections.*` 的provider概括为complete，实际cfg/stack仍为unknown；本验收仅确认decompile正文完整，不能把该句用于升级其他段。独立审计在模型外重新计算了正文摘要。

这是真实模型经实际DSH宿主CLI的工具链验收，不是桌面GUI聊天界面的模型验收，也不是原事故或业务语义恢复。

### 浏览器与显示层

`scripts/preview_client.mjs` 新增可选的有界本地原生结果夹具输入 `IG5_PREVIEW_UXR_JSON`，用于把已保存的真实正文送入原工作台renderer；HTTP仍只有模拟只读响应，不连接引擎。输入通过JSON序列化且转义`<`，不作为HTML注入。

实际Codex浏览器打开本地4193预览、选择Ghidra并选择函数。DOM检查确认 `pre.ig5-code-box` 包含15349字符、最后的`param_2[0xff]`及完整函数结尾；实际可见ELF vaddr标签。外围样本列表、身份和架构仍是预览夹具，因此此项只证明正文/标签渲染，不证明其外围虚拟会话与原生数据库映射。

`final-display-client.log`：77项客户端回归通过，包括新增长正文不裁剪、代码文本转义、只有mapped ELF地址显示标签的断言；原目标/引擎/attachment异步隔离测试仍通过。

## 工作包最终状态

| 工作包 | 本次交付状态 | 保留范围 |
| --- | --- | --- |
| UXR-00 | 基线、问题清单、能力与证据分层完成 | 原事故根因未知 |
| UXR-01 | 诊断、原账本保护、安装宿主恢复API审计、显式重新接入流程完成 | 不自动认领/恢复祖先；历史失联未复现 |
| UXR-02/03 | 有界保存、完整性分层、分页与实际模型连续读取通过 | provider未生成的内容不能补齐 |
| UXR-04 | 实际ELF静态转换及ARM64地址标签验证完成 | runtime_va缺可信Android观测后端，明确拒绝 |
| UXR-05 | 缓存原因、原型未知、查询能力、实际ARM64 xref通过 | 间接调用与未知分析范围不升级 |
| UXR-06 | 实际ARM64 72项保存、逐项计费与幂等验收通过 | 重开attachment后stale，不自动沿用旧任务 |
| UXR-07 | 分层回归、安装SDK、实际模型、浏览器显示均有记录 | 桌面GUI模型与冷启动未执行；本轮部署另记收尾 |

本策略书的八个工具问题及地址问题均已有对应处理和证据状态。剩余外部条件为：原SHA样本、历史会话故障现场，以及可信Android模块运行观测。没有这些条件时，保留未验证/不支持是当前交付的边界，不能写成已复现或已转换。

## 回退

维护文件回退不涉及产品格式迁移。保留共享账本、数据库修订、function-results/function-batches及原失败证据。原产品整体回退备份仍为v2；后续维护部署备份不替代它。

## 安装收尾

v5维护部署913个源码/stage/安装文件SHA一致；实际安装副本的8页大函数重组与DSH SDK服务验收均通过。全量语法360 JS/190 Python/33 PowerShell通过，29项UXR及77项客户端回归通过，日志分别见completion-syntax、completion-unit、final-display-client。

桌面于北京时间2026-10-24 00:14:16重载原实现，Core8/Full40和原13审批门确认，配置恢复原SHA，无活动session/job。证据为 `../../../_research/ig5-uxr-hot-reload-20261024-v5/hot-reload-receipt.json` 与 `../../../_research/ig5-uxr-final-receipt-20261024.json`。本段是部署后补记；后续未修改运行代码。
