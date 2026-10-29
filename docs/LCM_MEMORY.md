# 本地 LCM 历史恢复

理论、假设和收益判断先见 [LCM_THEORY.md](LCM_THEORY.md)。接入版本为
`lossless-claude/lcm@0c17dbffda452cf7fae46929af427dff355aeaa3`。

## 接入路径

DSH 已提交事件 → 精确 JSON 归档 → 上游 ConversationStore/FTS。
DSH compaction/summary → 上游 SummaryStore 来源 DAG → 有界恢复引用。
宿主的ContentBlock数组按完整JSON保留；依据相邻摘要事件及替换消息的sourceEventSeqs
连接跨轮来源，同时保留替换消息本身，不能靠摘要文字相似度推断祖先。
模型通过原有 `ig5_profile` 读取；Core8/Full40 和 13 项审批入口不变。
这是 LCM 存储/检索核心的 DSH 适配，不替换宿主压缩器，不调用额外模型 API。

首次调用任意 IG5 工具时懒启动；恢复曾使用 IG5 的会话时，由 agent/created
或下一次 pre-step 重新接入。按可信 session.header.id/cwd 隔离，最多同时8个会话。
扫描历史分批执行；状态未完成时保留 `captureComplete=false`。每批最多256事件，
25ms软调度预算（单次JSON序列化/SQLite操作不能中断，不是宿主硬时限）。
原生 scoped runtime-context 只注入导航/引用，不注入全部旧文本或改写全局persona。
导航在普通事件追加之间保持不变，避免事件计数每次变化都触发新的宿主持久上下文快照；
摘要或错误变化时才更新相应导航。实时计数和完整性通过status读取。

数据在 `projectRoot/lcm/<session+workspace SHA>/memory.sqlite`。默认 projectRoot
沿用现有IG5配置。插件配置 `memory: false` 可禁用，不删除已归档数据。
记录包含本会话用户、助手、工具调用/结果和压缩事件；runtime-context派生快照跳过。
原文不经过上游脱敏器，按本地DSH日志的内容保留；不读取其他产品历史或上传远端。
引用外部文件不等于保存其文件字节，仍需校验现有IG5报告SHA和当前运行身份。

## 使用

以下是 `ig5_profile` 的完整参数；memory与其他profile操作分开调用。

```json
{"memory":{"action":"status"}}
{"memory":{"action":"restore"}}
{"memory":{"action":"search","query":"counterexample","limit":4}}
```

将search命中的原样 `ref={kind,id,sha256}` 传入：

```text
{"memory":{"action":"read","ref":<ref>,"offset":0,"limit":2048}}
{"memory":{"action":"expand","ref":<summary-ref>,"offset":0,"limit":16}}
{"memory":{"action":"checkpoint","text":"待验证假设与未决条件","sources":[<ref>]}}
```

read每页最多2048个UTF-16单元，不切开代理对；按nextOffset读到null后才能说原文完整。
search最多16条、单条预览320字符，全文检索不是完备检索，空结果不证明不存在。
expand每页最多32个直接来源，递归展开summary子节点；`directSourcesComplete`
只描述本层，`transitiveLineageVerified=false`，缺失来源显式保留。
checkpoint最多32来源/4096 UTF-8字节，始终caller-unverified，不是独立证据。
存储只引用已存在节点，深度最多64；摘要文本SHA和绑定来源元数据的节点ID均核验。

单事件上限16MiB，单会话序列化载荷配额512MiB；SQLite索引/页/WAL另占磁盘。
达到原文限额或事件冲突后停止该会话采集并报告错误，原DSH日志和已提交档案保留。
仅派生摘要超深/失败时，记录summaryFailures并继续保存后续原文，不把索引失败变成原文丢失。
历史仍可读取；非法查询不污染采集状态。修复配置/文件原因后需重新加载会话或插件，
从宿主日志幂等重放，不静默跳过失败事件。自动保留不等于备份或任意磁盘损坏修复。

## 构建与验收

上游完整Git历史位于本次工作区的 `_research/lcm-full-20261021`，非浅克隆。
随代码保留全部上游受跟踪源码ZIP、MIT许可、依赖许可及PROVENANCE.json。
重建依赖放在scratch，不安装全局hooks：

```powershell
New-Item -ItemType Directory -Force scratch/lcm-build
Copy-Item third_party/lcm/build-package.json scratch/lcm-build/package.json
Copy-Item third_party/lcm/build-package-lock.json scratch/lcm-build/package-lock.json
npm ci --prefix scratch/lcm-build --ignore-scripts --no-audit --no-fund
node scripts/build_lcm_vendor.mjs ../_research/lcm-full-20261021
npm run test:lcm
node scripts/test_host_sdk.mjs
node scripts/benchmark_lcm_replay.mjs <新的实验输出目录>
```

2026-10-21初次确定性回放：1024条原始证据、16次摘要、32个查询，原文恢复32/32，
递归可达1024条。序列化载荷2,845,962字节，实际数据库10,637,312字节；
首次归档1538ms，32次检索与64次分页读取合计4.61ms，返回126,256字节。
这些是本机单次暖缓存测量，不是跨机器性能承诺。

对照诚实保留：人为遗漏事实的最终摘要中0/32可见；直接扫描DSH式原日志同样32/32，
本次约6.91ms。不能据此宣称模型准确率从0提升到100%，也不能证明优于优化后的原生日志索引。
价值在带身份的有界恢复入口、可递归来源链及会话恢复提示。真实模型逆向成功率、
总token/费用和节省重复取证的幅度仍需同任务、同预算的多次A/B实验。

实际已安装DSH 0.2.1-alpha.1的隔离SDK验收已覆盖schema、工具执行、会话隔离、
摘要恢复、scoped提示注册与卸载；它不是运行中桌面重载或真实模型验收的替代。

进一步回放本项目已有DSH v4真实历史：解压17,605,762字节，2714条事件；
归档1454条适用事件，跳过1260条非归档类型/派生运行上下文；8次压缩形成深度0–7
的8个摘要节点、7条父摘要边，摘要失败0。抽查46条原文经312页回读，46/46摘要
校验一致，原始压缩日志SHA未变。首次回放暴露ContentBlock数组和替换消息来源关联
不兼容，修复后重跑通过；没有用合成测试掩盖真实格式差异。

最终受影响回归27项通过，专用LCM测试11项通过；DSH自带Node v24.18.1也通过
这11项。自有263个JS、181个Python、28个PowerShell语法/编译检查通过，后续改动
文件单独重新检查。真实Reverse/Ghidra功能烟测通过，目录验收39/40项；因既有4551
阻断而跳过调试器执行，目录总报告保留ok=false，不能称全目录验收通过。


## PR09：按调查缺口恢复

先读取当前 target 的 workspace brief；只有具体历史前提缺失时，读取 `historyNavigation.fullRef` 指向的 `workspace={action:"resume",id:taskId}`。resume 为只读，不启动引擎；max_bytes 默认12288，允许4096..32768。它从同任务的验证反馈、失败、未决义务和过期报告中选择最多三个缺口，给出精确 ID 搜索与当前报告入口；不使用自由文本拼接历史指令。返回的 totalGaps/omittedGaps 明示导航并不穷尽。

原 memory search 现在附带最多三份 read 草稿和 checkpointDraft。草稿仅为 caller-unverified 检查清单，提醒记录失败输入、反例、路径条件和未知；没有自动保存或已验证结论。先按 nextOffset 回读所有页面、核验 SHA，summary 递归 expand。恢复后核对当前 artifact/attachment/database/task/research 修订；涉及执行还须核对 run/thread/stop/epoch、原 owner 和清理。历史不恢复控制权，搜索为空不证明没有历史。

runtime-context 继续只放稳定导航，不注入历史正文或大型研究状态。session/workspace 发生变化时拒绝使用旧档案；跨会话历史合并未实现。

对照入口：`node scripts/evals/memory_resume.mjs <全新插件外输出目录>`；添加 `--models` 启动原宿主 SDK，三种策略各三次真实模型回放。模型与提供方通过 IG5_EVAL_PROVIDER/IG5_EVAL_MODEL 指定已有路由，私有 overlay 用 IG5_EVAL_PROVIDER_PATCH，认证信息不得进入代码或报告。仅固定检索工具可执行，shell/文件/网络/其它工具全部拒绝，统一20次调用/64KiB返回/120秒预算。若模型或边界未就绪，保留失败批次并停止，不能把它记作算法失败或补跑覆盖。

冻结输入与被测实现后，使用 `node scripts/evals/audit_memory_resume.mjs <输出目录>` 从原始 SDK 消息和检索回执独立复核。统计遗忘约束、丢失反例、重复执行提议、错误接受、重复读取、返回量、耗时和 token；正确猜测答案但没有读完整来源不算通过。重复执行只评估提议，测试不执行目标。使用合成调查、模拟压缩标记和真实 SQLite 关闭重开，不能冒称真实模型压缩或新原生调查。单例三次不是可靠性证明，若同预算无收益则保留按需入口，不扩大默认注入。
