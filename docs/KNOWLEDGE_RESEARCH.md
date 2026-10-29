# 研究资料与方法：离线原文与关联阅读

当前实现标识：`20261024-knowledge-v2-1`；产品版本继续为1.2.0。本文保留v1原文基线说明；F02新增的分片、代次、兼容围栏及私有索引合同见[RESEARCH_V2](RESEARCH_V2.md)。没有v2发布时仍使用以下v1数据。原界面主题、导航和按需读取方式保持。

本批借鉴 Open-ReverseLab 的特征到方法导航、re-agent 的有界检索与引用、Rikugan 的方法分类，自行实现 Node 数据层及工作台界面。首批包含6份 IG5 原创方法笔记，保留6个项目的固定提交链接，没有复制上游文章正文、代码、样本或安装依赖。

## 使用

在原 ig5_profile 中单独查询，无需打开目标，也不传 target/engine：

```json
{"knowledge":{"action":"status"}}
{"knowledge":{"action":"search","query":"混合布尔算术","limit":5}}
{"knowledge":{"action":"methods","category":"vm","limit":5}}
```

search/methods 返回 `items[].ref={id,sha256}`。使用原样引用回读：

```json
{"knowledge":{"action":"read","ref":{"id":"响应中的id","sha256":"响应中的sha256"}}}
```

read每页最多2048个UTF-16单元，不切断代理对。将nextCursor原样放入下一次read，直到null；offset连续，bodySha256绑定完整正文。列表下一页使用nextOffset与同generation；内容或索引变化要求重新查询。

工作台入口：**调查状态 → 研究资料与方法**。输入中英文术语，按类别筛选，查看前提、局限及固定版本来源；正文读完后可生成并插入可编辑会话草稿。草稿不会自动发送或执行。无打开目标时也能浏览；有目标时草稿标明当前观察的会话身份，模型仍须重新核对当前调查。

当前类别：MBA、控制流、VM、研究流程、同源/类型、加密评测。msynth和同源搜索服务仅提供方法参考，尚未接入其算法或远端服务；实际分析仍通过现有工具。

## 数据与边界

响应明确 executionAuthorized=false、semanticVerified=false、automaticInjection=false。不改变现有规划器candidates、系统证据、验收状态、Core8/Full40、13审批门、原生预算或运行时pins。匹配分仅用于排序，不是正确概率；空查询结果只表示当前索引未命中。

资料仅在显式查询或打开资料子页时读取。普通工具与默认调查概览不检索。插件配置knowledge:false可禁用查询，状态仍可读；默认允许显式只读调用。本阶段没有assist或自动注入模式。

内置笔记在source/knowledge_seeds.js。可选本地目录位于配置的projectRoot/knowledge-v1/catalog.json，使用ig5-knowledge-catalog-v1 envelope及ig5-method-card-v1条目。该目录是插件实例共用参考库，并非会话私有知识空间；暂不支持将私有会话、密钥或目标正文导入其中。

目录由维护者离线准备，无公共导入、联网或安装入口。条目须通过validateKnowledgeCard完整校验，rightsStatus为original-notes-with-links/authorized-local，来源限固定提交的HTTPS GitHub链接；不能覆盖内置ID。最多128条含内置6条、目录1MiB、单正文16KiB、响应32KiB。损坏、重复ID、链接文件/祖先、硬链接、读取中变化及超限明确拒绝。

当前增加经人工审阅的离线原文导入；不是论坛自动采集或全文互联网索引。未经独立验证及留出样本对照，不能宣称提高高强度去虚拟化成功率。

## 原文导入与回读

维护入口是 `scripts/import_knowledge.mjs`，不注册为宿主工具。三个路径参数必须为绝对路径；输入根目录中仅允许普通、非硬链接、非符号链接的 md/txt 文件。先运行 `--dry-run`，审核输出后再去掉该参数发布：

```text
node scripts/import_knowledge.mjs --manifest ABS_MANIFEST --input-root ABS_RESEARCH_ROOT --project-root ABS_PROJECT_ROOT --dry-run
```

清单格式参见 `scripts/fixtures/research_import_sources.json`：逐项声明路径、作者、来源URL、发布日期、取得时间、精确SHA256、许可、权利状态、方法关联及阅读提示。没有网络请求，不运行文章中的安装命令，不注册导入的SKILL.md为技能。GPL原文只作本机资料，不放入插件分发包。首批三份来自固定提交的Rikugan算法参考、re-agent OLLVM研究说明及msynth README；上游可能存在启发式过强、示意代码、位向量数学误用，因此必须同时阅读reviewNotes，不把来源可信度当作结论证明。

默认仅创建不存在的目录文件；更新须显式传 `--expected-catalog-sha256 HASH`。发布使用独占锁、完整目录CAS、同目录临时文件和原子替换；旧目录按摘要保存在history，同来源内容改变时追加新正文并保留旧引用。异常遗留锁不自动抢占，须先人工检查。每个正文最多64KiB、最多32份，仍共享目录1MiB和响应32KiB限制。导入不修改会话、目标或系统证据。

`{"knowledge":{"action":"documents","query":"MBA"}}` 返回原文列表。继续使用原有read/ref/nextCursor合同；返回正文摘要、来源元数据、阅读提示及relatedReferences，方法和原文可以相互跳转。正文按纯文本显示，全部回读后才能插入可编辑草稿，不自动发送。发布引起generation变化时重新检索，不拼接不同版本页面。原有只含cards的v1目录仍兼容。

## 验收与回退

npm run test:knowledge包含新数据合同及原客户端回归；另运行data-route、实际安装包SDK、研究/规划/记忆/UXR、全量语法和打包缺件测试。浏览器预览的周边会话是夹具，研究查询使用本批真实Node数据层；不代表真实目标业务验收。源码、安装副本和桌面重载分别记录。

对应蓝图的基线、资料数据合同/查询入口、部分方法目录及调查页展示。持续采集、方法适用性自动核对、算法适配、收益对照尚未交付。

回退可关闭knowledge，或恢复部署前代码备份并重载；保留本地目录、数据库、预算、函数结果、批任务及报告。没有旧数据格式迁移。
