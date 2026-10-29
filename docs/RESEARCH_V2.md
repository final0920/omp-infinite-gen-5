# F02：资料v2与私有索引合同

F04已通过[CASE_INDEX](CASE_INDEX.md)接入可信静态任务上下文；下文“F04未接入”描述保留为F02当时的范围。公开knowledge/GET仍不接收私有scope，F04仅显式workspace入口，不自动导入历史开发案例。

实现标识：`20261024-knowledge-v2-1`；产品版本1.2.0。这是有界存储、发布与回读合同，不是算法接入、适用性判断或收益评测。Core8/Full40、13审批门、原生资产、求解/worker预算与planner输出保持。

## 公共资料存储与提交

`projectRoot/knowledge-v2`只接受`scope={kind:"public"}`：

```text
CURRENT.json                         最后一个原子可见提交点
generations/<SHA256>.json             不可变索引，含scope/parent/revision/entries
records/<SHA256>.json                 不可变元数据与正文描述符
chunks/<SHA256>.txt                   按UTF-8字符边界分片
publish.lock                         独占、带nonce的发布锁，不按年龄回收
```

`ig5-research-record-v2`严格字段为schema/id/kind/scope/metadata/body/searchText。kind为method/document/case-fact，case-fact只能私有。body保存全文SHA、UTF-8字节数、各分片SHA/字节数，以及段落id/start/end/SHA。段落坐标是正文UTF-16单元，原件字节身份另由source.contentSha256保存，不冒充原站HTML坐标。

索引每条保留确切ref={id,sha256}、元数据、显式searchText、bodySha256与state/reason/replacementRef。state为active/superseded/withdrawn。更改同id需supersedes精确引用当前版本；旧版本保留，撤回后不再进入新检索，但旧引用可读并明确显示状态。不能用同内容重新发布来静默撤销撤回。替换/冲突关系不授予语义证明。

发布顺序：验证全部输入 → 原v1兼容锁及v2独占锁 → generation CAS → 分片/记录/索引暂存并fsync → 重新核对全部历史引用 → 再次核对CURRENT → 同目录临时指针rename。读者只捕获一代，不等待发布锁，也不拼接不同代。每个捕获对象在进程内冻结并校验来源，调用方不能自造快照读取未发布孤立记录。

这是合作写者和稳定文件读取下的原子可见性，不宣称整个文件系统事务、对恶意同账户写入的防护或断电后目录持久性。更新失败保留旧代；指针已提交后清理失败必须返回generationSaved=true及publishedGeneration，不能谎报回滚。真实进程在指针rename前后退出均有回归；遗留/未知锁保持拒绝，不能自动重试或按时间删除。

初始v2硬上限：256条历史版本（包含撤回和被替代条目）、索引1MiB、记录描述符64KiB、单正文256KiB、单分片16KiB、段落1024、存储64MiB/16,384目录项量级。发布配额保守计入旧代、孤立stage及预留写入；没有自动GC或静默截断。大于上限的原件拒绝，F03若需要节选必须另行明确提取原件/正文摘要及范围，不能把被截断内容叫全文。

这些是本机首批有界合同，不是可承载无限语料的容量承诺。已测40篇合成文档和120,038字节正文；生产现有v1目录43,570字节、3篇原文作为基线。未测满配性能或跨机器上限。

## v1引用和旧代码围栏

没有v2发布时，v1方法卡/原文校验、容量和引用保持。v1方法来源仍限固定GitHub提交；未放宽旧schema字段。首次显式发布v2时，原v1目录字节按SHA保存在`knowledge-v1/history/<SHA>.json`，原catalog.json替换为严格的`ig5-knowledge-compat-fence-v2`围栏，仅含legacyCatalogSha256。新版校验摘要后读取冻结v1；旧读者和旧导入器对围栏明确拒绝，不静默忽略新正文或覆盖它。

兼容围栏与首次v2提交不是跨文件原子事务。若在二者之间失败，新版仍可读取冻结v1，status显示`v2-prepared-no-generation`；旧版保持拒绝。公共v2有指针但没有围栏时新版拒绝查询。发布器先完整校验输入/CAS，再写围栏；后续冲突/配额失败仍可能留下围栏，回执的compatibilityFenceSaved必须保留。

既有公共knowledge read/ref/cursor协议继续使用，response envelope仍为v1，v2结果另有format=v2、typed metadata、recordState、stateReason与replacementRef。每页2048 UTF-16单元、不切代理对、32KiB响应上限不变；精确段落引用每页最多8条，其余显式omitted。分页generation是v1引用和v2 generation的组合摘要；任何换代要求重新查询，即使读取的是未改的旧正文。

已激活v2的列表offset上限512，为v1+v2合并后的有界分页服务；纯v1仍拒绝超过128。v2列表检索只读索引中元数据和显式4096字符内searchText，不读取正文分片。它不是全库正文/语义检索；关键词分数只排序。正文read只重验所选完整记录及其最多256KiB正文，不重读v2全库正文。损坏不能隐式回退v1掩盖错误。knowledge:false在磁盘读取前关闭查询。

## 版本化来源、权利和方法元数据

source.type支持git/web/paper/local-case。严格字段：type/url/author/publishedAt/retrievedAt/contentSha256/commit/parserVersion/license/rightsStatus/review/qualityReview/verificationLevel/correctionRefs/localRef。git需要URL路径包含确切40位提交；web/paper绑定内容摘要，commit必须null；local-case只接受私有scope、null URL及精确localRef。

review必须reviewed。qualityReview按来源0–2/具体性0–2/复现0–3/边界0–2/相关性0–1记录，附审核者与说明；这只是审核登记，不是真实性或适用概率。F03质量门及原文深审另验，不能以字段存在宣称来源已复现。verificationLevel是来源声明，不能升级系统证据。

metadata.contentKind区分original-note与licensed-text。许可未知或metadata-only只允许原创笔记与链接，不允许按licensed-text存全文；全文须显式reviewed权利。方法元数据还含category/prerequisites/limitations/steps/verification/integration/relatedTools；文档含methodIds；所有额外字段拒绝，不允许正文变规则、脚本、动态导入或执行请求。

URL校验只是文本合同，不是DNS/SSRF防护。这个包完全不抓网、不跟重定向、不运行JS/附件/安装命令。发现/抓取/审核/定时发布属于F03/F11后续工作。

## 私有索引

`privateResearchStore(projectRoot, trustedScope)`位于独立`private-research-v2/<scopeDigest>`，不会被公共knowledge或GET路由读取。trustedScope必须由未来F04宿主桥接从当前context/task/research/run构造，不得从工具请求接收projectId来认领其他项目。

严格scope字段：kind=private、projectId、artifactSha256、engine、provider、attachmentId、dbRevision、taskId、taskRevision、contractDigest、runId、moduleEpoch。run/epoch必须同时为null或同时完整给出。每个指针、索引、记录都绑定同一摘要；复制/改目录、猜引用、改项目/样本/修订/attachment/合同/run均不能通过读取核对。缺少完整可信上下文时应在未来桥接返回needs-evidence，不猜测身份。

case-fact在公共字段外包含caseId/subject/claim/status/observedAt/unknowns/supersedes/contradicts。status仅reported/observed/contested/stale；本包不允许调用者导入verified-in-scope。关系引用限定本索引已发布条目；外部localRef只是来源声明，F04仍需连接现有不可变报告/LCM/research_state核验。只读query最多返回3项导航；内部read正文有256KiB存储界限，接公开入口前还须由F04实现响应预算和分页适配。

隔离保证限于本模块读取合同，不是操作系统ACL、秘密保险箱或对同账户终端读取的隔离。相同SHA不能证明项目权限，folder名字也不能证明授权。公共数据若人为伪装成web文本仍需人工审核脱敏；没有通用秘密检测器。

本包没有新增私有索引公共工具或接入planner。16个VS1.5案例只在独立验收目录按offline-development合同入库，HALT保持contested；这些attachment/task标识不是实际打开的目标会话。没有把历史完成报告升级为验证器回执。

## 维护命令与验证

```powershell
node scripts/publish_research_v2.mjs --manifest ABS_MANIFEST --input-root ABS_TEXT_ROOT --project-root ABS_PROJECT_ROOT --expected-generation absent --validate-only
# 完整审阅本地清单后去掉 --validate-only 显式发布。
```

清单schema为ig5-public-research-import-v2，只有upserts/withdrawals。每个upsert提供id/kind/metadata/bodyPath/bodySha256/searchText/supersedes；bodyPath限输入根内普通单链接md/txt相对路径。withdrawal提供ref/reason/replacementRef。更新必须给当前generation；没有默认CAS或自动重试。validate-only不写目录，检查输入和CAS；它明确不保证冲突/配额最终可提交，不冒充完整dry-run。

`npm run test:research-v2`覆盖来源/权利/容量/Unicode/段落/历史/兼容围栏/跨项目/真实双写者CAS/真实退出/清理故障/CLI与不读正文。`npm run test:knowledge`包含v2及旧客户端。`scripts/accept_research_v2.mjs`只读现有公共v1和私有案例，输出全新隔离目录；回读本机3篇原文、16个案例及数据回退。实际SDK另验工具输出和权限。合成数据、SDK、真实宿主只读查询、GUI及算法验证分别记录。

回退至旧代码前必须显式处理围栏：停止相关维护写者、核实锁/原资源所有者；保存整个v2及围栏/历史目录到确定的备份位置，核对所有摘要；将v2移入明确隔离备份并按围栏摘要恢复原v1字节，再核验旧引用。不能只改schema或丢弃新正文。无法确认时保留围栏并关闭knowledge。数据回退已在隔离副本演练，真实数据不做自动迁移或回退。
