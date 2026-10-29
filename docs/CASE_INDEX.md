# F04 私有任务结论和失败检索

实现标识20261024-private-case-bridge-1，产品1.2.0。入口复用ig5_workspace；先明确打开静态target，取得任务并初始化研究合同。F02私有分片存储保持，公共knowledge及HTTP GET不能访问这里。没有新增工具或审批门，没有自动执行。

```json
{"target":"实际已打开目标","workspace":{"action":"case-status","id":"任务UUID"}}
{"target":"实际已打开目标","workspace":{"action":"case-index","id":"任务UUID","expected_generation":"absent或status代次","expected_task_revision":0,"expected_research_revision":0}}
{"target":"实际已打开目标","workspace":{"action":"case-search","id":"任务UUID","query":"已知结果关键词"}}
{"target":"实际已打开目标","workspace":{"action":"case-read","id":"任务UUID","ref":{"id":"命中id","sha256":"命中SHA"}}}
```

case-index是显式索引元数据维护，不改任务或研究修订。查询、状态和read不写私有索引；case-search可复用原LCM懒归档机制保存已提交宿主事件，不是保证完全无磁盘写入。generation可选绑定查询/read；read将nextCursor原样续读到null，正文SHA绑定整份JSON笔记，2048 UTF-16单元不切代理对，每响应32KiB。

可信scope由mgr.evidence、InvestigationStore.get及ResearchState.get派生：project/artifact SHA/engine/provider/attachment/db/task/revision/contractDigest全绑定。外部没有scope/project/path/run输入。静态任务runId/moduleEpoch=null，liveRunBound=false，不声称运行态或VM实例身份已知；涉及执行仍须原工具和run/epoch证据。

缺少研究合同、研究任务/attachment/db陈旧返回needs-evidence；没有当前索引返回needs-index；源状态或合同版本改变返回needs-refresh。相同合同内容A→B→A仍被研究revision/contractRevision/sourceStamp识别，不复活旧事实。所有读写检查前后上下文，LCM异步等待后也复核；提交后源失效或读取失败返回indexSaved=true和确切代次，不能误报回滚。发布后锁清理失败明确保留已提交状态，未知锁不回收。

## 来源和等级

固定来源为当前任务声明、研究假设/义务/实验、任务绑定dossier、已关联verifier历史和原FailureRecords的最近3份已提交失败。另由宿主列出同project/artifact/engine/provider的最近8个其他任务声明，回读草稿指向原任务；这些旧结论始终reported，原声明没有attachment/db绑定时明确null/unknown，不当作当前数据库事实。其他任务的报告/研究不会借此自动获得访问或证明权限。源任务修订改变同样使sourceStamp失效。

最多8份相关任务/8份dossier/8份verifier（报告各份原128/256KiB上限）、每类研究提案最新8份，omittedSources逐项明示；共64记录。损坏报告只有诊断，不用未核验正文。body保存所选完整sourceData；搜索只覆盖元数据和显式source projection的前4096单元，不能称全库全文检索。

任务完成/结论始终reported，系统dossier只按来源完整性observed并保留truncated/unsupported/error章节。假设同时声明supporting/opposing链接时可标contested，这是提案中的冲突标记，不是独立语义裁决。verifier历史始终reported或stale，不复用其中pass关闭义务；真实有效性仍由research-verification/原性质注册表核对。搜索与阅读都明确algorithmExplained=not-established-by-index，知道输出与解释算法始终分开。

source.contentSha256在dossier/verifier/failure中是原报告完整字节摘要；任务/研究提案使用固定投影JSON摘要，parserVersion=case-host-projection-v1，不能误称原projects.json文件摘要。状态/数据没有自然语言推断、通用秘密检测或任意来源导入；私有目录是插件读取合同，不是同账户OS隔离。

LCM只在case-search中用真实执行agent/session/cwd对精确任务UUID做原搜索，最多3个read导航，无preview/正文写入索引。UUID在原文被提及不是项目事实认证，historyNavigation单独标session-navigation-only、contentIndexed=false；恢复仍用原memory read/expand逐页核验并重验目标范围。空命中不证明没有历史；不同宿主会话不合并。memory:false或缺可信session时索引仍可用，导航明确unavailable。

## 历史、兼容和范围

复用private-research-v2/<scopeDigest>的不可变记录/代次与CAS。相同scope显式刷新替换记录，旧版本和撤回正文保留；历史read明确recordState和currentSources=false/status=stale。task/db/attachment变化后不猜旧目录，没有公开的跨scope恢复入口。F02每scope 256历史版本、64MiB等上限不变，没有全局容量或GC承诺，超限拒绝而非自动删除。sourceStamp变化会为当前所选投影产生新版本，频繁刷新应留意历史配额。

旧任务格式、原planner candidates/恢复清理优先级、brief、UI不变；默认不检索或注入。方法适用性与实验去重/提案属于F05/F06；本包只检索原失败及建议，不新增抑制/重试权限。没有可用静态会话时返回缺件，不启动后端/受4551阻止组件。

回归npm run test:case-index。源码/安装SDK、模拟静态session、真实LCM SQLite、实际桌面路由、原生/GUI/模型收益分别报告，不能互相替代。回退部署前代码后保留独立私有索引及报告；旧代码忽略该入口，公共F03 v2不得移除或改回v1。执行既有备份/逐SHA同步/依赖重载流程；不删除任务、预算、失败或锁。
