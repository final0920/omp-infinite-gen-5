# 调查研究状态（PR 05）

F04新增显式私有任务结论/失败索引，见[CASE_INDEX](CASE_INDEX.md)。case-index只派生并发布独立索引，不改变下面的研究/任务修订和验证状态；case-search/read不修改原planner或自动恢复执行。

现有 `ig5_workspace` 新增 research-get、research-update、research-dependencies。保持 Core8/Full40、13 个审批门、旧任务 schema 和 taskRevision 不变。只读写调查元数据，不执行实验、引擎计算或修改数据库。

## 修订与存储

实际路径为 `projectRoot/investigations/research-v1/<task UUID>/projects.json`。复用现有 ProjectStore 的所有者锁、稳定读取和原子发布，每个任务一个独立命名空间。不建立第二套 blob 系统。不存在 sidecar 时只读查询返回 research=null，不创建目录；旧任务无需迁移。

每次写入需要当前 expected_research_revision、expected_task_revision 和 scope_digest。先读 research-get 获取 scopeDigest；首次初始化使用研究修订 0，初始化结果也是 0，后续每次提交加一。

合同保留完整版本，digest 标识内容，contractRevision 标识版本。合同 A→B→A 仍是新版本，旧义务不会重新变为当前义务。提案用 revise-hypothesis / revise-obligation / revise-experiment 和 entity_id 修订：追加新 UUID，通过 supersedes 指向旧提案，旧值保留，已被替代的版本不能再次被替代。objectStates 区分 proposed/open/planned/superseded 和 staleContract。

任务修订、attachment 或数据库修订改变后，研究状态标 stale。检查变化后，用 acknowledge-context 显式确认；确认不更新证据或证明合同。普通写入不能顺便确认旧状态。任务与研究不是跨文件原子事务；提交后重读上下文，变化标 stale。提交后取消或读取失败仍返回 researchSaved=true 和 writtenResearchRevision，不误报回滚。

上限：32 个假设版本、64 个义务版本、128 个实验版本、256 个证据链接、64 个合同版本，紧凑状态 JSON 256 KiB。旧版本计入上限，超限明确拒绝，不隐式删除未决项。格式化存储文件读取上限 1 MiB。用户不能指定输出路径。

## 入口

先读取：

```json
{"target":"已打开目标","workspace":{"action":"research-get","id":"任务 UUID"}}
```

初始化（占位符换成实际返回值）：

```json
{
  "target":"已打开目标",
  "workspace":{
    "action":"research-update",
    "id":"任务 UUID",
    "research":{
      "operation":"initialize",
      "expected_research_revision":0,
      "expected_task_revision":1,
      "scope_digest":"实际 scopeDigest",
      "value":{
        "question":"解释此函数的分支和返回",
        "inputDomain":"明确列出的输入范围",
        "returns":"需要确认的返回性质",
        "outputs":"需要检查的输出，或明确没有此要求",
        "sideEffects":"需要检查的内存副作用",
        "environment":"已知运行环境和前提",
        "exclusions":"未覆盖的输入和性质"
      }
    }
  }
}
```

operation 与 value：

| operation | value |
|---|---|
| initialize / set-contract | 上述七项合同字段 |
| add-hypothesis / revise-hypothesis | proposition、supporting/opposing（本研究 evidenceLinks UUID 数组）、competingExplanations（文本数组） |
| add-obligation / revise-obligation | property、dependencies（已有义务 UUID）、scope、verifier（拟用方法名称） |
| add-experiment / revise-experiment | template、question、inputs（证据链接 UUID）、hypotheses/obligations（UUID）、budget、predictedDivergence |
| acknowledge-context | 不接受 value |
| link-evidence | 不接受 value；workspace 同级给本任务 snapshot_id |

revise 还需 research.entity_id；其他操作拒绝此字段。所有数组和文本有固定上限，额外字段在运行时拒绝，不依赖宿主是否执行嵌套 JSON schema 校验。verifier 名称只是拟用方法，不能关闭义务。

实验模板固定为 refresh-static-source、review-evidence、compare-inputs、inspect-counterexample、locate-first-divergence。budget 的 toolCalls 为 1..32、timeoutMs 为 1..60000、bytes 为 1..8388608。这是提案预算，不授予权限或扩大原工具预算。执行仍须原工具和原审批；不接受命令、脚本、结果回执或调用者提供的通过状态。

## dossier 证据适配

本批接入固定 function-dossier 适配器，新链接单独放在 evidenceLinks。仅接受本任务已记录的系统 snapshot UUID，校验已提交报告 metadata、完整字节 SHA、UUID/schema/kind/action、目标 scope、函数和章节。单份读取上限 128 KiB，现有生成预算最高 64,000 字节。任意 path + SHA、其他任务报告和调用者 assurance 均不能成为新证据。

assurance=system-snapshot-integrity，supportedProperties 只有 dossier-provenance-and-structure。它不证明反编译语义、VM 角色、实验运行或完整函数合同。partial/truncated/unsupported/error 保留在原报告中；使用原 workspace evidence 回读完整内容。

关联失败返回 reportSaved=true、linked=false 和精确报告 UUID/SHA。重新读取当前修订后可以再次关联，不重跑采集。成功提交后的上下文读取失败仍是 linked=true，另报 postCommitContext=unavailable。

research-get 最多核验 16 份不同 dossier，重复链接复用本次核验，其余明确标 not-read-budget。DB-bound dossier 因 attachment/dbRevision 改变而 stale；合同版本变化另记 contract-changed。

research-dependencies 需要 evidence_id，重建本 sidecar 中假设和实验的依赖。completeWithinTask=true 仅指当前提交状态，globalStatus=partial；空结果不证明其他任务或报告没有依赖。

## 恢复与验收

brief 增加 researchRevision、合同引用、研究陈旧原因、提案计数和有界预览。按 research.fullRef 读完整状态。读取前后检查 taskRevision、researchRevision 和数据库上下文，一次有界重读后仍变化返回 SNAPSHOT_INCONSISTENT。游标同时绑定研究修订。

workStatus 来自旧任务；没有已核验回执时 acceptanceStatus 为 not-assessed、义务保持 open；固定狭义验证通过后最高为 partial，见 RESEARCH_VERIFICATION.md；没有可靠生命周期回执时 resourceStatus=retained-unknown，需向原资源所有者查询。三者不能互相推导。

PR 05 的基础状态和 dossier 适配保留。PR 06—07 已接入 VM context 三类直接父输入与固定狭义验证器，见 [固定离线验证](RESEARCH_VERIFICATION.md)。实验规划器另行推进，不沿用旧 VM case 的调用者 observations 宣布通过。

回滚恢复代码即可，独立 research-v1 目录保留；旧版本继续使用原任务，不清除新数据。回归入口 npm run test:research；真实静态流程 npm run test:investigation-runtime；宿主兼容 npm run test:host-sdk。本次执行记录见工作区根目录交付记录。

F05 方法合同与三值回执见 [METHOD_APPLICABILITY.md](METHOD_APPLICABILITY.md)，只读显式查询，不改变旧规划器。

F06 独立 shadow 建议与重复抑制见 [EXPERIMENT_SHADOW.md](EXPERIMENT_SHADOW.md)。旧 plan 默认路径不读取新资料或生成新建议。

F07 纯位向量候选合同与独立验证见 [BITVECTOR_CANDIDATES.md](BITVECTOR_CANDIDATES.md)。该独立回执不自动关联旧 obligation，不改变其证明状态或 F05 方法适用性。
