# 固定离线验证器与 VM context 证据（PR 06—07）

新增 `ig5_workspace` 的 research-verify、research-link-verification、research-verification；Core8/Full40 和 13 个原审批入口不变。生产验证不启动 Python、引擎、解码器、目标进程或网络操作。

## 证据入口与范围

在当前研究状态下调用 research-update，operation=link-vm-context，同级提供 report_ref={id,sha256}。仅接受当前 AnalysisArtifacts 中已提交的 vm-context-model/derive、ig5-vm-context-model-v1，目标 SHA 必须属于本调查。调用者不能传路径、角色、阶段或 opcode 解释。

适配器核验 context 及其 handlers / recurrence / selection 三类直接父输入：已提交 metadata、UUID/SHA、完整字节、kind/action/schema、目标身份、来源交叉绑定与存储位置。路径只作为原报告中的一致性约束，实际读取由受控 records 目录和 UUID 构造；不能借父引用读其他路径。单文件最多 4 MiB，一次聚合最多 8 MiB、最多 16 组父输入。核验回执视图另有最多 64 份不同提交记录的总读取上限。

该范围不包含更早的录制、投影解码器及 CPU 指令语义的重新证明。它们保留为前提，不能把直接父输入闭包宣传成整条采集链已独立验证。

VM context 的 dependencyType=immutable-bytes。无关数据库注释或 attachment 改变不会使该证据字节过期；任务研究上下文仍可单独 stale，写操作须先检查并确认。合同版本、模型版本、报告或任一直接父输入变化会影响相应验收。

首次关联 VM context 时，在同一次研究 CAS 中把该 sidecar 从 ig5-research-state-v1 升为 v2，增加只由系统写入的 verificationRefs。未使用新类型的 v1 保持原格式，旧任务 schema 不变。升级不删除原合同、提案或 dossier。旧 PR 05 代码不能读取 v2 研究记录；回滚时应保留新记录，使用原任务入口，或在明确需要时恢复升级前的 sidecar 备份，不能直接删字段降级。

## 建立有界义务与实验

当前唯一注册方法：

- property：vm-context-candidate-derivation-and-provenance
- verifier：vm-context-audit-v1
- scope：evidence:<本研究 evidenceLinks UUID>

三个字段必须精确匹配，才能关闭该项义务。自由文本的“全部输入”“业务恢复”等范围返回 unsupported。未关闭的依赖会得到 unknown，不运行 worker。

可关联一个当前合同下、未被替代的 review-evidence 实验。其 inputs 必须包含该证据 UUID，obligations 包含该义务 UUID。提案预算不能小于固定 worker 时间包络和实际输入字节量，否则返回 unsupported，要求显式修订提案，不偷偷扩大预算。

```json
{
  "target":"已打开目标",
  "workspace":{
    "action":"research-verify",
    "id":"任务 UUID",
    "verification":{
      "expected_research_revision":4,
      "expected_task_revision":1,
      "scope_digest":"research-get 返回的 scopeDigest",
      "evidence_id":"本任务关联的证据 UUID",
      "obligation_id":"当前合同下的义务 UUID",
      "experiment_id":"可选的实验 UUID"
    }
  }
}
```

不接受 command、verifier_script、passed、调用者 verifier 实现或任意路径。宿主的嵌套 schema 不能代替校验，入口在运行时再次检查全部字段。

## 独立复算与资源边界

source/verifiers/vm_context_audit.js 不导入候选派生代码；独立核对输入 SHA、typed parent、观察计数、fetch/dispatch/carrier 候选、VSP 候选统计和排序、handler 字典、unknown GPR/STORE 以及 false/unknown 证明边界。源 CPU/解码判断仍来自共同录制输入，sharedDependencies 明确披露这种共同前提。

独立 Python 审计 scripts/verify_vm_context_model.py 保持原实现，回归单独运行它并对照重叠范围。生产没有用 worker 再调用 Python，也没有开放用户脚本通道。

执行复用原 AnalysisJobs：64 MiB、15 秒、1 个活跃 worker＋4 个排队项。runSettled 等待本任务 worker 的 terminate 回执再交付结果；取消、超时只处理所属数据作业。若终止确认失败，保留资源未知状态并关闭此数据服务，不启动下一作业，不推断原生调试资源已清理。

## 验证报告、关联与恢复

不可变 research-verification/verify 报告保存：verifier ID、加载时代码摘要、规则摘要、Node/V8/平台/架构与宿主可执行文件 SHA，合同版本和 digest，义务及其内容摘要，证据/实验 UUID，完整输入及父输入 SHA，方法、前提、覆盖、排除范围、共同依赖、结果与失败见证。状态分别为 pass/fail/unknown/unsupported/error。加载后规则文件改变则要求重新加载，不能用旧宿主为新规则签发回执。

先提交完整报告和 metadata，再 CAS 关联研究状态。CAS 冲突返回 reportSaved=true / linked=false 和精确 UUID/SHA；重新读取修订后，用 research-link-verification 与同一 verification 输入、report_ref 重新关联，不能重跑实验替代关联。

报告记录文件已写入但 metadata 失败时，返回 recordSaved=true、reportSaved=false、linked=false。metadata 已提交而索引报错时，经实际回读核验后可返回 reportSaved=true、linked=false，允许恢复关联。保留原 Error 和提交阶段信息，不宣称跨文件回滚。

research-get / brief 从已提交完整报告重新核验规则、运行资产、合同、义务和输入，不信任 sidecar 的调用者判定。视图最多读取最近 8 个回执，其余明确 omittedOlder / complete=false；依赖查询也标注是否完整，不把空结果当作无依赖。旧回执始终可通过 research-verification 读取，并单独显示 currentAssessment，过期 pass 不作为当前验收。

通过时对应义务显示 closed-in-scope，实验关联真实系统报告。调查 acceptanceStatus 最高为 partial，不自动完成工作，不把资源状态升级为已清理，不修改原 VM case 的 verifierAdapter、观察或业务 false 字段。

## 验证入口

- npm run test:research：严格字段、CAS、来源、状态、独立验证、取消、预算、部分发布与恢复。
- npm run test:vm-context：原派生、独立 Python 与接口回归。
- scripts/replay_research_verification.mjs NEW_OUTPUT_ROOT ANALYSIS_ARTIFACT_ROOT MODEL_UUID SHA：固定已有录制报告，经真实 workspace 代码与数据 worker 验证并保存结果。静态 session 身份由夹具提供，不宣称宿主真实引擎会话或 GUI；不执行目标，不调用模型 API。

本次两页、16 个已有观察的复算保留 6 个未知 GPR 结果、10 个未知写入值。具体报告、源文件 SHA、安装副本与宿主检查见工作区根目录 PR 06—07 交付记录。
