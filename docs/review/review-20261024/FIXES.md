# 评审 review-20261024 的修复记录

对应报告：[REPORT.md](REPORT.md)（8 项 P2，涉及 5 个文件）。修复日期：2026-10-24。
**本文件由修复方（AI 代理）编写，不是复审结论。** 复审、重新判断整体是否通过，以及人工签字台账，仍须由评审方和真人完成；本次没有修改任何签字。

> 编号说明：下文 R1–R8 沿用评审报告的编号，与 `REVIEW_CHECKLIST.md` 里我方的 R1–R11 无关。

## 一览

| 评审编号 | 问题 | 修复 | 回归测试 | 验证层级 |
| :-: | :--- | :--- | :--- | :--- |
| R1 | 可重复注释 Undo 恢复了错误的注释通道 | 日志记录被修改的注释通道及其原值；Undo 按原通道恢复并回读核对 | `test_review_20261024_python.py` ×2 | 模拟 API |
| R2 | 商业调试写入忽略 `expected` | `setreg`/`writemem` 写前比较原值，不匹配、长度不符、读不全都拒绝且不写；写后回读核对寄存器 | `test_review_20261024_python.py` ×4 | 模拟 API |
| R3 | 显式分析吞掉 API 失败 | 任何一步失败返回 `ok=false`；仅一步失败标 `partial=true`；`auto_wait` 返回 `False` 视为失败 | `test_review_20261024_python.py` ×2 | 模拟 API |
| R4 | 商业导出查询把分析入口当导出表 | `exports` 改读真实 PE 导出目录（复用 Ghidra 分支的有界读取器），读不到时返回 `partial/unsupported` 而不是冒充；新增 `entries` 分支并标注语义 | `test_review_20261024_python.py` ×3 | 模拟 API |
| R5 | x64dbg 未确认进程退出便宣告清理完成 | `cleanup()` 返回是否有退出与 Job 关闭证据；没有证据则保留进程/Job 引用，`cleanedUp=false`、`state=cleanup-unconfirmed`；`close` 返回 `ECLEANUP`；有未确认进程时拒绝再次 `launch` | `test_review_20261024_python.py` ×4；既有 `test_x64dbg_cleanup.mjs` | 模拟进程 + **原生实机**（64/32 位各一次，通过） |
| R6 | 多实例保存使历史列表漏项 | 保留增量插入，但标记为"未校验"；下次命中缓存前核对目录里的记录文件个数，对不上就丢弃缓存并重扫 | `test_review_20261024_node.mjs` ×3；既有 `test_analysis_host.mjs`（大历史目录） | 真实临时目录 |
| R7 | 项目锁缺主机身份，可能回收异主机活锁 | 新锁写入 `hostName`/`platform`；异主机或异平台的锁视为存活，不用本机 PID 探测放行；缺少这两个字段的旧锁保持原样并按"无法识别"失败关闭 | `test_review_20261024_node.mjs` ×3；既有 `test_project_store.mjs`（22 条） | 真实临时目录 |
| R8 | 修订提交失败覆盖部分提交凭据 | 元数据失败时保留 worker 的原始回执（`committed/saved/partial_commit/recoveryRequired/journalId/revision` 等），另附 `metadataFailure`；成功路径同样保留 `operationResult` | `test_review_20261024_node.mjs` ×2 | 模拟 worker 进程 |

## 复现脚本对照
评审的两个原复现脚本（它们断言"缺陷存在"）在修复后的代码上都在第一条断言处**失败**：
`reproduce_python.py`（R1 的 Undo 断言）与 `reproduce_node.mjs`（R6 的列表断言）。这说明缺陷现象已消失，但只执行到第一条断言；各项的具体行为以上表的回归测试为准。

## 需要特别说明的取舍和风险
- **R6 先做了一版"保存即失效"，被既有测试 `test_analysis_host.mjs` 拦下**：一次性保存 2228 条记录后，下一次列出需要重扫超过 16 MB，只能返回部分结果，是性能退化。最终方案是"增量插入 + 命中前校验个数"。校验只数目录项，不读文件内容。它能发现"别的实例在我们之前提交、而我们没见过的记录"，但**不处理同名文件被替换**（元数据按 ID 命名、写后不可变，本就由既有的摘要比对覆盖）。
- **R7 的兼容影响**：升级前遗留的、没有 `hostName`/`platform` 的旧锁，不会再被自动回收，会报 `STORE_BUSY: Unrecognized project lock`，需要人工把 `projects.lock` 挪开。正常释放不会留下旧锁，只有进程崩溃遗留的才会触发。
- **R1–R4 只影响商业 Reverse（IDA）分支**，本机该商业安装的 DLL 无法加载，所以这四项**只有模拟 API 的验证，没有真实 IDA 验证**。默认的内置 Ghidra 分支不受影响。
- **R5 的"不确认就不释放所有权"**：宿主 `worker_manager.js` 只在 `cleanedUp` 为真或会话已死亡时才释放调试所有权，此处无需改动；适配器本身会保持存活并允许重试 `close`。若清理一直失败，需要人工结束残留的调试器进程。
- 评审提到的 31 个"未发现独立阻断项"的文件不在本次修复范围内，也不因本次修复而改变其状态。

## 变更文件
`worker/ig5_worker.py`、`adapters/x64dbg/adapter.py`、`source/worker_manager.js`、`source/project_store.js`、`source/history_index.js`；新增 `scripts/test_review_20261024_node.mjs`、`scripts/test_review_20261024_python.py`、`scripts/test_review_20261024_python.mjs`。这些文件的 SHA-256 已变化，台账里它们（若原先有签字）会自动变成"已过期"；目前台账仍是 0 个已审查。

## 后续复审与兼容处置（2026-10-24）

以上为修复时的历史记录。后续经 bai 明确授权，Codex 已复审并对 5 个新哈希记录代理签署；当前有效 5 项、未签署 31 项，非 bai 亲自逐行审查。结论与实测边界见 [RE_REVIEW.md](RE_REVIEW.md)。旧锁继续拒绝自动回收，新增显式离线预览/备份迁移工具，见 [LEGACY_LOCK_RECOVERY.md](LEGACY_LOCK_RECOVERY.md)。
