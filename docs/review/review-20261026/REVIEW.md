# 2026-10-26 顺序复核：R7、R10、发布前置项

执行者：Codex。本聊天指令为“依次推进审查”。审查及修复授权不被记成真人签字，不代替所有者接受契约或风险。`docs/review/ledger.json` 保持原样。

对象：Desktop 下源码目录 `dsh-infinite-gen-5`，版本 1.2.0。未修改真实已安装插件，未重启 DSH，未进行新的真实模型会话。原回测证据保留于工作区 `_research/ig5-regression-20261026/`，本轮新增证据在 `_research/ig5-review-20261026/`。

## R7：已定位并修复

原回测在 31 条 PASS 后中断。本轮使用 `scripts/test_install_package.ps1 -KeepFixture` 再现同一失败并保留 fixture：index.js 已恢复为 `export default {};`，其哈希与发行清单一致，而 `plugin/extra_payload.dll` 仍存在。默认 `Get-IG5PackFiles` 没有枚举这个 DLL；原始枚举可以看到它。因此明确是脚本第 603 行的“额外载荷应被拒绝”子检查失败，前面的代码篡改拒绝检查已完成。

原因：源码打包的根文件白名单过滤被完整发行包的库存校验复用，额外 DLL 被当作源码根杂物跳过。安装器实际没有将 DLL 复制进已安装目录，但错误地接受了不符合完整发行清单的输入。此问题不能描述成“DLL 已执行”。

修复在 `scripts/runtime_pack.ps1`：新增显式 `IncludeUnlistedRootFiles` 枚举选项，只有完整发行包的 `Assert-IG5PluginSource` 清单核验启用它；源码打包仍跳过 fixture.exe、err.log、out.log，未登记代码仍报错。既有排除目录规则、runtime pins 和工具契约未放宽。

验证：

- 快速打包回归 10 个场景通过；新增负例涵盖额外 DLL、EXE、日志、JS。
- 完整安装回归 **36 个场景通过**，退出 0；实际数量不是历史的 37，不增补或伪造场景数。包括篡改代码和额外载荷拒绝、失败回滚、卸载和用户数据保留。
- 证据：`R7-reproduce.log`、`R7-fixture-state.json`、`R7-pack-regression.log`、`R7-fixed-install.log`。原失败未删除或并入通过数。

## R10：带版本绑定的增量复核，签署状态不变

基线是 `docs/review/review-20261024/coverage.json` 的 36 文件逐文件阅读记录和 `RE_REVIEW.md` 的五文件修复复审，不把历史证据冒充本轮重新逐行阅读。

- 28 个文件与旧逐文件阅读版本字节一致：承接历史阅读记录并核对哈希，本轮不宣称重新逐行阅读。
- `history_index.js`、`project_store.js`、`worker/ig5_worker.py` 与仍有效的三项授权代理复审哈希一致：保留既有签署。
- 两个过期文件 `adapters/x64dbg/adapter.py`、`source/worker_manager.js`：安装副本经哈希证实仍是已签署基线；本轮直接比较该基线与源码，增量均为 P8 API trace 接线，核对暂停/后端前置条件、运行状态、返回证据及落盘失败不抹去执行事实。原清理/部分提交修复没有被增量删除。
- `index.js`：核对 P2 工具拆分、注册与队列、旧参数拒绝，P7 rules 字节上限及 P8 参数预算/后端接线。
- `capture_tools.js`：核对 correlate 的参数、分派和既有审批工具不变，另追踪 `traffic_correlate.js`。
- 新增 `source/api_trace.js`：核对 schema、调用数上限、覆盖计数、不可变报告、目标哈希绑定与释放。
- `worker/cpu_emulator.py`：复核新增写轨迹及其预算/截断。本轮发现并修复单区间长度截断漏报，详见下节。

这是一份“历史完整审查 + 字节一致核对 + 当前增量复核”的审查记录，不是全部 37 文件的全新独立完整阅读，不构成全部依赖链、商业后端或真实业务通过。

台账仍为 **3 有效 / 2 过期 / 32 未审查**。两项过期已有本轮增量复核证据，但不自动改签；未签署项也不因测试通过而签署。未经所有者明确授权，不执行 `--sign` 或更新 ledger。现有自动批准配置不构成人工复审或风险接受。

## 本轮另发现的两项证据完整性问题

1. CPU 写轨迹：合成 CPU-only 探针改写 5,000 字节，原实现只输出 4,096 字节，却返回 `writesTruncated=false`。修复将单区间裁剪纳入截断标志；1 MiB/64 区间/4,096 字节预算均不变。边界测试覆盖 4,096、4,097、5,000 字节，CPU/字符串相关离线套件实际 18 项通过。
2. P9：合成样本中相同 origin 出现 6 次，原实现只返回 4 次，却返回 `coverage.matchesTruncated=false`。修复用一个额外匹配探测每条字面量是否被截断，返回上限仍为 4、总上限仍为 256。P9 套件实际 8 项通过，含精确 4 次与超限边界。

前后探针分别保存在 `R10-cpu-probe-before/after.json` 和 `R11-P9-probe-before/after.json`。数据是合成内存和普通本地字节文件，没有执行原生目标或采集真实流量。失败现象和修复后结果分别保留。

## 发布前置项

五项契约的逐项技术建议及证据边界见 [CONTRACTS.md](CONTRACTS.md)。真实安装和模型会话的具体操作及验收条件见 [R8_R9_PLAN.md](R8_R9_PLAN.md)。这两份文件是待所有者确认的审查材料；没有把“推进审查”解释为已经批准真实安装、重启、签字或五项契约。

最终验证结果、当前哈希及便携包路径见工作区 `_research/ig5-review-20261026/RESULTS.md`。缺少真实安装、真实模型会话、台账收口或所有者逐项契约确认时，不宣称“改造完成/可发布”。
