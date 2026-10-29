# PR 01 任务基准

12 个 development、8 个 holdout，每类分别 3/2。registry.mjs 校验输入 SHA、参考摘要、预算和运行记录，不认证调用者填写的 verdict。

构建：scripts/evals/build_targets.ps1 -Output <插件外新目录>，再执行 node scripts/evals/freeze.mjs <targets.json>。保留实际 MSVC/C/PE/MAP 摘要。verify_targets.mjs 使用真实静态引擎和原审批下的 Unicorn 核对列出输入的返回/内存写，并保存单例调查恢复的回放证据。这不是原生调试观察、全域证明或自主 VM 恢复。

model_compare.mjs [output] [pilot-evidence.json] 通过已安装 DSH SDK 执行 baseline/brief 各三次。准备独立 SDK profile：dsh --profile ig5-eval-v2 --from-default-profile sdk --help。
用 IG5_EVAL_PROVIDER/IG5_EVAL_MODEL 指定已有路由；可用 IG5_EVAL_PROVIDER_PATCH 传入已有路由的私有 overlay。凭据由原宿主解析，不写入源码/报告，不使用 mock 模型。

model_guard.mjs 只允许固定 JSON 查询，没有路径、命令和 oracle action，其他工具分发全部拒绝。实际 DSH SDK 测试验证渲染、额外 path 拒绝、跨工具拒绝。边界内运行可标 isolated；普通源码工作区运行仍算 exposed。保留分区不是盲测证明。

冻结 prompt、dataset、driver/guard 摘要、预算、模型及提供方，保存原始事件和每次工具请求。先运行 audit_model_compare.mjs <run-dir> <dataset> 保留被测脚本快照，再修改评测器；已有快照支持后续重复审计。
audit 从原始 assistant/tool 事件重新核对格式、返回值、位置、旧证据标记、当前证据回读、预算、token 和清理。空值、缺字段、JSON 后额外正文不算成功；调用者 accepted 和独立结果分别统计。格式失败不补跑替换；环境/评测器故障保留原始批次。

本轮完成一个开发任务的六次真实模型回放，其余任务仍保留 unrun。每次 fresh session 不能控制提供方缓存，因此 cacheRead token 单列记录；未计算货币成本，不由单例推断全项目成功率。

PR09 独立入口为 memory_resume.mjs，三策略直接日志/LCM/brief+LCM、同预算各三次；--models 使用真实 SDK。使用合成调查及模拟压缩，保持与原真实静态任务回放统计分离。运行 audit_memory_resume.mjs 从原始 SDK 事件重验条件、反例、来源回读和调用成本；环境阻断保留，效果未知不补成成功。详见 ../../docs/LCM_MEMORY.md。
