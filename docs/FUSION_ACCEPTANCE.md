# F13 同预算和交付验收

`scripts/evals/fusion/protocol.mjs` 保留原F00/F01冻结设计与exposed边界，旧十项VS1.5开发决策和原20项任务的未运行分母不改。新增独立两家族A–E实际模型辅助实验，不混入原基准成绩。

`run_models.mjs --evidence <插件外目录> [--limit N]` 首次调用前封存提示、全部driver/guard/案例/算法源码SHA、模型路由、任务/独立参考、预算和30次顺序；相同输出目录只可用完全相同源与控制继续。每个新会话20工具调用/16000总token（含cache-read）/120秒/65536返回字节，单模型请求输出上限2048；不另赠检索预算。提供方缓存、temperature默认和网络延迟不可控，明确保留。

A仅原始显式模型，B加原创方法笔记，C加条件，D加明确自产失败历史/提案，E加可选原F07/F08求解与独立重放或原F10数据worker。E算法不是假模型；仅对固定自产输入，不接caller代码/预言机/native执行。算法时延和结果读取计入总预算。模型可自行不调用可选能力，统计实际verify使用次数。

独立SDK使用原已有deepseek-official/deepseek-flash路由，密钥由宿主管理。单独评测插件通过实际工具restriction/monotonic guard限制可见能力，仅固定JSON动作；统一简短完整提示和无runtime context用于控制测量。它不改变桌面配置或产品审批，也不等于OS/网络隔离，始终exposed。全局文件/终端/网络/代理/私有评分工具拒绝，正文指令当数据。源码可见的准备/审计角色不是独立盲恢复方。

`audit_models.py` 不导入JS评分器，从原始模型/工具事件重算值、范围、实际来源SHA、调用/字节/token和冻结预算；独立检查source snapshots、失败/缺失分母及清理记录。初版冻结参考使用精确hex字符串，等值前导零会严格失败；保留主成绩，并另报数值口径敏感性，不悄悄修改旧判断。无正确答案或成本收益时不能默认assist。

`benchmark_off.mjs` 交错50对实际workspace plan/off路径、10对热身，检查返回完全相同和单进程中位开销；它不是模型或真实目标时延收益。`audit_protected_targets.mjs` 只重绑旧保护目标、录制、blob并在新目录独立回放保存表达式；不启动目标，不修改原证据。`check_target_intake.mjs` 核对原APK/ARM64 SO与现有318项保护资料身份，不代表恢复。

真实新采集遵循GUEST_DEBUG.md：实际VMX运行、可见桌面、服务认证、本次目标SHA和原审批/清理都须满足。VMware“正在使用中”且vmrun为0时不抢所有权或删锁；4551历史阻断组件不重试、复制改名或修改安全设置。原Core8/Full40、13门、预算/pins不变，未通过真实目标与完整同预算净收益门槛保持assist=false。
