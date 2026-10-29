# PR10 首批：离线时间关系与观察点代码版本

显式调用原 `ig5_recovery recovery.observations`，增加 `phase_model:true`：

```json
{"recovery":{"observations":{"recordings":[{"id":"已提交 debug-trace UUID","sha256":"完整报告 SHA256"}],"target_sha256":"目标 SHA256","phase_model":true,"offset":0,"limit":32}}}
```

保持原录制 v1/v2、256 窗口/16 MiB、默认 50k 显式 100k 指令、1..64 停止组分页、64 MiB/15 秒单 worker 与 1+4 队列。只读已提交录制，不执行目标、解码器或模型，不新增审批入口。新模式使用原 runSettled 路径确认 worker 终止后才保存；原观察模式的默认输出不变。完整页面和全部窗口来源保存为原 `vm-native-observations` 报告的可选 `phaseModel` 扩展，未改写旧录制或旧报告。

## 时间关系

逐组保留进入和下一暂停点、读观察、STORE 变化、未读回的写位置、重复控制位置以及代码字节变化。进入不是已证明的函数入口，退出不是已证明的返回；重复 PC 不等于分发器。初始化、分发、业务阶段均保持 unknown，verifiedPhase=null、phaseVerified=false。

候选是 first-observed-control-location、revisited-control-location、observed-memory-change、observed-code-change；无法索引的位置为 unindexed-control-location。最多跟踪 4096 个控制位置，超限单列 unindexedVisits，不冒充“首次访问”。STORE 前后相同不证明没有写；没录制 STORE 时 unknownStores=null，不写成零个未知写。

变化位置与曾观察到的指令字节地址重叠时保存相关版本引用，只有地址重叠这一事实；并发、异常、变化后恢复或其它原因仍未排除，actualWriteCausalityProved=false。不由加载映像元数据推断执行期间代码不变。

## 观察点版本

每个指令字节观察都有内容 SHA 和独立版本 ID，绑定目标、run/thread/runtimeBase/执行位置指纹、源报告 UUID/SHA、原始 trace SHA、group/暂停区间、源行、PC、字节及中间状态是否可见。相同内容在不同停止点也有不同版本 ID。

code_epoch_map 跟踪最多 16384 个字节位置，按重叠字节比较而非只按指令起始地址；宽度变化不掩盖重叠变化。observationEpoch 只在已观察字节发生变化时递增，不是全局代码或内存 epoch。超限保留 lower-bound / trackingComplete=false；所有间隔 intervalStable=unknown。模块加载与全局内存 epoch 始终 null。

内部 requireObservedCodeVersion 只接受同一可信观察点的完整绑定，拒绝跨版本/跨停止点拼接。它不认证任意调用者提交的对象；宿主以已核验原录制重建 expected binding。CPUID 合并续指令仍没有中间 GPR/flags 快照，不借前后状态填空。

## 验收和范围

`npm run test:vm-phase` 覆盖变更后恢复原字节、地址重叠/宽度变化、版本及来源篡改、跨停止点拼接、缺失写、相同字节写观察、合并指令、分页、界限与取消、宿主拒绝伪造阶段。自产观察格式夹具可分辨前缀、重复控制、代码位置变化的时间关系，但它没有执行 CPU 指令，不能作为自产原生初始化/分发语义通过。

`replay_vm_phase_model.mjs <全新输出目录> <原 artifactDir> <录制 UUID> <报告 SHA>` 走原入口处理冻结旧录制，验证重叠分页身份和输入不变；`audit_vm_phase_replay.py <输出目录>` 独立解析无 STORE sidecar 的原记录，复算所有代码字节变化与控制统计，并核验公开页的观察点版本。审计不导入模型实现，不验证 CPU、SMC 完整性或 VM 阶段。

本批尚未接通独立初始化/分发/业务阶段验证器，也未补采新原生事件。已知 4551 阻断记录保留，不为扩大覆盖重复启动、复制或改名组件。后续在真实就绪且经过原审批的采集条件下补充自产初始化/分发/代码写入实验，不能用这份观察覆盖层宣称 PR10 的全部阶段验收完成。

回滚移除 phase_model 参数和 worker 可选分支，保留新报告作历史数据；原 v1/v2 读取、原观察输出和所有来源文件不变。


## PR10 第二批：已审计 context 与原录制的候选区间绑定

在 `phase_model:true` 时可增加 `phase_context_ref:{id,sha256}`，只接受已提交 context 报告的确切 UUID/SHA。输入 recordings 必须与 context 的 selection/recurrence 中保存的完整有序窗口清单一致，包含 report/trace SHA、位置、停止序列与计数；不能传子集后沿用原全局 group 编号，也不能合并不同 run/thread/runtimeBase。

宿主复用现有 VM context 证据适配器读取根与三类直接父报告；原64份/合计8MiB报告预算不扩。trace、STORE sidecar与context字节总量共同限制在16MiB。单次关联最多128个已有候选周期、2048个fetch/body组绑定；超限拒绝，不悄悄省略。原worker的64MiB/15秒与1+4队列不变，完成清理后才保存。

同一worker首先运行固定独立context派生审计，然后从原录制重新核对选中fetch指令字节、首次/末次完整GPR和暂停身份、实际源读值、间接目标、全部选中body快照，以及下一确切fetch头。输入后段损坏、任一绑定缺失或不一致都不发布结果。

phaseModel.contextAnnotation 保存 fetch-dispatch-candidate / handler-body-candidate 区间、原recurrence/selection引用和首末观察点版本ID。宿主从原始i/c行独立重建端点ID，包括返回页面以外的端点。前缀只标 unclassified-prefix-not-proved-initialization，未被选中周期覆盖的区域标 unclassified-context-gap；不是把整段录制都涂成分发或handler。所有语义阶段仍unknown，phaseClassificationProved/vmRoleProved/businessAccepted=false，区间稳定性仍unknown。

公共预览最多四段，并提供totalSegments/segmentsPreviewComplete；完整区间在原SHA绑定报告中。context审计的pass只描述候选派生，不能关闭阶段或函数合同。原运行包、解码器与CPU语义仍是前提；本批不新增采集，不扩大指令/求解预算，不接受调用者填写角色、阶段或地址。

`replay_vm_phase_context.mjs <全新输出目录> <原artifactDir> <context UUID> <SHA>` 通过原公开入口回放所有源窗口，冻结前后输入摘要，并保存前缀与选中周期页面；`audit_vm_phase_context.py <输出目录>` 调用既有独立Python context审计后，独立重建原始r/d/e/mr/i/c/f快照，复核选中body、fetch读值/前后状态、下一头和全部区间端点。当前Python原始回读审计限定无STORE sidecar的旧录制；有sidecar时明确拒绝而不跳过。它不证明VM阶段、原生可达性或完整SMC。

新增 INVALID_PHASE_CONTEXT / CODE_VERSION_MISMATCH 保留为结构化研究失败，分别要求重验完整清单或读取确切观察点版本；错误回执不授予执行权限。回滚第二批时移除phase_context_ref和候选注释桥，保留第一批观察点版本与历史报告。
# STORE 快照与下一代码观察（第三批）

`versions[].relation.storeObservations` 关联已观察代码上的 changed STORE 快照和下一次相同字节地址的执行观察。每个字节保存原报告/trace/STORE blob SHA、组号/停止序列/STORE索引、前后代码版本及四个原始字节值，分别给出 beforeMatches/afterMatches。冲突保留，不能通过匹配推断指令写入原因；`actualWriteCausalityProved=false`、`intervalStable=unknown`。

同一字节在下一代码观察前出现多份快照时，保留第一份、记录 observationCount 和 ambiguous，不按 decoder 枚举次序重建写序。只有已跟踪的最多16,384个代码字节可持有待关联快照；未观察代码、unknown/unchanged STORE 不产生 changed 关联。末尾 pending 和原 trackingComplete/下界明确记录；下一观察消费后不能跨越冲突重复沿用。

宿主在保存结果前完整回读原始录制，复算时间统计、代码变化和 STORE 关联，包括返回页之前的事件。它是 worker 输出与来源的一致性验证，不是独立 CPU 语义证明。原16MiB输入、64MiB/15秒数据worker、4MiB报告和分页预算保持不变。

## 独立参考夹具验收

`scripts/fixtures/phase_reference.py` 用固定有限指令参考生成5组不可覆盖的离线输入：CLC/STC代码修改、相同字节写、写后快照缺失、重复decoder枚举。它模拟MOV/JMP/NOP/CLC/STC及两处写入，不执行机器码。初始化前缀、重复控制、代码更新的标签只属于固定夹具布局；普通循环仍是竞争解释。

```powershell
.\runtimes\ghidra\python\python.exe -I -B scripts/fixtures/phase_reference.py NEW_FIXTURES
node scripts/accept_vm_phase_reference.mjs NEW_FIXTURES NEW_OUTPUT
.\runtimes\ghidra\python\python.exe -I -B scripts/audit_vm_phase_reference.py NEW_FIXTURES NEW_OUTPUT
```

验收器将原始trace/STORE提交到独立测试目录，经原recovery.observations入口运行完整页、单组页和默认模式；负例不能新增结果报告，数据worker必须退出。Python审计独立重算固定指令状态、原始字节/flags/完整GPR、来源摘要及代码观察区间内的STORE关联，拒绝篡改输出。它通过枚举观察区间计算关联，未调用JS的pending tracker。

录制schema要求的nativeTargetExecuted=true只存在于明确标注fixtureMode的模拟输入中；顶层夹具/验收/审计回执均为nativeTargetExecuted=false。输入、结果和测试污染均不进入用户真实录制目录。不得把格式字段当作采集证明，不证明通用VM阶段、完整CPU或SMC覆盖。

`test_vm_phase_model.mjs` 另在原64MiB/15秒worker中覆盖16,384个待关联字节、跟踪上限和清理；该压力夹具也只验证格式与资源边界。
