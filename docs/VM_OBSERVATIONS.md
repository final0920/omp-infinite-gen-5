# 已录制原生状态的统一观察层

可选`record_events`补采解码器store位置前后字节，见[NATIVE_STORE_EVENTS](NATIVE_STORE_EVENTS.md)。sidecar经摘要/停止身份重验后进入memoryWrites观察；旧记录缺失项保持未知。不提供因果写入、CPU footprint或全局epoch证明。

P1 首步提供只读证据导入，不执行目标。DSH 入口与 P0 `case_ref` 规划互斥：

```json
{"recovery":{"observations":{"recordings":[{"id":"原debug-trace报告UUID","sha256":"原报告SHA256"}],"target_sha256":"目标SHA256","offset":0,"limit":32}}}
```

引用必须来自当前 `artifactDir/debug-traces`，按录制顺序提供。UUID 和报告摘要共同绑定原报告；稳定读取后再次核对摘要，再核对 blob、目标、run/thread、基址、停止序号及完整前后GPR/flags/RIP。executionLocation 指纹不同也拒绝连接。调用者不能提供任意输入路径、状态、阶段标签、内存补值或可执行参数。

`ig5-native-observations-v1` 保存全窗口清单和请求页 stopGroups：16个GPR、flags、指令字节、内存读取的小端字节及原行号。读取尚不分类为字节码、VM寄存器或业务输入。停止序号由窗口元数据与顺序推导，`individuallyAttested=false`。CPUID合并停止只提供组前/后状态，明确缺失中间快照；本层不解码或验证后继指令语义。

同地址代码字节变化保留前后值，原因未知，不能称为已证明的SMC写。最多跟踪4096个地址，溢出后计数为下界，最多预览64次变化。没有来源的模块/内存epoch保持null，phase保持unclassified。旧loadedImage仅保留元数据SHA，明确未重验映像blob，不用于证明代码一致性。

每请求至多256段、报告合计16MiB、原始轨迹合计16MiB，每段1MiB/512个已确认停止。指令数默认50000、显式最多100000，包含CPUID后继。offset按停止组计，limit为1..64（默认32）；第一页也先核验全部输入。页面报告最多4MiB，共享原数据worker的64MiB/15秒、1活跃+4排队，不启动原生进程。取消或任何核验失败不提交输出报告。

公开预览至多2组、8段、4次代码变化；完整请求页及全窗口清单保存于reportPath/reportSha256。pagination描述报告内页面；eventPreviewComplete、windowPreviewComplete、responsePreviewComplete分别描述响应裁剪，不能把预览当整段轨迹。

执行、授权变更、活owner检查、业务、完整函数覆盖与架构证明六个范围标志均为false。本入口不解除租约，不认证返回、VM模型或CPU语义，不替代原生审批/清理。

`npm run test:vm-observations` 验证解析、实际数据worker、存储绑定、后段损坏、连续性及取消。`scripts/test_vm_observations_oracle.py <dataset.json>` 用既有Python parser独立核对观察，不加载Triton。真实历史录制、安装SDK和配置模型验收另存证据。

P1后续仍须采集真实模块/代码/内存变更事件，建立阶段与字节码读取角色，再进入P2自动VM模型推导。观察层完成不等于P1全部完成。
