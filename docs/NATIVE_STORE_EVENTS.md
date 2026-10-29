# 原生停止前后的存储位置观察

本宿主真实原生验收仍被已知headless.exe的4551策略阻断。当前只有源码、模拟原生停止、数据worker与SDK证据，不能称新增采集已完成原生验收。首次夹具漏传engine的失败和后来策略阻断分别保留。未更改系统策略或复制/改名受阻组件；后续不再启动同组件重试。

运行时新增应用级阻断历史：x64dbg将实际Popen的4551保存在IG5_HOME/runtime-policy-blocks，按配置组件绝对路径绑定，换目标/工作目录不会清除；无自动过期或清空入口。损坏记录拒绝启动，持久化失败也保留当前适配器内的拒绝。它是能力历史，不是OS策略编辑、执行许可或清理凭证。外部状态变化须另有核验，不能自动换路径绕过。旧证据导入标为imported-policy-evidence，recordedAt是登记时间，不是新的OS事件。

只读ig5_doctor保留launchReadiness的blocked/unknown/not-probed，runtimeReady/startupVerified均不由x64dbg文件存在升级为true。诊断元数据进程不启动调试器或样本。阻断缓存与公开审批均独立保留；本宿主原生测试命令目前不可执行。

P1可选采集仍由原`ig5_dbg`公共一次审批控制：

```json
{"target":"C:\\owned\\sample.exe","backend":"x64dbg","op":"trace","record_trace":true,"record_events":true,"max_steps":128}
```

须已有合法打开的目标和自有暂停会话，不接受任意PID、脚本或输出路径。VMCI须另验包含新源码的客体bundle；旧bundle不自动获得新能力。

录制器按既有解码器列出的store地址/宽度读取baseline，确认前暂停身份，再走原PAUSE/STEPPED单步。随后读取相同位置并重验run/pid/tid/stopSeq和主模块边界。sidecar绑定原trace SHA及每个停止组。CPUID合并停止仍无中间GPR/flags快照。

`ig5.native-store-events.v1`记录地址、宽度、beforeHex/afterHex、changed和状态。不可读或期限耗尽保留afterHex/changed=null；暂停不符使该组所有after字节失效。缺失followup保留已确认前缀并停止。changed=false不表示没写；空列表仅表示解码器没列出store，枚举顺序不是内部写入顺序。

`actualWriteCausalityProved=false`和`cpuWriteFootprintProved=false`始终保留。变化尚未归因到该指令，解码器集合不是独立CPU完备性证明；并发、异常、系统/设备写入、模块加载和全局epoch仍未补齐。

sidecar+raw共享原1MiB证据预算，每指令最多32位置/256字节。单步前预留最大事件空间，不足时以`recording-evidence-budget`保留前缀，不执行下一步。512确认停止/40秒和8MiB初始映像不扩。窗口连接仍核对完整末/初态，最多256段/16MiB/默认50k、显式100k指令；16MiB包含sidecar。

保存前核对摘要、严格compact ASCII JSON、完整trace身份及停止关系，再保存SHA blob与报告引用。`ig5_recovery recovery.observations`重验全部事件后分页，memoryWrites状态为decoded-locations-observed-across-stop；旧记录继续not-recorded-by-this-format。后段损坏即使不在返回页也拒绝。phase保持unclassified，模块/内存epoch保持null，VM/ISA/业务/覆盖均未升级。

`npm run test:store-events`覆盖Python采集器、真实解码+模拟原生停止、JS解析/保存和实际数据worker。模拟停止不是原生验收。显式原生回归另用：

```powershell
node scripts/test_native_store_events_runtime.mjs --run-owned-native-fixture --evidence C:\new-evidence-directory
```

仅执行固定store/load/RET的自产PE，测试审批服务绑定文件SHA与操作清单，经过产品原allowed-once门；检验拒绝不派发、实际变化/相同字节观察与关闭采集基线。不接受外部目标、不改DSH配置或产品策略。另查原进程退出；no-task不是独立清理证明。SDK、安装/重载及配置模型分层验收。

研究参考：[VMProtect-devirtualization](https://github.com/JonathanSalwan/VMProtect-devirtualization)描述纯函数动态轨迹及输入输出恢复；mr/r/i不构成本项目完整写入或精确3.8证明。[PANDA官方API](https://docs.panda.re/panda.html)提供另一后端的内存回调思路。本次未引入上游代码或部署整机后端；资料核对于2026-10-17。
