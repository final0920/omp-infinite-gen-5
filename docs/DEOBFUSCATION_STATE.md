# 只读去混淆与协议观察状态

v1.1.0 在已有 `ig5_microcode`、`ig5_protocol` 和 `ig5_capture` 中增加 action，工具总数仍为 Core8 / Full40。以下分析保存证据，不执行目标、不改数据库，也不发送网络请求。开始采集和请求重放仍使用经过审批的 `ig5_capture_control`。

## 从已保存交换建立轨迹

先在 `ig5_capture action=list/get` 中确定真实采集记录。调用者明确划分应用会话，按交换先后顺序选择记录；代理 `session_id` 只是采集身份，一个代理会话可以包含多个应用会话。TCP 连接、时间相邻和相同 URL 都不证明应用会话边界。

```json
{
  "action": "state_trace",
  "traces": [
    {"id":"train-1","session_id":"<采集会话UUID>","start":"session-start","complete":true,"ids":["<交换UUID-1>","<交换UUID-2>"]}
  ],
  "holdout": [
    {"id":"holdout-1","session_id":"<采集会话UUID>","start":"session-start","complete":true,"ids":["<另一交换UUID-3>","<另一交换UUID-4>"]}
  ]
}
```

此参数交给 `ig5_capture`。每条轨迹须来自同一准确 origin，HTTP 请求/响应已完整保存，时间区间有序且不重叠；加密隧道、WebSocket、失败或截断交换不能进入此构建器。`complete` 声明本次会话观察完整，不证明真实协议已经终止。不能确认起点时使用 `start:"unknown"`，不能为了得到模型改填已知起点。

构建器校验源报告摘要与正文 SHA-256。默认事件为请求 `METHOD:route:<pathname摘要前32位>` 和响应 `status:<状态码>`，保留方向、capture ID、源报告摘要及正文引用，不展开查询参数或正文。它们是观察符号，不是自动恢复的操作码语义。可以显式提供：

```json
{"symbols":{"request":{"source":"body-field","offset":0,"size":1},"response":{"source":"body-field","offset":0,"size":1}}}
```

`body-field` 按原字节顺序选取 1..8 字节，返回 `field:<hex>`，不解释端序或业务含义；压缩编码和 HTTP 范围响应不能作为完整字段来源。只能对已有完整消息使用此选项，不能把传输片段当成消息。

训练与 holdout 各最多 32 条轨迹，每条 1..128 个交换，总计最多 256 个交换；正文校验合计最多 8 MiB，输出 JSON 清单最多 1 MiB。记录不能重复，也不能在两组共享。输出 `input:{ref,result_id}` 可直接交给协议工具，来源保留在独立 `capture-traces` 报告中。这里只校验保存证据的一致性，不证明外部数据来源可信。

## 推断与独立重放

将上一步返回的 `input` 原样使用：

```json
{
  "action":"state_infer",
  "input":{"ref":"<state_trace 返回的 input.ref>","result_id":"<state_trace 返回的 input.result_id>"},
  "state_model":{"merge":"future-equivalent","merge_depth":2}
}
```

此参数交给 `ig5_protocol`。`value.state.observedModel` 是确定性的观察前缀树，完整轨迹终点提供接受证据。未知起点的轨迹保留为排除证据；不完整事件停止该轨迹的训练，后续事件不会跨缺口连接。部分终点留下的未知后续会沿已匹配边保留，不因另一条完整轨迹提供了同名边而消失。

`mergedHypothesis` 按 1..3 层观察未来进行可选合并，可能形成循环和非确定分支；它是外推假设。竞争目标全部保留，不能把 `mergedStates` 或较小状态数当成真实服务器状态恢复程度。`holdout` 对前缀树重放，`mergedHoldout` 对合并假设单独重放；holdout 不参与训练或合并。

新验证数据放入新清单的 `traces`，省略 `holdout` 字段。调用 `state_trace` 构建这种清单时也应省略 `holdout`，然后调用：

```json
{
  "action":"state_validate",
  "input":{"ref":"<新清单的 input.ref>","result_id":"<新清单的 input.result_id>"},
  "state_model":{"result_id":"<state_infer 报告UUID>","model":"prefix-tree"}
}
```

`input.result_id` 绑定新数据，`state_model.result_id` 选择旧模型，两者不可混用。`model:"merged-hypothesis"` 可选择此前确实生成的合并假设。验证从完整保存的训练证据和配置重建模型，并检查两个模型摘要；不会把模型响应中最多八个数组元素的预览当成完整模型，也不会把验证数据加入训练。

| 结果 | 可以得出的结论 |
| --- | --- |
| `accepted` | 完整路径符合所选模型；前缀树原因是 `observed-complete-path`，合并模型是 `fits-merged-hypothesis` |
| `rejected` | 路径或完整终止不在该观察模型中，附有反例；不证明真实服务器会拒绝 |
| `unknown` | 起点、事件、终点或部分后续不完整，或竞争分支未解决；不能提升为成功或失败 |

相同采集/来源 ID 可标记来源重叠；相同符号序列仅为 `duplicateBehavior`，相同字节摘要仅为 `repeatedContent`，都不单独证明复用了同一次观察。未发现来源重叠时 `independent:null`，`independentCollectionProven:false` 始终保留，不能把不同 ID 当成独立采集已经被证明。重复行为可以复核已知行为，但不增加新行为覆盖。

也可直接使用本地 UTF-8 JSON 文件或现有 inline/ref 输入。清单格式如下；接受 `version:1` 作为版本写法：

```json
{
  "schemaVersion":"ig5.protocol-traces.v1",
  "traces":[{
    "id":"conversation-1","sourceId":"explicit-source-1","start":"session-start","complete":true,
    "events":[
      {"direction":"client_to_server","symbol":"type-01","sourceId":"observation-1","complete":true},
      {"direction":"server_to_client","symbol":"type-81","sourceId":"observation-2","complete":true}
    ]
  }]
}
```

限制为 UTF-8 JSON 1 MiB、嵌套 16 层，拒绝重复键；默认训练与验证合计 64 条轨迹、4096 个事件、2048 个状态、100 万工作单位，硬上限分别为 256、8192、4096、200 万。通过 `state_model.max_traces/max_events/max_states/max_work` 显式设置预算，超限拒绝提交模型。保存完整报告后，可用 `action=result` 和 `select:"state.holdout"`、`select:"state.observedModel.states.0"` 查看窄范围证据。状态分析不支持字节切片参数。

## 单函数只读去混淆

先打开受支持的静态目标，确定函数入口，核对实际 provider 与能力。当前实现面向随包 Reverse 的 Ghidra provider 与显式 Ghidra，不能由同名工具推断商业扩展也有该 action。

```json
{"action":"deobfuscate","target":"C:\\samples\\target.exe","engine":"ghidra","ea":"0x140001000","max_steps":100000,"max_evidence":128}
```

此参数交给 `ig5_microcode`。默认使用 `generated` 对应的原生 `firstpass` HighFunction SSA，`deobfuscation` 返回 SCCP（稀疏条件常量传播）证据覆盖层。它处理受支持的 1..8 字节整数位向量运算、常量比较、同 SSA 身份规则、精确 PIECE/SUBPIECE 位片、低位与相邻整数乘积为偶数的证明。它按可执行入边处理 phi，返回常量、简化依据、已证明条件分支、观察 CFG 内的不可达块，以及保留状态赋值的入边条件化 dispatcher 路径。

`LOAD`、调用和间接副作用没有内存/函数模型；未知值、除零、带符号除法溢出、超宽整数和过量移位不会伪造常量。可达 `BRANCHIND` 标记控制流不完整。图截断、原生部分图、工作预算耗尽或间接控制流未解决时，`partial:true` 并撤下常量、分支、不可达与 dispatcher 证明结果；证据列表截断另看 `evidenceTruncated`。

SCCP 默认 100000 步、128 条证据，上限 250000 步、512 条。原生图仍受实际 512 块、4096 指令、32768 varnode、4096 边和文本预算约束；`timeout` 默认 30 秒、最多 120 秒，外层 RPC/宿主预算也可能更早终止。读取返回的 `limits` 与 `budget`，不能用较大的请求值宣称得到了更完整的图。

`expressionSimplifications` 是独立的局部 SSA 等价证据：对同宽 COPY/NOT/AND/OR/XOR，用最多 6 个独立输入的穷尽单比特真值表证明更短表达式；常量仅接受全零或全一。另提供五种精确模整数线性 MBA 恒等式，例如 `(x|y)-(x&y) = x^y`、`(x+y)-2*(x&y) = x^y`。每条返回原运算数、替换运算、输入 SSA、位宽和证明方式，不依赖采样输入“碰巧相等”。原生 x86 的同源位片、PIECE 与扩展后再取原宽的低位可以精确归一；相同物理寄存器不代表同一 SSA 值。

局部位运算表达式最多 32 节点、12 层、64 行真值表；间接目标 `indirectTransfers` 最多向后追踪 32 个 SSA 依赖节点，保留 LOAD 地址表达式、外部输入、截断和 `targetsResolved:false`。它不读取任意动态内存、不恢复 handler 表、不确定 VIP/密钥或解码 VM 字节码。两者共享 `max_steps` 与 `max_evidence` 预算；部分原生图或耗尽预算撤下局部证明。仅全局间接控制流未解决时，仍可返回完整观察图内的局部数学恒等式，不能据此推出完整函数或路径恢复。

覆盖层保留 `rewritten:false`、`idb_modified:false`、`executed:false`。它不改机器码或 SSA、不重新生成去混淆后的 C、不做任意 VM 去虚拟化或通用去壳。原有 `action=optimize` 的临时 IR 规则是另一条明确操作；命中次数和数据库修改状态必须分别核验。符号、类型、注释和补丁回写继续走原审批入口。

## 本地快捷命令与验收范围

```text
/ig5 deobfuscate --engine ghidra 0x140001000 "C:\samples\target.exe"
/ig5 state "C:\samples\training-traces.json"
/ig5 state-validate <state_infer报告UUID> "C:\samples\validation-traces.json"
```

快捷命令在宿主调用限定的只读工具，不需模型代为执行；当前只有一个静态目标时 `deobfuscate` 可省略样本路径，多目标时须明确。`state` 默认使用深度 2 的 future-equivalent 合并；`state-validate` 默认验证前缀树，要验证合并模型时用明确工具参数。状态命令不接受 `--engine`。

回归入口：`npm run test:protocol-state` 检查纯模型、实际 Node worker/公共工具与轨迹构建；`npm run test:protocol-state-network` 使用本地 HTTP 流量验证采集到模型的引用链；`npm run test:deobfuscation` 检查位向量/CFG 与工具路由；`npm run test:deobfuscation-runtime` 在实际随包 Ghidra 中分析生成的 PE，不运行目标进程。

这些证据分别覆盖离线算法、受控网络、宿主工具及原生静态引擎。它们不替代实际 DSH 桌面的安装、重载和 GUI 操作验收；该状态应按本次独立记录报告。网络状态模型不恢复隐藏的服务器代码，单函数覆盖层也不证明任意混淆程序已被完整还原。

## 外部学习样本回归

`npm run test:vmp-research` 是离线、显式运行的真实原生测试，样本根由 `IG5_VMP_SAMPLE_ROOT` 设置。固定来源、大小和 SHA-256 在 [样本清单](../scripts/fixtures/vmp_samples.json)，缺件或哈希不符会在启动 worker 前拒绝。脚本不联网、不运行样本；逐文件新建隔离项目，检查函数入口及最多两个观察到的直接被调函数，保存原始 SSA、预算与负面结果，最终核验输入哈希及数据库修订 0。包装函数的成功不能代替虚拟机计算体的恢复。

当前清单含 Jonathan Salwan 作者公开研究的 3 组原始/VMP 3.x ELF64 对照，以及吾爱官方爱盘 2012 zapline CrackMe（仅教育用途基线，未认定为 VMP）。二进制和上游源码只保存在本机研究工件，不随五代分发；仓库不复制研究代码。作者公开声明提供源码、原始与保护文件，见 [原研究](https://github.com/JonathanSalwan/VMProtect-devirtualization)。论坛 VMP2 学习帖 [2132351](https://www.52pojie.cn/thread-2132351-1-1.html) 可供研究；[CM_CrackMe4](https://www.52pojie.cn/thread-1936116-1-1.html) 的附件在本次访问要求登录，未取得，也未计入测试。

外部样本测试与人工构造原生 MBA 函数分别报告。前者用于暴露真实未知，后者有明确数学真值，用于检验新规则的正确性；都不代表通用 VMP 去虚拟化成功。DSH 模型的分析文本另做交叉复核：`ig5_funcs.filter` 按名称子串过滤，不是地址范围过滤；机器字节与高层伪代码形态不同不能单独证明解码矛盾，用原始 p-code 和相同地址的字节核验影响结论的指令。
