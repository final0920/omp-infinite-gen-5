# 真实使用反馈改造：使用与边界

## 诊断与结果

`ig5_doctor {"operation":"session"}` 必须单独调用。只报告当前执行者的已知元数据；observedAt是观察时间，faultStartedAt未知。失联时不读取其他根账本。默认doctor仍会探测引擎并正常计费。宿主重新索引原父对象后，原账本继续生效；没有开放字符串parentId认领或自动恢复入口。

实际宿主有会取得写所有权的 `agentLoop.resume`，不能在只读诊断中自动调用。原会话的显式恢复步骤、源码审计与 ARM64/72 函数补充验收见 [顺序推进记录](uxr/CONTINUATION-20261023.md)。

真实模型连续分页和15KB正文浏览器渲染的后续结果见 [最终验收](uxr/FINAL-ACCEPTANCE-20261024.md)。原样本由用户确认目前没有；该事故复现仍未验证。

```json
{"target":"已打开的路径","ea":"0x1000","style":"dossier"}
```

从响应取 `savedResult`，然后调用同一工具 ig5_decompile：

```json
{"target":"已打开的路径","operation":"read","result_ref":{"id":"响应中的UUID","sha256":"响应中的SHA256"},"section":"decompile","page_max_bytes":8000}
```

下一页增加响应的cursor，直到nextCursor=null。offset/nextOffset连续，contentSha256校验拼接后的UTF-8字节。CFG/callers/callees/stack默认records格式，保留字段名/索引/空数组长度；records摘要校验拼接全部记录的JSON UTF-8。`format=json-text`取回整个保存段的JSON原文，包括单条过长记录；`text`仅用于伪代码。游标绑定UUID/SHA/section/format与内容摘要，不是路径。

provider=partial/unknown时，完整保存和分页也不能补齐引擎未生成的数据。旧字段及schemaVersion=1保持；新增savedResult、completeness、cache原因和原型状态。存储失败返回savedResultError，不发布完整引用。当前策略严格拒绝其他target/attachment/revision，重开数据库后不能拼接旧页。

Ghidra的调用关系原本先生成全列表再按展示行数切片；dossier现在在独立128KiB/方向的字节上限内捕获这些已生成记录，展示行数仍由dossier_max_rows控制。超出捕获上限仍明确provider=partial，不增加后端遍历、分析或worker额度。

## 配额和保留

基线80KB代码足以说明64KB展示限制不适合完整产物。保存每项上限1MiB（含报告封装预留），每任务/默认会话身份组8MiB，结果数据目录64MiB、最多256个引用，保留7天。只保存原provider已有结果，不提高原生RPC或worker预算。索引使用独立ProjectStore锁与原子提交；不与预算账本混用。

写中断留下的未发布文件也计入配额，不能自动当有效结果。仅已知、过期、系统拥有的精确文件可被清理；不递归删除目录。批任务同样7天失效，活跃有效任务引用早于产物到期终止。未知孤立文件保留并占额度；没有开放任意目录GC或导出路径。

## 缓存、查询与参数

cache.scope=response；engineCache=unknown。reason区分冷/淘汰、身份、视图预算、能力、分析状态、先前section error、显式refresh与产物到期。地址/名称别名可能是不同key，不按数值猜等价。`refresh:true`只用于dossier，重新采集仍走共享计费，不自动重分析。

先 `ig5_profile {"toolset":"full"}` 才可发现ig5_xrefs/ig5_calls/ig5_cfg；`capabilities:true`显示后端声明和验收状态。queryState区分empty、observed、truncated、analysis_incomplete、error；不支持抛UNSUPPORTED_CAPABILITY。Ghidra xref附isCode/isData/isRead/isWrite/isCall与来源。分析失败仍抛原错误；未解析间接调用保持unknown，查询结果不声称完备。

interactive跳过批量Parameter ID时dossier明确警告。prototypeStatus保持unknown，不用空原型推断无参数，不输出未经校准置信度。full需显式选择，可能改变成本和修订。

## 地址

```json
{"target":"已打开ELF","address":{"value":"0x104008","space":"ghidra_va","to_space":"elf_vaddr"}}
```

在ig5_profile中单独调用。支持ghidra_va、elf_vaddr、file_offset、module_offset。Ghidra原FileBytes解析有界PT_LOAD表，实际MemoryBlockSourceInfo确定文件字节加载位置；不从imagebase或报告的+0x100000推测全局映射。非一致重定位可逐范围换算；overlay、BSS到文件、重叠和未知映射拒绝。函数元数据保留ea，新增addresses；工作台只另加已证明的ELF地址标签，不替换伪代码十六进制。

module_offset原点是最低PT_LOAD vaddr，runtime地址仍需可信load bias及run/module/epoch。这个新增ELF入口对runtime_va明确拒绝；既有address_ref的观察模块转换保留。不能拿静态偏移冒充当前ASLR映射。商业后端没有新ELF转换能力时明确不支持。

## 批任务

ig5_decompile operation=batch，batch={action:create,functions:[明确hex地址...]} 建立最多72项任务；重复地址拒绝。run用id与max_items（默认8、最多8）；status与cancel不启动新采集。每次run最多60秒，复用同session串行队列，没有新worker。外层调用支付首个新函数，每个后续函数在RPC前分别走原charge；create/status/cancel也仍按公共控制调用计费，不绕过耗尽。

每项pending/running/completed/failed/cancelled/stale及attempts/resultRef可追溯。先提交产物再提交任务，重启恢复先核验幂等提交，避免重复已生成内容。completed仅表示采集已保存；sectionStates仍可能partial/error/unknown。修订或attachment变化明确stale；缺少旧attachment时不能承诺重开后继续旧快照。失败项可定位；新目标或需要重做时创建新任务。cancel中断所属原RPC，沿用原进程清理合同。

## 验收与回退

`npm run test:uxr`、`runtimes/ghidra/python/python.exe -I -B scripts/test_uxr_addresses.py` 是夹具；`npm run test:uxr-runtime` 是自产PE/ELF的实际静态引擎验收，不执行目标。源码/安装SDK/宿主加载/模型实际调用/原报告样本分开记录，见docs/uxr。

回退只替换代码，保留function-results、function-batches、分析产物和共享预算账本。旧客户端可忽略新增字段；旧代码不读取新独立命名空间。不要用回退删除已消费预算或数据库修订。
