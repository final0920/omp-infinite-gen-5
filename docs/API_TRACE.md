# 动态 API 轨迹(P8,2026-10-25)

`ig5_dbg` 新增 `op=apitrace`:在**已经由本工具接管并暂停**的原生进程上,把该进程导入表里的 API 入口设置软件断点,继续执行,记录每次命中的入口参数、返回地址与调用线程,结束后清理断点并给出行为汇总。

> 证据口径:**调用列表是 E1**(这一轮运行里确实被断点命中),**行为类别与行为链是 E0**(按规则表对这些命中做的归并解释)。共现不等于意图、不证明调用成功、也不证明覆盖完整。软件断点会改动被调试进程里 API 代码页的首字节,可能被目标检测到。

不新增工具:Full 仍是 41,`op=apitrace` 与 `api_names`/`max_api_calls`/`max_apis` 属于 `ig5_dbg` 的操作面增量。

## 1. 调用方式

```jsonc
{
  "tool": "ig5_dbg",
  "arguments": {
    "target": "C:\\samples\\sample.exe",
    "backend": "x64dbg",
    "op": "apitrace",
    "api_names": ["IsDebuggerPresent", "Sleep"],   // 可选;省略=按行为分类表选择
    "max_api_calls": 64,                            // 命中预算,1..1024(默认 128)
    "max_apis": 16,                                 // 选中 API 预算,1..256(默认 64)
    "timeout": 45                                   // 单次事件等待秒数;apitrace 默认 45,最大 120
  }
}
```

前置条件(不满足直接拒绝,不降级):

- 目标必须已被 `ig5_open`,并用 `op=start` 启动到 `suspended`;`apitrace` 从**当前暂停**开始。
- 必须是 `backend=x64dbg`;win32/Bochs/guest 路径不支持。
- 目标必须是 x86 或 x64 原生 PE;主模块 base/size 必须可读。
- 运行态操作受审批门约束(`start`/继续执行都会真实执行目标)。

`api_names` 大小写不敏感,接受 `name`、`module!name`、`#ordinal`;不在导入表里的名字不会静默替换,而是列进 `apiSet.selection.notImported`。

## 2. 工作方式

1. **静态解析导入表**(`adapters/x64dbg/pe_imports.py`,只读文件、不执行、有界):DOS/PE 头、节表、导入目录、`OriginalFirstThunk`/`FirstThunk`、按名/按序号 thunk。超过 96 节、4096 个描述符、16,384 个导入或 256 KiB 表预算会被截断并标记 `importTableTruncated`。
2. **选择 API**:给了 `api_names` 就按请求顺序挑选(重复名字只取一次);否则按 `behavior_rules` 的分类做广度优先轮转,预算内尽量覆盖更多类别。
3. **读运行时 IAT**:对每个选中导入,在当前暂停读 `主模块基址 + IAT RVA` 的指针槽。槽为 0 或越界 → 记入 `coverage.unresolved`,不设断点、不猜地址。
4. **设软件断点**:同一地址被多个名字共用时只设一次,`apiSet.breakpoints` 记录地址与对应名字。
5. **继续执行**:走既有的 `run` + 事件等待路径(不是新的执行通道),每次 stop 必须是断点事件且地址在本次设置集合内;外部断点(`foreign-breakpoint`)与异常(`exception`)立即停止并把事件留在 `coverage.foreignStop`。
6. **记录命中**:入口寄存器参数(x64:`rcx`/`rdx`/`r8`/`r9`;x86:栈上 4 个 DWORD)、`[rsp]`/`[esp]` 返回地址、调用线程、`rip` 是否等于命中地址(`pauseMatchesHit`)。
7. **收尾**:无论正常结束、异常、超时还是取消,都在 `finally` 里清理本次设置的断点;进程已退出时记为 `attempted=false` 并说明原因,不谎称已清理。
8. **汇总**:`worker/api_trace_summary.py` 按分类聚合调用数/不同 API/线程/首末调用序号,并给出线程内行为链与"多种同类 API"规则。

## 3. 输出

顶层字段:`schema=ig5.apiTrace.v1`、`evidenceLevel=E1`、`behaviorEvidenceLevel=E0`、`nativeTargetExecuted`、`startedFrom`、`runId`/`stopSeq`/`state`/`pid`/`tid`、`apiSet`、`calls`、`behavior`、`coverage`、`note`。

`coverage.stopReason` 取值:

| 值 | 含义 |
|---|---|
| `call-budget` | 达到 `max_api_calls`,`callsTruncated=true` |
| `process-exited` | 进程在本轮退出(退出后无断点可清) |
| `exception` | 暂停在异常;`foreignStop` 带 `ExceptionCode` |
| `foreign-breakpoint` | 停在不是本轮设置的断点 |
| `no-breakpoints-set` | 没有可用的已解析 IAT 槽 |
| `interrupted-<原因>` | 等待事件被外部中断(取消/审批撤销等),原因原样跟在后面 |
| `unconfirmed-stop` / `continuation-rejected` / `breakpoint-address-unavailable` | 调试器没有确认 stop / 拒绝继续 / 事件里没有地址;`ok=false` |
| `history-gap` / `stop-<event>` | 事件历史断档 / 停在了非断点事件 |

`calls[]` 每行:`index`、`api`、`module`、`category`、`byOrdinal`、`iatRva`、`hitAddress`、`threadId`/`threadSource`、`instructionPointer`、`pauseMatchesHit`、`arguments{source,values[],complete?}`、`argumentsUnavailable`、`returnAddress`、`callerModule`、`callerRva`、`callerInMainModule`、`breakpointHitCount`。

- 参数是**原始入口值**:宽度、类型、是否指针、指针指向什么都不还原;浮点/向量参数不在通用寄存器里时记录不到。
- 返回值、`GetLastError`、调用是否成功都**没有观察**。
- `coverage.scope` 与顶层 `note` 用固定措辞写明以上口径。

成功(`ok=true`)时结果另存为分析产物:`<artifactDir>/api-traces/records/<id>.json`,`kind=api-trace`、`action=trace`、`result.request` 记录本次参数、`result.targetSha256`、`result.databaseModified=false`;返回 `apiTraceSaved`/`apiTraceReportId`/`apiTraceReportPath`/`apiTraceReportSha256`。保存失败不回滚调试结果,但 `apiTraceSaved=false` 且带 `apiTraceArtifactError`。

## 4. 证据层级与口径

| 内容 | 级别 | 能说明什么 |
|---|---|---|
| `calls[]` | E1 | 这一轮运行里,这些 API 入口被断点命中,参数与调用者如上 |
| `behavior.categories`/`chains` | E0 | 按分类表归并的线索:出现过什么、按线程的先后关系 |
| `callerRva` | E1 | 返回地址;`callerInMainModule=false` 时调用方不在主模块 |
| 参数数值 | E1 | 入口那一刻的寄存器/栈值本身 |

`behavior.evidenceLevel=E0` 与 `note` 已写进结果;不得把 `chains` 读成"它执行了某攻击流程"。同一次运行外的行为、分支没走到的路径、其他线程上的 API 都可能是空白。

## 5. 已知边界

- **只覆盖静态导入表且 IAT 在暂停时已解析的槽**。字符串 + `GetProcAddress` 动态解析、延迟导入、直接 `call` 进 DLL 代码、系统调用、未插桩模块里的调用都看不到。
- 一个 API 若在多个线程被调用,断点是进程级的,每个命中各自记录线程;但等待事件与寄存器快照都只在当前暂停线程上取。
- x86 只取返回地址与栈上 4 个 DWORD(cdecl/stdcall 前四个参数);`arguments.complete=false` 表示没有读满。
- 软件断点会改目标代码页首字节,可能被反调试发现;这不是隐蔽追踪器。不修改磁盘上的样本。
- 达到预算后进程**停在最后一个 API 入口**,需要显式 `cont`/`stop`;不要把它当成"已恢复运行"。
- 宿主侧(x64dbg headless)已实机验收;**VMCI guest 路径未验证**;x86 运行态未验收(PE32 解析与栈参数取值有离线测试)。
- 不支持 ARM64 PE、.NET 托管入口、加壳后入口尚未解密的样本(导入表读不到或槽未解析时如实体现在 `unresolved`)。

## 6. 安全与清理

- 只在已审批的、由本工具持有的调试进程上运行;继续执行复用既有 `run` 事件路径,没有新增执行通道。
- 不写数据库、不联网;报告只写到 `artifactDir` 下的 `api-traces/`。
- 断点清理在 `finally` 中执行;清理失败 → `breakpointCleanup.cleared=false` 并列出 `failures`,不声称已清理。
- 清理时读取状态本身失败,不会吞掉已经记录的调用;取消/传输丢失(`ECANCELLED`/`ETIMEDOUT`/`ETRANSPORT`/`EEXIT`/`EJOB`)仍然向上传播。

## 7. 验证

- `scripts/test_api_trace.py`(26 项,不启调试器、不执行目标):PE32/PE32+ 导入表(按名/按序号/IAT RVA/坏头/未终止名字/无导入目录/无 section 后备/落在节虚拟大小内但超出原始数据的目录被拒)、选择与预算(请求别名去重、`max_apis` 截断)、参数边界、x64 寄存器与 x86 栈参数、线程与调用链聚合、`distinct` 规则、4096 调用上限、零 IAT 槽、外部断点、异常、进程退出、清理失败、清理时状态读取失败(保留已记录调用)、取消传播、模块限定名与 `#序号`。
- `scripts/test_api_trace_runtime.mjs`(真实 x64dbg):生成自造 PE64 夹具 → `ig5_open`/`load`/`start` → 到入口点后确认 IAT 四个槽都已被加载器绑定 → `op=apitrace` 断言调用顺序、返回地址(`0x100a`/`0x1010`/`0x101b`)、线程、`Sleep` 的 `rcx=1`、`stopReason=call-budget`、断点清理、`debug-detection` 类别、产物写入与 `targetSha256`、`databaseModified=false`,再 `cont` 到进程退出并断言磁盘样本未变。
- 运行:`node scripts/test_api_trace.mjs`(随包 Python + 真实 x64dbg);门禁 `tools/ci/gate.json` 的 `api-trace`(`tier: extended`)。

## 8. 检查中发现并修正的问题

1. `pe_imports._sections` 的节表偏移写成 `文件头 + 20 + 可选头大小`,少算了 PE 签名的 4 字节;落在 RVA 边界的表会被错位的节行"蒙对",真实文件才会暴露。改为 `+24` 后,`notepad.exe` 正确解出 315 个导入 / 49 个模块。
2. 自造 PE64 夹具的磁盘 IAT 全是 0。Windows 加载器对这种镜像**不报错也不绑定**:进程能跑到入口,第一次 `call [rip+iat]` 才在 0 处 AV。把 ILT 的 thunk RVA 镜像写进 IAT(与所有真实链接器一致)后,加载器正常绑定,运行态验收才成立。运行态测试增加"四个槽都非零"的独立断言,避免以后再出现"看起来在跑其实导入没绑"。
3. 清理阶段读状态抛非致命异常时,原实现会丢掉已经记录的全部调用。改为记录 `cleanup-state-unavailable` 并保留调用;致命错误(取消/超时/传输)仍传播。
4. `api_names` 里同一个导入的不同写法(如 `Sleep` 与 `USER32.dll!Sleep`)会被重复选中,既浪费预算又让 `selectedCount` 虚高;原实现还用 `row not in selected` 反复扫描已选列表。改为按导入行身份去重,并对最多 64 个请求名各做一次线性匹配。
5. 变异检查第一轮有两个缺陷存活:`pe_imports` 的"节虚拟大小内但无文件字节"边界放宽 8 字节没被发现,`api_names` 允许重复别名也没被发现(原有的 `max_apis` 用例恰好把重复项截断掉了)。补了"目录 RVA 正好落在原始数据末尾"和"别名去重后 `truncated=false`"两条用例后,13 个定向缺陷全部被杀死(见验收文档)。
