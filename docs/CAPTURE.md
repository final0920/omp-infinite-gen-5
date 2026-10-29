# 无限五代 v1.1.0：独立应用层流量采集

此版本由五代自己的 Node 代码提供代理和存储，不启动、复制或调用 Burp 程序。插件加载时只读已有采集状态，不自动监听端口、不改变系统代理。

## 开始使用

1. 在 DSH 调用 `ig5_profile toolset=full`。完整目录是 43 个入口，默认 Core8 不变。
2. 确定测试程序实际访问的 HTTP/HTTPS origin（协议、主机、端口）。例如本机测试服务 `http://127.0.0.1:3000`。
3. 请求 `ig5_capture_control`，参数如下。宿主批准后返回回环代理地址和 `session_id`。

```json
{"action":"start","port":0,"scope":["http://127.0.0.1:3000"]}
```

4. 将测试客户端的显式 HTTP 代理设置为返回的 `127.0.0.1:端口`。客户端绕过代理的流量不会进入五代；部分客户端默认绕过 localhost，需要针对该测试配置。
5. 在“流量”页手动刷新历史，选中交换查看请求/响应；或调用 `ig5_capture action=list/get`。控制按钮只生成可编辑草稿，插入会话后仍需发送和审批。
6. 完成后调用 `ig5_capture_control action=stop session_id=...`，并恢复测试客户端自己的代理设置。停止保留已保存证据。

## HTTPS 与 WebSocket

默认 HTTPS CONNECT 只转发加密隧道，记录连接与字节计数，不产生 HTTP 明文。使用 HTTPS 解密时，start 添加 `tls:true` 并在 scope 中加入准确的 HTTPS origin。

五代在用户 artifacts/capture-ca 中生成本机 EC P-256 CA，返回公开证书路径和 SHA-256 指纹。仅将公开证书配置为测试客户端信任的 CA；私钥不作为工具输出。五代不会自动修改 Windows 证书库。上游 HTTPS 证书仍正常验证，证书固定、双向 TLS 等应用不保证兼容。不要把本机私钥放入源码或发行包。

WS/WSS 经同一个代理转发：scope 仍使用对应 HTTP/HTTPS origin。WSS 明文帧要求开启 TLS 解密且测试客户端信任 CA。帧方向、opcode、FIN、压缩及截断状态作为证据保留；掩码去除后的有限 payload 可以分析。当前不重组跨帧消息、不解压 permessage-deflate，分片/压缩帧不能冒称完整明文消息，也不能通过 HTTP replay 重放。

## AI 分析与重放

`ig5_capture action=export id=... body=response` 返回 producer `result_id` 与 SHA-256 `input.ref`。将返回的 `input` 原样传给 `ig5_protocol` 或 `ig5_crypto`，避免把大量正文重复塞入模型上下文。HTTP 传输分块已移除，Content-Encoding（如 gzip）仍保留；分析前按原响应头决定是否需要显式解压。截断正文只能支持部分证据，不代表完整消息。

`ig5_capture action=review id=...` 被动检查保存的 HTTP 元数据，例如明文传输、Cookie 属性和响应安全头。它不产生目标请求，观察结果不等于漏洞确认。

## 流量 ↔ 样本对应（P9，2026-10-25）

`ig5_capture action=correlate` 把一条已保存的交换记录与本地样本文件做只读对照：

```json
{"action":"correlate","id":"<记录UUID>","session_id":"<采集会话UUID>","sample":{"path":"C:\\samples\\client.exe","sha256":"<可选>"}}
```

- **正文同一性（E1）**：捕获正文的 SHA-256 与样本文件相同 → `body-bytes-identity`。只说明这段捕获字节就是这份文件，不说明客户端执行/加载了它。
- **字面量（E0）**：捕获到的 origin、主机、路径（不含查询串）、`user-agent`/`referer`/`origin`/`accept`/`content-type` 值，以及网络 API 导出名（如 `WinHttpOpen`、`InternetOpenW`），在样本字节中出现的位置（ASCII、UTF-16LE，偏移为文件偏移）。`unmatched` 明确写出"没找到不是证明"。

纯只读：不执行样本、不开引擎、不发请求、不写产物；样本上限 32 MiB；不读取 cookie/authorization 与查询串。详细口径、边界与验证见 [流量与样本对应指南](TRAFFIC_CORRELATION.md)。

## 已采集流量的观察状态建模

`ig5_capture action=state_trace` 从调用者明确选定的 HTTP/已解密 HTTPS 交换生成轨迹清单。每条轨迹提供 `id`、采集 `session_id`、`start:"session-start"|"unknown"`、`complete` 与有序交换 `ids`；应用会话划分由调用者提供，不从 TCP 或代理会话自动推导。每条轨迹要求同 origin、交换完整且时间区间不重叠，不接受加密隧道或 WebSocket。

默认符号为请求 method/pathname 摘要和响应状态码；可通过 `symbols.request/response={source:"body-field",offset:0,size:1}` 显式选择 1..8 字节作为中性符号。字段选择不支持未解码 Content-Encoding 或部分 HTTP 资源。报告保留方向、采集记录、源报告摘要和正文 SHA 引用；验证的是存储证据一致性，不是业务含义或外部来源真实性。

训练 `traces` 与独立保留的 `holdout` 各最多 32 条，每条最多 128 个交换，总共最多 256 个交换，正文校验预算 8 MiB。两组不能共享记录，不能因相同正文摘要就认定不同采集是同一次观察。返回 `input` 原样交给 `ig5_protocol action=state_infer`。前缀树与可选合并假设分别保留，合并可能带非确定分支；holdout 不参与建模。

验证新会话时，重新构建仅含 `traces` 的清单，省略 `holdout` 字段，再调用 `state_validate` 并在 `state_model.result_id` 指定旧推断报告。结果 accepted/rejected/unknown 只描述与所选观察模型的关系，不证明真实服务器接受或拒绝。部分前缀留下的不确定性会穿过已匹配边继续保留；相同符号序列仅为重复行为，相同内容 hash 仅为重复内容，不证明来源重叠或独立性。完整参数、JSON 示例及本地 `/ig5 state`、`state-validate` 命令见 [状态与去混淆指南](DEOBFUSCATION_STATE.md)。

## 下发内容到静态逆向

流量页的“分析下发载荷”和“保存为逆向样本”按钮生成显式工具草稿，绑定当前记录、会话和响应方向。AI 也可以依次调用：

```json
{"action":"inspect_payload","id":"<记录UUID>","session_id":"<采集会话UUID>","body":"response"}
```

`inspect_payload` 只读取已保存的字节，检查 PE、ELF、WASM 的有限头部、压缩/ZIP 标记、严格 UTF-8 和预算内 JSON 结构，提供 JS/HTML 文本线索。不会执行脚本、展开归档或推断压缩数据内部的代码。响应 MIME 仅是未可信提示；二进制头匹配不证明文件完整有效，脚本线索不等于语法或行为验证。JSON 仅返回结构计数，不向模型展开键名和数值。默认检查预算为输入 8 MiB、文本 256 KiB、JSON 嵌套 32 层及 8192 token。

确认 `canMaterialize` 与 `blockedReasons` 后调用：

```json
{"action":"materialize","id":"<同一记录UUID>","session_id":"<同一会话UUID>","body":"response"}
```

保存位置固定在 artifacts/capture-payloads/<SHA-256>.bin，不采用服务器提供的文件名或用户输出路径；已有文件须匹配原字节和哈希。来源报告保存捕获 ID、会话、方向、blob hash 和捕获报告摘要，不复制 Cookie 或完整请求 URL。`executed:false` 表示这一步仅创建分析产物，未启动样本或静态引擎。

截断、未完成传输、HTTP 206/Content-Range、加密隧道及未解码 Content-Encoding 不能直接作为完整逆向样本；WebSocket 仅支持完整未压缩 FIN 数据帧，不把 continuation/control frame 当完整消息。完整下载的 ZIP/gzip 文件可按原始字节保存为 .bin，容器格式提示要求后续显式处理，不冒称内部程序已恢复。传输编码的内容仍可导出到原有离线协议/解密工具进行显式处理，但本入口尚不接受变换后的报告作为 materialize 输入。未知格式的完整字节可保存，实际 loader 能力仍需核验。

对引擎支持的二进制，使用返回的绝对 `path` 显式调用 `ig5_open`，核对返回 `sha256` 与 materialize 相同，再用 `ig5_funcs` 定位函数。通过 `ig5_workspace` 建立调查任务，`ig5_decompile style=dossier task_id=...` 将反编译、CFG、调用者、被调函数和栈帧合为系统证据。流程见 [调查任务指南](INVESTIGATION_WORKFLOW.md)。采集报告与 dossier 是独立证据，哈希相同可证明分析的是同一份载荷，不能单凭这一点证明客户端实际执行了它，或该函数就是服务端生成响应的函数。

目标是分析实际观察到的请求、响应及客户端行为。未下发的服务器实现只能由额外源码、服务器日志或受控实验提供证据，不能承诺从任意流量完整还原。

## 请求重放

重放使用当前活跃 `session_id` 与该会话完整请求的 `id`：

```json
{"action":"replay","session_id":"返回的会话UUID","id":"保存的交换UUID","request":{"method":"POST","path":"/example","headers":{"content-type":"application/json"},"body":{"encoding":"base64","data":"e30="}}}
```

`request` 可省略以重放原请求，编辑路径仍限定原 origin；Host、长度和逐跳头由实现规范化。每次重放经过审批，只发送一次，不自动跟随重定向。错误/取消可能发生在远端执行之后，`outcomeUnknown` 不能解释为“未发送”。不能对截断、不完整、加密隧道或 WebSocket 帧进行 HTTP 重放。

## 实现与预算

- `source/capture_proxy.js`：原生 HTTP/TLS 转发与有界 WS 帧解析，连接/请求超时、范围核验、自有连接清理。
- `source/capture_service.js`：会话身份、受限历史、串行控制、重放与证据保存。
- `source/capture_ca.js`：本机 CA 和最多 64 个缓存叶证书；只生成文件，不修改系统信任。
- `source/capture_review.js`：仅检查已保存的 HTTP 证据。
- `source/delivered_payload.js`：无 I/O 的有界载荷格式检查；`source/capture_payload.js` 校验捕获来源并保存样本。
- `source/capture_state_trace.js`：校验显式选择的交换与正文，生成方向和来源绑定的 JSON 轨迹；`source/protocol_state.js` 在原数据 worker 中建模并重放。
- `source/traffic_correlate.js`：P9 只读对应（正文哈希同一性 + 端点/头值/网络 API 字面量与文件偏移）。
- `capture_tools.js`：一个只读入口、一个审批控制入口；Core8 按需展开，静态数据库队列和修订保持独立。

默认单方向正文最多截取 1 MiB，历史最多 1000 条，正文累计预算 64 MiB；预算满继续转发并明确累计 dropped，不静默删除已有报告。证据元数据另有大小限制。历史使用共享 analysis-data 内容地址 blob 和单独 capture-history 索引，退出重开保留报告；原始报告、正文可能含令牌或个人数据，默认界面仅对常见敏感头和 URL 查询值脱敏，不能把它当成磁盘秘密隔离机制。

代理使用流式转发和背压，纯协议/解密仍在原数据 worker 中运行。采集服务和保存逻辑目前运行于 Node 宿主，未实现独立进程隔离。2026-10-14 本机一次 `bench_capture.mjs`：100 个 64 KiB 响应、并发8，含保存约543ms，184请求/秒，事件循环P99约47.55ms，保存100、丢弃0；相同正文内容地址去重。仅为本机回环 HTTP 单次测量，不声称外网、TLS或高并发性能。

## 当前边界

这是独立应用代理采集版本，尚不能称为完整 Burp Professional 替代。未实现网卡级任意 TCP/UDP/IP 采集、HTTP/2 客户端代理、HTTP/3/QUIC、完整主动扫描器、爬虫、Intruder 批量攻击、Collaborator、完整拦截暂停编辑界面或证书固定绕过。现有状态功能建立有限观察模型与合并假设，不是通用协议语义、真实服务器状态或隐藏代码恢复。已有 PCAP/PCAPNG 离线分析保留。

1.1.0 继续使用固定 1.0.0 Ghidra/x64dbg 资产；供体 ZIP 和逐文件哈希不变。Burp 目录中的程序、加载器、配置、许可均未打包。版本号表示本地代码版本，不表示 GitHub 已发布新附件。

## 验证

运行 `npm run test:capture` 检查本地 HTTP/HTTPS/WS/WSS、CA、记录恢复、来源引用、审批与工作台 fixture；`node scripts/bench_capture.mjs` 测量回环保存吞吐。`node scripts/test_host_sdk.mjs` 验证实际安装 DSH SDK 的 Core8/Full 43 隔离和13个审批入口。Windows 安装版本兼容见 `scripts/test_capture_pack.ps1`。

`npm run test:capture-runtime` 使用本机 HTTP 服务实际下发生成的 PE64，经代理保存、载荷检查、固定目录提取，再在真实随包 Ghidra 中打开并生成五节函数 dossier。只使用临时样本与数据库，不执行目标进程；报告保存在用户 artifacts/capture-v110。此原生测试单独运行，不以分类器 mock 代替引擎验收。

这些测试分别使用可控本地服务、renderer fixture 和隔离 SDK，不等于外部网站、任意 App 或真实桌面所有交互已验收。

状态功能另用 `npm run test:protocol-state` 验证构建器、部分轨迹、来源重叠、模型假设和真实数据 worker；`npm run test:protocol-state-network` 验证本地 HTTP 采集到状态推断/新轨迹验证的完整引用链。该证据不代替本轮实际 DSH GUI 安装、重载和点击操作的独立验收记录。
