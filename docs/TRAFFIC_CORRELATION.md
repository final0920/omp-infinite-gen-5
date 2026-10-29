# 流量 ↔ 样本对应(P9,2026-10-25)

`ig5_capture` 新增 `action=correlate`:把一条已保存的交换记录与一个本地样本文件做**只读**对照,回答两个问题——

1. 捕获到的正文与这个文件是不是同一份字节?(**E1**)
2. 捕获到的 origin/主机/路径/请求头值/网络 API 名,是否以字面量出现在样本字节里、在哪个文件偏移?(**E0 线索**)

不新增工具;`action=correlate` 与 `sample` 参数属于 `ig5_capture` 的操作面增量。不执行样本、不打开任何引擎、不启动监听、不发送请求、不写数据库。

> 证据口径:**正文哈希同一性 = E1**(捕获字节与文件字节相同);**字面量出现 = E0**(样本字节里确实有这串字符,可能是字符串、导入名或无关数据,不证明样本在运行时使用它)。**没找到不是证据**:样本可能动态拼接、编码存放或根本不用。

## 1. 调用方式

```jsonc
{
  "tool": "ig5_capture",
  "arguments": {
    "action": "correlate",
    "id": "<保存的交换 UUID>",          // ig5_capture action=list 返回
    "session_id": "<采集会话 UUID>",     // 可选;给了就校验记录属于该会话
    "sample": {
      "path": "C:\\samples\\client.exe", // 本地普通文件,只读,≤ 32 MiB
      "sha256": "<可选,小写>"           // 给了就必须与磁盘一致,否则直接失败
    }
  }
}
```

前置条件:记录必须已在采集历史里(重启后仍可读);样本必须是普通非链接文件;样本超过 32 MiB 直接拒绝,不做部分扫描。

## 2. 输出

`schema=ig5.trafficCorrespondence.v1`,`executed=false`,`networkRequests=0`,`mode=read-only`。

- `capture`:记录 id、会话、方法、`origin`/`host`、`path`(**不含查询串**)、状态码、协议、`complete`/`truncated`/`encrypted`/`tunnel`/`websocket`,以及请求/响应正文的 `bodySha256`、捕获字节数、观测字节数、截断标志。
- `sample`:`path`、`sha256`、`bytes`。
- `evidence`:`identityLevel: "E1"`、`literalLevel: "E0"` 与固定措辞的口径说明。
- `links[]`:每项 `kind`、`label`、`needle`(仅端点/头值/API 名)、`evidenceLevel`、`matches[{offset, encoding, caseInsensitive}]`、`detail`。
- `unmatched[]`:端点与头值中没有找到的字面量,`detail` 固定写明"缺失不是证明"。
- `coverage`:扫描字节数、样本上限、评估的 needle 数、端点 needle 数、字面量匹配上限与 `matchesTruncated`。
- `note`。

| `kind` | 级别 | 含义 |
|---|---|---|
| `body-bytes-identity` | E1 | 捕获正文与该文件**字节完全相同**(哈希与长度都一致);`direction` 指出是请求还是响应。不表示客户端执行/加载了它 |
| `endpoint-origin` | E0 | `scheme://host[:port]` 字面量出现 |
| `endpoint-host` | E0 | 主机名(以及非默认端口时的 `host:port`)字面量出现 |
| `endpoint-path` | E0 | 路径字面量出现(查询串永不读取) |
| `request-header-value` | E0 | `user-agent`/`referer`/`origin`/`accept`/`content-type` 的值出现;这些是唯一会读取的头值 |
| `communication-api-literal` | E0 | 网络 API 导出名(如 `WinHttpOpen`、`InternetOpenW`)作为字面量出现;短名(`socket`/`connect`/`send`/`recv`)带 `ambiguous:true` |

匹配三种写法:ASCII 原样、UTF-16LE 原样、ASCII 大小写不敏感;偏移是**文件偏移**,不是 RVA/VA。API 名要求词边界(`WinHttpOpenW` 不会被当作 `WinHttpOpen`)。

## 3. 边界

- 只做字面量搜索:不支持正则、通配、Base64/UTF-16BE/其他编码、压缩或加密内容;加壳/压缩的样本里看不到原始字符串。
- 每次调用只对照**一条**交换记录;多条请逐条调用。不自动推导"这批流量都属于这个样本"。
- 只读文件字节,不读取已打开的静态数据库、不映射到函数/地址;得到偏移后用 `ig5_open` + `ig5_search`/`ig5_bytes` 自行落到函数(文件偏移与 RVA 需按节表换算)。
- 不读取 cookie/authorization 等敏感头,不读取查询串,不输出正文预览或上下文字节;`unmatched` 只回报我们选择的端点/头值字面量。
- 不证明因果关系:哈希相同只说明"这段捕获字节就是这份文件",不说明客户端执行了它,也不说明服务器端如何生成;字面量相同只说明"字节里有这串字符"。
- `.NET`/脚本/解释型载荷、动态拼接 URL、域名由算法生成、TLS 未解密隧道里的内层内容,都可能是空白。

## 4. 安全

- 纯只读:不启动样本、不打开 Ghidra/x64dbg、不建监听、不发网络请求(DNS 也不解析);运行态测试用 `ig5_status` 的会话数与服务器请求计数验证这一点。
- `sample.path` 由调用方显式给出,使用稳定读取(检查符号链接/替换/读取期间变化),超过 32 MiB 直接失败。
- 不写任何产物;结果只作为工具返回值。若需要保存,由调用方另行决定。

## 5. 验证

- `scripts/test_capture_correlate.mjs`(7 项,纯 Node,默认门禁 `capture-correlate`):正文同一性(E1)、同长度不同字节不误报、端点/头/API 字面量与精确偏移、UTF-16LE、大小写不敏感、词边界(`WinHttpOpenW` 不算 `WinHttpOpen`)、`unmatched` 措辞、查询串与敏感头不泄漏、样本哈希不匹配/形状/目录/超长路径/32 MiB 上限、空正文不伪造同一性、加密 CONNECT 隧道不冒充应用层正文、工具面枚举与参数、网络 API 清单与 `worker/behavior_rules.py` 分类表一致。
- `scripts/test_capture_correlate_runtime.mjs`(扩展层 `capture-correlate-runtime`):真实回环代理下发自造 PE64 夹具字节 → `materialize` 保存 → `correlate`;断言 E1 同一性、端点/路径/UA/`WinHttpOpen` 字面量偏移、零网络请求、未开引擎、保存字节未被修改、无查询串泄漏。
- 变异检查:14 个定向缺陷全部被杀死(见验收文档)。

## 6. 检查中发现并修正的问题

1. **测试假设错误**:origin 字面量的首个匹配偏移被写成 0,实际样本带 18 字节前缀;改为按样本内容计算期望偏移。产品逻辑无变化。
2. **变异脚本本身制造了语法错误**:`utf16-scan-removed` 只删除了 `for (...)` 而留下了 `if (...)`,导致"被杀"其实是测试文件语法错误,属于假杀。改为整条语句删除后重跑,该缺陷由断言真正杀死;其余 13 项结论不变。第一轮的 `14/14` 不作为最终数字,最终结果以修正后的 `mutation.log` 为准。
