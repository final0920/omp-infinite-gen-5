# 签名规则匹配(P7,2026-10-25)

`ig5_scan` 在原有静态扫描之外返回 `ruleMatches`:用一份**受限的 YARA 风格规则源**匹配同一次扫描已经读到的字节。规则源默认是内置表,也可以由调用方通过新的可选参数 `rules` 传入。

> 一条规则命中只说明**这些字节出现在已扫描的范围内**,属于证据等级 **E0(签名线索)**,不证明加壳、行为、意图或身份。它补充 `packing` 的结构判断,不能替代脱壳或动态分析。

## 1. 调用方式

```jsonc
{
  "tool": "ig5_scan",
  "arguments": {
    "target": "C:\\samples\\sample.exe",
    "rules": "rule my_marker : probe { strings: $a = \"MZ\" condition: $a }",
    "max_rule_matches": 256
  }
}
```

- `rules` 省略 → 使用 `worker/feature_rules.py` 的内置表(`ruleSet.origin = "builtin"`,`version = RULES_VERSION`)。
- 传入 `rules` → **整体替换**内置表(`origin = "custom"`,`version = 1`),不会与内置表合并。
- `rules` 必须是字符串,最长 65,536 字节;空串、纯空白、语法错误都在扫描前抛错,不会被静默忽略。
- `max_rule_matches` 控制记录的证据条数(默认 256,最大 4096);它不改变规则是否命中,也不改变出现次数的统计上限。
- 不新增工具。`rules` / `max_rule_matches` 是 `ig5_scan` 的**参数增量**,工具面在 P7 时为 Full 41(P2 拆分后为 Full 43);参数不属于既有契约的破坏性修改,但一并提交评审。

## 2. 支持的子集

```
rule NAME [: tag ...] {
  meta:
    description = "text"        // 也可以写整数
  strings:
    $text = "MZ"                // 默认按 ascii 匹配
    $text2 = "MZ" ascii wide nocase
    $hex = { 4D 5A ?? 00 ?A 4? } // ?? 任意字节, ?A 低半字节固定, 4? 高半字节固定
  condition:
    $text and not $hex or (2 of them)
}
```

- **文本**:`ascii`(默认)、`wide`(ASCII 字符逐字节插入 `\0`)、`nocase`(仅 ASCII 大小写不敏感);`wide ascii` 两种宽度都生成。转义支持 `\n \r \t \0 \\ \" \xNN`;非 ASCII 文本按 UTF-8 编码,但不能用 `wide`。
- **十六进制**:固定字节、`??`、`?h`、`h?`;至少一个固定半字节;模式长度计入固定宽度(不用变长通配)。
- **条件**:`$id`、`true`、`false`、`not`、`and`、`or`、括号、`all of them`、`any of them`、`N of them`。优先级:`not` > `and` > `or`。
- **meta**:`key = "value"` 或 `key = 123`;`description` 会原样进入每条命中。
- **标签**:规则名后的 `: tag ...`,小写 `[a-z0-9_-]`,最多 8 个;内置表还要求标签落在 `TAG_VOCABULARY` 内。

**明确拒绝**(编译期报错,不会静默降级):正则 `/.../`、跳转 `[n-m]`、选择 `( | )`、`fullword`/`xor` 等修饰符、计数 `#a`、`at`/`in`、`for` 循环、模块、`$a*` 通配标识符。

## 3. 输出

```jsonc
"ruleMatches": {
  "schema": "ig5.ruleMatches.v1",
  "evidenceLevel": "E0",
  "ruleSet": { "origin": "builtin", "version": 1, "rules": 16, "strings": 37 },
  "matches": [{
    "rule": "upx_stub",
    "tags": ["packer", "compressor"],
    "description": "UPX marker or the UPX packer banner",
    "stringsMatched": 1,
    "strings": 2,
    "occurrences": 1,
    "evidence": [{ "string": "$marker", "segment": ".text", "ea": "0x401010", "length": 4 }]
  }],
  "coverage": {
    "bytesScanned": 1048576,
    "sampling": "same bounded ranges as the indicator sweep; unread ranges were not matched",
    "matchedRules": 1,
    "matchesTruncated": false,
    "occurrencesTruncated": false,
    "truncated": false
  },
  "note": "A satisfied rule means those bytes occur in the scanned ranges. It is a signature lead, not proof of behavior, packing, intent or identity."
}
```

- 每条命中的 `evidence` 最多列 16 条;`occurrences` 是**已扫描范围内**的完整计数(到上限为止)。
- `matchesTruncated` = 证据条数超过 `max_rule_matches`;`occurrencesTruncated` = 某个模式达到 1024 次计数上限。两者任一为真时 `coverage.truncated` 与 `ig5_scan.truncation.rule_matches` 都为 true。
- `bytesScanned` 与 `ig5_scan.coverage.bytesRead` 相同;未读的区间没有被匹配,也不能据此说"不存在"。

## 4. 内置规则表(v1)

| 规则 | 标签 | 依据 |
|---|---|---|
| `upx_stub` | packer compressor | `UPX!` 或 UPX 横幅 |
| `themida_winlicense` | packer protector | `.themida` / `.winlice` / `WinLicense` |
| `vmprotect` | packer protector | `.vmp0`–`.vmp3` |
| `enigma_protector` | protector | `.enigma1` / `.enigma2` |
| `aspack` | packer compressor | `.aspack` / `.adata` |
| `mpress` | packer compressor | `.MPRESS1` / `.MPRESS2` |
| `pecompact` | packer compressor | `pec2to` / `pec2mo` |
| `petite` | packer compressor | `.petite` |
| `nspack` | packer compressor | `nsp0`–`nsp2`(含点号形式) |
| `rlpack` | packer compressor | `.RLPack` |
| `yoda_protector` | packer protector | `.y0da` |
| `pyinstaller_bundle` | packer runtime | `MEIPASS` / `PYZ-00.pyz` / `pyi-windows-manifest` |
| `nsis_installer` | installer | `Nullsoft Install System` |
| `inno_setup_installer` | installer | `Inno Setup Setup Data` / `InnoSetupLdr` |
| `dotnet_managed` | runtime | CLR 元数据根 `BSJB` **且** `#Strings` 堆名 |
| `autoit_compiled` | runtime | `AU3!EA` |

精度说明(实测中专门收紧过的点):

- `dotnet_managed` **不**匹配 `mscoree.dll` 导入或 `_CorExeMain`/`_CorDllMain`。原生 Windows DLL(msvcrt、ucrtbase、atl100、sxs、catsrv 等)会引用 `mscoree.dll` 作为 COM 激活垫片;`mscorlib.dll` 本身也没有 `_CorDllMain` 字符串。改用 CLR 元数据根后,300 个 System32 抽样文件的 `dotnet_managed` 命中从 16 个降到 4 个(其中 `mfcm140.dll` 是托管 MFC,属真实命中),原生对照组全部为零。
- `nsis_installer` 只认长横幅:`NullsoftInst`/`Nullsoft.NSIS` 也出现在 Windows 应用兼容数据库(kernel32.dll)里。
- `yoda_protector` 去掉了过短的 `.yp`(会命中 RAR/APK/EXE 的随机数据)。

内置表的每一次改动都应同时更新 `RULES_VERSION` 和本表;`feature_rules.validate()` 在导入时编译并检查描述、标签与字符串,写错会在第一次测试运行时报错。

## 5. 语义与边界

- 匹配的是**扫描器已经读取的字节**:默认每段 1 MiB、全局 8 MiB 的前缀/中段/后缀采样。超过预算的部分不会被匹配;报告用 `coverage.bytesScanned` 与 `truncated` 如实说明。
- 分块读取使用 `overlap = 最长模式长度 - 1` 的尾部重叠,跨 64 KiB 块的模式只计一次;跨不可读区间或不同段的字节不会被拼接。
- 模式在数据中任意位置出现即计数(包括重叠出现);`?A`、`4?`、`??` 只匹配单个字节。
- 规则源本身是**数据**:不执行、不联网、不写数据库、不改变目标文件;`ig5_scan` 仍是只读工具。
- 命中可以来自压缩/加密数据、资源或无关字符串;**签名可被伪造**,内置表是分诊线索而不是恶意判定。自定义规则源由调用方负责其内容与精度。
- 不支持按节/段限定作用域、正则、跳转、`fullword`、`xor`、计数、`for`、模块;这些在编译期拒绝。

## 6. 验证

- `scripts/test_rule_match.py`(41 项,含真实 Ghidra 验收):
  - 编译器:拒绝正则/跳转/选择/修饰符/计数/`for`/未定义 `$id`/越界 `N of them`/重复规则名/超限规则数与字符串数/超长模式/非法转义/元数据上限/条件节点上限;
  - 匹配:文本大小写、宽字符、转义、非 ASCII;十六进制 `??`、`?A`、`4?` 与逐字节暴力对拍;`nocase` 对拍;
  - 条件:`not`/`and`/`or` 优先级、`all/any/N of them`、`true`/`false`、宽/ASCII 变体只计一个字符串;
  - 分块:每个切分点只命中一次、精确 EA、重复标记不丢不重、跨段不拼接、未读区间不发明命中;
  - 预算:证据条数上限、1024 次出现上限、`truncation.rule_matches`、参数校验;
  - 真实文件:保护语料中 UPX/Themida/ASPack/VMProtect/PyInstaller 各命中对应规则;未保护原件与干净语料文件零命中;300 个 System32 抽样只有少量 `dotnet_managed`,且每个都确实含 `BSJB` 与 `#Strings`;原生对照组零命中;.NET Framework 真实托管程序集命中;
  - 真实 Ghidra:`ig5_scan` 走内置表与自定义规则、证据地址、`max_rule_matches` 截断、正则规则被 RPC 拒绝、样本 SHA 不变、`idb_modified=false`。
- 运行:`node scripts/test_rule_match.mjs`(随包 Python + 真实 Ghidra);纯 Python 可用 `runtimes\ghidra\python\python.exe -I -B -X utf8 scripts\test_rule_match.py [--runtime ghidra]`。
- 门禁:`tools/ci/gate.json` 的 `rule-match`(`tier: extended`),默认门禁不跑重测试。
- 变异检查(2026-10-25):对 `rule_match.py`/`feature_rules.py` 逐一注入 7 个定向缺陷(尾部重叠减一、关闭 `fresh_from` 去重、还原高半字节通配错误、条件节点预算不重置、出现次数上限 1024→1023、证据截断 16→15、`dotnet_managed` 改回 `mscoree.dll`),7 个全部被测试杀死。检查中发现两处测试弱点并已补强:出现次数上限改为同时断言字面量 1024,新增"短模式落在重叠尾部时不得重复计数"的用例。
