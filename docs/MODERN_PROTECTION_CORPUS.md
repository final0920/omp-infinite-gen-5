# 现代保护与原生采集验收

`scripts/fixtures/modern_corpus.json` 只分发来源、配置和固定摘要，所有保护二进制、生产器、SDK 与公开上游样本保留在私有 artifacts。公开外部样本不执行；原生调试仅使用本项目自产控制。

2026-10-14 取自 [官方下载页](https://www.vmpsoft.com/files) 的 VMProtect Demo 3.11.0 build 2835，安装器和 console producer 的 Authenticode 均有效。生产器 SHA256 为 `52e23d2f9c959a21bdc2067d03d29e20cd85995a202cb7f2116d89b19c88c527`；版本／签名记录保存在 `modern-protection-20261014/official-demo-provenance.json`。原插件原生供应资产和旧清单均未重新封存。

自产输入包括九类确定字节程序（加法、XOR、乘法、位混合、有符号选择、移位、固定／输入相关循环、栈读写）的直接入口与独立调用入口，以及 MSVC 19.51.36260.0 编译的加法、变量旋转混合、有符号64位选择、乘加位运算独立程序。官方生产器按 virtualization／mutation／ultra 三模式生成 66 份输出；配置 Options=0，只能称 Demo/basic options。每份固定输入／输出／项目／编译日志 SHA，产物不进插件；随机保护布局不承诺跨生产器重新生成逐字节相同输出。

公开对照来自 [mzakocs/VirtualizationObfuscatorAnalysis 固定版本](https://github.com/mzakocs/VirtualizationObfuscatorAnalysis/tree/2fb7ad84a90a73c950c39eccbad81cc2f6c25c33)。其中 VMP3／Themida 保护版本没有独立证实到具体小版本，不能冒称 3.8+。GitHub README 的作者成绩也不是五代的结果。

现代清单共 271 条记录、117 个二进制引用／116 个唯一 SHA：35 个唯一控制、15 个作者标注保护、66 个官方生产器自产保护。静态 intake 有 116 个引用加载通过、1 个不可用；那份自产 mutation 被 Defender 隔离，保留原 SHA 和状态，没有恢复、改名规避或修改安全设置。重复引用不计额外样本，静态加载不计业务恢复。

## 证据位置

根目录：`C:\Users\IG5User\.dsh\ig5\artifacts\modern-protection-20261014`。

- `intake.json`：清单与真实严格 PE loader，未执行目标。
- `generated-vmp311`／`generated-vmp311-harness`／`compiled-vmp311`：原输入、保护输出、完整生成配置与日志、generation receipt。
- `compiled-control/compiler-proof.json`：自产 C 源码、编译器和原输入摘要。
- `compiled-suite-control`／`compiled-suite-vmp311`：三个独立编译案例，固定源码与 case define；九份保护输出的完整项目和 producer 日志。恢复情况以 `native-*/acceptance.json` 为准，生成数量不计恢复成功数量。
- `native-compiled-add64-virtualization/receipt.json`：原公共调试／离线调用的历史结果，保留修复前的失败；最新 `acceptance.json` 另外记录重新通过公开只读工具的验收。VMP 3.11 virtualization 加法函数有 25,241 条记录指令、一个明确无中间快照的 CPUID/STC 连续指令，恢复 64 位 `x+y`，末态／SMT／1,124 个独立参考输入对通过。一个代码 DIR64 fixup 有原目录依据，loaded-image 字节全部匹配，原文件逐字节完全相同的声明为 false。仅证明记录环境下的函数模型，`wholeBinaryVerified=false`。
- `native-*/thread-address-labels.json`：由本机系统 DLL 导出位置标注保存的线程地址，仅最近导出提示，不是完整函数边界／栈回溯证明。
- `native-compiled-rotate-mix64-virtualization-continuation-fix/acceptance.json`：20,960 条实际记录指令、41 段，一个明确无中间快照的 CPUID/SUB RBP,8 连续指令。恢复模型与 `rol64(x,y&63) ^ uint64(x+y)` 的独立参考在2,409组输入核对一致，SMT、末态与加载字节绑定通过。`receipt.json` 保留原投影失败，`revalidation.json` 保存修复后公开只读工具报告；合成反例被拒绝并保留在 `synthesisAttempts`。报告 `b12b76ed-eda3-400b-aef8-8ed657f73ea9`／SHA `56b364be1200cccccda67d1a1904cd1a9e3d3312363852fc937127d063e3bc68`，仍是记录环境下的函数模型。
- `dsh-verified.json`：冷启动后的配置模型实际调用 `ig5_profile` 与 `ig5_ir`，报告 `debea49d-770f-40e7-9b76-db3c01367b8a`／SHA `47ae25b70a9a862487b3d54def5678c749df0898109dd126dd7ee028c8ff34d8`。25,241 指令、末态、SMT、加载字节绑定与 1,124 组独立输入核对通过；本次模型回放已有原生记录，没有再次启动目标。
- `native-compiled-signed-select64-two-path-validated/revalidation.json`：两个独立自产3.11 virtualization 原生运行，输入分别为1／2和2／1，25,205／26,260条记录指令；两条业务条件恢复为 signed64 的 <= 和 >。公开只读工具报告 `5833c9d4-03bb-4e28-b1b8-ceacacb41e94`／SHA `e04146063c55b55d06a74846a3f7d1f3bc315abd8e61d6675ae5b722d1b5c08e`，路径互斥与覆盖、末态和加载字节均通过。历史单路径 partial 和首轮合并状态预算失败保留；模型为 `signed(x)<=signed(y) ? y : x`，仍不宣称整个二进制已恢复。
- `dsh-compiled-signed-select64-verified.json`：冷启动后的配置模型实际双路径调用报告 `479497cd-78ae-42ec-a1a0-0b04ca74029d`，合计51,465条指令、两种初始EFLAGS（0x200／0x204）、两条独立GS/TEB观察均保留。模型与原生验收一致，路径覆盖／互斥、末态／字节绑定与2,409组独立参考通过；实际26次SMT查询、329次相同证明复用。`source-reference-proof.json` 另以全64位输入域的独立 signed max 参考证明等价。首次模型返回仍因详细观察过长而读取完整报告，此后增加16 KiB自适应预览；新预览的冷启动模型复验另行记录，不能以本条旧报告代替。
- 上述首次DSH回执已另外保存在 `dsh-compiled-signed-select64-verified-before-compact.json`；当前回执为新版预览的真实模型报告 `2a6c3d32-6879-403d-bab2-5129668aacc1`／SHA `d814c53aef4903cb93082e0ca74bfea1c5be11f73dc91d94a6936447f9b4670b`。两次工具调用直接返回完整核心字段，模型无需读全报告；摘要最初误写min，后续已明确更正为signed max，原证明不变。
- `native-compiled-mul-mix32-ultra-long-budget/acceptance.json`：自产3.11 Demo/basic options Ultra 完整原生记录59,167条指令；原50k前缀失败保存在 `native-compiled-mul-mix32-ultra-first-path`，重新采集显式100k预算后到达函数出口。公开只读恢复报告 `ebf20f5c-67ea-477e-9348-680fbdc8492d`／SHA `e6e482037558dc80d093e8347a99140f4bbcb36917aa57d4168f8d929e492217`，恢复为32位 `((x XOR y)+99)*143` 后零扩展到64位。局部SMT改写链、原投影证明、末态／加载字节、2,409组独立输入及全64位输入域的独立源码参考均通过；单块复杂MBA的参考查询超时被通用表达式简化解决，没有放宽SMT时间。原采集回执保留未简化式，修复后报告另存 `revalidation.json`。

已发现并针对性修复的能力缺口包括 Win64 输入对、ASLR 地址绑定、真实读内存和栈访问、PUSHF／原生标志位、参数暂时未使用时的符号生命周期、长轨迹的不可变分段连续性、暂停／单步先于 RESUME 的回调竞态、挂起系统调用的标准进程中断，以及原线程的只读上下文。受控自产样本已真实验证这些路径；现代 VM 的最终结果以 receipt 当前状态为准。

Demo 程序通过 NtRaiseHardError 显示普通提示，正常确认后才进入业务；普通提示的确认不等同于修改许可。失败调试留下的通知可在退出被调试进程后仍排队，不能据超时推断业务函数失败。生产工具不会改许可、自动清除安全隔离或用未经观察的默认值补齐隐藏状态。

复查 intake：设置 `IG5_CORPUS_MANIFEST=scripts/fixtures/modern_corpus.json`、`IG5_PROTECTION_CORPUS` 和 `IG5_CORPUS_EVIDENCE` 为上述根目录后运行 `npm run test:protection-corpus`。公开下载用原 downloader 的独立固定清单；本清单包含自产配方，不交给下载器。原生 fixture 回归见 `npm run test:debug-trace`，现代测试需明确选择本项目生成的固定输出，不运行外部挑战。

## 2026-10-14 多壳补充

[UPX 5.2.1 官方发布](https://github.com/upx/upx/releases/tag/v5.2.1) 的 win64 ZIP 摘要为 `eabc6792a347d45e945be7748423e7868fd01b0d2bcaa2f4b1031fd71ff69bda`，实际 producer 摘要 `d20ebe0b7b22b6be968c8c34be61f94ddea12cb11462e2cec27f548ef9574df8`。`upx-generated/generation.json` 保留三个自产编译案例的 NRV／LZMA 尝试；NRV 三份生成成功，LZMA 三份因小输入 NotCompressibleException 失败，后者不计有效样本。此补充独立于前述271条固定现代清单，不把新增文件自动计入旧 intake。

`native-compiled-*-nrv-best-snapshot-validated` 中旋转混合／signed max64／mul-mix32 分别记录7／4／4条实际指令，主映像快照和目标／原生暂停／摘要绑定、完整末态、输出SMT均通过；压缩原文件的对应代码字节不匹配保留为 false。每例2,409组独立参考输入一致；旋转另有64类旋转计数UNSAT，另两例有全输入域源参考UNSAT。仅恢复记录环境下的函数模型，`wholeBinaryVerified=false`。修复前多记硬件陷阱处 MOV 和磁盘映像绑定失败的回执独立保留。

Themida 使用 [官方 Demo](https://www.oreans.com/themida.php)，实际二进制版本3.2.4.34、有效签名；ZIP 摘要 `744ab8489d34b5080074de198b11c5f6ef6034dc3ebe3f4d9385e9639ce97d30`。官方命令行加显式自产输入可读取项目，但 Demo 将 Tiger 标记转换为 Falcon Tiny，不能作为三个不同 VM 强度的证明。首次源码被编译器把业务算术移到标记外，已改为 volatile 控制并重编译，旧空标记产物不计VM验收。有效保护尝试的输出临时文件被本机 Defender 实际隔离，`oreans-generated/template-cli-receipt.json`／日志保留失败；未恢复隔离、规避安全检测或修改系统设置，Themida 业务恢复尚未通过。

## 分支与固定轮数补充

`packed_compiled_suite.c` 是独立自产源码，增加低位条件分支和八轮64位旋转混合。64KiB导出常量数据只用于让LZMA得到可压缩输入，不计为业务逻辑难度。编译器 map／源码／输入固定摘要保存在 `packed-suite-control`，四份 UPX 生成记录在 `upx-packed-generated`。`upx-packed-format-verified/receipt.json` 用固定官方 producer 的 fileinfo 与校验模式证实 NRV method=2／LZMA method=14、目标字节不变；方法编号依据 [UPX 5.2.1 定义](https://github.com/upx/upx/blob/v5.2.1/src/conf.h)。该格式校验不执行目标。

NRV、LZMA 各自的分支案例有两份独立原生记录（10／9条指令），原来的单路径失败保留。`native-packed-branch-mix64-{nrv,lzma}-two-path-*` 保存两份独立快照引用、完整末态、条件互斥／覆盖与独立全输入域源码参考UNSAT。两次运行实际采用相同主映像地址，不能称为本轮原生验证了不同ASLR地址。八轮案例 `native-packed-round-mix64-{nrv,lzma}-best-first-snapshot` 各记录96条指令，2,409组独立参考及全输入域源码参考UNSAT；LZMA 首次显示预算失败仍在原 receipt，修复后只读报告另存 revalidation。求解次数／时间／内存及显示预算均未扩大，所有结果 `wholeBinaryVerified=false`。

同一自产源码另由固定 VMP 3.11 Demo 生成6份 virtualization／mutation／ultra 输出，摘要与配置在 `packed-suite-vmp311`；当前仅生成与静态核验，不计业务恢复通过。现代固定清单更新到318个元数据记录、137个二进制引用／131个唯一SHA：37个唯一控制、15个作者标注保护、79个官方自产保护（VMP72＋UPX7）。`expanded-corpus/intake.json` 有136个严格加载通过、1个旧隔离文件不可用；静态通过数量与原生／DSH业务验收分别报告。DSH 后续真实验收见下段，不能由源代码测试代替。

## DSH 内存快照真实验收

2026-10-14 16:04 正常退出宿主，核对进程停止后镜像同步源码，16份文件摘要一致，再冷启动；新的审批门与客户端启动日志保存在 `native-image-verification/cold-start-packed.log`。配置模型 `deepseek-v4.1-flash` 在新会话实际调用公共 profile／ir，回放四组已有原生记录，没有重新启动样本。

| 案例 | 新 DSH 报告 | 指令数 |
| --- | --- | --- |
| LZMA 双路径分支 | c5795ff0-f404-40be-846f-42490f5fd92a | 10＋9 |
| NRV 双路径分支 | ec66e457-c236-480e-bdfb-cc3c1ef706b6 | 10＋9 |
| LZMA 八轮混合 | 207e704c-8994-4762-b767-a5cb79b76279 | 96 |
| NRV 八轮混合 | 3dc90989-de98-49f0-a9a8-176ac8522814 | 96 |

`dsh-upx-batch-verified.json` 绑定四份 DSH 报告、独立原生验收、2,409组参考输入、部署摘要和现场截图。四份实际结果的目标／轨迹／录制环境／捕获映像来源／结构化表达式与独立验收完全一致；末态、输出证明和字节绑定通过，双路径覆盖与互斥均为UNSAT。模型初次说明把八轮写成七轮，并把单路径证明范围说得过窄，随后已明确更正；原答复和更正均保留。

在声明的记录环境中，`coverage=trace-model-input-domain` 是对全部符号化64位输入的模型证明；守卫为true的单路径不需要两路径覆盖证书。原二进制全部路径、环境和副作用仍未验证，四例 `wholeBinaryVerified=false`，原文件字节匹配为false；没有把模型证明升级为完整脱壳或整个程序恢复。

## 新增 VMP 分支原生验收

`native-packed-branch-mix64-virtualization-two-path-validated` 合并两个独立运行：23,889／23,476条指令，共47,365条，均明确到达自产调用者返回地址。各有一条显式CPUID／TEST DH,2合并停止，缺少中间快照的事实保留。启动通知超时和原来不支持的续指令失败回执另存，原保护文件未改动。

公开只读恢复报告 `03db32e8-bc99-4d50-8b9e-b0563e3345ee`／SHA `4a9c3dabc4bbbe800a0018aff62b92bd98f1d6eeca796fd2cbe98e407e36d52c`，两条条件为 `low1(x)!=low1(y)` 与 `low1(x)==low1(y)`；原来的141条未决输入约束经候选等价证明消除。两路径输出／条件／覆盖／互斥、完整末态和各自捕获映像绑定通过；实际76次SMT、507次证明复用，原有预算不扩大。

每例2,409组独立参考一致，`source-reference-proof.json` 在全部64位输入域证明与自产C源参考等价。virtualization分支函数已通过这项验收；同组各输出仍分别验收，不能按生产数量计通过。DSH新版安装与配置模型的结果另行保存，所有结果仍为 `wholeBinaryVerified=false`。

mutation分支另有22／16条完整原生指令，两份记录均到达调用者返回地址，未修改保护文件。`native-packed-branch-mix64-mutation-two-path-v1` 保留最初位片表达式；通用连续位片取反合并修复后报告另存 `native-packed-branch-mix64-mutation-two-path-normalized/revalidation.json`，报告 `6893a71b-2803-4340-86e7-52f1cfc023af`／SHA `99691e8a4a65313ddb403bedb46c2e8bc568320b95540f9b4bd8cc5a289e4ae8`。局部SMT证书、原投影证明、两路径覆盖／互斥、末态／映像字节、2,409组参考和全输入域源码参考均通过。实际DSH模型验收另存；Ultra和八轮其他模式仍需独立业务恢复。

八轮mutation另有完整167条原生指令，报告 `3d144297-fa53-4a2b-a5de-de8456e5a5a6`／SHA `ef6e4c9b75f998b0ad38f4b3fa6ee657e5e687feb946a29287bf2d5878c3e7cb`，证据在 `native-packed-round-mix64-mutation-owned-record-v1`。真实返回点、完整末态、映像绑定、2,409组独立参考和全输入域源码参考UNSAT通过，实际DSH模型复验另行记录。其余模式没有按本例外推通过。

Ultra分支的独立路径为69,119／67,678条指令，总136,797条。取反掩码守卫漏识别和原双路径处理期限失败均保留；通用掩码推导及标志位AST构造优化后，`native-packed-branch-mix64-ultra-two-path-compact-flags` 报告 `2bde831d-2e52-427c-ad1b-40c2132c48f3`／SHA `ea97d2e4215902fa6f4ab772529d9c814c2510ae059f5a5da8b005fd58857951`，56次实际SMT／517次复用，两路径互斥／覆盖、末态／映像字节、2,409组参考和全输入域源码参考通过。没有扩大128次SMT、100k每路径或50／60秒处理预算；最终代码复验和实际DSH报告另存。

八轮virtualization共有56,749条完整原生指令、111个窗口。首轮CPUID后CMP续指令失败、展示预算失败均保留；通用16位CMP续指令和AST前序简化补齐后，`native-packed-round-mix64-virtualization-word-cmp-record-v2` 报告 `ea4dd2e0-da13-4b36-ba10-f29467c2b698`／SHA `0c37777413559f63a3b10c5a17ff5b93d23b11b8bd2d8ac849409efcdff54675`，24处AST／3处表达式局部改写证书全部UNSAT，35次实际SMT。末态、捕获映像、2,409组参考和全输入域源码参考均通过；实际DSH模型另行验收。八轮Ultra尚未完成，不外推通过。
# Enigma 官方学习夹具与未通过项（2026-10-14）

新增 ScyllaHide 用户态环境与编译入口定位／显式异常续行后，v2自产分支函数的两条原生路径均到达返回点，分别7007／6998条指令。第一次录制把未退休的存储指令陷阱写进轨迹，重放明确拒绝；录制器增加每个存储位置前后字节核对后，重采轨迹的完整GPR／flags末态与捕获映像绑定通过，两条路径输出投影各有UNSAT。旧失败轨迹不删改。

v2八轮传统VM也已采到真实返回：`native-packed-round-mix64-enigma-classic-vm-scyllahide-store-round-v1`，66614条／131窗口，原目标SHA不变。首个重放错误定位到窄写／宽读重叠：低4字节已写，高4字节首次观察为 `0xbaadf00d`。内存模型改为仅初始化从未观察／写过的字节，保持已知具体值与输入符号，观察到的零同样标记已知；新增正反例后57项轨迹回归通过。修复后首轮在既有50秒期限内未完成输出证明，原失败记录保留。

2026-10-15 的通用互补移位旋转模板、引用展开／同宽加法扁平化及精确SMT DAG定义补齐后，报告 `88fcb6db-6e8e-4514-8a5a-5d67094ba3f0`／SHA `4298d2ee27b6c18e9bc0970fbdb66809429c504a209a431d8bb82a3aff79d2c3` 在原预算内完成末态／捕获映像核验，8处局部改写UNSAT及输出投影证明。独立2409组源码参考输入比较通过；独立全64位源码等价查询（原AST及DAG）都在2秒处超时，不能按比较样本升级证明。640条输入相关守卫未解、整体表达式null、覆盖为single-recorded-path，Enigma业务通过数仍0。64项轨迹回归、三份固定VMP样本及既有12个原生业务模型（各2409组参考及全宽源码UNSAT）重新通过；实际DSH调用另行核验。

后续表达式局部模板与结合交换规范化修复了全宽源码查询超时。新报告 `3f16dc3d-7d40-4de9-b450-f7c4d84d5b19`／SHA `daa74284fb7c80af36ebce45e1a935d48aebc553eb37117a1c84c6eef154559e` 在原512节点／64候选及求解预算内保存19处表达式UNSAT证书。独立2409组对照、完整uint64源码原查询与DAG查询分别通过，旧失败保留；68项轨迹回归与既有12个模型重新通过。原守卫分组诊断另找到 `x=0xbf8e3c24947ce2a2, y=0xfffbf3f707ab2019` 的真实SAT反例，不能把单条记录覆盖升级为全输入。Enigma业务通过数仍0，反例路径需要新的动态/语义证据。

`native-enigma-branch-scyllahide-two-path-v2` 保留离线结果：输入相关的VM内部条件／记录内存地址仍限制路径，奇数路径谓词超展示预算，尚未证明整体覆盖，`recoveredExpression=null`／`coverage=single-recorded-path`。将全部符号条件保留在合取中、集中证明候选等价，实际SMT由120减到78，128次／50秒等预算不变。不能将局部输出表达式视作完整函数通过；Enigma业务通过数仍0。ScyllaHide的自产诊断夹具已由实际DSH模型验收，17次真实工具调用单独记录，不计业务模型。

官方 x64 下载页提供 **7.80 Demo**；商业更新页的8.x不能作为该生成器版本依据。签名安装包SHA `8a31a018feb5ea1fec2fa1d1d3a9e004b143be6b9d16155ba0a2c6bbe8cd2813`，解包的签名CLI SHA `c393a08a7259c053ef9eff48fac64051422144bda6a5f7c8927113f50960fd30`。安装器只作为数据读取；所需文件通过官方 innoextract 解包，不执行上游示例／脚本／keygen，不安装到系统。传统 `vm_begin/vm_end` 由官方SDK标记；Demo没有RISC VM，不能宣传其通过。

私有证据根 `modern-protection-20261014`：`packed-suite-enigma780-v2` 保存两份原有自产分支／八轮运算的加壳输出；`enigma-classic-vm780` 保存两份传统VM输出；`enigma-classic-vm780-v2` 使用独立编译的调试入口版本。两版 C 源码分别为 `scripts/fixtures/enigma_compiled_suite.c`、`enigma_compiled_suite_v2.c`，原有 VMP／UPX 源码不变。v2只在业务VM区域之外加入自产 INT3/RET 调试入口，业务公式、八轮循环及VM标记不变。生产器日志记录实际标记地址与VM处理，生成日志／哈希仅证明来源与生成。

当前 Enigma 验收尚未恢复业务函数：先发现无标题普通Demo提示、多个输入法组件 C++ 首机会异常；正常确认提示后，早期硬件断点运行以 `0x80000004` 退出，独立 INT3 入口版本以 `0x80000003` 退出。新增只读 ThreadHideFromDebugger 查询已在运行中取得真实 False；没有证据把这些退出归因于隐藏线程。显式 NtSetInformationThread 观察试验捕获到其他信息类，但未捕获／改写隐藏请求，32普通停止预算到期失败，不能算反反调试或VM恢复通过。

八轮 VMP Ultra 的原有 `native-packed-round-mix64-ultra-owned-record-v1` 实际在100000指令处终止，196段／18166919原始字节，没有函数返回；单段、拼接、离线恢复与SMT预算保持原值。必须按真实失败记录，不能将旧“采集中”状态或已有四个VMP验收结果升级为该案例通过。

