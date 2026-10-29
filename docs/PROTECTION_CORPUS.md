# 复杂保护学习样本库

后续现代 VMP／Themida 对照和官方 VMP 3.11 自产控制采用独立 [MODERN_PROTECTION_CORPUS](MODERN_PROTECTION_CORPUS.md) 清单，保留本页原 93 个目标的独立证据，避免混算版本和恢复成绩。

固定清单为 `scripts/fixtures/protection_corpus.json`；源码包只包含 URL、固定 commit、大小、SHA-256、Git blob ID 和派生来源。二进制、作者源码和压缩包保存在 `C:/Users/IG5User/.dsh/ig5/artifacts/corpus-expansion-20261014/corpus`，不随插件分发，不启动样本或上游脚本。

本轮清单 147 条资料记录，其中 93 个不同测试目标：14 个原生对照、38 个作者报告的保护目标、41 个保护方式尚未确认的官方挑战目标。后两组不能互相混称为已识别 VMP。93 个目标包含 14 个 APK；2 个原生文件被 Windows Defender 隔离，保留为未测试，不恢复或关闭防护。另有文档、原始／派生轨迹、压缩包及模型数据；它们不计入测试目标。

## 实际来源

| 来源 | 固定版本／内容 | 用途与限制 |
| --- | --- | --- |
| [JonathanSalwan/VMProtect-devirtualization](https://github.com/JonathanSalwan/VMProtect-devirtualization/tree/d2b26d66db59e341f179c7e326246d28c4d25491) | sample1/5/6 原生对照、VMP 文件、5 份作者记录 | 新增真实轨迹恢复；原 sample2/3/4 验收单独保留 |
| [JonathanSalwan/Tigress_protection](https://github.com/JonathanSalwan/Tigress_protection/tree/382a8e9e9aacad553f0b3c228e2b76077ff0ced2) | level0–4 × 5，共 25 个 ELF；10 个原生对照 | 调度随机化、superoperators、隐式控制流、handler 编码和嵌套 VM；没有作者原挑战源码／完整真值 |
| [VMProtectResearch/samples](https://github.com/VMProtectResearch/samples/tree/90ed9ed06cc31b9b2e52bdf89ade9d911f0b73db/test1) | 一对学习 PE、源码、两份日志 | 日志格式不同，未冒认为已支持 IG5 trace；未收集仓库中的商业反作弊驱动 |
| [banda59/VMP-devirtualize-project](https://github.com/banda59/VMP-devirtualize-project/tree/8d0256b701e9c3b7c2a6423638786a2bb5be2f3a/Challenge) | x86/x64 两个教学挑战 | 静态跨架构测试，未执行或修改程序 |
| [mibho/exploringVMP](https://github.com/mibho/exploringVMP/tree/6920188188b349803b8cba2c8e2de3a2751b08ac) | 7 个 VMP 3.6 DEMO 重编译变体 | 独立文件但同类业务，不能当 7 种不同算法；一份被隔离 |
| [吾爱破解官方 Challenge](https://down.52pojie.cn/Challenge/) | 2023–2026 四届春节公开题包及嵌套资料 | 初／中／高级 Windows、Android 等；题目等级来自文件名，具体保护方式未确认 |

Tigress README 所述的 920 个实验输入不都在当前树中，实际只按已下载 25 个挑战计数。Arkana 的样本目录只有 `.gitkeep`，未当成样本；其他文档或未经证实的成功率也未作为五代证据。

## 复现

```powershell
$corpus = 'C:\Users\IG5User\.dsh\ig5\artifacts\corpus-expansion-20261014\corpus'
node scripts\collect_learning_corpus.mjs scripts\fixtures\protection_corpus.json $corpus
& '.\runtimes\ghidra\python\python.exe' -I -B scripts\prepare_protection_corpus.py scripts\fixtures\protection_corpus.json $corpus 'C:\Program Files\7-Zip\7z.exe'
npm run test:protection-corpus
npm run test:expanded-trace
npm run test:protection-native
```

下载逐文件 hash 核验；吾爱破解按官方要求单线程。提取只调用已安装 7-Zip 读取数据，SHA 文件名避免成员路径写穿；每成员 32 MiB、总提取 256 MiB、深度 2、1,000 条成员／记录、45 秒单次提取硬期限。原压缩包 hash、成员名、派生 hash 保留；APK 未自动执行或作为原生代码处理。已记录隔离项不重复恢复。

`IG5_PROTECTION_CORPUS` / `IG5_CORPUS_EVIDENCE` 可指定样本／报告根目录。初次收集的 52pojie SHA 为下载实测摘要，不是作者数字签名。

## 验证口径

- `intake.json`：全部可读文件固定摘要／父来源核验，真实 `BinaryImage` 的严格 PE/ELF 解析和入口映射。71 个严格加载通过、6 个严格格式拒绝、2 个隔离、14 个 APK 尚无字节码分析。三个 VMP ELF 可按 PT_LOAD 绑定轨迹，但不升级为 section 有效；PE 重叠与非法目录没有放宽检查。
- `trace-baseline.json` / `trace-acceptance.json`：新增三份 VMP 的真实公开工具恢复、字节绑定、SMT 及独立输入对验证，保留失败前后的结果。合计 71,469 条新增指令；没有启动样本，`wholeBinaryVerified=false`。
- `native-static/receipt.json`：代表样本的真实 Ghidra 导入、函数选择、SSA 去混淆覆盖层，逐项保存 partial／未决控制流／预算。函数选择范围最多 128 个，不保证定位了 VM 入口；局部 SSA 完成不表示业务逻辑恢复。
- 本轮 DSH 模型调用与源码／运行副本 hash、重启日志另外保存。算法、公共包装器和宿主 GUI 是不同证据层。

当前仍未证明任意新壳、输入相关循环／别名内存、未知导入／OS 行为、Android 字节码或无轨迹样本的完整去虚拟化。样本入库数不能用作恢复成功率。
