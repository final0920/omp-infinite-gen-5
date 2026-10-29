# 有界候选路径发现

`ig5_ir level=discover` 让Agent从原文件首选入口生成指令地址序列。输入仅target/ea，可选max_instructions（默认128、1..128）和follow_direct_calls（默认false）；不接受观察寄存器/flags、已有路径、解码器选择或组合摘要。40工具、13审批门保持。

```json
{"target":"C:\\research\\owned.exe","level":"discover","ea":"0x140001000","follow_direct_calls":true}
```

沿顺序指令与无前缀EB/E9直接跳转前进。默认调用即停；显式follow_direct_calls=true才跟随无前缀5字节E8 rel32的实际callee入口，并保存首选返回地址。RET始终停止，不根据调用栈假定返回到call fallthrough，不生成ABI/返回值/库摘要。条件分支不选择一侧，保留规范字节可确定的双后继；间接/其他前缀控制、系统指令、循环、重叠、未映射/非执行/非初始化文件字节及预算边界停止或拒绝，缺失内存不补零。

`ig5-path-discovery-v1` 始终partial/unverified、candidateOnly=true、pathSemanticsValidated=false。宿主核对原文件字节/映射/顺序/直接控制字节/停止元数据，不是第二个指令解码器，也未证明原生可达性。后续把实际candidatePath完整传给现有project的projection_path，显式projection_decoder=java、选择要保留的GPR和原有projection_mode，由固定官方Java SLEIGH独立重新解码并检查真实路径/状态。发现成功不能抵消活flags、未知作用、CALL形状或别名拒绝。下一分支/派发入口仍需要对应证据，候选不提供完整VM业务结论。

发现worker仅用固定Triton的disassembly/控制元数据，不调用processing、不初始化目标寄存器/内存、不执行PE、不打开数据库。原runtime/上游/Java包装器pins不变；复用独立Triton清单65bf673f1c4304cc2c09076e3b96e368da9e0df72aa0badeba0c2a5cae392934，导入前核对并持续持有全部固定依赖文件。API参考[Triton官方Instruction](https://triton-library.github.io/documentation/doxygen/py_Instruction_page.html)及[官方TritonContext](https://triton-library.github.io/documentation/doxygen/py_TritonContext_page.html)。本轮没有引入外部实现或改变资产。

复用原lifter两请求池、协议根、创建时单进程/2GiB/50秒Job、60秒请求/5秒清理余量及4MiB输出。发现和后续Java投影是独立只读请求，各自确认同nonce ACK及协议根真实exit才释放；报告/pending徽章不提供进程清理权限。失败保留原九文件/64KiB诊断，新增DISCOVERY_FAILED和discoveryExpectedManifestPin（预期清单，不冒充已经验证）。诊断旧projectionDecoder=native表示非Java协议路线，实际发现解码器由独立字段表明，不代表调用原SLEIGH DLL。旧project/compose两阶段、schema及拒绝保持。

自产官方3.11 Demo的208可由单入口发现12条到条件分支；78/136/250分别27/22/27条，入口显式跟随E8得到原98条；默认入口3条后停CALL。这些路径重新通过Java投影，不代表208条件连接或业务恢复。首次回归错误预期入口直接到RET的失败保留。此前CALL rel0夹具的精确模型拒绝原件保留；现新增规范零位移完整三条BRANCH形状，修复与证明见[CALL_REL0](CALL_REL0.md)。正常E8非零位移/显式callee正例保持。

纯walker/宿主回归覆盖循环、指令内部及整个extent重叠、截断、映射/权限、调用、条件、系统边界、取消，以及篡改字节/来源/停止/语义范围和跨模式参数。真实维护入口test:path-discovery-runtime使用封存绝对路径/SHA案例，PE夹具只作数据解析，不启动。源码/安装及实际配置模型均独立留回执；模型从入口discover，再把响应数组用于project，独立比较完整结果。

这个闭环验收有界地址生成与后续语义检查，尚未证明自主新VM指令语义发现、SMT/CPU对应或完整VMP3.8、Ultra、Enigma恢复。下一步继续208普通语义/条件连接、剩余ISA/路径及稳定性覆盖；CALL rel0有限模型不等于完整架构。
