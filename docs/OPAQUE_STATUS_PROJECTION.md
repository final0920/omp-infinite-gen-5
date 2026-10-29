# 保存已定义状态位关系的投影

`ig5_ir level=project projection_mode="opaque-status"` 使用独立 `ig5-pcode-opaque-status-projection-v1`。适用于普通运算后通过 PUSHFQ/POP 把状态字当作VM数据保存的路径。显式路径、原文件字节绑定和全部16GPR/顺序字节内存保持原规则；工具不执行PE或改数据库。

PUSHFQ仍要求完整无前缀9C及固定57条raw p-code的语义SHA同时匹配。每次生成独立64位未知输入U，只把同一路径已经定义、固定解码已建模且依赖闭合的状态位覆盖进去。先检查原raw的读前写flag依赖，再登记本条定义；仅preserved状态沿路径传播，未知分类清空来源，undefined/unmodeled状态失效。内部BSR/BSF省略例外不提供活flags。

当前ADD64示例保留CF、PF、ZF、SF、OF五位：

```
image = (U & 0xfffffffffffff73a) | known_status_bits
knownMask = 0x8c5
freshInputBits = 64
effectiveUnknownBits = unknownBits = 59
```

AF在固定解码中未建模，保留自由值；其余环境位也未知。没有已知定义时仍是完整任意64位。输出不是精确RFLAGS/CPU模型，不模拟保留位、特权、异常、MMIO、并发、代码自修改或原生可达性。初始flags不作为输入参数，也不能以记录值代入。RDTSC/规范16位BSWAP沿用旧未知效果。

`opaqueEffects[].flagImageRefinement`保存规范mask、逐位定义指令序号、未知输入位数、有效未知位数和实际STORE值根。宿主重验原完整指令、flag来源、布尔化/扩宽/位放置/OR树、全部根引用与工作计数；此核验是结构和来源检查，不是第二个CPU解释器或独立语义证明。

公开预览开头提供`reportSchema`、实际`nodeCount/dagReferences/storeCount`及partial/unverified/false范围标志，置于可变长度效果和解码元数据前。DSH可能只保留长响应头尾；不能把裁剪中段或旧报告猜测当成真实计数。完整报告仍由自身路径/SHA绑定，模型报告与独立审计分别记录。

上述五位实例保留原raw操作数57、原STORE索引56；替代操作数24、替代STORE索引23。公开工作量仍按raw全额统计，新未知输入与refinement.valueNode均计入完整引用。原128指令/256访问字节/2048节点/8192引用/128深度/4MiB、两槽、创建时单进程2GiB/50秒及5秒清理预算不变；同nonce ACK和协议根真实退出均须确认。

默认strict、guarded-path与opaque-effects保持；project的opaque-status不能叠加guarded-path。另可在显式sequence/transition-chain地址组合中选择[template_mode=opaque-status](OPAQUE_STATUS_COMPOSITION.md)，跨段保留保存标志映像的数据关系，各模板仍自行闭合CPU flags。没有公开跨报告连接、观察flags或用户p-code接口。representationValidation/预览计数不能升级成语义证明。

维护研究绑定官方3.11 Demo自产Ultra样本的完整原字节，分别验证handler250的15指令正文及27指令含派发版本。普通状态摘要为：先从初始内存读取A=[RBP]、B=[RBP+8]，RBX=A+B，R10为上式image，再按原顺序执行物理压栈、和写入、flag字写入，派发版本另保留完整目标读取及最后压栈。全16GPR、整个字节内存、全部STORE顺序与控制均保留，允许真实地址别名。

`prove_handler250_semantics.py`使用固定预算的局部SMT证书和明确连接引理：两个原始初态LOAD的全称变量重命名、完整flag映像公式、逐位/未知mask/分区证书，以及真实第三次STORE之后内存的目标读取。每个cut必须属于该查询实际sourceCase的完整DAG，不混用不同报告的节点ID。独立读取器核对原字节、报告/脚本/编码器/查询hash、全部限制和证书根；它不重跑CPU或制造额外数值覆盖。

在原入口/上下文/17/137的66个明确字节及区域、快路前提下，两VM操作数为零，故**仅image & 0x8c5 = 0x44**；AF为0和1均可满足。再增加一个selector字节，共67个初始字节，可条件性续接selector136、目标0x1400545b6。所需4个表字节已经包含在原66个前提中，复用而不重复计数。缺失前提及旧完整未知模式丢失关联的SAT负例保留。不是原生运行、完整VM ISA、精确3.8或Ultra/Enigma业务恢复证据。

回归入口：`npm run test:opaque-status`；真实官方Java字节解码使用`npm run test:handler250-runtime -- --plugin-root <插件绝对路径> --out <新绝对目录> --discovery <已绑定27地址JSON> --discovery-sha <SHA256>`。维护证明用`test:handler250-proof`传`--receipt/--receipt-sha/--incoming-proof/--incoming-sha/--out`，读取器用`test:handler250-audit -- --proof <verified.json> --out <新audit.json>`。`test:status-encoder-smt`传新产物目录检查carry/overflow/signed比较/POPCOUNT编码；历史证书不覆盖新脚本SHA。

架构位位置参考[Intel手册](https://www.intel.com/content/dam/develop/external/us/en/documents-tps/253665-sdm-vol-11.pdf)，p-code操作参考[Ghidra官方说明](https://ghidra.re/ghidra_docs/languages/html/pcodedescription.html)。固定解码匹配、纯数值回归、SMT、安装副本与真实配置模型的DSH验收分别保存，不相互替代。
