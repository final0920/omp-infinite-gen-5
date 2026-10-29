# CALL rel0 的完整字节绑定模型

真实固定Java SLEIGH把 `E8 00000000` 解成完整 `RSP-=8; STORE(RSP,nextEA,8); BRANCH nextEA`。原精确近调用匹配器只接受末CALL，因此真实发现能给出该地址，状态投影仍拒绝。旧失败报告及原raw保持，不能将发现成功追认为语义通过。

新增例外仅匹配无前缀5字节E8、零有符号位移、完整固定三操作和精确64位RSP/返回地址/目标。保留原BRANCH、不合成CALL、不删STORE、不变raw计数；directCall描述增加decoderControlOpcode=BRANCH及decoderForm=canonical-e8-rel0-branch-next-v1，语义hash仍由原规范化BRANCH形状计算。终端control按真实调用报告transfer=call/returnAddress，明确不提供callee/ABI摘要。普通非零CALL输出保持原样，非零E8冒用BRANCH、前缀/间接/远调用、缺失/错误/额外压栈或控制仍拒绝。

宿主对终端零位移重新核对原字节、完整三条raw操作、地址空间、位宽、RSP-8、保存返回地址与CALL/BRANCH到nextEA；字段顺序可不同，额外字段/缺件拒绝。CALL之后依赖初始CF等活状态仍拒绝，不能因栈/控制模型接受就注入flags。发现follow_direct_calls=true只进入字节给出的callee，RET始终停止；显式CALL→RET的投影和组合保留八字节栈写，即使RSP恢复。

纯回归覆盖普通/高VA、uint64栈回绕、全16GPR、完整内存及STORE、显式RET和两段36个精确state_binding。真实自产数据夹具SHA256为ef19e116449f152151b6f1a3a63d56da78acd2e4a0e98cbcca6486aa038d756b，只作文件数据解析，从不启动。

`prove_call_zero_semantics.py` 对终端CALL、显式CALL→RET、公开两段组合分别用未切割完整DAG证明全16GPR/整字节内存/有序STORE/末目标方程，3项UNSAT；另对CALL→RET末内存仍可不同于M0取得SAT，不能删除遗留写入。264个独立普通状态/792次报告计算含栈回绕，各部署复用同批，不增加独立覆盖。`verify_call_zero_semantics.py` 独立核对原字节、hash、完整typed DAG、无cuts查询、预算和原BRANCH语义摘要；它不重新求解或执行CPU。沿用每查询2秒/512MiB、128查询、45秒共享/单进程2GiB50秒Job及实际exit确认。

源码/安装真实Java、发现链路、旧核心及已配置DSH模型分别验收；详细计数和全部格式/分析失败由独立checkpoint记录。40工具、13审批门、原runtime/上游/Java/Triton pins、全部请求/指令/DAG/内存预算保持。

这是有限近调用普通状态模型，不是完整架构/flags、CET/shadow stack、异常/故障、原生可达性或业务证明。208处理器的完整状态/75字节条件连接、剩余VM ISA、精确VMP3.8及Ultra/Enigma业务与稳定覆盖仍未通过。
