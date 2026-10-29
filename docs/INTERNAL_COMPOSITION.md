# 内部闭合状态组合原型

`worker/projection_composition.py` 提供纯核心 `compose_paths` 和 `compose_until_exit`。纯函数不读取文件、不构成公开RPC或实际DSH验收；新公开地址计划包装为[ig5_ir level=compose](STATE_COMPOSITION.md)，负责锁定输入、真实解码、资源隔离和报告导入。它不是`level=project`的新模式；旧入口继续拒绝重复地址，并保持原128指令、256字节访问及其他预算，不能将组合请求改记为旧超限请求成功。

输入是由可信、固定解码器产生并绑定原文件字节的若干严格路径。核心不读取文件，不接受用户摘要或证书；调用者负责锁定并核验目标、运行时和解码器。每个实际应用的模板都由现有strict projector重新生成，保留全部16个GPR、普通字节内存和末控制。缓存只在一次内部调用中按规范化完整指令摘要复用。同一EA出现冲突字节或p-code时拒绝。

每个模板必须自行定义它读取的有效flags；活初始flags继续拒绝。模板之间只代入GPR和写后内存，不导出或传入flags。即使后一模板覆盖scratch寄存器，前一模板的全部16个GPR仍属于出口状态，不能跨模板抹去无法建模的写入。可能需要将第一轮正文并入前缀，使早期BSR/BSF写入在同一planner内确实已死。

每次应用将模板的16个自由GPR和初始内存节点替换为前一出口，保留顺序STORE、地址重叠和uint64回绕。共享DAG只复制结果所需节点；访问量和逻辑工作统计仍包括每次应用的全部原指令、raw p-code和内存读写。条件边按下一模板入口选择唯一后继，另一侧保存当时的全部GPR、内存和自身guard。每个STORE绑定进入模板的guard；终点状态只在`pathGuard`非零时有效。默认仍拒绝中途间接转移和RETURN。

内部调用可显式使用`indirect_mode="guarded-target"`，沿下一模板的确切uint64入口继续。续接条件是实际目标表达式与该入口相等；相反条件下的side exit保留原动态目标及控制指令执行后的16个GPR和内存，包含RET已发生的栈指针变化。它不把入口值写回目标表达式、寄存器或内存，也不丢弃其他目标；无法匹配的常量目标产生false pathGuard和有效的另侧出口，不能改记为可达。此前写入仍用此前的进入guard，之后写入才受新目标条件限制；所有新引用与节点计入原DAG预算。此显式模式使用`ig5-internal-guarded-target-composition-v1` schema，默认报告结构不变。它尚不自动发现或穷举间接目标，不证明路径可满足性、可达性或全输入覆盖，纯函数不是FC；公开包装仅通过composition_plan接收地址计划及该模式。

`compose_until_exit`接收一个已闭合前缀、一段可重复正文及退出续程，不接收循环次数或观察状态。它仅在当前自由初态DAG中的条件通过精确常量运算成为确定值时决定重复或退出；该条件可以选择taken或fallthrough回到正文。未知条件、入口/出口不匹配、flags缺口和预算内未能退出均拒绝。它是有限常量分支传播，尚无一般符号循环不变量、SMT循环证明或复杂多出口循环分析。

内部原型最多64次路径应用、128条不同指令、1024次逻辑指令、65536个逻辑p-code操作和1024字节累计读写；DAG保持2048节点、8192引用、128深度，报告4MiB。循环推导每轮尝试及其逻辑指令/内存访问总量单独记录，各不超过65536；最终组合统计另外保留。推导复用已验证翻译，仍需调用者提供真实取消/期限检查，并在固定单进程2GiB/50秒Job中执行原生解码研究。这些核心预算不授予旧level=project入口更大的请求；新level=compose包装显式采用独立工作上限。

`inferredRepeat.bodyApplicationsAfterPrefix`不包含已给定前缀内可能存在的首次正文；`attempts`和`trace`保存完整推导。纯函数结果始终`translated-unverified/publicToolRouteExposed=false`；受限公开包装另标`ig5-pcode-composition-v1`和实际路由范围，不能用纯函数报告冒充公开验收。普通GPR/数据内存/控制的组合不证明CPU未定义结果、完整架构flags、访问故障、指令取数与数据写入一致性、原生可达性、保护函数返回或全输入业务覆盖。

纯回归入口为 `scripts/test_projection_composition.py`，纳入`npm run test:projection`。真实文件/解码、独立原始p-code数值复核、源码部署和实际DSH模型验收分别记录。
