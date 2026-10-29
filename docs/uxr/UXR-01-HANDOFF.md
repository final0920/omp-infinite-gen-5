# UXR-01 会话诊断

起始HEAD与工作区摘要见baseline/workspace.json。状态：verified（源码夹具、实际安装SDK服务）；真实历史失联未复现。

修改delegation_control.js、index.js；原有未提交内容上增量修改，未暂存/提交。保留AGENT_LINEAGE_UNAVAILABLE兼容码，细分reason；循环、缺父、身份冲突、限额、损坏可区分。仅operation=session的独立doctor在charge/memory/目标读取前返回本执行者有限元数据，不RPC、不改账本。观察时间不冒充故障时间。

没有接入可信宿主恢复证明接口，因此自动恢复未实现；宿主重新索引原父对象可沿原账本继续，不支持用户parentId认领。账本延迟打开使损坏时仍能诊断；校验byAgent总计和used一致，不自动重建损坏状态。

后续已核实实际宿主有 AgentLoop.resume，但会取得持久会话写权并可能补写中断事件，不能放入只读 doctor。按策略书第4项交付显式宿主重新接入流程，详见 CONTINUATION-20261023.md 与 host-recovery-audit.json；不是宣称宿主没有恢复 API。真实历史会话恢复仍未验证。

测试：test_uxr_session、test_delegation_control、test_host_sdk（regression.log）。包含孤儿、循环、冲突、重载、耗尽、损坏、读取不写账本，实际DSH SDK的共享预算分派。测试中的首个循环断言曾因恶意host索引优先而失败，已把直接循环检查提前并保留说明；后续回归通过。

部署状态见07；回退代码保留delegation-control账本，不回退used；旧code仍可识别。未知：真实宿主故障发生时间、历史回收原因、自动恢复证明。
