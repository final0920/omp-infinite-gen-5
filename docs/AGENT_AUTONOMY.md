# 持续自主逆向与单次验收

五代向 DSH 提供工具与原生 Skill。`ig5-reverse-agent` 约束如何识别保护、选择静态/动态/语义路线、处理失败和验收；DSH 的 `goals` / `tool-goal` / `goal-round-driver` 管理持久目标及同会话续轮。不会另建私有模型 API、复制密钥或伪造人类消息来源。40个工具与13个公共审批入口保持原结构。

用户要求持续工作时，模型读 Skill 并通过宿主 `create_goal` 创建原范围目标；已有目标用 `get_goal` 核对状态。每轮产生实际证据、验证后更新调查笔记，未完成就保持 active。模型的一次回答结束，宿主在该 agent 真正 idle 且 Goal active/armed、轮次尚有容量时接纳下一 Goal Round。普通单次问题不自动建立目标。Goal 有自己的轮次/取消/恢复规则，不等于扩大目标执行授权、录制或求解预算。

`ig5_profile.autonomy` 仅检查本次执行 agent 的 Goal 工具、原生服务、精确目标和续行资格。`continuationEligible=true` 只说明当前 phase/activation/round count 满足必要条件，不证明驱动器已运行；`driverVerifiedByThisQuery=false` 和 `queryStartsWork=false` 明确保留这一范围。缺服务或过期 agent 显式返回不可确认，不能按 id 从别人的会话借用目标。

`ig5_workspace` 管理静态目标的调查笔记与系统 dossier，保留修订和来源；它本身不调度模型。Skill 引用的完整目标、失败位置与 next_step 使压缩和恢复后可以继续，但假设/结论仍是调用者陈述。用户取消不自动复活；会话重启后原生 Goal 可以 active/disarmed，须按 DSH 的明确恢复入口恢复，而不是插件暗中重启任务。

真实闭环验收需在配置好的 DSH 模型中：读取新注册 Skill；原生 `create_goal` 写入当前会话；首轮产生实际工具报告并保留 active；无需额外人类“继续”，自动 Round 被接纳并产生后续工具调用；当前 Goal、报告、模型、部署与会话事件摘要一致；最终按实际验收范围完成或保留未解决。单次 RPC、schema/SDK、模拟测试和源码中存在驱动器都不能替代这项观察。

壳与虚拟化算法的验收独立于自主机制。Enigma 八轮的完整输出表达式及全 uint64 源码代数等价已通过，单条记录的内部分支/地址守卫存在不覆盖全输入的反例，完整业务覆盖仍未证明。具体 VMP 3.8 版本和 Ultra 八轮仍要独立真实测试。Skill 和 Goal 只能组织研究，不能使这些未通过项自动变成通过。
