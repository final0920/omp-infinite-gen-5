# VM 上下文候选与阶段边界

`ig5_recovery recovery.context` 将一到十六份已提交的 `ig5-recorded-handlers-v1` 报告连同其 recurrence 与 body-selection 上游重新做逐字节 SHA-256 绑定，然后从完整观察中归纳候选关系。调用者只提供 `handler_refs`，不能提交 VIP/VSP、阶段或 opcode 语义答案。

当前输出 `ig5-vm-context-model-v1` 包含：

- fetch 地址更新寄存器候选、索引分发表基址输入候选、取流值载体和处理器目标载体；
- 基于 handler 边界内寄存器变化与邻近内存访问得到的 VSP 候选排序；
- 每个观测 source byte 到 handler entry、投影 SHA、完整/partial 状态、未知 GPR 与未知 STORE 数量的字典；
- initialization、fixup、dispatch execution 与 business execution 四类互不混淆的阶段状态。

该阶段刻意不把一致观察命名成已证明角色。单个录制运行只能输出 `single-run-context-candidates-phases-unknown`；初始化、fixup 和业务执行在缺少模块/内存 epoch、函数合同、独立 oracle、不同输入和不同 VM 实例时必须保持 `unknown`。dispatch 也仅为 `observed-candidate`。`0x39`、`0x5c` 等 partial body 的未知结果原样进入字典，不由末态观察补值。

公开入口示例：

```json
{
  "recovery": {
    "context": {
      "handler_refs": [
        { "id": "<uuid>", "sha256": "<64 lowercase hex>" }
      ]
    }
  }
}
```

验证分三层：`npm run test:vm-context` 覆盖归纳、拒绝与 CAS 接口；`scripts/reproduce_vm_context_model.mjs` 将外部冻结 handler 闭包按摘要导入新的隔离 CAS 并生成报告；`scripts/verify_vm_context_model.py` 不调用 JavaScript 实现，重新读取并逐字节核验所有 source report，独立复算候选、计数、handler 字典与 false/unknown 边界。

这一能力仍不证明 CPU 指令语义、真实可达性、通用 VM ISA、具体字节码程序、VMP 3.8 合格样本或业务合同。下一步必须补齐 phase/SMC/module/memory epoch，随后用独立输入和替代路径重复同一映射并恢复具体虚拟 CFG。
