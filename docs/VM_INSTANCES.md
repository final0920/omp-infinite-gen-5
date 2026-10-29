# F10 实例身份和指定小 VM

实现 `20261024-vm-instances-1`。新增原 `ig5_recovery.recovery.instances={source_refs:[{path,sha256}]}`，读取1..8份明确本地JSON、每份≤64KiB，封存完整字节及声明。`instance_check={comparison_ref:{id,sha256}}` 重读不可变正文、重建比较，再在原AnalysisJobs settled64MiB/15秒/1+4中检查。没有原生执行、任意oracle或caller proof入口。

JSON严格schema见 `scripts/fixtures/vm_instance_cases.mjs`。身份含codeSHA、实际bytecode字节SHA、规范JSON tableSHA、seed/位宽/旋转/减法方向、runId、memoryEpoch和三种角色声明。缺失字段使用null，两个相同null不算身份相同；完整相等仅称same-declared-identity，不允许原生合并。角色交换、seed、table、代码及epoch变化均保留差异。声明不等于观察，不称ARM64或VS1.5角色已恢复。

指定小VM是显式虚拟机器：8/16/32/64位accumulator和独立result；表中0..5表示HALT、INPUT、ADD、ROTATE、SUB、RESULT。每条opcode按seed异或、seed递增；立即数不加密。HALT只返回原result；不隐式把input/accumulator赋给result。最多256步，未知table/缺HALT/截断不补零或猜语义。输入域≤256、最多4个初始result、合计≤1024输入/状态组合；独立JS参考及不导入JS的Python逐项复算。有限模型通过不能升级CPU、全域、整VM或业务。

原VM上下文、角色、录制验证、固定来源program/function_check入口保持，旧报告不迁移。新入口无网络、求解、调试、引擎启动或默认assist。测试 `npm run test:instances`；独立验收 `node scripts/accept_vm_instances.mjs --plugin-root <实际插件目录> --evidence <新目录>`。
