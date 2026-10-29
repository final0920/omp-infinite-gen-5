# UXR-04 地址

起始HEAD/摘要见baseline/workspace.json。状态：implemented；静态ELF映射verified，新增runtime_va公共转换未实现。

新增adapters/ghidra/elf_addresses.py，worker.py的address_convert RPC及函数addresses；index.js在既有profile address参数接入，client.js增量标签。共享入口由本轮串行修改，原address_ref.js的合同保持。

从Ghidra保存的原FileBytes读取ELF PT_LOAD，使用真实MemoryBlockSourceInfo映射，范围不一致不套全局偏移。最多1024 program headers/64KiB表、1024块/4096源范围；大整数全程Python整数/hex字符串，拒绝溢出、BSS文件地址、重叠、overlay、未知。module_offset以最低PT_LOAD vaddr为原点；明确不等于runtime load bias。

test_uxr_addresses.py验证合成+0x100000、非一致重定位、非零最低vaddr、文件偏移、BSS、重复范围、边界和>JS安全整数；原test_address_ref保留跨run/epoch检查。test_uxr_runtime真实自产ELF往返、file_offset、module_offset和BSS拒绝通过；native目标未执行。日志runtime.log/addresses.log。

runtime_va必须有可信模块SHA/run/load epoch；当前静态ELF入口没有该证据，明确拒绝，不能称动态链路完成。商业后端此新RPC不支持时返回UNSUPPORTED_CAPABILITY。部署见07，回退代码保留元数据产物，不改机器码/伪代码常量/runtime pins。

后续审计：既有 address_ref 只验证传入映射，不能产生 Android 模块观测；VM录制仍缺 moduleLoadEpoch。自产实际 ARM64 ELF 的静态 file_offset 转换已通过，见 CONTINUATION-20261023.md，runtime_va 范围不提升。
