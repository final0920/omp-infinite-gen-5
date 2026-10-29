# 官方 Java SLEIGH 路径解码

`ig5_ir` 的 `level=project` 和 `level=compose` 可显式设置 `projection_decoder="java"`。默认仍为原有 `native`，没有静默切换；其他 level 拒绝此参数。Java 路径通过固定的 Ghidra Java API 解码原文件地址，不加载 IG5 自定义解码 DLL，不打开数据库、不执行目标。

```json
{
  "target": "C:\\samples\\owned.exe",
  "level": "project",
  "projection_decoder": "java",
  "projection_path": ["0x140001000"],
  "projection_registers": ["rax"]
}
```

`compose` 的内联计划和 `composition_plan_ref` 同样支持该选项。地址计划、指令字节、边界及全部原始 p-code 仍须验证，不接受用户提供的 p-code、观察值或语义证书。strict、guarded-path、opaque-effects、BSR/BSF 有界死 frame、flags 与未定义 BSWAP 的既有检查不变；换解码接口不能消除语义缺口。

监督根锁定目标 SHA 快照及固定配置。Java JVM/JAR、语言配置和自有包装器均按独立清单和原上游清单核验；614 个上游文件采用分块散列并持续持有拒绝写入/删除的只读句柄，避免在根进程保留全部运行时字节。语言描述在加载前检查精确 SLA/pspec 路径，内存空间操作数通过实际 AddressFactory 解析，不把 Java 内部空间编号当目标常量。包装器的 JAR `Class-Path` 只引用固定的原上游 JAR，解决 Windows 命令行长度和非 ASCII 参数文件问题。

Java 解码与 Python 状态计算分别在创建时绑定到单进程、2GiB 的 Windows Job，顺序运行。整个请求共享原 50 秒计算截止时间和原两槽占用；不为第二阶段重置总预算。固定 JVM 堆上限为512MiB。取消沿原协议只终止所属 Job，两个子阶段实际退出及原 nonce 清理确认、协议根退出共同约束占用释放。失败、未知及清理缺件不当作通过。`processStages` 保存两阶段资源/退出回执，`javaDecoder` 保存独立清单、包装器、输入和输出摘要；完整 raw p-code 仍在 SHA 报告中。

自有包装器和独立清单位于 `adapters/ghidra/projection-java/`，随源码包携带；目录不命名为 `java`，以免在 Python worker 中遮蔽 JPype 的 Java 包。原 `runtimes/manifest.json`、上游运行时、发行供体和许可均不修改。源 ZIP 仍需按原流程取得完整固定运行时。可在新目录重建包装器：

```powershell
& .\runtimes\ghidra\python\python.exe -I -B -X utf8 scripts\build_java_projection.py C:\ig5-build\new-java-wrapper
```

重建只使用已有固定 JDK/JAR，不联网、不执行目标。脚本保存源码/类/JAR/清单 SHA 及受限编译进程回执；不会自动修改代码中的 pin。更新包装器时需复核产物、更新独立 pin，并完成源码、原生分析、安装与 DSH 模型各层验收。

回归入口为 `test_java_projection.py`、`test_projection_decoder.mjs`、`test_java_projection_runtime.mjs`；已有寄存器/内存和 flags 原生分析套件可显式选择 `java`，数值参考和保守拒绝条件保持。运行时测试中的 PE 只作为数据。真实安装及配置模型是否通过，以本次独立部署记录为准，不能由这些脚本的存在代替验收。

结果仍为 `partial/unverified`，`businessAccepted/wholeBinaryVerified=false`。相同固定 SLA 的两种实现得到相同 p-code，不等于独立 CPU 语义证明；本接口不证明代码获取一致性、原生可达性、完整 VMP3.8 或其他保护业务恢复。

失败时，Java 诊断优先保留首个异常及最多三个嵌套原因，完整 stderr 原字节保持。project/compose 监督根在已验证的自有作业目录中生成最多64KiB的 `analysis-failure.json`；它绑定目标 SHA、作业/nonce、失败阶段、错误、运行时 pin、实际取得的阶段回执，以及固定九种文件的字节数和 SHA。每份日志仍最多4MiB，超限或缺失明确标记；清理未确认时不读取仍可能写入的日志，也不伪造 PID/退出回执。

宿主重新验证身份、目录、文件摘要、预算及失败范围后导入独立 `analysis-failure` 报告。错误文本携带 `analysisFailure stage=...; report=...; SHA256=...`，程序调用同时可读取 `error.analysisFailure`。Agent 可据此读取完整报告定位下一步；报告状态始终 `failed-unverified`，不会把被拒绝的请求当作成功。证据写入/核验失败保持原错误并标记，早期参数错误可能没有报告。作业容量释放仍只依赖原匹配 nonce 的清理 ACK 加协议根真实退出；失败报告不能替代清理。回归入口为 `test:analysis-failure` 和真实 `test:java-projection-runtime`。
