# UXR-06 函数批任务

起始HEAD/摘要见baseline/workspace.json；依赖01/03/04/05。状态：verified（72项夹具、中断恢复、真实静态单项）；真实72函数样本未验证。

新增source/function_batches.js、test_function_batches.mjs；index.js在decompile operation=batch接入create/status/run/cancel。AnalysisJobs是64MiB隔离数据工作线程队列，不能承担静态会话RPC；本轮复用ProjectStore持久状态、ResultArtifacts产物、原withSessions队列和原coordination.charge，不建立新worker池。

最多64任务，每任务1..72不重复明确地址；每run最多8项、60秒，串行。公共外层调用支付第一个新函数，后续每函数在RPC前分别charge，失败也计费；状态/创建/取消维持公共调用计费。预算耗尽保留pending和pauseReason，未启动项不误标失败。

产物先提交、任务后提交；UUID/index幂等键在重启后校验已提交结果，测试模拟两步之间中断且不重复RPC。每项status/attempts/resultRef/sectionStates保存；completed仅表示保存，并非分析完备。原进程取消信号传入；cancel使所属原RPC中断并清active owner。固定target/attachment/revision；重开或修订变化stale，7天任务到期，不重用旧快照。未实现跨失效attachment的重新绑定和自动重试失败项。

测试72项360 RPC、逐项计费、重复地址、重启窗口、耗尽、取消、修订变化见regression与unit日志；真实自产PE各后端单项通过runtime.log。部署见07；回退保留function-batches/function-results及预算，旧代码忽略独立命名空间。整模块无限导出和Frida生成不在本包范围。
