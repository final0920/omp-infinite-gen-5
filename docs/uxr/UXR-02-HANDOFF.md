# UXR-02 结果产物

起始HEAD/摘要见baseline/workspace.json。状态：verified（夹具及自产PE/ELF真实静态worker）。

新增source/result_artifacts.js，复用AnalysisArtifacts稳定读/摘要/两阶段发布及ProjectStore锁，不重写原模块。独立function-results命名空间；完整provenance/query/section保存于不可变报告，UUID/SHA与索引commit同时有效才发布。配额1MiB项、8MiB任务组、64MiB数据目录、256引用、7天，依据80KB基线选择有限容量，原RPC预算不变。孤立partial文件计额度，未知文件不自动删除。

写中断、存储满、metadata缺失、摘要替换、目标修订变化、硬链接、目录junction与路径参数测试见test_result_artifacts.mjs及regression.log。过期清理只删索引拥有的精确普通文件，不递归；同步读/清理共用同一索引锁，无活跃读取被删。批任务生命周期7天，早于其结果过期，过期任务拒绝续跑。

新增格式仅存在独立命名空间，旧代码不消费它；预算账本不受影响。结果超过限额或提交失败时dossier返回savedResultError且无引用；不声称保存了完整来源。部署见07。回退保留function-results与孤立文件，不删除用户数据；未实现任意目录GC和超限文件强制导出。

最终复核补充result_capture.py：Ghidra已生成调用列表按每方向128KiB捕获后保存，避免先被展示的32行裁剪丢失。超限保留partial。4项Python专项含72记录与显示32行的差别，安装副本真实静态回归重新通过。
