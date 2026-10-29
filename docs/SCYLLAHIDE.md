# 自有目标的 ScyllaHide 调试环境

来源：[x64dbg/ScyllaHide](https://github.com/x64dbg/ScyllaHide)，固定修订 `baa5c8e853ace2bee752631f27fdfe5b271d92f6`，GPL-3.0。独立 CLI 进程使用用户态 HookLibrary；五代不静态链接该库。对应源码、原始许可和逐文件清单在 `third_party/scyllahide`，二进制和固定运行清单在 `runtimes/scyllahide`。项目的 NC 条款不覆盖这些组件。

经公共审批调用 `ig5_dbg backend=x64dbg op=start anti_debug_profile=scyllahide-thread-context`。默认 `none`；只支持五代自己启动、正在调试、属于当前清理 job 的 x64 目标，在已确认启动暂停后安装。不能指定任意 PID、注入路径或自定义配置。`antiDebugEnvironment` 记录目标环境改动、来源、配置、暂停身份和日志摘要；安装确认不等于每个 hook 的行为通过。

配置关闭所有上游数字选项，仅开启正常 DLL 映射、NtSetInformationThread、NtGetContextThread、NtSetContextThread、NtContinue 和 KiUserExceptionDispatcher hooks。不调整 SeDebugPrivilege、加载驱动、修改 OS 安全设置或原目标文件。侧进程最多20秒／64KiB日志；取消、安装失败或身份改变时清理自己管理的目标。配置改变真实进程环境，不能当作被动观察。

本地修改：CLI main 返回真实结果、去掉权限调整调用、资源使用 `winres.h`、从固定修订生成 SCM 头。编译使用 MSVC 19.51.36260／v145，静态 CRT。重建：

```powershell
.\scripts\build_scyllahide.ps1 -OutputRoot C:\your-private-artifacts\scyllahide-build
```

需要已安装 MSVC C++ x64；可指定 `-MSBuild`／`-PlatformToolset`。脚本核验179个源码文件，在全新外部目录编译四项目，不执行上游批处理／date.exe、不安装重建产物、不更新运行 hash。时间戳／工具链变化可能使 hash 不同，应另行审计，不能自动更新固定来源。

`scripts/test_scylla_hide.py` 覆盖固定资产／拒绝路径。原生验收设置 `IG5_SCYLLAHIDE_TEST=1`，运行 `scripts/test_thread_visibility_runtime.mjs <自产编译证明目录> <全新证据目录>`。验证主线程自设隐藏被阻止、辅助线程可见、查询保留当前线程/GPR和目标摘要。默认测试验证未安装 hooks 的 False→True；两种结果不可混合。

`ig5_dbg backend=x64dbg op=cont exception_disposition=handled` 仅在本轮观察到的异常暂停可用。它以 DBG_CONTINUE 消耗本次异常，保存 `continuedException` 的异常／run／stop／thread；默认 `preserve` 保持原行为。通过自有 headless 的私有标准输入管道仅发送固定 `serun` 一行，保留原桥与运行包 pins；仍须真实原生回调确认结果。无任意命令入口，不自动吞保护器异常或跳过业务指令。自产 Enigma 仅对编译证明绑定且内存字节匹配的业务区外 INT3 使用该选项；控制文件中的 `66 90` 前缀通过导出解析。

这增强调试环境，不是 VMP／Enigma 全程序恢复证明。业务恢复仍须采集返回路径、独立重放、全输入域等价和真实 DSH 调用验收。
