# VMCI 客体调试（实验接入）

此入口把现有 x64dbg 调试器放进预先配置的 Windows 客体。它不提供去虚拟化通解；客体执行、离线轨迹语义、DSH 模型调用和保护业务恢复分别验收。目前仅 Windows x64 宿主支持此接入；x86 调试仍须单独原生验收。

## 每次实验必做的启动与就绪检查

每次接手、新样本实验和恢复中断均从此处开始。先满足环境依赖，再评价模型和恢复算法；上次会话中曾运行过虚拟机不代表本次仍在运行。

1. **定位实际实验机。** 当前本地实验机为 `D:\IG5-VMs\IG5-Win11-Lab\IG5-Win11-Lab.vmx`；从 VMware 库或 `inventory.vmls` 重新确认路径。`C:\Users\IG5User\Desktop\win11镜像\完整win11镜像` 存放安装 ISO，不是运行中的 VMX。不要新建替代机器或恢复旧快照覆盖现有工作。
2. **启动或恢复 VMware 客体。** 打开已安装 VMware Workstation，选择该实验机；已挂起时正常“继续运行”，已关机时正常开机，正在运行时复用。保留现有加密、TPM、安全及侧通道缓解设置。信息提示可正常关闭；认证或锁屏由用户处理，不索取或记录口令。
3. **独立核对运行状态。** 使用下面的只读命令，输出必须包含本次 VMX 完整路径；只有 VMware 窗口或 `vmware-vmx` 进程存在不够。随后观察客体确实已进入桌面。宿主进程状态与客体桌面状态分别记录。
4. **启动预置客体服务。** 在客体已验证的私有包目录中打开 `IG5-Guest-Debug.exe`。当前已有 `IG5PRODUCTV2` 目录，但每次仍须核对它与所选 host profile、bundle manifest 和目标目录对应。服务有一小时/64连接期限；VM 恢复、快照变化、CID 变化、服务退出或期限届满后需重新检查。点过启动器不代表服务已成功监听或认证。
5. **核对配置和实际连接。** 在 DSH 调用 `ig5_profile guest_debug=lab` 获取当前 binding；这是文件检查，`authenticatedStartupVerified=false` 由 `publicGuestProfile` 固定返回，不是连接失败证据。通过既有公共审批调试路线取得本次认证连接和服务身份的真实响应；连接超时、HMAC/CID/端口不符分别保留。不得用目录存在、旧报告或 profile 字段代替连接实测，不直接 Worker RPC 绕过产品审批。
6. **核对本次样本已接入。** 本次目标 SHA 必须同时匹配宿主原文件、静态 artifact、host profile 和客体预置目录。旧 `lab` 仅含 `owned-add64`，不能自动执行新生成的 VMP 3.7 样本。缺目标时先用下文准备脚本生成新私有 bundle/profile、核验并部署到客体，再按正常配置流程接入；不在旧目录塞文件或绕过哈希。配对密钥及私有介质不得输出到模型或公开日志。
7. **开始恢复并正确收尾。** 前述运行、桌面、认证和样本条件齐备后，才在原审批下启动目标、采集入口至返回证据、恢复并独立验收。沿用原预算/所有权和 close/recover 协议。没有真实返回或独立验收时保持业务未知；环境未就绪归类 `environment-not-ready`，不能据此判定该版本算法不支持。

```powershell
& 'C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe' list
```

就绪记录至少保存 VMX、运行状态原始输出、桌面观察时间、host profile 的字节 SHA、bundle SHA、目标 SHA、实际连接/服务身份响应引用和当前清理持有状态。任何未检查项保持 unknown。此记录是实验前置证据，不是执行授权或业务成功证书；不要预先填入 `ready=true`。解锁后从桌面检查继续，不重复索取已经授予的实验授权。

### 样本正常运行准入与 Demo 跨机器限制

VMProtect 官方说明 Demo 保护输出只能在生成它的电脑上运行（[官方论坛](https://forum.vmpsoft.com/t/problem-with-demo-version/525)）。2026-10-17 的 3.7.3 自产样本在宿主保护后移入客体，真实启动出现未注册版不能在本机执行提示并退出；归类 `sample-runtime-restriction`，不能归类去虚拟化失败。下一次受控实验应在同一客体使用经过来源核验的官方 Demo 生成自有目标，再在该客体正常运行；保护器在客体可用性、许可条件、生成日志与目标 SHA 仍须实测，不预先记为通过。

外部公开 challenge 先记录提交、原始说明、文件大小、SHA 与 PE 架构；作者允许研究不自动等于可复制工具源码或可分发样本。精确版本、生产器、配置及 oracle 缺失分别保持 unknown。既有外部样本只读策略不变，不能因公开下载就直接执行，更不能关闭安全软件或恢复隔离文件。正常启动、业务入口到返回、多输入与清理是不同验收门。

模型遇到许可拒绝应停止业务恢复并保留原提示/退出证据，不得跳过初始化或改 RIP 后声称正常运行。手工入口试验即使有输出，也必须标记 intervention，不能替代完整正常执行或零提示自主验收。

### 恢复调用的最小参数

`op=recover` 是原始清理回执查询，不是执行操作。只发送 `target`、`op`、`backend=x64dbg`、`guest_profile`、`guest_binding_sha256`，可选 `engine` 与 `control`（跨 agent 需 `takeover`）。不要附加 `timeout`、`expected_run_id`、`expected_stop_seq`、寄存器、地址或采集参数；错误不会被静默删去。`GUEST_RECOVERY_NOT_FOUND` 表示本地没有该路径/客体的未清理占用，不证明远端已清理；先查 `ig5_status.remoteExecutions` 与原绑定，不重复相同请求、重启或换绑定制造成功。HMAC、原服务/会话、root 实际退出和 Job 关闭标准均不变。

2026-10-17 的教训：3.7 自主尝试前未拉起实验机；随后 `vmrun list` 确认最初为 0 台，正常恢复后为 1 台并出现 Windows 锁屏。用户解锁后继续检查服务和样本。此前的失败报告保留，不能把该次环境缺口扩大成“3.7 无法恢复”或“增加仿真预算即可恢复”的结论。

准备时先构建固定 GUI 启动器：`scripts/build_guest_launcher.ps1`，再用随包 Python 运行 `scripts/prepare_guest_debug.py --spec <绝对 JSON 路径> --output <全新目录> --host-profile <全新 JSON 路径>`。输入 JSON 精确包含 `guestCID`、`port`、`guestLabel`、`targets`；每个目标为 `{id,path,sha256}`，必须是显式自有或授权执行的 x86/x64 PE。准备脚本只复制和校验文件，不运行目标。最多64目标、每个64MiB，完整包最多1024文件、512MiB。运行依赖保留原许可与 pins，VMware 程序/许可不打包。

完整私有目录复制到客体后打开 `IG5-Guest-Debug.exe`。服务只接受 VMCI host CID2，不监听 IP、不自动启动、不提供 shell/上传/任意目标路径。它按预置目录检查目标哈希，并在 load/start 前再次核对。服务最多一小时、64连接；每会话1024条消息，沿用现有512步/1MiB/40秒录制和8MiB映像额度。

准备包含新生成的32字节配对密钥，目录与衍生 ISO 都不能公开发布。HMAC 验证配对密钥持有者及消息方向/序号/会话，**不加密流量，也不证明客体进程可信**；客体 OS 和可读取配对密钥的进程在信任范围内。程序与输入哈希核验不是硬件远程认证。

授权的私有测试如需 app-local DLL，准备 spec 的单个目标可额外声明 `dependencies:[{name,path,sha256}]`，最多16项、每项64MiB，并保持原512MiB/1024文件包预算。来源须事先核验，名称保留源文件 DLL basename，逐字节 hash 与目标架构/PE DLL 标记核对；含依赖的目标进入独立子目录，防止 x86/x64 同名 DLL 冲突。准备脚本不下载、不加载 DLL、不修改系统目录或 PATH，也不认定依赖闭包完整。`ucrtbased.dll` / `vcruntime140d.dll` 是 Debug CRT，不能把普通 VC Redistributable 安装当作补齐；微软允许仅在本人其他测试机为调试/测试作私有部署，禁止进入公开发行包，见[微软测试机说明](https://learn.microsoft.com/en-us/cpp/windows/preparing-a-test-machine-to-run-a-debug-executable)。依赖缺失属于装载/环境失败，不是业务恢复失败。

DSH 插件配置增加 `guestDebugProfiles: {lab: "<host-profile.json 绝对路径>"}`。先调用 `ig5_profile guest_debug=lab` 获取 `bindingSha256`，再在每次 `ig5_dbg` 调用中显式指定 `backend=x64dbg`、`guest_profile=lab`、`guest_binding_sha256=<摘要>`。所有调试调用仍经过原公共一次审批，40工具/13审批门数量不变。目标须先由静态入口打开，并与客体预置目录的 SHA-256 完全匹配；不向客体发送宿主可执行路径。

宿主在发送原生请求前持久化执行占用，按 guestCID + 目标 SHA 排他，路径/配置别名不能重复启动。桥接进程或宿主退出都不能释放已执行的客体占用；未知状态在重启后仍保留。stop/no-task 只描述被调试进程，完整 close 的原始终止回执才确认所有已观察原生根进程退出及 Job 关闭。

断线后用同一绑定的审批调用 `ig5_dbg op=recover` 查询原始服务实例/会话/目标的已签名终止回执。恢复连接只查询元数据，不打开/执行目标。新服务或新会话本身不能替代旧清理证据；缺失、错误或不完整回执仍为 unknown。客体回执持久化后可跨服务重启查询。其它 agent 恢复需要显式 `control=takeover`。宿主保存经校验回执的独立 SHA 文件；旧 generation 的延迟回包不能释放新占用。

`ig5_status.remoteExecutions` 是持久化归属记录，不是客体进程实时存活证明。`ig5_profile` 的文件检查也不代表已连接或执行。测试入口为 `test_guest_debug.mjs`、`test_remote_execution_store.mjs`、`test_vmci_rpc.py`、`test_vmci_rpc_session.py`、`test_guest_profile.py`；这些回归本身不执行客体目标，真实原生和模型验收须另存证据。

`ig5_status.remoteCleanupEvidence` 单独显示当前账本里最多8个已清理 generation 的存证，按 lease key 排序，报告 total/omitted/partial；不称完整历史。每个已签收终止回执再次核对字节 SHA、长度、原服务/会话/目标和所有观察 root 的退出/Job关闭，缺件/损坏保留 unknown，未执行 reservation 的放弃仅标 bridge-exit-only。此只读展示不释放占用、不重新做 HMAC 交换、不证明当前其他进程已退出，也不授予新执行权限。2026-10-18 审计发现此前空 pending 列表背后已有3.7旧回执；不能把过滤掉 cleaned 行误报为“没有证据”。
