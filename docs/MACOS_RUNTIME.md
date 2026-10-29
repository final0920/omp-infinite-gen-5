# macOS Apple Silicon Ghidra 运行包（实验性）

此支持仅针对 **运行 DSH Node worker 的 macOS arm64 宿主**，不是浏览器设备/Android/iOS。Ghidra 12.1.4 的静态数据库车道及默认内置 Reverse 的 Ghidra 后端使用此包；商业 Reverse 仍仅支持 Windows x64，x64dbg、原生调试及 Ghidra Unicorn 函数仿真在 macOS 不可用。目标二进制可为其他架构。源码仓库不含原生依赖，老版本已安装插件也不会因拉取此 PR 自动更新。

## 离线输入与许可

运行 `scripts/prepare_macos_runtime.mjs` 前，由操作者分别准备 **已经核对来源与 SHA-256** 的三棵 arm64 目录（脚本不联网、不安装 Homebrew、不修改全局 Python）：

| 输入 | 要求 |
| --- | --- |
| `--ghidra` | Ghidra **12.1.4** 发行根目录，含 `Ghidra/application.properties`、`Ghidra/Features/PyGhidra/lib/PyGhidra.jar`、`Ghidra/Features/Decompiler/os/mac_arm_64/{decompile,sleigh}`、`LICENSE`、`bom.json` 与 `licenses/`。可从对应版本的上游发行构建或经校验的 Homebrew 12.1.4 bottle `libexec` 获取；不要把 Homebrew 的 `bin/ghidraRun` 当作根目录。若本地源码构建只生成 `Ghidra/Features/Decompiler/build/os/mac_arm_64/`，脚本仅在复制后的包内补齐两个 native 程序。 |
| `--python` | **CPython 3.12 arm64 可搬移前缀**，含 `bin/python3.12`、`lib/libpython3.12.dylib`、标准库及 `lib/python3.12/site-packages`；需预装与 Ghidra 对应的 `pyghidra==3.1.0`、`JPype1==1.5.2`（含 `org.jpype.jar`）及 `packaging`。Ghidra 12.1.4 自带 `Ghidra/Features/PyGhidra/pypkg/dist/` 的版本匹配 wheels，包括 cp312 macOS universal2 JPype wheel；必须从**工作副本**提取 arm64 slice，最终 `_jpype.cpython-312-darwin.so` 要是 thin arm64，不能直接复制 FAT/universal2 文件。Python-build-standalone 的 `lib/python3.12/LICENSE.txt` 会在输出包中额外复制到 Python 前缀根 `LICENSE.txt`；源目录不会改变。|
| `--jdk` | **JDK 21 arm64 的 `Contents/Home`**，含 `bin/java`、`lib/server/libjvm.dylib`、`lib/libjli.dylib`、`jmods/java.base.jmod`、`release` 和 `legal/`。推荐从固定、校验过的可移植 JDK 21 archive 提取；不要把 `/usr/bin/java` stub 或系统默认 JDK 当成包内 JDK。|

参考 [Ghidra 12.1.4 官方构建说明](https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.4_build/GhidraDocs/GettingStarted.md)（官方 PUBLIC zip 不自带 macOS ARM64 natives）和 [Homebrew ghidra formula](https://formulae.brew.sh/formula/ghidra)。`Ghidra/Features/PyGhidra/pypkg/dist/` 的三个对应版本 wheel 可以在**隔离 Python 前缀**按上游说明离线安装（若前缀有 pip，则使用 `python3.12 -m pip install --no-index --find-links <该目录> pyghidra==3.1.0`）；对安装后的 `_jpype.cpython-312-darwin.so` 另用 `lipo -thin arm64` 处理并检查签名，仅在工作副本上操作。上游 Ghidra/源码构建与第三方依赖各按自己的许可分发；勿在 PR 中提交二进制（`runtimes/` 被 Git 排除），勿将 Windows 构建证明冒充 macOS 原生构建证明。查验被复制的完整许可证、组件清单及各 wheel 的 `*.dist-info` 许可，按部署环境做最终许可审查。仅使用可信、已验证的输入；生成的清单不是来源证书或代码签名，也不能证明 Apple Developer ID/notarization。

## 生成新目录（不覆盖原包）

以下仅示意**操作者已有的物理绝对路径**，需替换为实际路径；`/tmp` 在 macOS 常是 `/private/tmp` 的别名，输入/输出应传 `realpath` 所得物理路径。先在源码目录创建忽略的包父目录，再运行：

```sh
mkdir -p runtimes
node scripts/prepare_macos_runtime.mjs \
  --ghidra '/actual/ghidra-12.1.4/libexec' \
  --python '/actual/isolated-python-3.12' \
  --jdk '/actual/jdk-21.jdk/Contents/Home' \
  --output "$PWD/runtimes/darwin-arm64"
```

输入目录不得互相重叠或指向输出，输出必须不存在，父目录须已存在且无符号链接别名。脚本检查树内 symlink 不逃逸、必需的 Mac Mach-O arm64/CPython ABI/JDK metadata、Ghidra 文件与许可；在输出父目录的临时 staging 完成 `readRuntime` 结构核验、逐文件 SHA-256/size 与符号链接清单、**包内** Python 隔离 import 与 JDK21/JPype JVM 启动测试后才发布新包。`manifest.json` 记录全量 SHA-256/size；实际启动路径只做有界结构及原生文件头检查，**不会重新哈希全部文件**，所以 `integrityVerified=false` 是预期值。首次发布后按可信来源保护目录权限，若资产变动须重新核对清单。

独立源码副本可用 `IG5_RUNTIME_ROOT="$PWD/runtimes/darwin-arm64"` 指定外部运行包根；或在部署新插件时按版本将整个 `darwin-arm64/` 目录交付于**该已加载插件自身**的 `runtimes/` 下。也可仅指定 `IG5_GHIDRA_RUNTIME=/absolute/path/ghidra/runtime.json`。环境变量须由真正运行 DSH 的宿主进程继承；从 Finder 启动的 GUI 不会继承一个无关 shell 的临时变量。显式覆盖失败绝不回退到其他版本目录。不要直接改动当前 DSH 已安装运行副本；正常升级并完全退出/重启 DSH 后，再在**实际已安装新插件的进程中**执行 `/ig5 engines`、`ig5_doctor engine=ghidra`、`ig5_open engine=ghidra`、`ig5_funcs` 和 `ig5_decompile`，最后 `ig5_close`。切换源码目录本身不足以更新已经加载的插件。macOS 官方/通用 Ghidra 12.1.4 的 `open_project` 会拒绝项目路径中以 `.` 开头的目录段（典型报错：`java.lang.IllegalArgumentException: Path element starting with '.' is not permitted`），因此 Mac 默认分析数据库放在 `~/Library/Application Support/DeepSeek Harness/IG5/projects`，不放在 `~/.dsh/ig5/projects`。显式 `projectRoot` 覆盖须同样避开隐藏目录；例如持久配置可设为 `/Users/<user>/IG5Projects`，建议目录权限 `0700`。其它平台默认数据库位置未变。

可在源码目录先跑 `node scripts/test_host_platform.mjs`、`node scripts/test_worker_transport.mjs`、`npm run test:macos-pack`；合成 fixture 验证选包、Mach-O/路径拒绝等，但**不是原生引擎启动验收**。脚本的包内依赖 probe 成功同样不等于 doctor/open/decompile 成功。使用已授权本地样本做真正的隔离验收（只静态导入、不执行样本）：

```sh
node scripts/test_macos_runtime_native.mjs "$PWD/runtimes/darwin-arm64" '/absolute/path/to/local-sample' 'function-name-filter'
# 同时验证 Mac 默认的非隐藏 Ghidra 项目根（HOME 临时隔离、结束后清理）：
IG5_MAC_NATIVE_DEFAULT_PROJECT_ROOT=1 node scripts/test_macos_runtime_native.mjs "$PWD/runtimes/darwin-arm64" '/absolute/path/to/local-sample' 'function-name-filter'
```

此命令走仓库实际 `runtimeConfiguration → workerLaunch`，分别对 Ghidra 与默认内置 Reverse 路由要求 doctor/open/funcs/decompile/close 成功，并把临时 Ghidra 项目留在隔离空间直到结束后删除。2026 年 10 月的维护机验证：Apple Silicon/macOS，Ghidra 12.1.4、Python 3.12.12、JPype 1.5.2、JDK 21.0.11，离线包共校验 8,000 文件及 214 相对 symlinks；本地 ARM64 Mach-O `weighted_sum` 的完整静态调用链 doctor→open（2 函数、非 partial）→funcs→decompile（`local_c * 7`）→close 通过。该单一样本结果不代表所有格式、部署方式或 DSH GUI 安装态已验证。macOS `ig5_doctor` 显示的 x64dbg/商业 Reverse 不可用属预期。密钥/报文等纯数据工具仍可不依赖任何静态引擎工作。
