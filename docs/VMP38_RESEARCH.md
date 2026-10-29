# VMP 3.8 资料与工具适配记录

2026-10-14核查的原始资料：

- [REcon 2024：Architecture Analysis of VMProtect 3.8](https://www.recon.cx/cfp.recon.cx/recon2024/talk/YQK3FK/index.html)，Holger Unterbrink 的版本针对性研究。[原演示](https://recon.cx/cfp.recon.cx/media/recon2024/submissions/YQK3FK/resources/Recon_final_sBaotaG.pdf)介绍 rolling key、运行期变化的寄存器角色、handler 连接和虚拟栈。资料可指导架构，演讲不是五代自动恢复通过证据。
- [NoVmp](https://github.com/can1357/NoVmp) 的作者声明 x64 VMP3.0–3.5、输入须先解包、实验性 PoC。不能将仓库名中的3.x当作3.8实测。
- [VMPLift](https://github.com/sexyiam/VMPLift) 固定研究副本修订 `5d9a93e404217b322f1b931a851d79d46e533f3e`。作者宣称3.8–3.10；五代源码审读发现其恢复侧补零未观测寄存器／未映射内存，且公式拟合可能仅比较32位。未满足五代的完整状态、64位和SMT要求，未接作已通过引擎。
- [titan](https://github.com/archercreat/titan) 提供 Triton handler 语义与虚拟指令指针／栈指针研究；作者明确写支持 `<3.8` 且输出不理想，不能充当3.8引擎。源码和许可及原生验收仍须分别核对。
- [Naci 的 lifting 研究](https://nac-l.github.io/2025/01/25/lifting_0.html)对比VMP3.8和Themida的控制流与 lifting，属于作者原始研究；无版本与输入生成证明的附件不当作自产3.8通过样本。
- [VMProtect-devirtualization](https://github.com/JonathanSalwan/VMProtect-devirtualization) 是既有 Triton 路线的研究来源，范围受纯函数和实际采集路径限制；不重复计算为本轮新增能力。

本轮实际接入的工具是 [ScyllaHide](SCYLLAHIDE.md)，用于补齐自产目标的调试环境。它不完成 VM handler 翻译，也不证明VMP3.8兼容。

下一层架构需要把原生 handler 的状态转移转成可组合的语义摘要，显式保留虚拟PC、虚拟栈、rolling key、内存写入与控制流。每个摘要须独立证明，组合后仍须检查入口／返回、环境依赖和路径覆盖。仅聚类地址、拟合少量输入或提取一个运行结果不能作为业务恢复。

现有自产 VMP3.11 测试与VMP3.8分开。八轮Ultra在100000指令处仍未返回；不扩大录制／离线预算掩盖失败。未核验到固定来源、版本和输入生成证明的3.8保护样本时，版本专项目标保持未通过。外部学习挑战仍仅只读，不执行上游攻击脚本或使用泄漏保护器源码。
