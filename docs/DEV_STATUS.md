# 开发版状态说明（自 README 迁出，原文未改）

这些段落原先位于 README.md 开头。它们记录本地开发版的实现标识和阶段性功能，面向维护者；使用者请看 README 与 `LIMITATIONS.md`。

本地当前版本为 **1.2.0**，当前实现标识 `20261024-knowledge-documents-1`。在完整结果分页、会话诊断、静态ELF地址、缓存与持久函数批任务基础上，增加按需研究方法检索、离线原文导入、阅读提示与关联跳转，保持原调查页简约风格；见 [研究资料与方法](docs/KNOWLEDGE_RESEARCH.md) 与 [1.2.0 发布说明](docs/RELEASE_1.2.0.md)。下方1.1.0下载链接是已有公开版本，本次本地升级不代表1.2.0附件已发布。

长任务上下文恢复：本地开发版已接入固定 LCM 存储/检索核心，使用 `ig5_profile memory` 保存与精确回取本会话历史。见[理论与可证明边界](docs/LCM_THEORY.md)、[使用与验收](docs/LCM_MEMORY.md)。不替换DSH压缩器，不代表已提高真实逆向成功率；现有公开发行包尚不包含此开发变更。

调查改造首批开发版：`ig5_profile capabilities=true` 读取能力维度与范围验收记录，`ig5_workspace workspace={action:"brief",id:"任务UUID"}` 恢复任务、过期证据和持久失败。已完成编译资产冻结与单例真实模型对照；有限结果、完整指标和边界见[实现与验收](docs/INVESTIGATION_UPGRADE.md)。

研究状态开发版：`workspace action=research-get/research-update` 保存独立修订的验收合同、假设、待验证事项和实验提案，关联本任务 dossier，并在 brief 中恢复。修订保留历史，进度、验收和资源清理分别表示。用法与边界见[调查研究状态](docs/RESEARCH_STATE.md)。 固定 VM context 狭义验证器可将证据绑定的候选派生义务关闭为 closed-in-scope；整项调查最高 partial，详见[离线验证与边界](docs/RESEARCH_VERIFICATION.md)。
