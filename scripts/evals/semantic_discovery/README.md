# B01 隔离骨架

本目录独立于 PR01 二十任务登记和历史成绩。当前只封存一份 U1 隐藏变体，用于测试准备、边界拒绝和泄露判定，不作为语义发现通过案例。

`suite.mjs` 仅用于准备端：固定 seed，生成自产 PE、公开结构化合同、私有生成信息/源码身份、256 输入 oracle、秘密 canary、预算和评分规则。相同 seed 与生成器产生相同封存摘要。恢复可见目录仅有 target.exe 和 contract.json；不放答案、MAP/PDB、源码或生成日志。

`broker.mjs` 是只读最小文件工具代理骨架：只能读取封存的 target/contract ID；任意路径、执行、网络、跨套件请求拒绝。请求摘要和拒绝原因形成 hash 链，默认最多保留 256 条，超限明确 omittedAudit/auditComplete=false；有工具调用、字节和时间上限。它不是 OS 隔离边界，也不能限制宿主上其他工具。

`isolation_probe.mjs` 在独立 Node `--permission` 子进程中实际尝试读取公开文件、私有 canary 和生成器源码。公开读取成功，秘密/源码读取应返回 ERR_ACCESS_DENIED。该探针仅验证此子进程文件系统限制；Node 文件权限不能证明网络隔离，更不能限制发起调查的宿主代理。

因此即使文件探针通过，当前结果固定为 `exposed`、`isolatedCreditAllowed=false`。requireIsolatedScore 拒绝调用者自行提交 isolated=true。尚需独立受限客体/身份、实际工具/网络边界及独立恢复角色的完整泄露自测，之后才能实现正式隔离评分适配器。禁止将该骨架的通过计为 isolated、未知样本恢复或 M1 完整验收。

测试入口：`npm run test:semantic-isolation`。首批纵向验收脚本会在独立证据目录生成一份套件及探针结果。准备端与恢复端的角色重叠明确保留；隐藏样本未用于模型调参或正式得分。
