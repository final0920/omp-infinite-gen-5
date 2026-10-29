# UXR-03 分页与dossier

起始HEAD/摘要见baseline/workspace.json；前置02。状态：verified（夹具/真实静态worker/DSH SDK）。

index.js串行接入ig5_decompile operation=read；function_dossier.js在compact前保存已有provider结果，保留旧字段/schema=1，新增savedResult与provider/stored/response三层完整性。原evidence_adapters/dossier可接受新增字段，无需改写。客户端仅新增独立已证明ELF地址标签，旧反编译内容不替换。

游标HMAC密钥持久在独立索引，绑定结果SHA/section/format/contentSha/offset。UTF-8正文按字节边界，CFG等按带字段/索引的稳定记录；单条过长可改json-text全文分页。包含_ig5及游标的整页JSON按4000..64000字节预算计算。重开attachment/revision严格stale，禁止混页；每页含连续offset、nextOffset和内容摘要，末页nextCursor=null。

test_result_artifacts覆盖>64KB、中文emoji/转义、空段、末页、篡改/跨section、重启续页、超长单记录和完整重组摘要；原dossier九组回归及真实Reverse/Ghidra读取通过，日志regression.log/runtime.log。

部署见07。回退只停用新增operation、保留报告与索引；旧schema可忽略新字段。边界：provider未生成内容不会凭分页补出，宿主模型展示再次裁剪尚未实测；内容摘要与页序号可检测缺页。
