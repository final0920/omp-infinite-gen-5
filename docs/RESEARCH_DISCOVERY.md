# F11 显式来源发现与待审发布

`discover_research_sources.mjs --list` 查看六个固定官方GitHub公开commit元数据端点。单次 `--source ID --queue-root ABS_DIR --expected-generation N` 只读取该端点，保存完整JSON到私有待审目录。不是全文抓取、定时任务或方法启用器；不读取项目/密钥，不发送私有内容。没有新增产品工具或后台联网。

每跳仅精确注册HTTPS端点，最多两次重定向；每次DNS全结果均须公网地址并固定到本次TLS连接，检查实际remoteAddress。拒绝loopback/私网/link-local/metadata、混合公网私网DNS、IPv4映射IPv6、非全局IPv6、外域/路径跳转、URL凭证/端口、压缩响应、登录/验证码HTML、非200/304与错误JSON。TLS证书仍正常校验，无代理环境继承。单响应512KiB，DNS5秒、每请求10秒、最多3请求；不执行网页/附件/脚本。

ETag/Last-Modified按来源保存；304须有完整缓存正文。成功一小时最短轮询间隔，失败指数退避上限一天。状态generation CAS、独占锁和原子rename；不抢占未知锁。元数据对象最多128份/8MiB，待审最多128项，满额需显式归档。原始SHA去重及相同commit修订去重，不把元数据近似当作不同论文。取消不提交新状态，已保存不可变对象可留作孤儿证据；失败保存退避，不进入公共索引。

待审内容不能直接发布。`review_research_discovery.mjs` 要求原item精确SHA和独立本地review JSON，明确metadata-only、质量量表、原创笔记及reviewer，导出document/reference-only清单；不支持method、全文、自动reproduced或proof。随后使用原 `publish_research_v2.mjs` 的manifest/input-root/project-root/expected-generation接口进行明确CAS发布，旧引用、撤回、代次和回退边界不变。导出本身不改公共目录。调用者审查声明不能替代人工第二审核。

`npm run test:discovery` 包括网络边界、DNS换绑/重定向、缓存、重复、失败退避、锁/CAS、待审拒绝与隔离v2代次发布。实网元数据发现另存结果；不由模拟传输测试代替。新维护模块不进入planner，不自动启用MethodSpec，assist保持false。
