# 旧项目锁离线恢复

R7 继续拒绝自动回收缺少主机身份的旧锁。仅凭本机 PID 不存在，不能证明原主机上的所有者已退出。本工具提供显式离线迁移，保留完整 owner.json，避免直接删除锁。

1. 停止使用该项目根目录的所有主机上的 DSH/IG5 写入进程，并在迁移期间阻止它们重启。共享目录必须逐主机确认。
2. 使用绝对路径预览，默认不会修改任何文件：

   `node scripts/recover_legacy_project_lock.mjs --root "C:\Users\IG5User\.dsh\ig5\projects"`

3. 核对预览的根目录、PID、ownerSha256。只有确认目录已完全离线后，携带预览中的真实摘要执行：

   `node scripts/recover_legacy_project_lock.mjs --root "C:\Users\IG5User\.dsh\ig5\projects" --expected-owner-sha256 <预览摘要> --offline-confirmed`

工具拒绝本机仍存活或状态未知的 PID、非旧版锁、摘要变化、符号链接和非预期路径。成功后把锁移到同目录下唯一的 `.projects-legacy-lock-*`，保留原始内容，不修改 projects.json。确认恢复期间没有并发写入后再启动 DSH。`--offline-confirmed` 是操作者对所有主机已离线的声明，不能替代外部停机协调。

本轮实际检查 `C:\Users\IG5User\.dsh\ig5\projects` 返回 `no-lock`，没有对用户项目锁实施迁移。测试在临时目录验证预览不写、摘要不匹配拒绝、活 PID 拒绝、现代锁拒绝，以及成功迁移后原始证据完整保留。
