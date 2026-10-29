import fs from 'node:fs';
import path from 'node:path';

// 诊断日志:任何失败都不得影响插件主路径。
export function diagAppend(cfg, line) {
  try {
    fs.mkdirSync(cfg.artifactDir, { recursive: true });
    const stamp = new Date().toISOString();
    fs.appendFileSync(path.join(cfg.artifactDir, 'ig5-diag.log'), `[${stamp}] ${line}\n`, 'utf8');
  } catch {
    // diagnostics must never break the plugin
  }
}
