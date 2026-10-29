import fs from 'node:fs';
import path from 'node:path';
import { ProjectStore } from './project_store.js';
import { readStableFile } from './analysis_artifacts.js';

const fail = message => { throw Object.assign(new Error(message), { code: 'DIAGNOSTIC_STORE_INVALID' }); };
function safeRoot(root) {
  const resolved = path.resolve(root);
  for (let current = resolved; ; current = path.dirname(current)) {
    if (fs.existsSync(current) && (fs.lstatSync(current).isSymbolicLink() || !fs.lstatSync(current).isDirectory())) fail('Diagnostic directory must not contain links');
    if (path.dirname(current) === current) break;
  }
  return resolved;
}
/** Separate metadata namespace, existing owner lock + atomic publication. */
export class DiagnosticStore extends ProjectStore {
  constructor({ root }) { super({ root: safeRoot(root) }); }
  guard() {
    for (let current = this.root; ; current = path.dirname(current)) {
      if (fs.existsSync(current)) {
        const stat = fs.lstatSync(current);
        if (!stat.isDirectory() || stat.isSymbolicLink()) fail('Diagnostic directory must not contain links');
      }
      if (path.dirname(current) === current) break;
    }
  }
  _read() {
    this.guard();
    if (!fs.existsSync(this.file)) return super._read();
    const value = JSON.parse(readStableFile(this.file, this.maximumBytes ?? 32 * 1024 * 1024).data.toString('utf8'));
    if (value.schemaVersion !== 1 || !Number.isSafeInteger(value.revision) || value.revision < 0
      || ['projects', 'artifacts', 'targets', 'databases', 'attachments', 'runtimes'].some(k => !value[k] || typeof value[k] !== 'object' || Array.isArray(value[k]))
      || value.investigations !== undefined && (!value.investigations || typeof value.investigations !== 'object' || Array.isArray(value.investigations))) fail('Invalid diagnostic metadata');
    return value;
  }
}
