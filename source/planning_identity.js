import { createHash } from 'node:crypto';

const scopeKeys = ['projectId', 'artifactId', 'sha256', 'engine', 'provider', 'attachmentId', 'dbRevision'];
const stable = value => Array.isArray(value) ? value.map(stable) : value && typeof value === 'object'
  ? Object.fromEntries(Object.keys(value).sort().map(k => [k, stable(value[k])])) : value;
export const planningDigest = value => createHash('sha256').update(JSON.stringify(stable(value))).digest('hex');

/** Fixed supported request identities, without IO, raw scripts, keys or caller text. */
export function planningRequestKey(request, context, implementationDigest = null) {
  if (!context || scopeKeys.some(k => context[k] === undefined)) return null;
  if (request.engine !== undefined && request.engine !== context.engine) return null;
  const scope = Object.fromEntries(scopeKeys.map(k => [k, context[k]]));
  if (request.tool === 'ig5_decompile' && request.style === 'dossier' && typeof request.ea === 'string' && /^0x[0-9a-f]+$/i.test(request.ea)) {
    const allowed = ['tool', 'target', 'engine', 'ea', 'style', 'task_id', 'dossier_max_bytes', 'dossier_max_rows'];
    if (Object.keys(request).some(k => !allowed.includes(k))) return null;
    return planningDigest({ schema: 'ig5-planning-request-v1', implementationDigest, scope, tool: request.tool, ea: '0x' + BigInt(request.ea).toString(16), style: 'dossier',
      bytes: request.dossier_max_bytes ?? 16000, rows: request.dossier_max_rows ?? 32 });
  }
  if (['ig5_workspace', 'ig5_profile'].includes(request.tool) && request.workspace?.action === 'evidence') {
    const w = request.workspace;
    if (Object.keys(w).some(k => !['action', 'id', 'snapshot_id'].includes(k))) return null;
    return planningDigest({ schema: 'ig5-planning-request-v1', implementationDigest, scope, tool: request.tool, action: w.action, taskId: w.id, snapshotId: w.snapshot_id });
  }
  return null;
}
