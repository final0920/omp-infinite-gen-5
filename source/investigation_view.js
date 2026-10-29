import { runWorkspace } from './investigation_workflow.js';

/** Fixed read-only adapter; URL input can never become an arbitrary workspace action. */
export function readInvestigationView(mgr, cfg, session, params) {
  const action = params.action;
  if (!['list', 'brief'].includes(action)) throw new Error('Investigation view supports list/brief only');
  const scoped = Object.create(mgr);
  scoped.get = target => {
    if (target !== session.target || !mgr.alive(session)) throw new Error('Investigation target changed');
    return session;
  };
  const workspace = action === 'list' ? { action } : { action, id: params.id, max_bytes: 16384 };
  const data = runWorkspace(scoped, cfg, { target: session.target, workspace }, {}).workspace;
  if (action === 'brief' && (!Number.isSafeInteger(params.taskRevision) || params.taskRevision !== data.snapshot.taskRevision))
    throw Object.assign(new Error('Task revision changed; refresh the investigation list'), { code: 'STALE_TASK_REVISION' });
  return { ...data, _ig5: mgr.evidence(session) };
}
