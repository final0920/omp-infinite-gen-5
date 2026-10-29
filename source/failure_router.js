import { RECOVERY_FAILURES } from './vm_recovery_case.js';

const routes = {
  ENVIRONMENT_NOT_READY: 'check-prerequisites-or-use-offline-evidence',
  REVERSE_UNAVAILABLE: 'check-prerequisites-or-use-offline-evidence',
  RUNTIME_POLICY_BLOCKED: 'use-offline-evidence-no-native-retry',
  ERUNTIME_POLICY: 'use-offline-evidence-no-native-retry',
  ERUNTIME: 'check-prerequisites-or-use-offline-evidence',
  STALE_TASK_REVISION: 'read-current-task-and-replan',
  STALE_SESSION_CONTEXT: 'read-current-context-and-replan',
  INVALID_PHASE_CONTEXT: 'revalidate-context-and-complete-recording-manifest',
  CODE_VERSION_MISMATCH: 'read-exact-observation-code-version',
  ARTIFACT_CHANGED: 'revalidate-original-evidence',
  INVALID_ARGUMENT: 'inspect-operation-schema',
  INVALID_INVESTIGATION: 'inspect-operation-schema',
};

/** Advice only. Never grants execution, budgets, acceptance or cleanup. */
export function routeFailure(record, occurrences = 1) {
  const code = record.failureCode;
  const recovery = typeof code === 'string' && Object.hasOwn(RECOVERY_FAILURES, code) ? RECOVERY_FAILURES[code] : null;
  const route = typeof code === 'string' && Object.hasOwn(routes, code) ? routes[code] : null;
  const environment = ['ENVIRONMENT_NOT_READY', 'REVERSE_UNAVAILABLE', 'RUNTIME_POLICY_BLOCKED', 'ERUNTIME_POLICY', 'ERUNTIME'].includes(code);
  const cleanup = code === 'CLEANUP_UNCONFIRMED' || record.original?.cleanupConfirmed === false || record.original?.guestCleanupConfirmed === false;
  const repeat = occurrences >= 2;
  return {
    category: cleanup ? 'resource' : environment ? 'environment' : recovery || ['INVALID_PHASE_CONTEXT', 'CODE_VERSION_MISMATCH'].includes(code) ? 'research' : route ? 'usage' : 'unclassified',
    nextCheck: cleanup ? 'recover-original-execution-owner' : record.original?.metadataPublished === true ? 'read-current-metadata-before-retry'
      : record.original?.metadataPublished === false ? 'inspect-metadata-publication-failure' : repeat && !environment ? 'design-discriminating-experiment' : recovery?.[1] || route || 'inspect-original-failure-and-diagnose',
    occurrences, needsRediagnosis: repeat, executionAuthorized: false,
    acceptanceChanged: false, cleanupConfirmed: null,
  };
}
