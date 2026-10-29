import path from 'node:path';
import { AnalysisArtifacts } from './analysis_artifacts.js';

/** Save the bounded API-call evidence outside databases and outside the UI cache. */
export async function saveApiTrace(cfg, session, result, params) {
  if (result?.schema !== 'ig5.apiTrace.v1' || !Array.isArray(result.calls)) throw new Error('API trace result is missing its schema or call list');
  if (result.calls.length > 1024 || result.coverage?.callsRecorded !== result.calls.length) throw new Error('API trace call list exceeds its budget or disagrees with coverage');
  const artifacts = new AnalysisArtifacts(path.join(cfg.artifactDir || cfg.projectRoot, 'api-traces'));
  try {
    const record = artifacts.save({ kind: 'api-trace', action: 'trace', result: {
      ...result, target: session.target, targetSha256: session.sha256, databaseModified: false,
      request: { api_names: params.api_names ?? null, max_api_calls: params.max_api_calls ?? null, max_apis: params.max_apis ?? null },
    } });
    return { ...result, apiTraceSaved: true, apiTraceReportId: record.id,
      apiTraceReportPath: path.join(artifacts.root, 'records', record.id + '.json'),
      apiTraceReportSha256: artifacts.metadata(record.id).result.recordSha256 };
  } finally { await artifacts.dispose(); }
}
