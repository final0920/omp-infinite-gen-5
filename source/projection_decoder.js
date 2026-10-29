import path from 'node:path';
import { readStableFile, hashBytes } from './analysis_artifacts.js';

export const JAVA_PROJECTION_RUNTIME_PIN = 'a2d70b018865c39e2d176c0997b4bc91b60942ee8944ed63069c2b6456d5dda0';
export const JAVA_PROJECTION_HELPER_PIN = '7a3ed54a8546f419da3ff29f7163f59500e1e0f6ed631dd943f25ea60c17598f';
const sha = value => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);

export function selectProjectionDecoder(args) {
  if (!Object.hasOwn(args, 'projection_decoder')) return {};
  if (!['native', 'java'].includes(args.projection_decoder)) throw new Error('projection_decoder requires native or java');
  return { projection_decoder: args.projection_decoder };
}

/** Both sequential children must have exited within one original request budget. */
export function validateDecoderEvidence(selected, result, reply, directory) {
  if (selected.projection_decoder !== 'java') {
    if (result.projectionDecoder !== undefined || result.javaDecoder !== undefined || reply.processStages !== undefined || reply.projectionDecoder !== undefined) {
      throw new Error('Native projection returned an unrequested decoder route');
    }
    return;
  }
  const meta = result.javaDecoder, stages = reply.processStages;
  if (result.projectionDecoder !== 'java' || reply.projectionDecoder !== 'java' ||
      reply.javaDecoderManifestPin !== JAVA_PROJECTION_RUNTIME_PIN || meta?.runtimeManifestPin !== JAVA_PROJECTION_RUNTIME_PIN ||
      meta.upstreamManifestPin !== '8fc4ae42f775f0139aa5f184c912db71f77e68d661c14564ab6f4820d434abea' ||
      meta.helperSha256 !== JAVA_PROJECTION_HELPER_PIN || meta.language !== 'x86:LE:64:default' || meta.runtimeAssetCount !== 614 ||
      !sha(meta.inputSha256) || !sha(meta.outputSha256) ||
      !Number.isSafeInteger(reply.sharedBudgetMs) || reply.sharedBudgetMs < 1 || reply.sharedBudgetMs > 50000 ||
      !Array.isArray(stages) || stages.length !== 2 || stages[0]?.stage !== 'java-decode' || stages[1]?.stage !== 'state-computation') {
    throw new Error('Java projection decoder provenance mismatch');
  }
  for (const stage of stages) {
    const process = stage.process;
    if (!Number.isSafeInteger(stage.budgetMs) || stage.budgetMs < 1 || stage.budgetMs > reply.sharedBudgetMs ||
        process?.status !== 'completed' || process.exitCode !== 0 || process.childExitConfirmed !== true ||
        process.jobAssignedAtCreation !== true || process.activeProcessLimit !== 1 || process.memoryLimitBytes !== 2 * 1024 ** 3 ||
        !Number.isSafeInteger(process.pid) || process.pid < 1 ||
        !Number.isSafeInteger(process.elapsedMs) || process.elapsedMs < 0 || process.elapsedMs > stage.budgetMs + 100) {
      throw new Error('Java projection sequential child resource/cleanup mismatch');
    }
  }
  if (stages[1].budgetMs > stages[0].budgetMs - stages[0].process.elapsedMs + 2 ||
      JSON.stringify(stages[1].process) !== JSON.stringify(reply.process)) throw new Error('Java projection reset the shared compute deadline');
  const { data: input } = readStableFile(path.join(directory, 'java-input.json'), 65536);
  const { data: output } = readStableFile(path.join(directory, 'java-decode', 'stdout.log'), 4 * 1024 ** 2);
  if (hashBytes(input) !== meta.inputSha256 || hashBytes(output) !== meta.outputSha256) throw new Error('Java projection staged decode digest mismatch');
}

export function decoderPreview(result, reply) {
  return result.projectionDecoder === 'java' ? { projectionDecoder: 'java', javaDecoder: result.javaDecoder,
    processStages: reply.processStages, sharedBudgetMs: reply.sharedBudgetMs } : {};
}
