import { fileURLToPath } from 'node:url';
import { hashBytes, readStableFile } from './analysis_artifacts.js';
import { planningDigest } from './planning_identity.js';

// Host collection/validation rules, captured once at module load. This is not a native-runtime attestation.
export const planningImplementationDigest = planningDigest(Object.fromEntries(['function_dossier.js', 'evidence_adapters/dossier.js', 'planning_identity.js']
  .map(name => [name, hashBytes(readStableFile(fileURLToPath(new URL(name, import.meta.url)), 1024 * 1024).data)])));
