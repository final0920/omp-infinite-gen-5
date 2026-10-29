// Read-only framework entry. No subprocess, network, target execution or writes.
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { recoveryError } from '../source/vm_recovery_case.js';
import { readRecoveryPlan } from '../source/vm_recovery_io.js';
export { readRecoveryPlan } from '../source/vm_recovery_io.js';
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    if (process.argv.length !== 3) recoveryError('INVALID_ARGUMENT', 'Usage: node scripts/plan_vm_recovery.mjs <absolute-case.json>');
    process.stdout.write(JSON.stringify(readRecoveryPlan(process.argv[2]), null, 2) + '\n');
  } catch (error) {
    process.stderr.write(JSON.stringify({ ok: false, code: error.code || 'RECOVERY_PLAN_FAILED', message: error.message }) + '\n');
    process.exitCode = 1;
  }
}
