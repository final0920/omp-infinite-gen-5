import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { prepareKnowledgeImport, publishKnowledgeImport } from '../source/knowledge_import.js';

export function main(argv) {
  const options = {};
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--dry-run') { if (options.dryRun) throw new Error('Duplicate --dry-run'); options.dryRun = true; continue; }
    const names = { '--manifest': 'manifestPath', '--input-root': 'inputRoot', '--project-root': 'projectRoot', '--expected-catalog-sha256': 'expectedCatalogSha256' };
    if (!names[arg] || options[names[arg]] !== undefined || !argv[i + 1] || argv[i + 1].startsWith('--')) throw new Error('Use --manifest FILE --input-root DIR --project-root DIR [--expected-catalog-sha256 HASH] [--dry-run]');
    options[names[arg]] = argv[++i];
  }
  const prepared = prepareKnowledgeImport(options);
  return publishKnowledgeImport({ ...options, prepared });
}
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try { console.log(JSON.stringify(main(process.argv.slice(2)), null, 2)); }
  catch (error) { console.error(JSON.stringify({ code: error.code || 'IMPORT_FAILED', message: error.message, catalogSaved: error.catalogSaved || false, cleanupConfirmed: error.cleanupConfirmed ?? null, catalogSha256: error.catalogSha256 || null })); process.exitCode = 1; }
}
