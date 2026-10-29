import fs from 'node:fs/promises';
import path from 'node:path';
import {readEvidence,auditCases} from './evidence.mjs';

const [input,root,output]=process.argv.slice(2);
try {
  if(![input,root,output].every(p=>p && path.isAbsolute(p)))throw new Error('Use absolute CASES_JSON EVIDENCE_ROOT NEW_RECEIPT paths');
  const destination=path.join(await fs.realpath(path.dirname(output)),path.basename(output)).toLowerCase();
  const evidence=(await fs.realpath(root)).toLowerCase();
  if(destination===evidence || destination.startsWith(evidence+path.sep))throw new Error('Receipt must be outside evidence tree');
  const source=await readEvidence(path.dirname(input),path.basename(input));
  const receipt=await auditCases(JSON.parse(source.bytes.toString('utf8')),root);
  await fs.writeFile(output,JSON.stringify({...receipt,rawBundleSha256:source.sha256},null,2),{flag:'wx'});
  console.log(JSON.stringify({caseCount:receipt.caseCount,semanticVerified:false,output}));
}catch(error){console.error(error.message);process.exitCode=1;}
