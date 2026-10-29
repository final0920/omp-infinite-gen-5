// A data-only proxy skeleton. This is not an OS or model tool-access security boundary.
import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { readStableFile } from '../../../source/analysis_artifacts.js';
const digest=b=>createHash('sha256').update(b).digest('hex');
export function semanticBroker(publicRoot,files,budget) {
  publicRoot=fs.realpathSync(publicRoot);const started=Date.now();let calls=0,bytes=0,omittedAudit=0,previous='0'.repeat(64);const audit=[];
  const names={target:'target.exe',contract:'contract.json'};
  function handle(request) {
    calls++;let response;
    if(Date.now()-started>(budget.timeoutMs??60000))response={status:'denied',reason:'time-budget'};
    else if(calls>budget.toolCalls)response={status:'denied',reason:'call-budget'};
    else if(!request||Object.keys(request).sort().join()!=='action,id'||request.action!=='read'||!Object.hasOwn(names,request.id))response={status:'denied',reason:'capability-not-allowed'};
    else {
      try {
        const file=path.join(publicRoot,names[request.id]),physical=fs.realpathSync(file);
        if(physical!==file||fs.lstatSync(file).isSymbolicLink())throw Error('linked-public-file');
        const {data}=readStableFile(file,Math.min(budget.bytes-bytes,65536));bytes+=data.length;
        if(digest(data)!==files[request.id].sha256||data.length!==files[request.id].bytes)throw Error('public-file-changed');
        response={status:'ok',id:request.id,sha256:files[request.id].sha256,bytes:data.length,data:data.toString('base64')};
      } catch(error) { response={status:'denied',reason:bytes>=budget.bytes?'byte-budget':'input-integrity'}; }
    }
    // Do not put secret contents or arbitrary caller paths into the audit log.
    const event={sequence:calls,requestDigest:digest(Buffer.from(JSON.stringify(request))),status:response.status,reason:response.reason??null,previous};
    previous=digest(Buffer.from(JSON.stringify(event)));if(audit.length<256)audit.push({...event,sha256:previous});else omittedAudit++;
    return response;
  }
  return {handle,snapshot:()=>({audit:structuredClone(audit),omittedAudit,auditComplete:omittedAudit===0,auditHead:previous,calls,bytes,isolationStatus:'exposed',isolatedCreditAllowed:false})};
}
export function requireIsolatedScore(report) {
  // No actual independent environment adapter is installed yet. Never accept a caller's boolean attestation.
  throw Object.assign(new Error('Isolated discovery scoring is unavailable until an independent constrained recovery environment is verified'),{code:'ISOLATION_NOT_ESTABLISHED'});
}
