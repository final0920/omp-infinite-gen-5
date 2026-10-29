import fs from 'node:fs';
const [target,secret,generator]=process.argv.slice(2);
const result={publicReadable:fs.readFileSync(target).length>0};
for(const [key,file] of [['secret',secret],['generator',generator]]) {
  try { fs.readFileSync(file);result[key+'Read']='exposed'; }
  catch(error) { result[key+'Read']=error.code==='ERR_ACCESS_DENIED'?'denied':'unknown'; }
}
process.stdout.write(JSON.stringify(result));
