import {hashBytes} from '../../source/analysis_artifacts.js';
export function smallVm({seed=0,tableSwap=false,haltOnly=false,bits=8,rotate=3,subtract='acc-minus-operand',runId='owned-run-1',memoryEpoch='epoch-1',roles={vip:'r10',accumulator:'r11',result:'r12'}}={}){
 const table=Array(256).fill(null);for(let i=0;i<6;i++)table[i]=i;if(tableSwap)[table[2],table[4]]=[table[4],table[2]];
 const ops=haltOnly?[[0]]:[[1],[2,7],[3,0],[4,2],[5],[0]];let key=seed;const bytes=[];for(const [op,operand]of ops){bytes.push(op^key);key=(key+1)&255;if(operand!==undefined)bytes.push(operand);}
 return {schema:'ig5-small-vm-instance-v1',codeSha256:hashBytes(Buffer.from('Owned explicit small VM v1; no native interpretation')),bytecodeHex:Buffer.from(bytes).toString('hex'),table,decode:{seed,bits,rotate,subtract},runId,memoryEpoch,roles,contract:{minimum:'0x0',maximum:'0xf',initialResults:['0x0','0x39'],normalReturn:'explicit-halt'}};
}
