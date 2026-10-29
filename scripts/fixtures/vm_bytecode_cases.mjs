import { buildPE64Fixture } from './pe64.mjs';
export const branchMemoryCode = Buffer.from('07070305090855060b010400','hex');
export function ownedVmImage() {
  const {image}=buildPE64Fixture();image.fill(0xcc,0x400,0x800);
  Buffer.from('4c8d0df91f00004989094889c84c8d15ec200000410fb61249ffc284d20f842500000080fa010f840a00000080fa020f840a000000cc4883c007e9d5ffffff4883f055e9ccffffff498901c3','hex').copy(image,0x400);
  image.fill(0,0xe00,0xe08);Buffer.from('010200','hex').copy(image,0xf00);return image;
}
// Owned native interpreter for the same branch/write-read bytecode reference.
// Building bytes does not execute the image or infer a protected VM's ISA.
export function ownedBranchVmFixture() {
  const {image}=buildPE64Fixture();image.fill(0xcc,0x400,0x800);
  const labels={},instructions=[],fixups=[];let pc=0x1000;
  const label=(name,rva=pc)=>{labels[name]=rva;};
  const emit=(hex,phase)=>{const bytes=Buffer.from(hex,'hex');bytes.copy(image,0x400+pc-0x1000);instructions.push({rva:pc,bytes:hex,phase});pc+=bytes.length;};
  const rel=(hex,target,phase='dispatch')=>{const at=pc;emit(hex+'00000000',phase);fixups.push({at:at+hex.length/2,next:pc,target});};
  const back=()=>rel('e9','fetch','handler-control');
  label('entry');rel('4c8d0d','output','initialization');emit('498909','initialization');emit('4889c8','initialization');
  rel('4c8d1d','bytecode','initialization');emit('4d89da','initialization');
  label('fetch');emit('410fb612','dispatch');emit('49ffc2','dispatch');emit('84d2','dispatch');rel('0f84','finish');
  for(let opcode=1;opcode<=8;opcode++){emit('80fa'+opcode.toString(16).padStart(2,'0'),'dispatch');rel('0f84','op'+opcode);}
  emit('cc','invalid-opcode');
  label('op1');emit('4883c007','handler-add');back();
  label('op2');emit('4883f055','handler-xor');back();
  label('op3');emit('498901','handler-store');back();
  label('op4');emit('498b01','handler-load');back();
  label('op5');emit('410fb612','operand');emit('49ffc2','operand');emit('a801','handler-parity');rel('0f85','fetch','handler-parity');emit('4d8d1413','handler-branch');back();
  label('op6');emit('410fb612','operand');emit('4d8d1413','handler-jump');back();
  label('op7');emit('410fb612','operand');emit('49ffc2','operand');emit('4801d0','handler-add-immediate');back();
  label('op8');emit('410fb612','operand');emit('49ffc2','operand');emit('4831d0','handler-xor-immediate');back();
  label('finish');emit('498901','output-store');emit('c3','return');
  label('output',0x3000);label('bytecode',0x3100);
  for(const f of fixups)image.writeInt32LE(labels[f.target]-f.next,0x400+f.at-0x1000);
  for(const ins of instructions)ins.bytes=image.subarray(0x400+ins.rva-0x1000,0x400+ins.rva-0x1000+ins.bytes.length/2).toString('hex');
  image.fill(0,0xe00,0xe08);branchMemoryCode.copy(image,0xf00);
  return {image,labels,instructions};
}
export function bytecodeContract(targetSha256, pe = false) {
  return {schema:'ig5-function-contract-v1',targetSha256,entryRva:pe?'0x1000':'0x0',normalReturn:pe?'native-ret':'bytecode-halt',
    input:{register:'rcx',bits:8,minimum:'0x0',maximum:'0xff'},outputs:{returnRegister:'rax',memory:[{rva:'0x3000',bytes:8}]},
    environment:'single-threaded-no-external-calls',exclusions:['exceptions','concurrency','external calls']};
}
