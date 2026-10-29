// Independent source-level reference. No decoder, program builder, candidate evaluator or caller expressions.
const mask = 18446744073709551615n;
export function fixedFunctionOracle(targetSha256, input) {
  let result;
  if(targetSha256 === '71d1ceaedaebeb572c63c33485405fa7612beab047aff0c00f96044bd92223f0') result=((input+7n)&mask)^85n;
  else if(['6e71d6e35ce1939e6a44825918979e3188cd5c83f3d9d3afafa7d136b979224e','d9bf31e34c5e95307f88fcc7ce544101bd61e566c284a4622afc9700f29da61c'].includes(targetSha256)) {
    const saved=(input+7n)&mask; result=saved%2n === 0n ? saved : saved^85n;
  } else return null;
  let hex=''; for(let i=0;i<8;i++)hex+=Number((result>>BigInt(8*i))&255n).toString(16).padStart(2,'0');
  return {returnValue:'0x'+result.toString(16),memoryHex:hex,normalReturn:true};
}
