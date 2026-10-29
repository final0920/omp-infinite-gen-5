// Maintenance-only, fixed source locators. No private source text/keys/answers are copied.
import fs from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {readEvidence,sha256,auditCases} from './evidence.mjs';
import {freezeProtocol,summarizeRuns} from '../evals/fusion/protocol.mjs';

const reflection='IG5使用问题反思报告.txt', notes='notes/18_alu_calibrated.md';
const definitions=[
  ['known-output','提取结果是否已存在','恢复输出 / 解释全部实现','继续统一解密尝试','§146回顾发现早期笔记已有结果','先回读旧结果，输出已知不能关闭算法解释义务','known-result-needs-implementation',[[reflection,205,216],[notes,18324,18345],['notes/06_version_config.md',50,55]]],
  ['callee-families','是否可统一全部变换','共同实现 / 分支实现存在差异','按单个实例的算法继续尝试其他索引','§143与§144回顾记录不同callee及失败组合','按调用族提出区分实验；不同函数也不能直接证明语义不同','needs-instance-grouping',[[notes,17953,17976],[notes,18005,18020],[notes,18039,18067]]],
  ['address-space','地址为何错位','已是ELF地址 / 仍是分析器地址','重复减去分析器偏移','反思列举多次换算错误','缺唯一字节映射时保持未知，不用全局偏移推测','needs-evidence',[[reflection,159,179]]],
  ['runtime-identity','静态地址能否直接用于运行','当前模块映射有效 / 映射缺失或已过期','据静态地址生成运行观察点','旧反思将静态与运行地址联动列为需求','缺run、模块和epoch时不发布运行地址','needs-evidence',[[reflection,245,255],['交接文档.md',187,209]]],
  ['prototype','空原型是否无参数','确实无参数 / 参数恢复失败','曾据空参数判断函数用途','反思指出调用点实际有输入','读取调用点寄存器及raw，unknown不升级无参','needs-evidence',[[reflection,77,92]]],
  ['movk-register','提取常量是否串入其他寄存器','同SSA定义链 / 无关寄存器被合并','通过操作数字符串提取seed','反思记载无关寄存器污染及两次失败','追踪确切目的寄存器定义与覆盖，不能只匹配文本','needs-definition-chain',[[reflection,222,235]]],
  ['movk-shift','MOVK位移是否保留','编码半字位移有效 / 文本解析丢失位移','解析lsl字符串得到错误移位','§134记载位级提取及手工复核','结构化解码并独立核对位宽和半字覆盖，不无条件OR','needs-independent-decode',[[notes,16213,16235],[reflection,230,235]]],
  ['adr-variant','提取器是否覆盖ADR单指令','ADRP加ADD / ADR有符号PC相对变体','旧提取器仅覆盖部分寻址和寄存器布局','§146.3记录ADR和寄存器角色变体','缺ADR及角色支持时返回unsupported，不能漏掉实例','unsupported',[[notes,18363,18375]]],
  ['halt-conflict','HALT是否清result','只清ok / 同时清result','旧头注释将HALT写成清结果','当前实现和测试保留result，旧说明未改','状态contested，回溯确切入口原指令及跳转目标','contested',[['src/vm_l3.py',38,44],['src/vm_l3.py',270,273],['src/test_vm_l3.py',192,202],[notes,16523,16544]]],
  ['sub-direction','SUB的两个源方向','C减B / B减C','按虚拟寄存器名归纳减法','当前代码与测试记录方向和掩码','使用不相等非对称输入区分，并独立核对原生指令','needs-independent-native-evidence',[['src/vm_l3.py',273,277],['src/test_vm_l3.py',209,220]]],
  ['ror-width','旋转使用何种宽度','8位旋转 / 机器寄存器宽度旋转','从模型恢复局部操作','当前代码显式采用ROR8','以跨最高位的值区分宽度，模型自洽不是CPU证明','needs-independent-native-evidence',[['src/vm_l3.py',265,269],['src/vm_l3.py',38,44]]],
  ['truncated-cfg','看到的函数与调用表是否完整','完整结果 / 展示或provider缺失','在不完整dossier上作用途和调用族判断','反思记录大函数和CFG截断','先完整分页，provider缺失仍需补采集，不能补零','needs-complete-source',[[reflection,37,58],[reflection,127,137]]],
  ['branch-coverage','索引枚举是否漏了分支形式','仅比较分支足够 / 其他寻址跳转亦有索引','最初仅提取比较分支','§144修正枚举后才发现更多入口','保留未知出口并核对全CFG，不以匹配数量宣称完整','needs-complete-cfg',[[notes,18039,18067]]],
  ['completion-claim','最终报告能否继承为系统证明','报告已完成 / 仅有自述与限定自检','以总断言数和完成描述交接','反思和最终报告包含不同层级声明','原子拆分来源与范围，自检不等于独立语义验证','reported-only',[[reflection,4,8],['VM完全逆向_最终验收报告.md',1,12]]],
  ['environment','工具失联是否算法失败','环境未就绪 / 算法反例','会话失联后切换分析路径','反思记录父会话不可用，原因仍有疑问','先诊断真实会话和预算；不旁路账本、不重复试受阻组件','environment-not-ready',[[reflection,15,33],[notes,18214,18225]]],
  ['instance-identity','结构相似是否同实例语义','共享结构 / seed表及角色不同','按相似节点布局复用模型','源码声明两个变体，§146记载更多参数布局','代码、表、字节码、参数及run身份缺件保持unknown','needs-instance-binding',[['src/vm_l3.py',88,109],[notes,18347,18375]]],
];

export async function buildCases(root) {
  const expected={ 'sample.apk':'69d5490075167ac330833a3389a3271a8c8cd96ea10ca9ebe88349a593c4b235', 'ext/lib/arm64-v8a/libjinverify.so':'f18037fdf042ab0b4628546dbcc81f4f9db50000391381c3922ae99257e55de0' };
  const samples=[];
  for(const [name,hash] of Object.entries(expected)) {
    const {bytes,...item}=await readEvidence(root,name);
    if(item.sha256!==hash)throw new Error('Original sample identity mismatch');
    samples.push(item);
  }
  const cache=new Map();
  const cases=[];
  for(const [id,question,hypotheses,historicalAction,locatedResult,laterCorrection,expectedDecision,locators] of definitions) {
    const sourceRefs=[];
    for(const [name,startLine,endLine] of locators) {
      if(!cache.has(name))cache.set(name,await readEvidence(root,name));
      const source=cache.get(name),lines=source.bytes.toString('utf8').split(/\r?\n/);
      if(endLine>lines.length)throw new Error('Source locator out of range');
      sourceRefs.push({path:name,sha256:source.sha256,startLine,endLine,rangeSha256:sha256(lines.slice(startLine-1,endLine).join('\n'))});
    }
    cases.push({caseId:'vs15-'+id,projectId:'private-vs15-development',artifactSha256:expected['ext/lib/arm64-v8a/libjinverify.so'],question,
      visibleInput:'当前只读源记录指定行；历史决策时是否已可见未独立证明',observations:locatedResult,hypotheses:hypotheses.split(' / '),historicalAction,locatedResult,laterCorrection,
      unknowns:'未运行原脚本、样本或设备；未独立复算原生语义、轮次成本及历史时间顺序',redaction:'仅保留原创问题摘要和路径/SHA/行范围，不复制原文、密钥、主机地址、设备标识或最终答案',
      expectedDecision,status:id==='halt-conflict'?'contested':'reported',timeline:'retrospective-order-unverified',sourceRefs});
  }
  return {schema:'ig5-private-decision-cases-v1',projectId:'private-vs15-development',partition:'development',publicExportAllowed:false,samples,
    versionClues:{projectDirectoryLabel:'VS1.5',historicalReport:'VM完全逆向_最终验收报告.md',historicalApkLabel:'腾讯游戏安全中心10-05.apk',versionIndependentlyProved:false},
    sampleAliases:[{historicalLabel:'腾讯游戏安全中心10-05.apk',currentPath:path.join(path.resolve(root),'sample.apk'),sha256:expected['sample.apk'],basis:'historical-report-apk-digest-matches-current-bytes',historicalAbsolutePathProved:false}],
    historicalPathMappings:[{historicalRoot:'C:\\RE\\VS1.5',currentRoot:path.resolve(root),basis:'relative-path-plus-current-sha-not-historical-filesystem-identity',sampleSha256:expected}],cases};
}
async function main() {
  const [root,output]=process.argv.slice(2);
  if(!root || !output || !path.isAbsolute(root) || !path.isAbsolute(output))throw new Error('Explicit absolute input and new output directory required');
  const realRoot=await fs.realpath(root),realParent=await fs.realpath(path.dirname(output));
  const dest=path.join(realParent,path.basename(output));
  if(dest.toLowerCase()===realRoot.toLowerCase() || dest.toLowerCase().startsWith(realRoot.toLowerCase()+path.sep))throw new Error('Output must be outside evidence tree');
  const bundle=await buildCases(root),audit=await auditCases(bundle,root);
  await fs.mkdir(output);
  for(const [name,value] of [['cases.json',bundle],['case-audit.json',audit]])await fs.writeFile(path.join(output,name),JSON.stringify(value,null,2),{flag:'wx'});
  const protocol=freezeProtocol({schema:'ig5-fusion-eval-input-v1',model:'unresolved-no-model-runs',route:'unresolved',parameters:{temperature:0},context:'ten-development-decisions-only',toolVersion:'20261024-knowledge-documents-1',corpusGeneration:'knowledge-v1',promptSha256:sha256('Review supplied source evidence; preserve unknowns; return decision and source hashes.'),
    budget:{toolCalls:20,tokens:16000,elapsedMs:120000,returnedBytes:65536},thresholds:{falseAccepts:0,boundaryViolations:0,nonInferiorityPercentagePoints:5,offOverheadPercent:10},
    tasks:bundle.cases.slice(0,10).map(c=>({id:c.caseId,family:'VS1.5',partition:'development',project:'VS1.5',inputSha256:sha256(JSON.stringify(c)),judgeSha256:sha256(c.expectedDecision)}))});
  await fs.writeFile(path.join(output,'eval-development-protocol.json'),JSON.stringify(protocol,null,2),{flag:'wx'});
  await fs.writeFile(path.join(output,'eval-unrun-summary.json'),JSON.stringify(summarizeRuns(protocol,[]),null,2),{flag:'wx'});
  console.log(JSON.stringify({cases:bundle.cases.length,sourceIntegrity:audit.caseCount,modelRuns:0,output}));
}
if(process.argv[1] && path.resolve(process.argv[1])===fileURLToPath(import.meta.url))main().catch(e=>{console.error(e.message);process.exitCode=1;});
