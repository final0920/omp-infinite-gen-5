import {validateOpaqueProjection} from './projection_opaque.js';
const canon=v=>JSON.stringify(v,(_k,x)=>x&&typeof x==='object'&&!Array.isArray(x)?Object.fromEntries(Object.keys(x).sort().map(k=>[k,x[k]])):x);
const need=(ok,m)=>{if(!ok)throw new Error('Opaque composition: '+m);};

/** Every application rebinds its live unknowns and every raw approximation.
 * Shared template metadata is not authority for caller-supplied unknown values.
 */
export function validateOpaqueComposition(result,plan,reference) {
  const inputs=result.nondeterministicInputs,nodes=result.dag.nodes,seen=new Set();
  const status=plan.template_mode==='opaque-status';
  need(plan.strategy==='sequence'&&plan.representation==='transition-chain'&&['opaque-effects','opaque-status'].includes(plan.template_mode)&&result.templateMode===plan.template_mode&&
    Array.isArray(inputs)&&inputs.length<=1024,'explicit mode/input scope mismatch');
  const decoded=new Map(result.decodedPath.map(r=>[r.ea,r]));
  let abstracted=0,raw=0,replacements=0;
  result.steps.forEach((id,step)=>{
    const template=result.templates[id],layer=result.layers[step];
    need(template.projectionMode===plan.template_mode&&Array.isArray(template.opaqueEffects)&&
      Array.isArray(template.liveUnknownInstructions),'template approximation provenance absent');
    let effects=template.opaqueEffects;
    if(status){
      const images=layer.flagImages,expected=effects.filter(e=>e.kind==='unknown-pushed-flag-image').map(e=>e.instructionIndex);
      need(Array.isArray(images)&&images.length===expected.length&&canon(images.map(x=>x.instructionIndex))===canon(expected), 'application flag images missing or reordered');
      for(const x of images){need(canon(Object.keys(x).sort())===canon(['instructionIndex','valueNode'])&&Number.isSafeInteger(x.valueNode)&&x.valueNode>=layer.nodeStart&&x.valueNode<layer.nodeEnd,'invalid application flag image');reference(x.valueNode,'bv',64);}
      effects=structuredClone(effects);
      for(const e of effects)if(e.kind==='unknown-pushed-flag-image'){
        need(e.flagImageRefinement&&!Object.hasOwn(e.flagImageRefinement,'valueNode'),'template flag value must be application-scoped');
        e.flagImageRefinement.valueNode=images.find(x=>x.instructionIndex===e.instructionIndex).valueNode;
      }
    }else need(!Object.hasOwn(layer,'flagImages')&&!Object.hasOwn(template,'flagPolicies'),'old opaque mode returned status-image scope');
    const selected=inputs.filter(x=>x.stepIndex===step);
    const descriptors=selected.map(x=>Object.fromEntries(['instructionIndex','bits','kind','source'].map(k=>[k,x[k]])))
      .sort((a,b)=>a.instructionIndex-b.instructionIndex);
    need(canon(descriptors)===canon([...template.liveUnknownInstructions].sort((a,b)=>a.instructionIndex-b.instructionIndex)),
      'live unknown template/application mismatch');
    for(const x of selected){
      const n=nodes[x.node];
      need(Number.isSafeInteger(x.node)&&x.node>=layer.nodeStart&&x.node<layer.nodeEnd&&!seen.has(x.node)&&
        x.templateIndex===id&&n?.stepIndex===step&&n.templateIndex===id&&n.instructionIndex===x.instructionIndex,
        'unknown freshness or application identity mismatch');
      need(canon(Object.keys(x).sort())===canon(['node','bits','kind','source','instructionIndex','stepIndex','templateIndex'].sort())&&
        canon(Object.keys(n).sort())===canon(['id','op','type','args','bits','name','kind','source','stepIndex','templateIndex','instructionIndex'].sort()),
        'unknown values or extra definitions are not accepted');
      seen.add(x.node);reference(x.node,'bv',64);
    }
    const path=template.instructions.map((r,i)=>({ea:r.ea,...(effects.find(e=>e.instructionIndex===i)?
      {opaqueEffect:effects.find(e=>e.instructionIndex===i)}:{})}));
    validateOpaqueProjection({projectionMode:plan.template_mode,opaqueEffects:effects,nondeterministicInputs:selected,
      path,decodedPath:template.instructions.map(r=>decoded.get(r.ea)),dag:result.dag,
      ...(status?{flagPolicies:template.flagPolicies}:{}),
      stores:result.stores.filter(s=>s.stepIndex===step),statistics:template.statistics,memoryNormalization:result.memoryNormalization},
      {namePrefix:`step_${step}_`,nodeRange:[layer.nodeStart,layer.nodeEnd],...(status?{statusStep:step}:{})});
    abstracted+=template.opaqueEffects.length;
    raw+=template.opaqueEffects.reduce((n,e)=>n+e.rawOperationCount,0);
    replacements+=template.opaqueEffects.reduce((n,e)=>n+e.replacementOperationCount,0);
  });
  need(seen.size===inputs.length&&nodes.every(n=>n.op!=='nondeterministic'||seen.has(n.id)),
    'undeclared/shared/out-of-range unknown');
  const s=result.statistics;
  need(s.expandedAbstractedInstructions===abstracted&&s.expandedAbstractedRawOperations===raw&&
    s.expandedReplacementOperations===replacements&&s.liveNondeterministicInputs===inputs.length,
    'expanded raw approximation accounting mismatch');
}
