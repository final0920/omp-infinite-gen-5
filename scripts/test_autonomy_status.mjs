import assert from 'node:assert/strict';
import { autonomyStatus } from '../source/autonomy_status.js';
const calls = [];
const agent = { id: 'live-owner', ctx: { tools: { get(name, subject) { assert.equal(subject,agent); return name === 'get_goal' || name === 'create_goal' ? { name } : undefined; } } } };
const goals = { get(subject) { assert.equal(subject, agent); calls.push(subject); return { id:'goal-a', revision:2, objective:'Recover the owned function', phase:'active', activation:'armed', roundsStarted:1, maxGoalRounds:3, unrelatedSecret:'excluded' }; }, create() { assert.fail('Inspection must not create work'); } };
agent.ctx.get = name => name === 'goals' ? goals : undefined;
const current = autonomyStatus({}, { agent });
assert.deepEqual(current.goalTools,['get_goal','create_goal']);assert.equal(current.goalServiceAvailable,true);assert.equal(current.continuationEligible,true);
assert.equal(current.queryStartsWork,false);assert.equal(current.driverVerifiedByThisQuery,false);assert(!('unrelatedSecret' in current.goal));assert.equal(calls.length,1);
for (const [phase,activation,roundsStarted] of [['paused','disarmed',1],['blocked','armed',1],['active','disarmed',1],['active','armed',3]]) {
  agent.ctx.get = () => ({get(subject){assert.equal(subject,agent);return {phase,activation,roundsStarted,maxGoalRounds:3}}});
  assert.equal(autonomyStatus({}, {agent}).continuationEligible,false);
}
assert.equal(autonomyStatus({}, {agent:{id:'live-owner'}}).scopeAvailable,false);
agent.ctx.get = () => ({get(){throw Object.assign(new Error('private detail'),{code:'STALE_AGENT'})}});
const rejected=autonomyStatus({}, {agent});assert.equal(rejected.inspectionError,'STALE_AGENT');assert.equal(rejected.goal,null);assert(!JSON.stringify(rejected).includes('private detail'));
agent.ctx.get = () => undefined;
assert.equal(autonomyStatus({}, {agent}).goalServiceAvailable,false);
assert.equal(autonomyStatus({get:()=>({get(subject){assert.equal(subject,agent);return undefined}})}, {agent}).goalServiceAvailable,true);
console.log('PASS caller-owned goal inspection, cancellation/phase/round eligibility, no driving, missing services and stale agent refusal');
