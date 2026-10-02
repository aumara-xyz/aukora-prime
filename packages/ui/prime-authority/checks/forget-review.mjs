import assert from 'node:assert/strict'
import {validateForgetReview,FORGET_STATEMENT_MAX_BYTES,FORGET_REFERENCE_MAX_BYTES} from '../../adapters/forget-review.mjs'

const summary = {record_id:'rem:' + '1'.repeat(64),revision:'7',statement:'  Original <tag>&\r\n\t🍌 e\u0301 \u200f  ',attributed_to:null}
const proposal = () => ({version:1,operation_id:'00000000-0000-4000-8000-000000000001',task_id:'synthetic-task',
  owner_id:'synthetic-owner',agent_id:'synthetic-agent',audience:'aukora-prime.memory',action_type:'memory.forget',
  target_identity:{kind:'prime-memory',owner_subject:'aukora:1:' + '2'.repeat(64)},
  canonical_parameters:{profile:'prime-logical-forget/v1',...summary,canonical_sha256:'3'.repeat(64),
    at:'2026-10-01T11:03:00Z',heads:{remembered:'4'.repeat(64),approved:'aukora:aura-record:v1'}},
  data_scope:['synthetic'],expected_state_version:'sha256:' + '5'.repeat(64),
  provider_and_region:{provider:'local',region:'local'},maximum_cost:{currency:'USD',amount:'0'},
  expiry:'2026-10-01T11:05:00Z',nonce:'6'.repeat(64),policy_version:'synthetic-v1',authorization_epoch:1})
let assertions = 0
const equal = (actual,expected) => {assert.deepEqual(actual,expected);assertions++}
const refuses = (operation,...retained) => {assert.throws(() => validateForgetReview(operation,retained.length ? retained[0] : summary),
  error => error instanceof TypeError && error.message === 'ui:forget-review-invalid');assertions++}

{
  const operation = proposal(),before = JSON.stringify(operation),retained = {...summary}
  const result = validateForgetReview(operation,retained)
  equal(result,summary);equal(Object.isFrozen(result),true);equal(result === retained,false)
  equal(JSON.stringify(operation),before)
  retained.statement = 'Changed caller summary';operation.canonical_parameters.statement = 'Changed caller operation'
  equal(result.statement,summary.statement)
  equal(Object.isFrozen(operation),false);equal(Object.isFrozen(retained),false)
}
for (const field of ['record_id','revision','statement','attributed_to']) {
  const operation = proposal();operation.canonical_parameters[field] = 'Changed ' + field;refuses(operation)
  refuses(proposal(),{...summary,[field]:'Changed independently retained ' + field})
  const missing = {...summary};delete missing[field];refuses(proposal(),missing)
}
refuses(proposal(),undefined);refuses(proposal(),null);refuses(proposal(),{...summary,extra:true})
for (const value of ['other-profile','prime-active-record-payloads/v1',null]) {const operation = proposal();operation.canonical_parameters.profile = value;refuses(operation)}
for (const value of ['A'.repeat(64),'a'.repeat(63),'sha256:' + 'a'.repeat(64),64,null]) {
  const operation = proposal();operation.canonical_parameters.canonical_sha256 = value;refuses(operation)
}
{
  const extra = proposal();extra.canonical_parameters.collateral_scope = {discard:true};refuses(extra)
  const missing = proposal();delete missing.canonical_parameters.statement;refuses(missing)
  for (const field of ['action_type','audience','expected_state_version']) {const operation = proposal();operation[field] = 'Changed';refuses(operation)}
  const extraTarget = proposal();extraTarget.target_identity.other = true;refuses(extraTarget)
  const wrongOwner = proposal();wrongOwner.target_identity.owner_subject = 'aukora:1:' + 'A'.repeat(64);refuses(wrongOwner)
  const version = proposal();version.version = 2;refuses(version)
  const envelope = proposal();envelope.extra = true;refuses(envelope)
}
for (const heads of [{other:'a'.repeat(64)},{remembered:'A'.repeat(64)},{approved:0},{remembered:'sha256:' + 'a'.repeat(64)},null,[]]) {
  const operation = proposal();operation.canonical_parameters.heads = heads;refuses(operation)
}
for (const at of ['2026-10-01T11:03:00.000Z','2026-10-01T11:03:00+00:00','2026-02-30T11:03:00Z','2026-10-01T24:00:00Z','2026-10-01T11:03:60Z']) {
  const operation = proposal();operation.canonical_parameters.at = at;refuses(operation)
}
for (const field of ['record_id','revision','statement','attributed_to']) {
  for (const value of ['',17,{},'\ud800','\udc00']) {
    const operation = proposal(),retained = {...summary,[field]:value};operation.canonical_parameters[field] = value;refuses(operation,retained)
  }
}
{
  const operation = proposal(),retained = {...summary,statement:'🙂'.repeat(FORGET_STATEMENT_MAX_BYTES / 4)}
  operation.canonical_parameters.statement = retained.statement;equal(validateForgetReview(operation,retained),retained)
  operation.canonical_parameters.statement += 'x';refuses(operation,{...retained,statement:retained.statement + 'x'})
  const legacy = {...summary,statement:'Legacy\u0000\r\n\t\u202e ' + 'x'.repeat(5000),attributed_to:'historical donor author'}
  const older = proposal();Object.assign(older.canonical_parameters,legacy);equal(validateForgetReview(older,legacy),legacy)
  for (const field of ['record_id','revision','attributed_to']) {
    const retained = {...summary,[field]:'é'.repeat(FORGET_REFERENCE_MAX_BYTES / 2)},operation = proposal()
    operation.canonical_parameters[field] = retained[field];equal(validateForgetReview(operation,retained),retained)
    operation.canonical_parameters[field] += 'x';refuses(operation,{...retained,[field]:retained[field] + 'x'})
  }
}
{
  // No hidden value access/coercion may execute, even in unused envelope fields.
  let reads = 0
  const accessor = (object,field) => {Object.defineProperty(object,field,{enumerable:true,get(){reads++;return 'Getter'}});return object}
  refuses(accessor(proposal(),'action_type'))
  refuses(proposal(),accessor({...summary},'statement'))
  const params = proposal();accessor(params.canonical_parameters,'canonical_sha256');refuses(params)
  const heads = proposal();accessor(heads.canonical_parameters.heads,'remembered');refuses(heads)
  const unused = proposal();accessor(unused.maximum_cost,'amount');refuses(unused)
  const symbol = proposal();symbol.canonical_parameters[Symbol('hidden')] = 'extra';refuses(symbol)
  const symbolSummary = {...summary};symbolSummary[Symbol('hidden')] = 'extra';refuses(proposal(),symbolSummary)
  const hidden = {...summary};Object.defineProperty(hidden,'statement',{value:summary.statement,enumerable:false});refuses(proposal(),hidden)
  const inherited = Object.assign(Object.create({other:true}),summary);refuses(proposal(),inherited)
  const coercible = proposal();coercible.canonical_parameters.canonical_sha256 = {toString(){reads++;return 'a'.repeat(64)}};refuses(coercible)
  const cycle = proposal();cycle.maximum_cost.self = cycle;refuses(cycle)
  const arrayGetter = proposal();Object.defineProperty(arrayGetter.data_scope,'0',{enumerable:true,get(){reads++;return 'synthetic'}});refuses(arrayGetter)
  const sparse = proposal();sparse.data_scope = Array(1);refuses(sparse)
  equal(reads,0)
}
{
  const operation = proposal(),retained = Object.assign(Object.create(null),summary)
  operation.canonical_parameters = Object.assign(Object.create(null),operation.canonical_parameters)
  operation.canonical_parameters.heads = Object.assign(Object.create(null),operation.canonical_parameters.heads)
  equal(validateForgetReview(operation,retained),summary)
  // Changed private hash/head values remain syntactically valid: this helper
  // cannot audit them. The unchanged full signed operation and D do bind them.
  operation.canonical_parameters.canonical_sha256 = 'a'.repeat(64)
  operation.canonical_parameters.heads = {remembered:'b'.repeat(64)}
  equal(validateForgetReview(operation,retained),summary)
}
console.log(JSON.stringify({result:'PASS',assertions,browser_safe:true,private_original_hash_audited:false,
  private_heads_audited:false,real_record_reads:false,effects:false}))
