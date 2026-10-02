// SPDX-License-Identifier: AGPL-3.0-or-later
// Pure keyless evidence/retention checks. History and proof bytes below are
// explicitly modeled parser fixtures, not verified approval or durable state.
import assert from 'node:assert/strict'
import {createHash} from 'node:crypto'
import {canonicalJson} from '../contracts/src/runtime.mjs'
import {operationDigest} from './src/operation.mjs'
import {inferenceRequestDigest} from './src/inference-admission.mjs'
import {inferenceEffectReceipt,inferenceEffectReceiptDigest,validateInferenceReceiptBinding} from './src/inference-effect.mjs'
import {memoryEffectReceipt,memoryEffectReceiptDigest,memoryResultDigest} from './src/memory-effect.mjs'
import {validatedReceipt,executionReceiptDigest} from './src/execution.mjs'
import {compactTerminalRow,compactRetainedRows,consumedGrantDigest,isTerminalRecord,ownerKey,validateTerminalRecord} from './src/retention.mjs'

let checks=0
const groups=[]
const same=(actual,expected,reason)=>{checks++;assert.deepEqual(actual,expected,reason)}
const check=(value,reason)=>{checks++;assert.ok(value,reason)}
const refuses=(fn,reason)=>{checks++;assert.throws(fn,/INVALID/,reason)}
const clone=value=>JSON.parse(canonicalJson(value))
const sha=bytes=>createHash('sha256').update(bytes).digest('hex')
const digest=(domain,value)=>'sha256:'+sha(domain+'\0'+canonicalJson(value))
const subject='aukora:1:'+'11'.repeat(32)
const nonce='22'.repeat(32),effectId='33'.repeat(32)
const observedAt='2030-01-01T00:00:01.000Z'
const requestId='10000000-0000-4000-8000-000000000001'
const usd=micros=>({currency:'USD',amount:`${BigInt(micros)/1000000n}.${String(BigInt(micros)%1000000n).padStart(6,'0')}`})

function fixture(options={}) {
  const reserved_tokens=options.reserved_tokens??4352,reserved_cost_microusd=options.reserved_cost_microusd??10000
  const rates=options.rates??{input_microusd_per_token:2,output_microusd_per_token:3}
  const binding={owner_id:'synthetic-owner',task_id:'synthetic-task',conversation_id:'synthetic-conversation',
    request_uuid:requestId,body_sha256:'44'.repeat(32),binding_hash:'55'.repeat(32),
    citations_sha256:'66'.repeat(32),config_digest:'sha256:'+'77'.repeat(32),
    reserved_tokens,reserved_cost_microusd,credential_generation:1,total_budget_id:'synthetic-budget'}
  const request_digest=inferenceRequestDigest(binding)
  const operation={version:1,operation_id:options.operation_id??'synthetic-inference-operation',task_id:binding.task_id,
    owner_id:binding.owner_id,agent_id:'synthetic-agent',audience:'aukora-prime.inference',action_type:'inference.generate',
    target_identity:{version:1,kind:'prime-inference-route/v1',owner_subject:subject,route_id:'externalDeepSeek',
      provider:'deepseek',endpoint:'https://api.deepseek.com',model:'synthetic-model',region:'synthetic-region',
      config_digest:binding.config_digest,credential_generation:1,total_budget_id:binding.total_budget_id},
    canonical_parameters:{version:1,kind:'prime-inference-request/v1',binding,request_digest,
      limits:{max_requests:1,max_input_tokens:options.max_input_tokens??4096,max_output_tokens:options.max_output_tokens??256,
        max_total_tokens:options.max_total_tokens??4352,max_request_ms:15000,task_spend_ceiling:usd(reserved_cost_microusd)},
      total_budget:{budget_id:binding.total_budget_id,ceiling:usd(reserved_cost_microusd),policy_digest:'sha256:'+'88'.repeat(32)}},
    data_scope:['conversation'],expected_state_version:'sha256:'+'99'.repeat(32),
    provider_and_region:{provider:'deepseek',region:'synthetic-region'},maximum_cost:usd(reserved_cost_microusd),
    expiry:'2030-01-01T00:02:00.000Z',nonce:'synthetic-proposal-nonce',policy_version:'synthetic-policy',authorization_epoch:1}
  const operation_digest=operationDigest(operation)
  const grant={version:1,grant_id:'grant:'+nonce,operation_id:operation.operation_id,operation_digest,
    owner_id:binding.owner_id,audience:operation.audience,authorization_epoch:operation.authorization_epoch,
    prepared_at:'2030-01-01T00:00:00.000Z',reservation_id:'prepared:'+effectId}
  // This structurally valid placeholder is never signed or signature-verified.
  // There is no key, owner credential, session, service or authorization fixture.
  const proof={version:1,operation_id:operation.operation_id,operation_digest,owner_id:operation.owner_id,
    audience:operation.audience,authorization_epoch:1,expiry:operation.expiry,nonce,
    material:{kind:'owner_key',request:{domain:'aukora:owner-approval-request:v1',subject,
      activeControlDigest:'aa'.repeat(32),operationDigest:operation_digest.slice(7),challenge:nonce,
      issuedAt:1893456000,expiresAt:1893456120},signature:'00'.repeat(64)}}
  const receipt={version:1,kind:'prime-inference-effect/v1',operation_id:operation.operation_id,operation_digest,
    grant_id:grant.grant_id,request_id:requestId,request_digest,owner_subject:subject,task_id:binding.task_id,
    conversation_id:binding.conversation_id,route_id:'externalDeepSeek',config_digest:binding.config_digest,
    credential_generation:1,total_budget_id:binding.total_budget_id,body_sha256:binding.body_sha256,
    outcome:'completed',result_digest:digest('aukora-prime.inference-result.v1',
      {text:'Synthetic proposal only.',source_ids:[],input_tokens:100,output_tokens:10}),
    usage:{input_tokens:100,output_tokens:10,cost_microusd:230},reservation_retained:false,observed_at:observedAt}
  const context={operation,consumed_grant:grant,request_id:requestId,request_digest,owner_subject:subject,rates}
  const receipt_digest=inferenceEffectReceiptDigest(receipt)
  const row={operation,operation_digest,status:'COMPLETED',review:null,approval:{proof},grant,
    inference_context:{rates},dispatch:{request_id:requestId,request_digest,cancel_requested:false,cancel_reason:null,
      receipt,receipt_digest,settlement_digests:[receipt_digest]}}
  const record={state:{consumedIds:['approval:'+nonce],receiptHead:{count:1}},
    prepared:[{consumptionId:'approval:'+nonce,effectId,contentHash:operation_digest.slice(7),receiptCountAfter:1}]}
  const owners={[ownerKey(operation.owner_id)]:{subject}}
  const key=sha(canonicalJson([operation.owner_id,operation.operation_id]))
  return {operation,grant,proof,receipt,context,row,record,owners,key,binding,rates}
}
function unknown(receipt) {
  return {...clone(receipt),outcome:'outcome_unknown',result_digest:null,usage:null,reservation_retained:true}
}
function withUsage(f,input_tokens,output_tokens,cost_microusd) {
  return {...clone(f.receipt),usage:{input_tokens,output_tokens,cost_microusd}}
}
function group(name,fn) {fn();groups.push(name)}

try {
  group('detached exact twenty-field completed and unknown receipts',()=>{
    const f=fixture(),input=clone(f.receipt),parsed=inferenceEffectReceipt(input)
    same(Object.keys(parsed).length,20,'receipt has exactly the agreed twenty fields')
    check(parsed!==input&&parsed.usage!==input.usage,'receipt and usage are detached')
    check(Object.isFrozen(parsed)&&Object.isFrozen(parsed.usage),'detached receipt is immutable')
    input.body_sha256='bb'.repeat(32);input.usage.input_tokens=101
    same(parsed.body_sha256,f.receipt.body_sha256,'caller changes cannot change recognized evidence')
    same(parsed.usage.input_tokens,100,'nested caller changes cannot change recognized evidence')
    same(validateInferenceReceiptBinding(parsed,f.context),parsed,'matching context recognizes completed evidence')
    const uncertain=unknown(f.receipt)
    same(validateInferenceReceiptBinding(uncertain,f.context),uncertain,'unknown evidence keeps held-reservation facts')
    same(uncertain.reservation_retained,true,'unknown retains reservation')
  })
  group('closed fields and discriminated null/outcome semantics',()=>{
    const f=fixture()
    for(const field of Object.keys(f.receipt)) {
      const bad=clone(f.receipt);delete bad[field]
      refuses(()=>inferenceEffectReceipt(bad),'missing '+field+' is refused')
    }
    refuses(()=>inferenceEffectReceipt({...f.receipt,extra:true}),'extra receipt field')
    for(const patch of [{version:2},{kind:'prime-memory-effect/v1'},{outcome:'cancelled'},
      {result_digest:null},{usage:null},{reservation_retained:true}])
      refuses(()=>inferenceEffectReceipt({...f.receipt,...patch}),'completed semantics '+canonicalJson(patch))
    const uncertain=unknown(f.receipt)
    for(const patch of [{result_digest:f.receipt.result_digest},{usage:f.receipt.usage},{reservation_retained:false}])
      refuses(()=>inferenceEffectReceipt({...uncertain,...patch}),'unknown semantics '+canonicalJson(patch))
    for(const usage of [{input_tokens:100,output_tokens:10},
      {...f.receipt.usage,extra:0},{...f.receipt.usage,input_tokens:-1},
      {...f.receipt.usage,input_tokens:-0},{...f.receipt.usage,output_tokens:0.5},
      {...f.receipt.usage,cost_microusd:Number.MAX_SAFE_INTEGER+1}])
      refuses(()=>inferenceEffectReceipt({...f.receipt,usage}),'closed safe-integer usage')
    const accessor=clone(f.receipt);delete accessor.usage;let reads=0
    Object.defineProperty(accessor,'usage',{enumerable:true,get(){reads++;return f.receipt.usage}})
    refuses(()=>inferenceEffectReceipt(accessor),'accessor refused before interpretation')
    same(reads,0,'recognition never invokes an accessor')
    const symbolic=clone(f.receipt);symbolic[Symbol('extra')]=true
    refuses(()=>inferenceEffectReceipt(symbolic),'symbol fields refused')
  })
  group('canonical UTC timestamp and exact receipt digest domain',()=>{
    const f=fixture()
    for(const value of ['2030-01-01T00:00:01Z','2030-01-01T00:00:01.000+00:00',
      '2030-01-01T00:00:01.000z','2030-02-30T00:00:01.000Z','2030-01-01T24:00:00.000Z',
      ' 2030-01-01T00:00:01.000Z',null])
      refuses(()=>inferenceEffectReceipt({...f.receipt,observed_at:value}),'noncanonical/impossible timestamp')
    const expected='sha256:'+sha('aukora-prime.inference-receipt.v1\0'+canonicalJson(f.receipt))
    same(inferenceEffectReceiptDigest(f.receipt),expected,'independent accepted receipt-domain preimage')
    const reordered=Object.fromEntries(Object.entries(f.receipt).reverse())
    same(inferenceEffectReceiptDigest(reordered),expected,'canonical field order gives identical digest')
    check(expected!==digest('aukora-prime.execution-receipt.v1',f.receipt),'execution domain cannot alias inference evidence')
    check(expected!==digest('aukora-prime.memory-receipt.v1',f.receipt),'memory domain cannot alias inference evidence')
    check(inferenceEffectReceiptDigest({...f.receipt,observed_at:'2030-01-01T00:00:02.000Z'})!==expected,
      'changed durable timestamp is changed evidence')
  })
  group('all operation/grant/request/owner/configuration/body bindings',()=>{
    const f=fixture()
    const patches={operation_id:'other-operation',operation_digest:'sha256:'+'bb'.repeat(32),grant_id:'grant:'+'cc'.repeat(32),
      request_id:'20000000-0000-4000-8000-000000000002',request_digest:'sha256:'+'dd'.repeat(32),
      owner_subject:'aukora:1:'+'ee'.repeat(32),task_id:'other-task',conversation_id:'other-conversation',
      config_digest:'sha256:'+'ff'.repeat(32),credential_generation:2,total_budget_id:'other-budget',body_sha256:'ab'.repeat(32)}
    for(const [field,value] of Object.entries(patches))
      refuses(()=>validateInferenceReceiptBinding({...f.receipt,[field]:value},f.context),'receipt mismatch '+field)
    refuses(()=>validateInferenceReceiptBinding({...f.receipt,route_id:'other-route'},f.context),'wrong route')
    for(const patch of [{request_id:'20000000-0000-4000-8000-000000000002'},
      {request_digest:'sha256:'+'cc'.repeat(32)},{owner_subject:'aukora:1:'+'dd'.repeat(32)}])
      refuses(()=>validateInferenceReceiptBinding(f.receipt,{...f.context,...patch}),'trusted tuple mismatch')
    for(const [field,value] of Object.entries({operation_id:'other-operation',operation_digest:'sha256:'+'cc'.repeat(32),
      owner_id:'other-owner',audience:'aukora-prime.memory',authorization_epoch:2,grant_id:'grant:'+'dd'.repeat(32)}))
      refuses(()=>validateInferenceReceiptBinding(f.receipt,{...f.context,consumed_grant:{...f.grant,[field]:value}}),
        'grant mismatch '+field)
    refuses(()=>validateInferenceReceiptBinding(f.receipt,{...f.context,operation:{...f.operation,operation_id:'other-operation'}}),
      'changed operation cannot retain original grant')
  })
  group('original rates and bounded actual usage/cost',()=>{
    const f=fixture()
    refuses(()=>validateInferenceReceiptBinding(withUsage(f,100,10,231),f.context),'cost must equal original rate arithmetic')
    refuses(()=>validateInferenceReceiptBinding(f.receipt,{...f.context,rates:{input_microusd_per_token:3,output_microusd_per_token:4}}),
      'replacement rates cannot reinterpret original evidence')
    for(const rates of [{input_microusd_per_token:2},{input_microusd_per_token:2,output_microusd_per_token:3,extra:1},
      {input_microusd_per_token:0,output_microusd_per_token:3},{input_microusd_per_token:2,output_microusd_per_token:1.5}])
      refuses(()=>validateInferenceReceiptBinding(f.receipt,{...f.context,rates}),'closed positive original rates')
    refuses(()=>validateInferenceReceiptBinding(withUsage(f,4097,0,8194),f.context),'input cap')
    refuses(()=>validateInferenceReceiptBinding(withUsage(f,0,257,771),f.context),'output cap')
    const aggregate=fixture({reserved_tokens:200,max_total_tokens:200})
    refuses(()=>validateInferenceReceiptBinding(withUsage(aggregate,150,60,480),aggregate.context),'aggregate token cap')
    const reservation=fixture({reserved_tokens:150})
    refuses(()=>validateInferenceReceiptBinding(withUsage(reservation,100,60,380),reservation.context),'original token reservation')
    refuses(()=>validateInferenceReceiptBinding(withUsage(f,100,10,23000),
      {...f.context,rates:{input_microusd_per_token:200,output_microusd_per_token:300}}),'original cost reservation')
  })
  group('exact BigInt arithmetic at safe-integer boundaries',()=>{
    const maximum=Number.MAX_SAFE_INTEGER
    const f=fixture({reserved_tokens:maximum,reserved_cost_microusd:maximum,
      max_input_tokens:maximum,max_output_tokens:1,max_total_tokens:maximum,
      rates:{input_microusd_per_token:1,output_microusd_per_token:1}})
    const exact=withUsage(f,maximum-1,1,maximum)
    same(validateInferenceReceiptBinding(exact,f.context).usage,exact.usage,'safe integer boundary remains exact')
    refuses(()=>validateInferenceReceiptBinding(withUsage(f,maximum,1,maximum),f.context),
      'sum above safe reservation is rejected without rounded arithmetic')
    const largeRate=fixture({reserved_cost_microusd:maximum,
      rates:{input_microusd_per_token:maximum,output_microusd_per_token:1}})
    same(validateInferenceReceiptBinding(withUsage(largeRate,1,0,maximum),largeRate.context).usage.cost_microusd,
      maximum,'exact original rate product at maximum')
    refuses(()=>validateInferenceReceiptBinding(withUsage(largeRate,2,0,maximum),largeRate.context),
      'product exceeding the declared safe charge cannot round into acceptance')
  })
  group('completed compaction preserves modeled original kernel obligations',()=>{
    const f=fixture(),history=canonicalJson(f.record),rowBytes=canonicalJson(f.row)
    const compact=compactTerminalRow(f.key,f.row,f.record,f.owners)
    check(isTerminalRecord(compact),'completed inference becomes a bounded terminal record')
    same(compact.dispatch.evidence_kind,'inference','genuine model evidence kind')
    same(compact.dispatch.result_digest,f.receipt.result_digest,'result digest is retained')
    same(compact.grant_digest,consumedGrantDigest(f.grant),'grant binding is retained')
    same(compact.dispatch.request_id,f.context.request_id,'request UUID is retained')
    same(compact.dispatch.request_digest,f.context.request_digest,'request digest is retained')
    same(compact.dispatch.receipt_digest,f.row.dispatch.receipt_digest,'receipt digest is retained')
    same(compact.dispatch.settlement_digests,f.row.dispatch.settlement_digests,'evidence membership is retained')
    for(const field of ['operation','grant','approval','inference_context','receipt'])
      check(!Object.hasOwn(compact,field),'terminal row drops full '+field)
    same(canonicalJson(f.record),history,'compaction changes no modeled kernel consumption/preparation/history')
    same(canonicalJson(f.row),rowBytes,'pure compaction changes no input row')
    same(validateTerminalRecord(compact),compact,'terminal record validates')
    same(compactTerminalRow(f.key,compact,f.record,f.owners),compact,'terminal recognition is idempotent')
    const broker={owners:f.owners,operations:{[f.key]:f.row}}
    const replaced=compactRetainedRows(broker,f.record)
    same(replaced.operations[f.key],compact,'broker compactor uses genuine inference branch')
    same(canonicalJson(f.record),history,'broker compaction preserves modeled original kernel obligations')
  })
  group('unknown/prepared/dispatched rows stay full and retain obligations',()=>{
    const f=fixture(),history=canonicalJson(f.record)
    for(const status of ['OUTCOME_UNKNOWN','PREPARED','DISPATCHED']) {
      const row=clone(f.row);row.status=status
      if(status==='OUTCOME_UNKNOWN') {
        row.dispatch.receipt=unknown(f.receipt)
        row.dispatch.receipt_digest=inferenceEffectReceiptDigest(row.dispatch.receipt)
        row.dispatch.settlement_digests=[row.dispatch.receipt_digest]
      }
      const before=canonicalJson(row),compacted=compactTerminalRow(f.key,row,f.record,f.owners)
      same(compacted,row,'nonterminal row stays the same object')
      same(canonicalJson(compacted),before,'nonterminal full bytes retained')
      check(!isTerminalRecord(compacted)&&compacted.operation&&compacted.approval&&compacted.grant&&compacted.inference_context,
        'nonterminal operation/proof/grant/original rates retained')
    }
    same(canonicalJson(f.record),history,'unknown retention cannot release modeled consumption or preparation')
  })
  group('missing modeled kernel history and original context refuse compaction',()=>{
    const f=fixture()
    for(const change of [record=>{record.state.consumedIds=[]},record=>{record.prepared=[]},
      record=>{record.prepared[0].contentHash='bb'.repeat(32)},
      record=>{record.prepared[0].effectId='cc'.repeat(32)},
      record=>{record.prepared[0].consumptionId='approval:'+'dd'.repeat(32)},
      record=>{record.state.receiptHead.count=0}]) {
      const record=clone(f.record);change(record)
      refuses(()=>compactTerminalRow(f.key,f.row,record,f.owners),'required original modeled preparation/consumption')
    }
    const withoutRates=clone(f.row);delete withoutRates.inference_context
    refuses(()=>compactTerminalRow(f.key,withoutRates,f.record,f.owners),'missing original rate context')
    refuses(()=>compactTerminalRow(f.key,f.row,f.record,{}),'missing authoritative owner-subject mapping')
    refuses(()=>compactTerminalRow('ee'.repeat(32),f.row,f.record,f.owners),'operation key cannot change')
  })
  group('receipt/history conflicts and cross-kind evidence refuse compaction',()=>{
    const f=fixture()
    const wrongDigest=clone(f.row);wrongDigest.dispatch.receipt_digest='sha256:'+'bb'.repeat(32)
    refuses(()=>compactTerminalRow(f.key,wrongDigest,f.record,f.owners),'wrong inference receipt digest')
    for(const list of [[],['sha256:'+'bb'.repeat(32)],[f.row.dispatch.receipt_digest,f.row.dispatch.receipt_digest]]) {
      const row=clone(f.row);row.dispatch.settlement_digests=list
      refuses(()=>compactTerminalRow(f.key,row,f.record,f.owners),'missing/duplicate evidence membership')
    }
    const uncertain=clone(f.row);uncertain.dispatch.receipt=unknown(f.receipt)
    uncertain.dispatch.receipt_digest=inferenceEffectReceiptDigest(uncertain.dispatch.receipt)
    uncertain.dispatch.settlement_digests=[uncertain.dispatch.receipt_digest]
    refuses(()=>compactTerminalRow(f.key,uncertain,f.record,f.owners),'unknown evidence cannot be labeled completed')
    const memory=memoryEffectReceipt({version:1,kind:'prime-memory-effect/v1',operation_id:f.operation.operation_id,
      operation_digest:f.row.operation_digest,grant_id:f.grant.grant_id,request_id:requestId,
      request_digest:f.context.request_digest,owner_subject:subject,action_type:'memory.save',status:'applied',
      result:{record_id:'synthetic-memory-record'},result_digest:memoryResultDigest({record_id:'synthetic-memory-record'})})
    const execution=validatedReceipt({version:1,receipt_id:'30000000-0000-4000-8000-000000000003',
      operation_id:f.operation.operation_id,task_id:f.operation.task_id,owner_id:f.operation.owner_id,
      operation_digest:f.row.operation_digest,grant_id:f.grant.grant_id,request_id:requestId,status:'completed',
      stdout:'synthetic output',stderr:'',exit_code:0,rpc_completion:'complete',output_truncated:false,
      sandbox:null,cleanup:'confirmed_absent',started_at:'2030-01-01T00:00:00.000Z',finished_at:observedAt,
      error_code:null,reconciliation_required:false})
    for(const [receipt,receipt_digest] of [[memory,memoryEffectReceiptDigest(memory)],[execution,executionReceiptDigest(execution)]]) {
      const row=clone(f.row);row.dispatch={...row.dispatch,receipt,receipt_digest,settlement_digests:[receipt_digest]}
      refuses(()=>compactTerminalRow(f.key,row,f.record,f.owners),'structurally recognized other evidence kind cannot settle inference')
    }
    const compact=compactTerminalRow(f.key,f.row,f.record,f.owners)
    refuses(()=>validateTerminalRecord({...compact,status:'FAILED'}),'inference terminal evidence is completed only')
  })
  console.log(JSON.stringify({status:'PASS',cases:groups.length,checks,groups,
    command:'node packages/authority/check-inference-evidence.mjs',
    limits:'Pure genuine source validators and compactor with public synthetic metadata and modeled consumed/prepared kernel history. Placeholder proof bytes are not signed or verified; no keys, credentials, owner session, authentic lifecycle, raw-provider provenance, persistent store, service, network or deployed qualification. No unchanged suites or mutants ran.'},null,2))
} catch(error) {
  console.error(JSON.stringify({status:'FAIL',cases_completed:groups.length,checks,error:String(error.message),stack:error.stack,
    limits:'Pure synthetic/modelled-history fixture only; no signing, credentials, provider, network, services or runtime qualification.'},null,2))
  process.exitCode=1
}
