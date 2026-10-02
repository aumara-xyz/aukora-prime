// SPDX-License-Identifier: AGPL-3.0-or-later
// Local H composition only. No public/IPC method, independent effect ledger,
// negative retirement, original13 restore row or host qualification is added.
import {randomUUID,randomBytes} from 'node:crypto'
import {types} from 'node:util'
import {canonicalJson,parseStrictJson,validateContract,operationDigest} from '../../contracts/src/runtime.mjs'
import {validateRetainedRestoreOperation,validateRetainedRestoreResult,retainedRestoreRequestDigest} from '../../authority/src/retained-restore.mjs'
import {detachPrivateData} from '../../memory/src/private-v2-control.mjs'
import {isPrivateV2Participant} from '../../memory/src/private-v2-participant.mjs'
import {memoryResultDigest,memoryReceiptDigest} from '../../memory/src/authorization.mjs'
import {closed,copy} from './registry.mjs'
import {validateClosureHost,validateClosureProfile} from './closure-v2.mjs'
import {retainedUnknown} from './retained-pending.mjs'

const same=(a,b)=>canonicalJson(a)===canonicalJson(b)
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/
const DIGEST=/^sha256:[a-f0-9]{64}$/
const refuse=(code,reason)=>{throw Object.assign(new Error(reason),{error_code:code})}
const fail=reason=>refuse('OUTCOME_UNKNOWN',reason)
const own=(value,key)=>{
  if(!value||typeof value!=='object'||types.isProxy(value))return undefined
  const d=Object.getOwnPropertyDescriptor(value,key)
  return d&&Object.hasOwn(d,'value')?d.value:undefined
}
const capture=(source,names)=>Object.freeze(Object.fromEntries(names.map(name=>{
  const fn=own(source,name)
  return [name,typeof fn==='function'?fn.bind(source):null]
})))

/** Typed response check only. D and C still establish actual storage/settlement. */
export function validateRestoreEffect(input,operation,inputHost) {
  const value=copy(input),host=validateClosureHost(inputHost)
  validateRetainedRestoreOperation(operation)
  if(operation.owner_id!==host.owner_id||operation.task_id!==host.task_id
    ||operation.authorization_epoch!==host.authorization_epoch
    ||operation.target_identity.owner_subject!==host.owner_subject)fail('RETAINED_RESTORE_OWNER_CHANGED')
  const completed=value.authority_settlement==='completed'
  closed(value,completed?['result','receipt','authority_settlement','receipt_digest','reconciliation_required']
    :['result','receipt','authority_settlement','reconciliation_required','settlement_reason'])
  if(value.authority_settlement!==(completed?'completed':'pending')||value.reconciliation_required!==!completed)
    fail('RETAINED_RESTORE_SETTLEMENT_CHANGED')
  const result=validateRetainedRestoreResult(value.result,operation),receipt=value.receipt
  closed(receipt,['version','kind','operation_id','operation_digest','grant_id','request_id','request_digest',
    'owner_subject','action_type','status','result_digest','result'])
  if(receipt.version!==1||receipt.kind!=='prime-memory-effect/v1'||receipt.operation_id!==operation.operation_id
    ||receipt.operation_digest!==operationDigest(operation)||receipt.owner_subject!==host.owner_subject
    ||receipt.action_type!=='memory.restore'||receipt.status!=='applied'||typeof receipt.grant_id!=='string'
    ||!receipt.grant_id.length||Buffer.byteLength(receipt.grant_id)>1024||typeof receipt.request_id!=='string'
    ||!UUID.test(receipt.request_id)||receipt.request_digest!==retainedRestoreRequestDigest(operation)
    ||receipt.result_digest!==memoryResultDigest(result)||!same(receipt.result,result))fail('RETAINED_RESTORE_RECEIPT_CHANGED')
  if(completed&&value.receipt_digest!==memoryReceiptDigest(receipt))fail('RETAINED_RESTORE_RECEIPT_CHANGED')
  if(!completed&&(typeof value.settlement_reason!=='string'||!value.settlement_reason.length
    ||Buffer.byteLength(value.settlement_reason)>1024))fail('RETAINED_RESTORE_SETTLEMENT_CHANGED')
  return value
}

/** Only createRuntimeBridge supplies sourceContext, reusing its actual C session
 * authentication and trusted registry/host derivation. Channel role is a local
 * H context, never authority inferred from a caller's restore bundle. */
export function createRetainedRestoreForwarder({authority,memory,profile,taskRegistry,sourceContext,inFlight}) {
  profile=validateClosureProfile(profile)
  const participant=own(memory,'participant')
  const source=isPrivateV2Participant(participant)&&same(own(participant,'profile'),profile)
  authority=capture(authority,['propose','approvalChallenge','approvalComplete','status'])
  memory=capture(memory,['prepareRestoreBinding','withAuthorityTargetObservation','restoreSnapshot','reconcileEffect'])
  function mounted() {
    if(!source||Object.values(authority).some(fn=>!fn)||Object.values(memory).some(fn=>!fn))
      refuse('UNAVAILABLE','RETAINED_RESTORE_SOURCE_UNMOUNTED')
  }
  function inputs(input,fields,contextValue) {
    const request=parseStrictJson(canonicalJson(input),{maxBytes:65_536,maxDepth:32})
    closed(request,fields)
    const context=parseStrictJson(canonicalJson(contextValue),{maxBytes:8192,maxDepth:8})
    closed(context,['request','role'])
    if(context.role!=='owner_control')refuse('UNAUTHORIZED','RETAINED_RESTORE_OWNER_CONTROL_REQUIRED')
    return {input:copy(request),context:copy(context)}
  }
  async function contextOf(input,context) {
    mounted()
    const {identity,entry}=await sourceContext(input,context.request)
    if(entry.audience!=='aukora-prime.memory')refuse('UNAUTHORIZED','RETAINED_RESTORE_TASK_REQUIRED')
    return {identity,entry,host:validateClosureHost({owner_id:identity.owner_id,owner_subject:identity.subject,
      task_id:entry.task.task_id,authorization_epoch:identity.authorization_epoch})}
  }
  function owned(operation,identity,entry,host) {
    operation=copy(operation);validateRetainedRestoreOperation(operation)
    if(operation.owner_id!==identity.owner_id||operation.task_id!==entry.task.task_id
      ||operation.authorization_epoch!==identity.authorization_epoch
      ||!same(operation.target_identity,{kind:'prime-memory',owner_subject:host.owner_subject})
      ||taskRegistry.authorizeTask(operation)?.authenticated!==true)
      refuse('UNAUTHORIZED','EXACT_OWNED_RESTORE_REQUIRED')
    return operation
  }
  function proofOf(proof,operation) {
    proof=copy(proof);validateContract('ApprovalProof',proof)
    if(proof.operation_id!==operation.operation_id||proof.operation_digest!==operationDigest(operation)
      ||proof.owner_id!==operation.owner_id||proof.audience!==operation.audience
      ||proof.authorization_epoch!==operation.authorization_epoch)
      refuse('INVALID','EXACT_RESTORE_PROOF_REQUIRED')
    return proof
  }
  function unresolved(error,operation,receipt=null) {
    const failure=retainedUnknown(error)
    failure.operation_id=operation.operation_id;failure.operation_digest=operationDigest(operation)
    for(const [key,pattern] of [['request_id',UUID],['request_digest',DIGEST]]) {
      const bound=own(receipt,'operation_id')===operation.operation_id
        &&(own(receipt,'operation_digest')===undefined||own(receipt,'operation_digest')===operationDigest(operation))
      const value=(bound?own(receipt,key):undefined)??own(error,key)
      if(typeof value==='string'&&pattern.test(value))failure[key]=value
    }
    return failure
  }
  async function factualSettlement(input,operation,effect) {
    if(effect.authority_settlement!=='completed')return effect
    const status=await authority.status({session_token:input.session_token,operation_id:operation.operation_id})
    if(status?.ok!==true||status.status!=='COMPLETED'||status.operation_digest!==operationDigest(operation)
      ||status.reconciliation_required!==false)fail('RETAINED_RESTORE_C_SETTLEMENT_UNAVAILABLE')
    return effect
  }
  async function propose(rawInput,rawBundle,rawContext) {
    const {input,context}=inputs(rawInput,['session_token'],rawContext),bundle=detachPrivateData(rawBundle)
    const {identity,entry,host}=await contextOf(input,context)
    // Restore admission relates actual ancestor A to protected P. Ordinary
    // current-census admission and original13 registration are inapplicable.
    const binding=copy(await memory.prepareRestoreBinding(host,bundle))
    closed(binding,['target_identity','state_version','canonical_parameters'])
    const operation=owned({version:1,operation_id:randomUUID(),task_id:entry.task.task_id,owner_id:identity.owner_id,
      agent_id:entry.task.agent_id,audience:entry.audience,action_type:'memory.restore',target_identity:binding.target_identity,
      canonical_parameters:binding.canonical_parameters,data_scope:entry.data_scope,expected_state_version:binding.state_version,
      provider_and_region:entry.provider_and_region,maximum_cost:{currency:'USD',amount:'0'},
      expiry:new Date(Math.min(Date.now()+120_000,Date.parse(identity.expiry))).toISOString(),
      nonce:randomBytes(32).toString('hex'),policy_version:entry.policy_version,authorization_epoch:identity.authorization_epoch},identity,entry,host)
    try {
      const reply=await authority.propose({session_token:input.session_token,operation})
      if(reply?.ok!==true)return copy(reply)
      closed(reply,['ok','operation','operation_digest','status'])
      if(reply.status!=='PROPOSED'||reply.operation_digest!==operationDigest(operation)||!same(reply.operation,operation))
        fail('RETAINED_RESTORE_PROPOSAL_CHANGED')
      return copy(reply)
    } catch(error){throw unresolved(error,operation)}
  }
  async function approval(rawInput,rawContext,complete) {
    const {input,context}=inputs(rawInput,complete?['session_token','operation','proof']:['session_token','operation'],rawContext)
    const {identity,entry,host}=await contextOf(input,context),operation=owned(input.operation,identity,entry,host)
    const proof=complete?proofOf(input.proof,operation):null
    return copy(await memory.withAuthorityTargetObservation(host,operation,()=>complete
      ?authority.approvalComplete({session_token:input.session_token,proof})
      :authority.approvalChallenge({session_token:input.session_token,operation})))
  }
  async function apply(rawInput,rawBundle,rawContext) {
    const {input,context}=inputs(rawInput,['session_token','operation','approval_proof'],rawContext),bundle=detachPrivateData(rawBundle)
    const {identity,entry,host}=await contextOf(input,context),operation=owned(input.operation,identity,entry,host)
    const proof=proofOf(input.approval_proof,operation),key=host.owner_subject+'\0'+operation.operation_id
    if(inFlight.has(key))throw unresolved(Error('RETAINED_RESTORE_IN_FLIGHT'),operation)
    inFlight.add(key);let receipt
    try {
      const status=await authority.status({session_token:input.session_token,operation_id:operation.operation_id})
      if(status?.ok!==true||status.operation_digest!==operationDigest(operation)||status.status!=='APPROVED'
        ||status.reconciliation_required!==false)fail('RETAINED_RESTORE_APPROVED_OPERATION_REQUIRED')
      // D alone owns reserve/claim/physical SQL/journal/receipt/settlement. Never
      // repeat apply on uncertainty; reconcile reads only its original receipt.
      const reply=await memory.restoreSnapshot(host,bundle,{operation,approval_proof:proof})
      receipt=own(reply,'receipt')
      const effect=validateRestoreEffect(reply,operation,host)
      return await factualSettlement(input,operation,effect)
    } catch(error){throw unresolved(error,operation,receipt)}
    finally {inFlight.delete(key)}
  }
  async function reconcile(rawInput,rawContext) {
    const {input,context}=inputs(rawInput,['session_token','operation'],rawContext)
    const {identity,entry,host}=await contextOf(input,context),operation=owned(input.operation,identity,entry,host)
    const key=host.owner_subject+'\0'+operation.operation_id
    if(inFlight.has(key))throw unresolved(Error('RETAINED_RESTORE_IN_FLIGHT'),operation)
    inFlight.add(key);let receipt
    try {
      const reply=await memory.reconcileEffect(host,operation.operation_id)
      receipt=own(reply,'receipt')??reply
      const effect=validateRestoreEffect(reply,operation,host)
      return await factualSettlement(input,operation,effect)
    } catch(error){throw unresolved(error,operation,receipt)}
    finally {inFlight.delete(key)}
  }
  return Object.freeze({propose,approvalChallenge:(i,c)=>approval(i,c,false),
    approvalComplete:(i,c)=>approval(i,c,true),apply,reconcile})
}
