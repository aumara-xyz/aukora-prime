// SPDX-License-Identifier: AGPL-3.0-or-later
// Private E/C connection only. No public route, signer, secret store or ledger.
import {validateContract} from '../../contracts/src/runtime.mjs'
import {createInferenceAuthorityIpcClient} from './ipc.mjs'
import {canonicalJson,operationDigest,closed,configRecord,data,inferenceOperation,
  loadInferenceContracts,refusal,unavailableStatus} from './inference-support.mjs'

const CLAIM=['operation','consumed_grant','request_id','request_digest']
const SETTLEMENT=[...CLAIM,'receipt','receipt_digest']
const key=(session,operation)=>canonicalJson([session,operation.owner_id,operation.operation_id,operationDigest(operation)])
const C_REFUSALS=new Set(['INVALID','UNAUTHORIZED','UNAVAILABLE','EXPIRED','REVOKED','REPLAYED','CANCELLED','STALE',
  'TARGET_MISMATCH','RECONCILIATION_REQUIRED','OUTCOME_UNKNOWN'])
const success = reply => {
  if(reply?.ok!==true)throw refusal(reply?.ok===false&&C_REFUSALS.has(reply.error_code)?reply.error_code:'OUTCOME_UNKNOWN',
    'INFERENCE_AUTHORITY_REPLY_NOT_CONFIRMED')
  return reply
}
function approval(operation,proof) {
  validateContract('ApprovalProof',proof)
  if(proof.operation_id!==operation.operation_id||proof.operation_digest!==operationDigest(operation)
    ||proof.owner_id!==operation.owner_id||proof.audience!==operation.audience
    ||proof.authorization_epoch!==operation.authorization_epoch)
    throw refusal('UNAUTHORIZED','INFERENCE_EXACT_OWNER_PROOF_REQUIRED')
}
function claimOf(admission) {return data({operation:admission.operation,consumed_grant:admission.consumed_grant,
  request_id:admission.request_uuid,request_digest:admission.request_digest})}
function lookup(operation,requestId,requestDigest) {return data({owner_id:operation.owner_id,task_id:operation.task_id,
  operation_digest:operationDigest(operation),request_uuid:requestId,request_digest:requestDigest})}
async function boundClaim(input) {
  const candidate=closed(data(input),CLAIM),operation=await inferenceOperation(candidate.operation)
  const parser=await loadInferenceContracts()
  const admission=parser.parseInferenceAdmission({...operation.canonical_parameters.binding,operation,
    consumed_grant:candidate.consumed_grant,request_digest:candidate.request_digest})
  if(candidate.request_id!==admission.request_uuid)throw refusal('INVALID','INFERENCE_ORIGINAL_REQUEST_UUID_REQUIRED')
  return claimOf(admission)
}
function dispatched(reply,input) {
  success(reply)
  try {
    closed(reply,['ok','status','consumed_grant','request_id','request_digest'])
    if(reply.status!=='DISPATCHED'||reply.request_id!==input.request_id||reply.request_digest!==input.request_digest
      ||canonicalJson(reply.consumed_grant)!==canonicalJson(input.consumed_grant))throw new Error('binding')
    return data(reply)
  } catch {
    throw refusal('OUTCOME_UNKNOWN','INFERENCE_DISPATCH_REPLY_BINDING_MISMATCH')
  }
}
function settled(reply,input) {
  success(reply)
  try {
    closed(reply,['ok','status','request_id','request_digest','receipt_digest','idempotent','reconciliation_required'])
    if(!['COMPLETED','OUTCOME_UNKNOWN'].includes(reply.status)||reply.request_id!==input.request_id
      ||reply.request_digest!==input.request_digest||reply.receipt_digest!==input.receipt_digest
      ||typeof reply.idempotent!=='boolean'||reply.reconciliation_required!==(reply.status==='OUTCOME_UNKNOWN')
      ||reply.status!==(input.receipt.outcome==='completed'?'COMPLETED':'OUTCOME_UNKNOWN'))throw new Error('binding')
    return data(reply)
  } catch {
    throw refusal('OUTCOME_UNKNOWN','INFERENCE_SETTLEMENT_REPLY_BINDING_MISMATCH')
  }
}

/** Internal host adapters consume E's existing durable ledger; none is a wire
 * field or a boolean gate. Missing adapters refuse their path. NEXT/E must join
 * these to the reviewed intent/reservation, dispatch and immutable outbox APIs.
 * authorityChannel and this object stay outside app/guest credential access. */
export function createInferenceAuthorityConnection(config) {
  configRecord(config,['authorityChannel','observer'],['getReviewedApproval','withCommittedIntent',
    'dispatchCommitted','withCommittedSettlement'])
  configRecord(config.observer,['withObservation'],['status'])
  const withObservation=config.observer.withObservation
  if(typeof withObservation!=='function')throw refusal('UNAVAILABLE','INFERENCE_TRUSTED_OBSERVER_UNMOUNTED')
  for(const name of ['getReviewedApproval','withCommittedIntent','dispatchCommitted','withCommittedSettlement'])
    if(config[name]!==undefined&&typeof config[name]!=='function')throw refusal('INVALID','INFERENCE_TRUSTED_ADAPTER_INVALID')
  // Never retain a caller-mutable credential/config object across awaits.
  const channelConfig=data(config.authorityChannel),observe=withObservation.bind(config.observer)
  const getApproval=config.getReviewedApproval,withIntent=config.withCommittedIntent,
    dispatch=config.dispatchCommitted,withSettlement=config.withCommittedSettlement
  const reviews=new Map()
  // Content-free local latches supplement E's durable replay fences. Never
  // evict/reset one after uncertainty or claim they survive a process restart.
  const reserveAttempts=new Set(),dispatchAttempts=new Set()
  let revision=0,disposed=false,dispatchActive=false,settlementActive=false
  const invalidate=()=>{revision++;reviews.clear()}
  function open() {if(disposed)throw refusal('UNAVAILABLE','INFERENCE_CONNECTION_DISPOSED')}
  async function invoke(name,input,operation=null,observation=null,assertScope=()=>{}) {
    open();assertScope()
    const wrapper=data({input,operation,operation_digest:operation?operationDigest(operation):null,observation})
    const channel=await createInferenceAuthorityIpcClient(channelConfig)
    try {open();assertScope();return data(await channel.request('authority.'+name,wrapper))}
    finally {await channel.close()}
  }
  const live=(name,input,operation)=>observe(operation,(observation,assertScope)=>
    invoke(name,input,operation,observation,assertScope))
  const authority=Object.freeze({
    loginChallenge(input){invalidate();return invoke('loginChallenge',closed(data(input),['owner_id','kind']))},
    loginComplete(input){invalidate();return invoke('loginComplete',closed(data(input),['challenge','material']))},
    authenticateSession(input){return invoke('authenticateSession',closed(data(input),['session_token']))},
    logoutSession(input){invalidate();return invoke('logoutSession',closed(data(input),['session_token']))},
    status(input){return invoke('status',closed(data(input),['session_token','operation_id']))},
    async propose(input) {
      const v=closed(data(input),['session_token','operation']),operation=await inferenceOperation(v.operation)
      // Validate trusted facts even though C propose does not call observeTarget.
      return observe(operation,(_observation,assertScope)=>invoke('propose',v,operation,null,assertScope))
    },
    async approvalChallenge(input) {
      const v=closed(data(input),['session_token','operation']),operation=await inferenceOperation(v.operation)
      open();const id=key(v.session_token,operation),stamp=revision
      if(reviews.has(id)||reviews.size>=16)throw refusal('UNAVAILABLE','INFERENCE_REVIEW_CONTEXT_BOUND')
      reviews.set(id,{operation,pending:true})
      try {
        const reply=await live('approvalChallenge',v,operation)
        if(stamp!==revision||disposed)throw refusal('UNAUTHORIZED','INFERENCE_REVIEW_CONTEXT_CHANGED')
        if(reply.ok!==true){reviews.delete(id);return reply}
        if(canonicalJson(reply.operation)!==canonicalJson(operation)||reply.operation_digest!==operationDigest(operation))
          throw refusal('UNAUTHORIZED','INFERENCE_CHALLENGE_OPERATION_MISMATCH')
        reviews.set(id,{operation,pending:false});return reply
      } catch(error){if(stamp===revision)reviews.delete(id);throw error}
    },
    async approvalComplete(input) {
      const v=closed(data(input),['session_token','proof']);validateContract('ApprovalProof',v.proof)
      const id=canonicalJson([v.session_token,v.proof.owner_id,v.proof.operation_id,v.proof.operation_digest])
      const retained=reviews.get(id)
      if(!retained||retained.pending)throw refusal('UNAUTHORIZED','INFERENCE_RETAINED_REVIEW_REQUIRED')
      approval(retained.operation,v.proof)
      // Keep C's input exactly session/proof; the operation belongs only to the
      // private scope. Discard before submission, including uncertain replies.
      reviews.delete(id)
      return live('approvalComplete',v,retained.operation)
    },
    declineApproval(input) {
      const v=closed(data(input),['session_token','operation_id'])
      for(const [id,value]of reviews)if(id===key(v.session_token,value.operation)&&value.operation.operation_id===v.operation_id)reviews.delete(id)
      return invoke('declineApproval',v)
    },
  })
  return Object.freeze({authority,status:unavailableStatus,
    dispose(){disposed=true;invalidate()},
    /** Existing app gateway seam, exposed by NEXT through its bounded host join.
     * It reserves once and returns flat15; it never claims or launches HTTP. */
    async authorizeDispatch(input) {
      open();const detached=data(input),parser=await loadInferenceContracts(),binding=parser.parseInferenceBinding(detached)
      if(typeof getApproval!=='function')throw refusal('UNAVAILABLE','INFERENCE_OWNER_REVIEW_ADAPTER_UNMOUNTED')
      const attempt=canonicalJson([binding.owner_id,binding.request_uuid])
      if(reserveAttempts.has(attempt))throw refusal('RECONCILIATION_REQUIRED','INFERENCE_RESERVE_ATTEMPT_RETAINED')
      if(reserveAttempts.size>=128)throw refusal('UNAVAILABLE','INFERENCE_RESERVE_ATTEMPT_BOUND')
      reserveAttempts.add(attempt)
      const reviewed=closed(data(await getApproval(binding)),['operation','approval_proof'])
      const operation=parser.parseInferenceOperation(reviewed.operation)
      if(canonicalJson(operation.canonical_parameters.binding)!==canonicalJson(binding))
        throw refusal('UNAUTHORIZED','INFERENCE_REVIEWED_REQUEST_MISMATCH')
      approval(operation,reviewed.approval_proof)
      const reply=success(await live('reserve',reviewed,operation))
      try {
        closed(reply,['ok','status','consumed_grant','kernel_receipt','profile'])
        if(reply.status!=='PREPARED')throw new Error('binding')
        return parser.parseInferenceAdmission({...binding,operation,consumed_grant:reply.consumed_grant,
          request_digest:parser.inferenceRequestDigest(binding)})
      } catch {throw refusal('OUTCOME_UNKNOWN','INFERENCE_PREPARATION_BINDING_MISMATCH')}
    },
    /** Called only after E atomically commits immutable intent, original policy
     * and allowance. E's adapter admits this callback once, never after unknown.
     * The qualified-state fence encloses both C claim and E's actual dispatch. */
    async withDispatch(input) {
      open();const detached=data(input)
      if(typeof withIntent!=='function'||typeof dispatch!=='function')
        throw refusal('UNAVAILABLE','INFERENCE_DURABLE_DISPATCH_ADAPTER_UNMOUNTED')
      if(dispatchActive)throw refusal('UNAVAILABLE','INFERENCE_DISPATCH_REENTRANT')
      dispatchActive=true
      let entered=false,completed=false,flight,result,scopeOpen=true
      try {
        const candidate=await boundClaim(detached),parser=await loadInferenceContracts()
        const attempt=canonicalJson([candidate.operation.owner_id,candidate.request_id])
        if(dispatchAttempts.has(attempt))throw refusal('RECONCILIATION_REQUIRED','INFERENCE_DISPATCH_ATTEMPT_RETAINED')
        if(dispatchAttempts.size>=128)throw refusal('UNAVAILABLE','INFERENCE_DISPATCH_ATTEMPT_BOUND')
        dispatchAttempts.add(attempt)
        await withIntent(lookup(candidate.operation,candidate.request_id,candidate.request_digest),stored=>{
          if(entered||!scopeOpen)throw refusal('REPLAYED','INFERENCE_COMMITTED_INTENT_SCOPE_REUSED')
          entered=true
          flight=(async()=>{
            const admission=parser.parseInferenceAdmission(data(stored)),actual=claimOf(admission)
            if(canonicalJson(candidate)!==canonicalJson(actual))throw refusal('UNAUTHORIZED','INFERENCE_COMMITTED_INTENT_MISMATCH')
            result=await observe(admission.operation,async(observation,assertScope)=>{
              if(!scopeOpen)throw refusal('UNAUTHORIZED','INFERENCE_COMMITTED_INTENT_SCOPE_CLOSED')
              const reply=dispatched(await invoke('claimDispatch',actual,admission.operation,observation,assertScope),actual)
              if(!scopeOpen||disposed)throw refusal('OUTCOME_UNKNOWN','INFERENCE_POST_CLAIM_SCOPE_CLOSED')
              assertScope()
              // E owns body, credential, transport, durable unknown/evidence and
              // outbox. The bridge neither stores nor regenerates any of them.
              try {return await dispatch(admission,reply)}
              catch {throw refusal('OUTCOME_UNKNOWN','INFERENCE_DISPATCH_OR_EVIDENCE_UNCONFIRMED')}
            })
            completed=true;return result
          })()
          return flight
        })
        if(!entered||!completed)throw refusal('OUTCOME_UNKNOWN','INFERENCE_INTENT_FENCE_NOT_AWAITED')
        return result
      } finally {scopeOpen=false;try {await flight} catch {} finally {dispatchActive=false}}
    },
    settleInference(input){return settle('settleInference',input)},
    reconcileInferenceSettlement(input){return settle('reconcileInferenceSettlement',input)},
  })

  async function settle(name,input) {
    open();const detached=closed(data(input),SETTLEMENT)
    if(typeof withSettlement!=='function')throw refusal('UNAVAILABLE','INFERENCE_COMMITTED_SETTLEMENT_ADAPTER_UNMOUNTED')
    if(settlementActive)throw refusal('UNAVAILABLE','INFERENCE_SETTLEMENT_REENTRANT')
    settlementActive=true
    let entered=false,completed=false,flight,result,scopeOpen=true
    try {
      const candidate=await boundClaim({operation:detached.operation,consumed_grant:detached.consumed_grant,
        request_id:detached.request_id,request_digest:detached.request_digest})
      await withSettlement(name,data({...lookup(candidate.operation,candidate.request_id,candidate.request_digest),
        receipt_digest:detached.receipt_digest}),stored=>{
        if(entered||!scopeOpen)throw refusal('UNAUTHORIZED','INFERENCE_SETTLEMENT_SCOPE_REUSED')
        entered=true
        flight=(async()=>{
          const committed=closed(data(stored),SETTLEMENT)
          if(canonicalJson(committed)!==canonicalJson(detached))throw refusal('UNAUTHORIZED','INFERENCE_COMMITTED_RECEIPT_MISMATCH')
          if(!scopeOpen)throw refusal('UNAUTHORIZED','INFERENCE_SETTLEMENT_SCOPE_CLOSED')
          // Historical factual evidence: no current session, live observation,
          // current replacement route/rates or newly generated observed_at.
          result=settled(await invoke(name,committed,candidate.operation),committed)
          completed=true;return result
        })()
        return flight
      })
      if(!entered||!completed)throw refusal('OUTCOME_UNKNOWN','INFERENCE_SETTLEMENT_FENCE_NOT_AWAITED')
      return result
    } finally {scopeOpen=false;try {await flight} catch {} finally {settlementActive=false}}
  }
}
