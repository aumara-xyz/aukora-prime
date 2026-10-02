// SPDX-License-Identifier: AGPL-3.0-or-later
import { canonicalJSON } from '../genesis/plugins/aukora-kira/lib/record.mjs'
import { requireMemory } from './codecs.mjs'
import { sha256 } from './codecs.mjs'

export const MEMORY_AUDIENCE='aukora-prime.memory'
export const memoryTarget=owner=>({kind:'prime-memory',owner_subject:owner})
export const memoryStateVersion=heads=>'sha256:'+sha256(Buffer.from('aukora-prime.memory.state.v1\0'+canonicalJSON(heads)))
export const memoryEffectDigest=request=>'sha256:'+sha256(Buffer.from('aukora-prime.memory.effect.v1\0'+canonicalJSON(request)))
export const memoryResultDigest=result=>'sha256:'+sha256(Buffer.from('aukora-prime.memory-result.v1\0'+canonicalJSON(result)))
export const memoryReceiptDigest=receipt=>'sha256:'+sha256(Buffer.from('aukora-prime.memory-receipt.v1\0'+canonicalJSON(receipt)))

// Proof checking stays in C. A boolean callback, a CLI flag or a snapshot's synthetic label is not authority.
export async function memoryAuthorization({authority,contracts,retainedMemory=false},host,action,parameters,options) {
  const reserveMethod=retainedMemory?'reserveRetained':'reserve',dispatchMethod=retainedMemory?'claimDispatchRetained':'claimDispatch'
  requireMemory(typeof authority?.[reserveMethod]==='function' && typeof authority?.[dispatchMethod]==='function'
    && (!retainedMemory || typeof authority?.settleMemoryRetained==='function'),
    retainedMemory?'memory:retained-authority-unavailable':'memory:authority-unavailable')
  contracts ??= await import('@aukora-prime/contracts').catch(()=>null)
  requireMemory(typeof contracts?.validateContract==='function' && typeof contracts?.operationDigest==='function',
    'memory:contracts-unavailable')
  const operation=structuredClone(options?.operation),proof=structuredClone(options?.approval_proof)
  try {contracts.validateContract('OperationProposal',operation);contracts.validateContract('ApprovalProof',proof)}
  catch {requireMemory(false,'memory:validated-operation-required')}
  requireMemory(typeof host.owner_id==='string' && operation.owner_id===host.owner_id && operation.task_id===host.task_id
    && operation.audience===MEMORY_AUDIENCE && operation.action_type===action
    && canonicalJSON(operation.target_identity)===canonicalJSON(memoryTarget(host.owner_subject))
    && canonicalJSON(operation.canonical_parameters)===canonicalJSON(parameters), 'memory:operation-binding-mismatch')
  const digest=contracts.operationDigest(operation)
  requireMemory(proof.operation_id===operation.operation_id && proof.operation_digest===digest
    && proof.owner_id===operation.owner_id && proof.audience===operation.audience
    && proof.authorization_epoch===operation.authorization_epoch && Date.parse(proof.expiry)<=Date.parse(operation.expiry),
    'memory:proof-binding-mismatch')
  return {
    operation,digest,
    async reserve() {
      const prepared=await authority[reserveMethod]({operation,approval_proof:proof})
      requireMemory(prepared?.ok===true && prepared.status==='PREPARED','memory:authority-refused')
      const grant=prepared.consumed_grant
      try {contracts.validateContract('ConsumedGrant',grant)} catch {requireMemory(false,'memory:grant-invalid')}
      requireMemory(grant.operation_id===operation.operation_id && grant.operation_digest===digest
        && grant.owner_id===operation.owner_id && grant.audience===operation.audience
        && grant.authorization_epoch===operation.authorization_epoch,'memory:grant-binding-mismatch')
      return grant
    },
    async dispatch({grant,request_id,request_digest}) {
      const dispatched=await authority[dispatchMethod]({operation,consumed_grant:grant,request_id,request_digest})
      requireMemory(dispatched?.ok===true && dispatched.status==='DISPATCHED'
        && canonicalJSON(dispatched.consumed_grant)===canonicalJSON(grant),'memory:authority-dispatch-refused')
      return grant
    }
  }
}
