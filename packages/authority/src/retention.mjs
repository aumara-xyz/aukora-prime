// SPDX-License-Identifier: AGPL-3.0-or-later
// Terminal payload minimization. Kernel consumption/prepared history is never pruned.
import {createHash} from 'node:crypto'
import {canonicalJson} from '../../contracts/src/runtime.mjs'
import {assertData,detachContract,operationDigest} from './operation.mjs'
import {DIGEST,UUID,executionReceiptDigest,validatedReceipt,settlementStatus} from './execution.mjs'
import {memoryEffectReceipt,memoryEffectReceiptDigest} from './memory-effect.mjs'
import {retainedMemoryLineage,validateRetainedMemoryLineage} from './retained-memory.mjs'

export const TERMINAL_SCHEMA='prime-terminal-operation-v1'
export const RETAINED_TERMINAL_SCHEMA='prime-retained-terminal-operation-v1'
export const TERMINAL_STATUSES=Object.freeze(['COMPLETED','FAILED','CANCELLED','UNAVAILABLE'])
const hex=/^[a-f0-9]{64}$/
const sha=value=>createHash('sha256').update(value).digest('hex')
const keys=(value,expected)=>Object.keys(value).sort().join(',')===expected.split(',').sort().join(',')
const invalid=()=>{throw new TypeError('INVALID: terminal authority retention record')}
const stringMatch=(value,pattern)=>typeof value==='string'&&pattern.test(value)
export const ownerKey=ownerId=>sha(ownerId)
export const isTerminalRecord=row=>[TERMINAL_SCHEMA,RETAINED_TERMINAL_SCHEMA].includes(row?.schema)
export function consumedGrantDigest(input) {
 const grant=detachContract('ConsumedGrant',input)
 return 'sha256:'+sha('aukora-prime.consumed-grant.v1\0'+canonicalJson(grant))
}
export function validateTerminalRecord(row) {
 assertData(row)
 const retained=row?.schema===RETAINED_TERMINAL_SCHEMA
 if(!row||Array.isArray(row)||!keys(row,'schema,owner_key,operation_digest,status,grant_digest,dispatch'+(retained?',retained_memory':''))||
    !isTerminalRecord(row)||!stringMatch(row.owner_key,hex)||!stringMatch(row.operation_digest,DIGEST)||!stringMatch(row.grant_digest,DIGEST)||!TERMINAL_STATUSES.includes(row.status))invalid()
 const d=row.dispatch
 if(!d||Array.isArray(d)||!keys(d,'request_id,request_digest,receipt_digest,settlement_digests,evidence_kind,result_digest')||
    !stringMatch(d.request_id,UUID)||!stringMatch(d.request_digest,DIGEST)||!stringMatch(d.receipt_digest,DIGEST)||
    !Array.isArray(d.settlement_digests)||d.settlement_digests.length<1||d.settlement_digests.length>32||
    d.settlement_digests.some(x=>!stringMatch(x,DIGEST))||new Set(d.settlement_digests).size!==d.settlement_digests.length||
    !d.settlement_digests.includes(d.receipt_digest)||!['memory','execution'].includes(d.evidence_kind)||
    (d.evidence_kind==='memory'?(row.status!=='COMPLETED'||!stringMatch(d.result_digest,DIGEST)):d.result_digest!==null)||
    Buffer.byteLength(canonicalJson(row))>4096)invalid()
 if(retained) {
  if(d.evidence_kind!=='memory'||row.status!=='COMPLETED')invalid()
  validateRetainedMemoryLineage(row.retained_memory)
 }
 return row
}
export function kernelPreparationMatches(record,op,grant,nonce) {
 const effectId=grant.reservation_id.startsWith('prepared:')?grant.reservation_id.slice(9):null
 return stringMatch(nonce,hex)&&stringMatch(effectId,hex)&&record.state.consumedIds.includes('approval:'+nonce)&&
  record.prepared.some(p=>p.consumptionId==='approval:'+nonce&&p.effectId===effectId&&p.contentHash===grant.operation_digest.slice(7)&&p.receiptCountAfter<=record.state.receiptHead.count)
}
export function compactTerminalRow(key,row,record,owners) {
 if(isTerminalRecord(row))return validateTerminalRecord(row)
 if(!TERMINAL_STATUSES.includes(row.status))return row
 const op=detachContract('OperationProposal',row.operation),grant=detachContract('ConsumedGrant',row.grant),proof=detachContract('ApprovalProof',row.approval?.proof),d=row.dispatch,nonce=proof.nonce
 if(key!==sha(canonicalJson([op.owner_id,op.operation_id]))||row.operation_digest!==operationDigest(op)||
    grant.operation_digest!==row.operation_digest||proof.operation_digest!==row.operation_digest||
    proof.operation_id!==op.operation_id||proof.owner_id!==op.owner_id||proof.audience!==op.audience||proof.authorization_epoch!==op.authorization_epoch||
    grant.operation_id!==op.operation_id||grant.owner_id!==op.owner_id||grant.audience!==op.audience||grant.authorization_epoch!==op.authorization_epoch||
    grant.grant_id!=='grant:'+nonce||!kernelPreparationMatches(record,op,grant,nonce)||!d||!d.receipt)invalid()
 let receipt,evidence_kind,result_digest
 if(d.receipt.kind==='prime-memory-effect/v1') {
  receipt=memoryEffectReceipt(d.receipt);evidence_kind='memory';result_digest=receipt.result_digest
  if(row.status!=='COMPLETED'||op.target_identity?.kind!=='prime-memory'||!op.action_type.startsWith('memory.')||
     receipt.owner_subject!==op.target_identity.owner_subject||receipt.owner_subject!==owners[ownerKey(op.owner_id)]?.subject||
     receipt.action_type!==op.action_type||receipt.request_digest!==d.request_digest||memoryEffectReceiptDigest(receipt)!==d.receipt_digest)invalid()
 } else {
  receipt=validatedReceipt(d.receipt);evidence_kind='execution';result_digest=null
  if(settlementStatus(receipt,d.cancel_requested)!==row.status||executionReceiptDigest(receipt)!==d.receipt_digest||receipt.owner_id!==op.owner_id||receipt.task_id!==op.task_id)invalid()
  if(receipt.sandbox&&op.target_identity&&typeof op.target_identity==='object') {
   for(const field of ['image_digest','policy_digest'])if(Object.hasOwn(op.target_identity,field)&&receipt.sandbox[field]!==op.target_identity[field])invalid()
  }
 }
 if(receipt.operation_id!==op.operation_id||receipt.operation_digest!==row.operation_digest||receipt.grant_id!==grant.grant_id||receipt.request_id!==d.request_id)invalid()
 return validateTerminalRecord({schema:TERMINAL_SCHEMA,owner_key:ownerKey(op.owner_id),operation_digest:row.operation_digest,status:row.status,grant_digest:consumedGrantDigest(grant),
  dispatch:{request_id:d.request_id,request_digest:d.request_digest,receipt_digest:d.receipt_digest,settlement_digests:structuredClone(d.settlement_digests),evidence_kind,result_digest}})
}
export function validateRetainedRows(operations) {
 for(const [key,row]of Object.entries(operations)) {
  if(!hex.test(key)||!row||typeof row!=='object'||Array.isArray(row))invalid()
  if(Object.hasOwn(row,'schema'))validateTerminalRecord(row)
 }
}
export function compactRetainedRows(broker,record,{deferMemoryPayloads=false,memorySettlementPermit=null}={}) {
 validateRetainedRows(broker.operations)
 // Build all candidates before replacing any row. A malformed legacy terminal
 // record refuses the whole commit; no partial payload removal/history eviction.
 const candidates=Object.fromEntries(Object.entries(broker.operations).map(([key,row])=>{
  const candidate=compactTerminalRow(key,row,record,broker.owners)
  if(!isTerminalRecord(row)&&isTerminalRecord(candidate)&&candidate.dispatch.evidence_kind==='memory'
    &&(deferMemoryPayloads||row.retained_memory)) {
   // Validate every legacy candidate, but missing retained evidence never blocks logout.
   if(memorySettlementPermit?.operation_key!==key||memorySettlementPermit.receipt_digest!==candidate.dispatch.receipt_digest
      ||!row.retained_memory?.settle)return [key,row]
   return [key,validateTerminalRecord({...candidate,schema:RETAINED_TERMINAL_SCHEMA,
    retained_memory:retainedMemoryLineage(row.retained_memory)})]
  }
  return [key,candidate]
 }))
 return {...broker,operations:candidates}
}
