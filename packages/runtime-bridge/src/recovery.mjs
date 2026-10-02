// SPDX-License-Identifier: AGPL-3.0-or-later
// C and D retain authority/effect facts. This layer reads their durable state
// using the host's content-free references; it never reserves or repeats effects.
import {createHash} from 'node:crypto'
import {canonicalJson,validateContract} from '../../contracts/src/runtime.mjs'

const hash=(domain,value)=>'sha256:'+createHash('sha256').update(domain+'\0'+canonicalJson(value)).digest('hex')
const fail=reason=>{throw Object.assign(new Error(reason),{error_code:'OUTCOME_UNKNOWN'})}
const empty=(host,row,state)=>({ok:true,owner_id:host.owner_id,owner_subject:host.owner_subject,task_id:host.task_id,
  operation_id:row?.operation_id??null,operation_digest:row?.operation_digest??null,
  action_type:row?.action_type??null,state,reconciliation_required:state==='unknown',result:null,receipt:null,
  receipt_digest:null,authority_settlement:null,citation:null,index:null})

export function createRecovery({authority,memory,workflowStore,inFlight}) {
  function verifiedEffect(host,row,effect) {
    const receipt=effect?.receipt,result=effect?.result
    if(!receipt||receipt.version!==1||receipt.kind!=='prime-memory-effect/v1'
      ||receipt.operation_id!==row.operation_id||receipt.operation_digest!==row.operation_digest
      ||receipt.owner_subject!==host.owner_subject||receipt.action_type!==row.action_type||receipt.status!=='applied'
      ||typeof receipt.request_id!=='string'||!/^sha256:[a-f0-9]{64}$/.test(receipt.request_digest??'')
      ||receipt.result_digest!==hash('aukora-prime.memory-result.v1',result)
      ||canonicalJson(receipt.result)!==canonicalJson(result))fail('RECOVERY_EFFECT_BINDING_REQUIRED')
    const receiptDigest=hash('aukora-prime.memory-receipt.v1',receipt)
    if(effect.authority_settlement!=='completed'||effect.reconciliation_required!==false||effect.receipt_digest!==receiptDigest)fail('RECOVERY_SETTLEMENT_PENDING')
    for(const key of ['request_id','request_digest','receipt_digest'])if(row[key]!==null&&row[key]!==({receipt_digest:receiptDigest,...receipt})[key])fail('RECOVERY_REFERENCE_CHANGED')
    if(row.action_type==='memory.save') {
      validateContract('MemoryRecord',result)
      if(result.owner_subject!==host.owner_subject||result.task_id!==host.task_id||result.storage_status!=='saved'
        ||result.grants_authority!==false)fail('RECOVERY_RECORD_BINDING_REQUIRED')
    } else if(result?.record_id!==row.record_id||result.state!=='tombstoned'||result.grants_authority!==false
      ||result.canonical_payload_retained!==true||result.physical_media_erasure!==false)fail('RECOVERY_FORGET_BINDING_REQUIRED')
    return {receiptDigest,result,receipt}
  }
  async function rowState(host,session_token,row,{read=true}={}) {
    if(inFlight.has(row.owner_subject+'\0'+row.operation_id))return empty(host,row,'unknown')
    const status=await authority.status({session_token,operation_id:row.operation_id})
    const absent=status?.ok===false&&status.error_code==='UNAUTHORIZED'&&status.reason==='OWNER_OPERATION_REQUIRED'
    if(status?.ok!==true&&!absent||status?.ok===true&&status.operation_digest!==row.operation_digest)return empty(host,row,'unknown')
    // W1 closure is OFF: a legacy read-time label is not a durable C/D writer
    // fence. Keep it unresolved until the separate closure contract exists.
    if(row.phase==='known_unsent')return empty(host,row,'unknown')
    let effect
    try {effect=await memory.reconcileEffect(host,row.operation_id)}
    catch {return empty(host,row,'unknown')}
    if(effect?.status==='unresolved'||effect?.authority_settlement!=='completed')return empty(host,row,'unknown')
    try {
      const factual=verifiedEffect(host,row,effect)
      // Receipt delivery above is factual settlement only. Confirm C's durable
      // status even when its terminal row has compacted payload/proof fields.
      const settled=await authority.status({session_token,operation_id:row.operation_id})
      if(settled?.ok!==true||settled.status!=='COMPLETED'||settled.operation_digest!==row.operation_digest
        ||settled.reconciliation_required!==false)return empty(host,row,'unknown')
      const phase=row.action_type==='memory.save'?'saved':'forgotten'
      await workflowStore.mark(host,row.operation_id,phase,{record_id:factual.result.record_id,
        request_id:factual.receipt.request_id,request_digest:factual.receipt.request_digest,receipt_digest:factual.receiptDigest})
      const reply={...empty(host,row,phase),result:factual.result,receipt:factual.receipt,receipt_digest:factual.receiptDigest,authority_settlement:'completed'}
      if(read&&phase==='saved') {
        try {reply.index=await memory.status(host,factual.result.record_id,factual.result.revision)}catch{/* Read availability cannot undo a completed save. */}
        try {reply.citation=await memory.cite(host,factual.result.record_id,factual.result.revision)}catch{/* Preserve confirmed effect facts. */}
      }
      return reply
    } catch {return empty(host,row,'unknown')}
  }
  async function pending(host,session_token,{exclude=null}={}) {
    const listed=await workflowStore.list(host,{active:true})
    for(const row of listed.items) {
      if(row.operation_id===exclude)continue
      const recovered=await rowState(host,session_token,row,{read:false})
      if(recovered.state==='unknown')return recovered
    }
    return null
  }
  async function recover(host,session_token,operation_id) {
    // Never return another confirmed record while a pending effect is unknown.
    const blocked=await pending(host,session_token)
    if(blocked)return blocked
    if(operation_id!==null)return rowState(host,session_token,await workflowStore.get(host,operation_id))
    const latest=(await workflowStore.list(host,{active:false,limit:1})).items[0]
    if(!latest)return empty(host,null,'idle')
    if(latest.phase==='known_unsent')return empty(host,latest,'unknown')
    return rowState(host,session_token,latest)
  }
  return Object.freeze({pending,recover,verifiedEffect})
}
