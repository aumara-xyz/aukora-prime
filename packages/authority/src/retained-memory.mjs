// SPDX-License-Identifier: AGPL-3.0-or-later
// Private D participant binding. Permit syntax alone grants no authority.
import {existsSync} from 'node:fs'
import {createHash} from 'node:crypto'
import {canonicalJson} from '../../contracts/src/runtime.mjs'
import {assertData,deepFreeze,operationDigest} from './operation.mjs'
import {consumedGrantDigest} from './retention.mjs'
import {memoryEffectReceiptDigest} from './memory-effect.mjs'

// Default authority use remains independent of the optional D retained profile.
// The path is source-owned and fixed; no caller chooses a module or brand predicate.
const participantSource=new URL('../../memory/src/retained-memory-participant.mjs',import.meta.url)
const isRetainedMemoryParticipant=existsSync(participantSource)
 ? (await import(participantSource.href)).isRetainedMemoryParticipant : ()=>false

const HEX=/^[a-f0-9]{64}$/, DIGEST=/^sha256:[a-f0-9]{64}$/
const UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/
const PERMIT=['version','kind','phase','owner_id','owner_subject','authorization_epoch','operation_id','operation_digest',
 'request_id','request_digest','owner_session','predecessor_checkpoint_sha256','checkpoint_sha256','control_sha256',
 'marker_sha256','grant_digest','receipt_digest','result_digest']
const SESSION=['kind','owner_id','owner_subject','authorization_epoch','session_id','backend_pid','lock_key_sha256']
const match=(value,pattern)=>typeof value==='string'&&pattern.test(value)
const same=(a,b)=>canonicalJson(a)===canonicalJson(b)
const fail=reason=>{throw Object.assign(new TypeError(reason),{error_code:'INVALID'})}
const need=(value,reason)=>{if(!value)fail(reason)}
function closed(input,keys) {
 assertData(input)
 need(input&&typeof input==='object'&&!Array.isArray(input)&&Reflect.ownKeys(input).length===keys.length
  &&keys.every(key=>Object.hasOwn(input,key)),'RETAINED_MEMORY_PERMIT_FIELDS')
 return input
}
export function configureRetainedMemoryParticipant(input) {
 if(input===undefined)return null
 need(isRetainedMemoryParticipant(input),'D_OWNED_RETAINED_MEMORY_PARTICIPANT_REQUIRED')
 // D's branded object is frozen. Capture its own methods, never a caller predicate.
 const ds=Object.getOwnPropertyDescriptors(input)
 need(['prepare','dispatch','settle'].every(key=>ds[key]&&typeof ds[key].value==='function'),
  'D_OWNED_RETAINED_MEMORY_PARTICIPANT_REQUIRED')
 return Object.freeze(Object.fromEntries(['prepare','dispatch','settle'].map(key=>[key,ds[key].value.bind(input)])))
}
export function validateRetainedMemoryPermit(input,{phase,operation,ownerSubject,request_id,request_digest,grant,receipt,
 prepare,dispatch}={}) {
 const p=JSON.parse(canonicalJson(closed(input,PERMIT)))
 need(p.version===1&&p.kind==='prime-retained-memory-permit/v1'&&p.phase===phase
  &&['prepare','dispatch','settle'].includes(phase),'RETAINED_MEMORY_PERMIT_PHASE')
 need(p.owner_id===operation.owner_id&&p.owner_subject===ownerSubject&&p.authorization_epoch===operation.authorization_epoch
  &&p.operation_id===operation.operation_id&&p.operation_digest===operationDigest(operation),
 'RETAINED_MEMORY_PERMIT_OPERATION_BINDING')
 need(match(p.request_id,UUID)&&match(p.request_digest,DIGEST)
  &&(request_id===undefined||p.request_id===request_id)&&(request_digest===undefined||p.request_digest===request_digest),
 'RETAINED_MEMORY_PERMIT_REQUEST_BINDING')
 const s=closed(p.owner_session,SESSION)
 need(s.kind==='postgres-owner-session/v1'&&s.owner_id===p.owner_id&&s.owner_subject===p.owner_subject
  &&s.authorization_epoch===p.authorization_epoch&&match(s.session_id,UUID)
  &&Number.isSafeInteger(s.backend_pid)&&s.backend_pid>0&&match(s.lock_key_sha256,HEX)
  &&s.lock_key_sha256===createHash('sha256').update('aukora-prime.memory-owner-lock.v1\0'+p.owner_subject).digest('hex'),
 'RETAINED_MEMORY_PERMIT_OWNER_SESSION')
 need(match(p.predecessor_checkpoint_sha256,HEX)&&match(p.checkpoint_sha256,HEX)&&match(p.control_sha256,HEX),
  'RETAINED_MEMORY_PERMIT_CHECKPOINT')
 if(phase==='prepare') {
  need(p.checkpoint_sha256===p.predecessor_checkpoint_sha256&&match(p.marker_sha256,HEX)
   &&p.grant_digest===null&&p.receipt_digest===null&&p.result_digest===null,'RETAINED_MEMORY_PREPARE_PERMIT')
 } else {
  need(prepare&&p.predecessor_checkpoint_sha256===prepare.predecessor_checkpoint_sha256
   &&p.request_id===prepare.request_id&&p.request_digest===prepare.request_digest
   &&p.checkpoint_sha256!==p.predecessor_checkpoint_sha256&&p.grant_digest===consumedGrantDigest(grant),
  'RETAINED_MEMORY_PERMIT_PREPARED_BINDING')
  if(phase==='dispatch') {
   need(same(s,prepare.owner_session)&&match(p.marker_sha256,HEX)&&p.marker_sha256!==prepare.marker_sha256
    &&p.receipt_digest===null&&p.result_digest===null,'RETAINED_MEMORY_DISPATCH_PERMIT')
  } else {
   need(dispatch&&p.marker_sha256===null&&p.checkpoint_sha256!==dispatch.checkpoint_sha256
    &&p.control_sha256!==dispatch.control_sha256&&p.receipt_digest===memoryEffectReceiptDigest(receipt)
    &&p.result_digest===receipt.result_digest,'RETAINED_MEMORY_SETTLEMENT_PERMIT')
   // Factual reconciliation can use a fresh D-owned SQL session after restart.
  }
 }
 return deepFreeze(p)
}
export function retainedMemoryLineage(binding) {
 const {prepare,dispatch,settle}=binding
 need(prepare&&dispatch&&settle,'RETAINED_MEMORY_TERMINAL_EVIDENCE_REQUIRED')
 return {version:1,predecessor_checkpoint_sha256:prepare.predecessor_checkpoint_sha256,
  prepared_checkpoint_sha256:dispatch.checkpoint_sha256,prepared_control_sha256:dispatch.control_sha256,
  checkpoint_sha256:settle.checkpoint_sha256,control_sha256:settle.control_sha256}
}
export function validateRetainedMemoryLineage(input) {
 const value=closed(input,['version','predecessor_checkpoint_sha256','prepared_checkpoint_sha256','prepared_control_sha256',
  'checkpoint_sha256','control_sha256'])
 need(value.version===1&&Object.entries(value).every(([key,v])=>key==='version'||match(v,HEX))
  &&value.prepared_checkpoint_sha256!==value.predecessor_checkpoint_sha256
  &&value.checkpoint_sha256!==value.predecessor_checkpoint_sha256
  &&value.checkpoint_sha256!==value.prepared_checkpoint_sha256&&value.control_sha256!==value.prepared_control_sha256,
 'RETAINED_MEMORY_TERMINAL_LINEAGE')
 return value
}
export function validateRetainedMemoryRows(operations) {
 for(const row of Object.values(operations)) {
  if(!Object.hasOwn(row,'retained_memory')||Object.hasOwn(row,'schema'))continue
  const b=closed(row.retained_memory,['prepare','dispatch','settle']),op=row.operation
  need(op?.target_identity?.kind==='prime-memory'&&op.action_type?.startsWith('memory.'),
   'RETAINED_MEMORY_ROW_TARGET')
  const prepare=validateRetainedMemoryPermit(b.prepare,{phase:'prepare',operation:op,ownerSubject:op.target_identity.owner_subject})
  need(row.grant&&row.grant.operation_digest===prepare.operation_digest,'RETAINED_MEMORY_ROW_GRANT')
  if(b.dispatch!==null) {
   const dispatch=validateRetainedMemoryPermit(b.dispatch,{phase:'dispatch',operation:op,ownerSubject:prepare.owner_subject,
    request_id:row.dispatch?.request_id,request_digest:row.dispatch?.request_digest,grant:row.grant,prepare})
   need(row.dispatch&&row.dispatch.request_id===dispatch.request_id&&row.dispatch.request_digest===dispatch.request_digest,
    'RETAINED_MEMORY_ROW_DISPATCH')
   if(b.settle!==null) {
    need(row.status==='COMPLETED'&&row.dispatch.receipt,'RETAINED_MEMORY_ROW_TERMINAL')
    validateRetainedMemoryPermit(b.settle,{phase:'settle',operation:op,ownerSubject:prepare.owner_subject,
     request_id:dispatch.request_id,request_digest:dispatch.request_digest,grant:row.grant,
     receipt:row.dispatch.receipt,prepare,dispatch})
   }
  } else need(row.status==='PREPARED'&&row.dispatch===undefined&&b.settle===null,'RETAINED_MEMORY_ROW_PREPARED')
 }
}
