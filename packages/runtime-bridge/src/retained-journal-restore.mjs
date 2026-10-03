// SPDX-License-Identifier: AGPL-3.0-or-later
// Fixed journal participant for D's qualified full-control restore. D alone
// authenticates published ancestry, the owner scope, native writer guards and
// the retained transaction/publication. This module supplies no such evidence.
import {createHash} from 'node:crypto'
import {types} from 'node:util'
import {canonicalJson} from '../../contracts/src/runtime.mjs'
import {canonicalJSON as memoryCanonicalJSON} from '../../memory/genesis/plugins/aukora-kira/lib/record.mjs'
import {parseOriginal,MAX_BYTES,AURA_RECORD_DOMAIN,CHAIN_DOMAINS} from '../../memory/src/codecs.mjs'
import {closedClosureData,validateClosureProfile,validateWorkflowRow,validateWorkflowAdvance,
  parseClosureProgressBytes,validateProgressAdvance,progressDigest,WORKFLOW_FIELDS,REFERENCE_FIELDS} from './closure-v2.mjs'
import {RETAINED_JOURNAL_STATEMENTS as SQL} from './retained-journal-sql.mjs'

const CONTROL_FIELDS=Object.freeze(['schema','owner_subject','owner_id','logical_store','closure_profile','heads','tables','control_sha256'])
const TABLES=Object.freeze(['purges','requests','intents','effects','tombstones','controls','redactions','replay_fences',
  'unsent_closures','runtime_workflows','workflow_closure_progress'])
const PROGRESS_ROW_FIELDS=Object.freeze(['owner_subject','owner_id','task_id','operation_id','progress_bytes','progress_digest'])
const MUTABLE_FIELDS=Object.freeze(['record_id','phase','request_id','request_digest','receipt_digest'])
const HEX=/^[a-f0-9]{64}$/
const SUBJECT=/^aukora:1:[a-f0-9]{64}$/
const identifier=value=>typeof value==='string'&&value.length>0&&Buffer.byteLength(value,'utf8')<=1024&&!/[\x00-\x1f\x7f]/u.test(value)
const match=(value,pattern)=>typeof value==='string'&&pattern.test(value)
const same=(left,right)=>canonicalJson(left)===canonicalJson(right)
const referenceOf=row=>Object.fromEntries(REFERENCE_FIELDS.map(key=>[key,row[key]]))
const ownerParameters=row=>['owner_subject','owner_id','task_id','operation_id'].map(key=>row[key])
const hash=(domain,value)=>createHash('sha256').update(domain,'utf8').update(memoryCanonicalJSON(value),'utf8').digest('hex')
function refuse(reason) {
  throw Object.assign(new Error(reason),{error_code:'OUTCOME_UNKNOWN',reason,
    reconciliation_required:true,automatic_retry:false})
}
function requireValue(condition,reason) {if(!condition)refuse(reason)}
function exact(value,fields,reason) {
  requireValue(value&&typeof value==='object'&&!Array.isArray(value)
    &&Object.keys(value).length===fields.length&&fields.every(key=>Object.hasOwn(value,key)),reason)
}

// Full D control projections use D's existing 64 MiB representation, rather
// than the smaller contract/progress parser limit. Refuse executable objects
// before encoding; preserve D's donor number/byte representation unchanged.
function copyControl(input) {
  const ancestors=new WeakSet();let size=0,count=0
  function inspect(value,depth) {
    requireValue(depth<=64&&++count<=1000000,'RETAINED_RESTORE_DATA_LIMIT')
    if(typeof value==='string')size+=Buffer.byteLength(value,'utf8')
    if(typeof value==='number')requireValue(Number.isFinite(value)
      &&(!Number.isInteger(value)||Number.isSafeInteger(value))&&!Object.is(value,-0),'RETAINED_RESTORE_NUMBER_INVALID')
    if(value===null||['string','number','boolean'].includes(typeof value)) {
      requireValue(size<=MAX_BYTES,'RETAINED_RESTORE_DATA_LIMIT');return
    }
    requireValue(value&&typeof value==='object'&&!types.isProxy(value)&&!ancestors.has(value),'RETAINED_RESTORE_INERT_DATA_REQUIRED')
    const array=Array.isArray(value),prototype=Object.getPrototypeOf(value)
    requireValue(array?prototype===Array.prototype:prototype===Object.prototype||prototype===null,'RETAINED_RESTORE_INERT_DATA_REQUIRED')
    if(array)requireValue(value.length<=10000,'RETAINED_RESTORE_ROW_LIMIT')
    ancestors.add(value)
    for(const key of Reflect.ownKeys(value)) {
      const descriptor=Object.getOwnPropertyDescriptor(value,key)
      requireValue(typeof key==='string'&&descriptor&&Object.hasOwn(descriptor,'value')
        &&(descriptor.enumerable||array&&key==='length'),'RETAINED_RESTORE_INERT_DATA_REQUIRED')
      if(array&&key==='length')continue
      if(array)requireValue(/^(?:0|[1-9][0-9]*)$/.test(key),'RETAINED_RESTORE_INERT_DATA_REQUIRED')
      size+=Buffer.byteLength(key,'utf8');requireValue(size<=MAX_BYTES,'RETAINED_RESTORE_DATA_LIMIT')
      inspect(descriptor.value,depth+1)
    }
    if(array)requireValue(Object.keys(value).length===value.length,'RETAINED_RESTORE_INERT_DATA_REQUIRED')
    ancestors.delete(value)
  }
  inspect(input,0)
  const bytes=Buffer.from(memoryCanonicalJSON(input),'utf8')
  requireValue(bytes.length<=MAX_BYTES,'RETAINED_RESTORE_DATA_LIMIT')
  return parseOriginal(bytes)
}
function order(left,right) {return Buffer.compare(Buffer.from(left.operation_id,'utf8'),Buffer.from(right.operation_id,'utf8'))}
function sorted(rows) {return [...rows].sort(order)}
function indexRows(rows,name) {
  const map=new Map()
  for(const row of rows) {
    requireValue(!map.has(row.operation_id),'RETAINED_RESTORE_DUPLICATE_'+name)
    map.set(row.operation_id,row)
  }
  return map
}
const byteHash=bytes=>createHash('sha256').update(bytes).digest('hex')
const encodeProgressBytes=bytes=>({bytes_base64:bytes.toString('base64'),sha256:byteHash(bytes)})
// This is D's exact portable byte-column pair, not another JSON buffer form.
function decodeProgressBytes(input) {
  const encoded=closedClosureData(input,['bytes_base64','sha256'])
  requireValue(typeof encoded.bytes_base64==='string'&&match(encoded.sha256,HEX),'RETAINED_RESTORE_PROGRESS_ENCODING_INVALID')
  const bytes=Buffer.from(encoded.bytes_base64,'base64')
  requireValue(bytes.toString('base64')===encoded.bytes_base64&&byteHash(bytes)===encoded.sha256,
    'RETAINED_RESTORE_PROGRESS_ENCODING_CHANGED')
  return bytes
}
// Only the native SQL bytea boundary accepts Buffer. Generic retained JSON
// remains inert and continues to refuse Buffers, proxies and accessors.
function nativeProgressRow(input) {
  requireValue(input&&typeof input==='object'&&!types.isProxy(input)&&!Array.isArray(input)
    &&[Object.prototype,null].includes(Object.getPrototypeOf(input)),'RETAINED_RESTORE_NATIVE_PROGRESS_INVALID')
  const descriptors=Object.getOwnPropertyDescriptors(input)
  requireValue(Reflect.ownKeys(descriptors).length===PROGRESS_ROW_FIELDS.length
    &&PROGRESS_ROW_FIELDS.every(key=>descriptors[key]&&descriptors[key].enumerable&&Object.hasOwn(descriptors[key],'value')),
    'RETAINED_RESTORE_NATIVE_PROGRESS_INVALID')
  const native=descriptors.progress_bytes.value
  requireValue(native&&typeof native==='object'&&!types.isProxy(native)&&Buffer.isBuffer(native)
    &&Object.getPrototypeOf(native)===Buffer.prototype
    &&Reflect.ownKeys(native).every(key=>typeof key==='string'&&/^(?:0|[1-9][0-9]*)$/.test(key)),
    'RETAINED_RESTORE_NATIVE_PROGRESS_BYTES_REQUIRED')
  const bytes=Buffer.from(native)
  const row=Object.fromEntries(PROGRESS_ROW_FIELDS.map(key=>[key,key==='progress_bytes'
    ?encodeProgressBytes(bytes):descriptors[key].value]))
  return closedClosureData(row,PROGRESS_ROW_FIELDS)
}
function progressRow(input,workflow,profile) {
  const row=closedClosureData(input,PROGRESS_ROW_FIELDS)
  requireValue(workflow&&['owner_subject','owner_id','task_id','operation_id'].every(key=>row[key]===workflow[key]),
    'RETAINED_RESTORE_PROGRESS_BINDING_INVALID')
  const bytes=decodeProgressBytes(row.progress_bytes),progress=parseClosureProgressBytes(bytes,profile)
  requireValue(bytes.equals(Buffer.from(canonicalJson(progress),'utf8'))&&progressDigest(progress)===row.progress_digest
    &&same(progress.reference,referenceOf(workflow))&&progress.idempotency_key_sha256===workflow.idempotency_key_sha256,
    'RETAINED_RESTORE_PROGRESS_BYTES_INVALID')
  requireValue(workflow.phase===(progress.stage==='complete'?'known_unsent':'attempted'),'RETAINED_RESTORE_PHASE_PROGRESS_CONFLICT')
  return {row,bytes,progress}
}
function projection(input,profile) {
  const control=copyControl(input)
  exact(control,CONTROL_FIELDS,'RETAINED_RESTORE_CONTROL_FIELDS_INVALID')
  requireValue(control.schema==='aukora-prime-memory-control-state/v3'&&match(control.owner_subject,SUBJECT)
    &&identifier(control.owner_id),'RETAINED_RESTORE_CONTROL_OWNER_INVALID')
  requireValue(same(validateClosureProfile(control.closure_profile),profile),'RETAINED_RESTORE_PROFILE_CHANGED')
  exact(control.logical_store,['metadata','metadata_digest'],'RETAINED_RESTORE_LOGICAL_STORE_INVALID')
  const metadata=control.logical_store.metadata
  exact(metadata,['version','kind','store_id'],'RETAINED_RESTORE_LOGICAL_STORE_INVALID')
  requireValue(metadata.version===1&&metadata.kind==='prime-memory-logical-store/v1'
    &&metadata.store_id===profile.expected_memory_store_id
    &&control.logical_store.metadata_digest==='sha256:'+hash('aukora-prime.memory-logical-store.v1\0',metadata),
    'RETAINED_RESTORE_LOGICAL_STORE_CHANGED')
  requireValue(control.heads&&typeof control.heads==='object'&&!Array.isArray(control.heads)
    &&Object.entries(control.heads).every(([domain,head])=>CHAIN_DOMAINS.includes(domain)
      &&(head===AURA_RECORD_DOMAIN||match(head,HEX))),'RETAINED_RESTORE_HEADS_INVALID')
  exact(control.tables,TABLES,'RETAINED_RESTORE_TABLES_INVALID')
  requireValue(TABLES.every(name=>Array.isArray(control.tables[name])),'RETAINED_RESTORE_TABLES_INVALID')
  const {control_sha256:digest,...body}=control
  requireValue(match(digest,HEX)&&digest===hash('aukora-prime.memory-control-state.v3\0',body),'RETAINED_RESTORE_CONTROL_DIGEST_INVALID')
  const workflows=control.tables.runtime_workflows.map(inputRow=>{
    const row=validateWorkflowRow(inputRow)
    requireValue(row.owner_subject===control.owner_subject&&row.owner_id===control.owner_id,'RETAINED_RESTORE_WORKFLOW_OWNER_CHANGED')
    return row
  })
  const owned=indexRows(workflows,'WORKFLOW'),keys=new Set()
  for(const row of workflows)if(row.idempotency_key_sha256!==null) {
    const key=canonicalJson([row.task_id,row.idempotency_key_sha256])
    requireValue(!keys.has(key),'RETAINED_RESTORE_IDEMPOTENCY_KEY_REUSED');keys.add(key)
  }
  const progress=control.tables.workflow_closure_progress.map(row=>progressRow(row,owned.get(row.operation_id),profile))
  const stages=indexRows(progress.map(entry=>entry.row),'PROGRESS')
  for(const row of workflows)requireValue(row.phase!=='known_unsent'||stages.has(row.operation_id),'RETAINED_RESTORE_COMPLETE_PROGRESS_MISSING')
  return {control,workflows:sorted(workflows),owned,progress:progress.sort((a,b)=>order(a.row,b.row)),
    stages:new Map(progress.map(entry=>[entry.row.operation_id,entry]))}
}
function validateStep(before,after,profile) {
  requireValue(before.control.owner_id===after.control.owner_id&&before.control.owner_subject===after.control.owner_subject
    &&same(before.control.logical_store,after.control.logical_store),'RETAINED_RESTORE_OWNER_OR_STORE_CHANGED')
  for(const row of before.workflows)requireValue(after.owned.has(row.operation_id),'RETAINED_RESTORE_WORKFLOW_DROPPED')
  for(const entry of before.progress)requireValue(after.stages.has(entry.row.operation_id),'RETAINED_RESTORE_PROGRESS_DROPPED')
  for(const row of after.workflows) {
    const prior=before.owned.get(row.operation_id)??null,oldStage=before.stages.get(row.operation_id)??null,newStage=after.stages.get(row.operation_id)??null
    if(newStage) {
      requireValue(prior!==null,'RETAINED_RESTORE_PROGRESS_WITHOUT_PRIOR_ATTEMPT')
      validateProgressAdvance(oldStage?.progress??null,newStage.progress,profile,undefined,oldStage?.row.progress_digest??null)
      if(newStage.progress.stage==='complete'&&oldStage?.progress.stage!=='complete') {
        requireValue(prior.phase==='attempted'&&row.phase==='known_unsent'
          &&WORKFLOW_FIELDS.filter(key=>key!=='phase').every(key=>same(prior[key],row[key])),
          'RETAINED_RESTORE_TERMINAL_PHASE_INVALID')
      } else requireValue(same(prior,row),'RETAINED_RESTORE_CLOSURE_WORKFLOW_CHANGED')
    } else if(prior?.phase==='known_unsent') {
      refuse('RETAINED_RESTORE_COMPLETE_PROGRESS_MISSING')
    } else validateWorkflowAdvance(prior,row)
  }
}
async function query(tx,statement,parameters,single=false) {
  const result=await tx.query(statement,parameters)
  requireValue(result&&Array.isArray(result.rows)&&(!Object.hasOwn(result,'rowCount')||result.rowCount===result.rows.length)
    &&(!single||result.rows.length<=1),'RETAINED_RESTORE_SQL_RESULT_INVALID')
  return result.rows
}
async function assertActual(tx,expected,profile) {
  const owner=[expected.control.owner_subject,expected.control.owner_id]
  const workflows=(await query(tx,SQL.lockOwnerWorkflows,owner)).map(row=>validateWorkflowRow(row))
  const owned=indexRows(workflows,'LOCAL_WORKFLOW')
  const progress=(await query(tx,SQL.lockOwnerProgress,owner)).map(input=>{
    const row=nativeProgressRow(input)
    return progressRow(row,owned.get(row.operation_id),profile)
  })
  indexRows(progress.map(entry=>entry.row),'LOCAL_PROGRESS')
  requireValue(same(sorted(workflows),expected.workflows)
    &&same(sorted(progress.map(entry=>entry.row)),expected.progress.map(entry=>entry.row)),
    'RETAINED_RESTORE_LOCAL_BASELINE_CHANGED')
}
async function applyStep(tx,before,after) {
  for(const row of after.workflows) {
    const prior=before.owned.get(row.operation_id)??null
    // A complete progress step owns its paired attempted->known_unsent CAS.
    if(after.stages.has(row.operation_id)||prior!==null&&same(prior,row))continue
    const rows=prior===null
      ?await query(tx,SQL.insertWorkflow,WORKFLOW_FIELDS.map(key=>row[key]),true)
      :await query(tx,SQL.updateWorkflow,[...WORKFLOW_FIELDS.map(key=>prior[key]),...MUTABLE_FIELDS.map(key=>row[key])],true)
    requireValue(rows.length===1&&same(validateWorkflowRow(rows[0]),row),'RETAINED_RESTORE_WORKFLOW_CAS_REFUSED')
  }
  for(const entry of after.progress) {
    const prior=before.stages.get(entry.row.operation_id)??null
    if(prior&&same(prior.row,entry.row))continue
    const workflow=before.owned.get(entry.row.operation_id),parameters=ownerParameters(entry.row)
    let rows
    if(prior===null)rows=await query(tx,SQL.insertProgress,[...parameters,entry.bytes,entry.row.progress_digest],true)
    else if(entry.progress.stage==='complete')rows=await query(tx,SQL.completeProgress,[...WORKFLOW_FIELDS.map(key=>workflow[key]),
      prior.bytes,prior.row.progress_digest,prior.progress.stage,entry.bytes,entry.row.progress_digest],true)
    else rows=await query(tx,SQL.updateProgress,[...parameters,prior.bytes,prior.row.progress_digest,
      prior.progress.stage,entry.bytes,entry.row.progress_digest],true)
    requireValue(rows.length===1&&same(nativeProgressRow(rows[0]),entry.row),'RETAINED_RESTORE_PROGRESS_CAS_REFUSED')
  }
}

/** D calls this only inside its qualified full restore, with the original live
 * owner facade and ordered published projections from the verified local
 * ancestor (first) through the current retained anchor (last). No serialized
 * authentication flag, verifier callback or caller-selected anchor is accepted.
 * D's qualified lineage reader must bound the complete ancestry's cumulative
 * bytes and entries before this call. This helper bounds each projection and
 * entry count; those local limits do not establish an aggregate lineage bound.
 * Successful return is undefined, never restoration or retained evidence. */
export async function restoreRetainedJournal(tx,ancestry,inputProfile) {
  requireValue(tx&&typeof tx.query==='function','RETAINED_RESTORE_D_SCOPE_REQUIRED')
  requireValue(Array.isArray(ancestry)&&!types.isProxy(ancestry)&&Object.getPrototypeOf(ancestry)===Array.prototype
    &&ancestry.length>0&&ancestry.length<=10000,'RETAINED_RESTORE_ANCESTRY_REQUIRED')
  // Freeze every complete source projection before the first query or await.
  const profile=validateClosureProfile(inputProfile),path=[]
  requireValue(Reflect.ownKeys(ancestry).every(key=>typeof key==='string'&&(key==='length'||/^(?:0|[1-9][0-9]*)$/.test(key)))
    &&Object.keys(ancestry).length===ancestry.length,'RETAINED_RESTORE_ANCESTRY_INVALID')
  for(let index=0;index<ancestry.length;index++) {
    const descriptor=Object.getOwnPropertyDescriptor(ancestry,String(index))
    requireValue(descriptor&&descriptor.enumerable&&Object.hasOwn(descriptor,'value'),'RETAINED_RESTORE_ANCESTRY_INVALID')
    path.push(projection(descriptor.value,profile))
    if(index>0)validateStep(path[index-1],path[index],profile)
  }
  await assertActual(tx,path[0],profile)
  for(let index=1;index<path.length;index++) {
    await applyStep(tx,path[index-1],path[index])
    await assertActual(tx,path[index],profile)
  }
}
