// SPDX-License-Identifier: AGPL-3.0-or-later
// Pure private-v2 checks selected by closure-interface-decision-v004-private-v2.
// Valid bytes do not establish protected provenance, retained publication,
// PostgreSQL fencing or permission. Those checks belong to the C/D participants.
import {createHash} from 'node:crypto'
import {types} from 'node:util'
import {canonicalJson,parseStrictJson,MAX_JSON_BYTES,MAX_JSON_DEPTH} from '../../contracts/src/runtime.mjs'
import {validateAuthorityUnconsumedClosure,AUTHORITY_UNCONSUMED_CLOSURE_FIELDS} from './unsent-closure.mjs'
// D uses its donor encoding. Its marker/completion hash must not silently use JCS.
import {canonicalJSON as memoryCanonicalJSON} from '../../memory/genesis/plugins/aukora-kira/lib/record.mjs'

export const WORKFLOW_FIELDS=Object.freeze(['owner_subject','owner_id','task_id','operation_id','operation_digest','action_type',
  'idempotency_key_sha256','record_id','phase','request_id','request_digest','receipt_digest','created_at'])
export const REFERENCE_FIELDS=Object.freeze(['owner_id','owner_subject','task_id','operation_id','operation_digest','action_type'])
export const PROFILE_FIELDS=Object.freeze(['version','kind','expected_authority_store_id','expected_memory_store_id','retention_profile'])
export const HOST_FIELDS=Object.freeze(['owner_id','owner_subject','task_id','authorization_epoch'])
export const PROGRESS_FIELDS=Object.freeze(['version','kind','reference','idempotency_key_sha256','closure_attempt_id',
  'expected_authority_store_id','expected_memory_store_id','closing_authorization_epoch','stage','authority','memory'])
export const ATTEMPT_FIELDS=Object.freeze(['reference','idempotency_key_sha256','expected_authority_store_id',
  'expected_memory_store_id','closing_authorization_epoch'])
export const NORMAL_TRANSITION_FIELDS=Object.freeze(['version','kind','memory_store_id','reference','idempotency_key_sha256',
  'expected_checkpoint_sha256','previous_workflow_digest','target_workflow'])
export const JOURNAL_TRANSITION_FIELDS=Object.freeze(['version','kind','memory_store_id','reference','idempotency_key_sha256',
  'expected_checkpoint_sha256','previous_progress_digest','target_stage','target_progress'])
export const MEMORY_CLOSURE_FIELDS=Object.freeze(['version','kind','store_id',...REFERENCE_FIELDS,'authorization_epoch','closure_id',
  'writer_closed','intent_absent','effect_absent','grants_authority'])
export const MEMORY_REPLY_FIELDS=Object.freeze(['status','closure','closure_digest','completion','completion_digest','idempotent','grants_authority'])
const AUTHORITY_FIELDS=Object.freeze(['closure','closure_digest'])
const MEMORY_FIELDS=Object.freeze(['closure','closure_digest','completion','completion_digest'])
const COMPLETION_FIELDS=Object.freeze(['version','kind','store_id','closure_digest','retention'])
const RETENTION_FIELDS=Object.freeze(['version','kind','checkpoint_sha256','control_sha256','authorization_epoch'])
const STAGES=Object.freeze(['started','authority_confirmed','memory_confirmed','complete'])
const PHASES=Object.freeze(['proposed','attempted','known_unsent','saved','forgotten'])
const ACTIONS=Object.freeze(['memory.save','memory.forget'])
const METADATA=Object.freeze(['record_id','request_id','request_digest','receipt_digest'])
const DIGEST=/^sha256:[a-f0-9]{64}$/
const HEX=/^[a-f0-9]{64}$/
const SUBJECT=/^aukora:1:[a-f0-9]{64}$/
const UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/
const INSTANT=/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/
const UTF8=new TextDecoder('utf-8',{fatal:true,ignoreBOM:true})
const matches=(value,pattern)=>typeof value==='string'&&pattern.test(value)
const uint=value=>Number.isSafeInteger(value)&&value>=0&&!Object.is(value,-0)
const identifier=value=>typeof value==='string'&&value.length>0&&Buffer.byteLength(value,'utf8')<=1024&&!/[\x00-\x1f\x7f]/u.test(value)
const same=(a,b)=>canonicalJson(a)===canonicalJson(b)
function requireValue(condition,reason) {
  if(!condition)throw Object.assign(new TypeError('Invalid private-v2 closure: '+reason),{
    code:'closure-v2:'+reason,error_code:'OUTCOME_UNKNOWN',reconciliation_required:true,automatic_retry:false,
  })
}
function hash(domain,value,encode=canonicalJson) {
  return 'sha256:'+createHash('sha256').update(domain,'utf8').update(encode(value),'utf8').digest('hex')
}
function freeze(value) {
  if(value&&typeof value==='object') {for(const child of Object.values(value))freeze(child);Object.freeze(value)}
  return value
}
/** Refuse proxies/accessors before reflection or encoding; detach all accepted data. */
export function copyClosureData(input) {
  const ancestors=new WeakSet();let count=0
  function inspect(value,depth) {
    requireValue(depth<=MAX_JSON_DEPTH&&++count<=100000,'data-limit')
    if(value===null||typeof value!=='object')return
    requireValue(!types.isProxy(value)&&!ancestors.has(value),'inert-data-required')
    const array=Array.isArray(value),prototype=Object.getPrototypeOf(value)
    requireValue(array?prototype===Array.prototype:prototype===Object.prototype||prototype===null,'data-prototype')
    ancestors.add(value)
    for(const key of Reflect.ownKeys(value)) {
      const descriptor=Object.getOwnPropertyDescriptor(value,key)
      requireValue(typeof key==='string'&&descriptor&&Object.hasOwn(descriptor,'value')
        &&(descriptor.enumerable||array&&key==='length'),'data-property')
      if(!(array&&key==='length'))inspect(descriptor.value,depth+1)
    }
    ancestors.delete(value)
  }
  inspect(input,0)
  const text=canonicalJson(input)
  requireValue(Buffer.byteLength(text,'utf8')<=MAX_JSON_BYTES,'data-size')
  return freeze(parseStrictJson(text))
}
export const freezeClosureData=copyClosureData
export function closedClosureData(input,fields) {
  const value=copyClosureData(input)
  requireValue(value&&typeof value==='object'&&!Array.isArray(value)&&Object.keys(value).length===fields.length
    &&fields.every(key=>Object.hasOwn(value,key)),'closed-fields')
  return value
}
function ref(input,host) {
  const value=closedClosureData(input,REFERENCE_FIELDS)
  requireValue(['owner_id','owner_subject','task_id','operation_id'].every(key=>identifier(value[key]))
    &&matches(value.owner_subject,SUBJECT)&&matches(value.operation_digest,DIGEST)&&ACTIONS.includes(value.action_type),'reference')
  if(host)requireValue(['owner_id','owner_subject','task_id'].every(key=>value[key]===host[key]),'reference-host')
  return value
}
export function validateClosureReference(value,host) {return ref(value,host===undefined?undefined:validateClosureHost(host))}
export function validateClosureProfile(input) {
  const value=closedClosureData(input,PROFILE_FIELDS)
  requireValue(value.version===2&&value.kind==='prime-private-unsent-closure/v2'
    &&value.retention_profile==='required-retained/v2'&&matches(value.expected_authority_store_id,HEX)
    &&matches(value.expected_memory_store_id,HEX),'profile')
  return value
}
export function validateClosureHost(input) {
  const value=closedClosureData(input,HOST_FIELDS)
  requireValue(['owner_id','owner_subject','task_id'].every(key=>identifier(value[key]))
    &&matches(value.owner_subject,SUBJECT)&&uint(value.authorization_epoch),'host')
  return value
}
function nullableDigest(value,raw=false) {return value===null||matches(value,raw?HEX:DIGEST)}
function instant(value) {return matches(value,INSTANT)&&Number.isFinite(Date.parse(value))&&new Date(value).toISOString()===value}
export function validateWorkflowRow(input,inputHost) {
  const value=closedClosureData(input,WORKFLOW_FIELDS),host=inputHost===undefined?undefined:validateClosureHost(inputHost)
  ref(Object.fromEntries(REFERENCE_FIELDS.map(key=>[key,value[key]])),host)
  requireValue(PHASES.includes(value.phase)&&nullableDigest(value.idempotency_key_sha256,true)
    &&(value.record_id===null||identifier(value.record_id))&&(value.request_id===null||identifier(value.request_id))
    &&nullableDigest(value.request_digest)&&nullableDigest(value.receipt_digest)&&instant(value.created_at)
    &&(value.request_id===null)===(value.request_digest===null),'workflow-row')
  requireValue(value.action_type!=='memory.forget'||value.idempotency_key_sha256===null&&value.record_id!==null,'forget-reference')
  requireValue(value.phase!=='saved'||value.action_type==='memory.save','saved-action')
  requireValue(value.phase!=='forgotten'||value.action_type==='memory.forget','forgotten-action')
  if(['saved','forgotten'].includes(value.phase)) {
    requireValue(METADATA.every(key=>value[key]!==null),'effect-metadata')
  } else {
    requireValue(['request_id','request_digest','receipt_digest'].every(key=>value[key]===null)
      &&(value.action_type!=='memory.save'||value.record_id===null),'uneffected-metadata')
  }
  return value
}
export function workflowDigest(value) {return hash('aukora-prime.runtime-workflow-row.v3\0',validateWorkflowRow(value))}
/** Normal history only. Negative terminal promotion belongs to completeClosure. */
export function validateWorkflowAdvance(inputBefore,inputAfter) {
  const after=validateWorkflowRow(inputAfter)
  requireValue(after.phase!=='known_unsent','normal-known-unsent')
  if(inputBefore===null) {
    requireValue(after.phase==='proposed'&&['request_id','request_digest','receipt_digest'].every(key=>after[key]===null)
      &&(after.action_type==='memory.save'?after.record_id===null:after.record_id!==null),'initial-workflow')
    return after
  }
  const before=validateWorkflowRow(inputBefore)
  requireValue(before.phase!=='known_unsent','normal-closed-workflow')
  requireValue([...REFERENCE_FIELDS,'idempotency_key_sha256','created_at'].every(key=>same(before[key],after[key])),'workflow-immutable')
  requireValue(METADATA.every(key=>before[key]===null||before[key]===after[key]),'workflow-metadata-immutable')
  if(same(before,after))return after
  if(before.phase==='proposed') {
    requireValue(after.phase==='attempted'&&WORKFLOW_FIELDS.filter(key=>key!=='phase').every(key=>same(before[key],after[key])),'workflow-attempt')
  } else {
    const terminal=after.action_type==='memory.save'?'saved':'forgotten'
    requireValue((before.phase==='attempted'||before.phase===terminal)&&after.phase===terminal
      &&METADATA.every(key=>after[key]!==null),'workflow-settlement')
  }
  return after
}
function authorityProjection(input,inputReference,profile) {
  const value=closedClosureData(input,AUTHORITY_FIELDS),reference=ref(inputReference),marker=value.closure
  closedClosureData(marker,AUTHORITY_UNCONSUMED_CLOSURE_FIELDS)
  requireValue(marker.version===1&&marker.kind==='prime-authority-never-consumed/v1'&&matches(marker.store_id,HEX)
    &&['owner_id','owner_subject','task_id','operation_id','operation_digest'].every(key=>marker[key]===reference[key])
    &&uint(marker.authorization_epoch)&&instant(marker.closed_at)&&uint(marker.broker_revision)&&marker.broker_revision>=1
    &&uint(marker.kernel_receipt_count)&&(marker.kernel_receipt_count===0?marker.kernel_receipt_head===null:matches(marker.kernel_receipt_head,HEX))
    &&matches(value.closure_digest,DIGEST)
    &&value.closure_digest===hash('aukora-prime.authority-never-consumed.v1\0',marker),'authority-projection')
  if(profile)requireValue(marker.store_id===profile.expected_authority_store_id,'authority-store')
  return value
}
/** Stored C2 has no full operation; fresh C reads must validate it transiently. */
export function validateAuthorityProjection(value,reference,profile) {return authorityProjection(value,reference,validateClosureProfile(profile))}
export function validateAuthorityClosureReply(value,reference,profile) {
  const selected=validateClosureProfile(profile),reply=validateAuthorityUnconsumedClosure(ref(reference),value)
  authorityProjection({closure:reply.closure,closure_digest:reply.closure_digest},reference,selected)
  return reply
}
function memoryProjection(input,inputReference,profile,epoch) {
  const value=closedClosureData(input,MEMORY_FIELDS),reference=ref(inputReference),marker=value.closure,completion=value.completion
  closedClosureData(marker,MEMORY_CLOSURE_FIELDS)
  requireValue(uint(epoch)&&marker.version===2&&marker.kind==='prime-memory-writer-closure/v2'&&matches(marker.store_id,HEX)
    &&REFERENCE_FIELDS.every(key=>marker[key]===reference[key])&&marker.authorization_epoch===epoch
    &&matches(marker.closure_id,UUID)&&marker.writer_closed===true&&marker.intent_absent===true&&marker.effect_absent===true
    &&marker.grants_authority===false&&matches(value.closure_digest,DIGEST)
    &&value.closure_digest===hash('aukora-prime.memory-writer-closure.v2\0',marker,memoryCanonicalJSON),'memory-closure')
  if(profile)requireValue(marker.store_id===profile.expected_memory_store_id,'memory-store')
  closedClosureData(completion,COMPLETION_FIELDS)
  requireValue(completion.version===2&&completion.kind==='prime-memory-writer-completion/v2'&&completion.store_id===marker.store_id
    &&completion.closure_digest===value.closure_digest,'memory-completion')
  const retention=closedClosureData(completion.retention,RETENTION_FIELDS)
  requireValue(retention.version===2&&retention.kind==='prime-memory-writer-retention/v2'
    &&matches(retention.checkpoint_sha256,HEX)&&matches(retention.control_sha256,HEX)
    &&uint(retention.authorization_epoch)&&retention.authorization_epoch===epoch,'memory-retention')
  requireValue(matches(value.completion_digest,DIGEST)
    &&value.completion_digest===hash('aukora-prime.memory-writer-completion.v2\0',completion,memoryCanonicalJSON),'memory-completion-digest')
  return value
}
export function validateMemoryProjection(value,reference,profile,epoch) {return memoryProjection(value,reference,validateClosureProfile(profile),epoch)}
export function validateMemoryClosureReply(input,reference,profile,epoch) {
  const value=closedClosureData(input,MEMORY_REPLY_FIELDS)
  requireValue(value.status==='closed-unsent'&&typeof value.idempotent==='boolean'&&value.grants_authority===false,'memory-reply')
  validateMemoryProjection(Object.fromEntries(MEMORY_FIELDS.map(key=>[key,value[key]])),reference,profile,epoch)
  return value
}
function attempt(input) {
  const value=closedClosureData(input,ATTEMPT_FIELDS)
  ref(value.reference)
  requireValue(nullableDigest(value.idempotency_key_sha256,true)&&matches(value.expected_authority_store_id,HEX)
    &&matches(value.expected_memory_store_id,HEX)&&uint(value.closing_authorization_epoch),'attempt-binding')
  requireValue(value.reference.action_type!=='memory.forget'||value.idempotency_key_sha256===null,'attempt-forget-key')
  return value
}
export function closureAttemptId(input) {
  const value=copyClosureData(input)
  // Accept only the exact immutable projection or exact closed progress shape.
  const fields=Object.keys(value??{})
  let projection
  if(fields.length===ATTEMPT_FIELDS.length)projection=attempt(value)
  else {
    closedClosureData(value,PROGRESS_FIELDS)
    projection=attempt(Object.fromEntries(ATTEMPT_FIELDS.map(key=>[key,value[key]])))
  }
  return hash('aukora-prime.runtime-unsent-closure-attempt.v2\0',projection)
}
function progress(input,profile,inputHost) {
  const value=closedClosureData(input,PROGRESS_FIELDS),host=inputHost===undefined?undefined:validateClosureHost(inputHost)
  const reference=ref(value.reference,host)
  attempt(Object.fromEntries(ATTEMPT_FIELDS.map(key=>[key,value[key]])))
  requireValue(value.version===2&&value.kind==='prime-runtime-unsent-closure-progress/v2'&&STAGES.includes(value.stage)
    &&value.closure_attempt_id===closureAttemptId(value),'progress-binding')
  if(profile)requireValue(value.expected_authority_store_id===profile.expected_authority_store_id
    &&value.expected_memory_store_id===profile.expected_memory_store_id,'progress-profile')
  if(host)requireValue(value.closing_authorization_epoch===host.authorization_epoch,'progress-host-epoch')
  const stage=STAGES.indexOf(value.stage)
  if(stage===0)requireValue(value.authority===null,'started-authority')
  else {
    const authority=authorityProjection(value.authority,reference,profile)
    requireValue(authority.closure.store_id===value.expected_authority_store_id,'progress-authority-store')
  }
  if(stage<2)requireValue(value.memory===null,'early-memory')
  else {
    const memory=memoryProjection(value.memory,reference,profile,value.closing_authorization_epoch)
    requireValue(memory.closure.store_id===value.expected_memory_store_id,'progress-memory-store')
  }
  return value
}
export function validateClosureProgress(value,profile,host) {return progress(value,validateClosureProfile(profile),host)}
// Syntax-only entry points are for fixed SQL already validated by D's protected
// participant. They cannot establish configured profile equality or provenance.
export function validateClosureProgressSyntax(value) {return progress(value)}
export function progressDigest(value) {return hash('aukora-prime.runtime-unsent-closure-progress.v2\0',progress(value))}
function progressAdvance(inputBefore,inputAfter,profile,inputHost,expectedDigest) {
  const after=progress(inputAfter,profile,inputHost)
  if(expectedDigest!==undefined)requireValue(nullableDigest(expectedDigest),'progress-cas-digest')
  if(inputBefore===null) {
    requireValue(after.stage==='started'&&(expectedDigest===undefined||expectedDigest===null),'initial-progress')
    return after
  }
  const before=progress(inputBefore,profile,inputHost)
  requireValue([...ATTEMPT_FIELDS,'closure_attempt_id'].every(key=>same(before[key],after[key])),'progress-immutable')
  if(expectedDigest!==undefined)requireValue(expectedDigest===progressDigest(before),'progress-cas')
  // Duplicate bodies still require the caller's exact supplied prior digest.
  if(same(before,after))return after
  requireValue(STAGES.indexOf(after.stage)===STAGES.indexOf(before.stage)+1,'progress-stage')
  requireValue(before.authority===null||same(before.authority,after.authority),'authority-immutable')
  requireValue(before.memory===null||same(before.memory,after.memory),'memory-immutable')
  return after
}
export function validateProgressAdvance(before,after,profile,host,expectedDigest) {
  return progressAdvance(before,after,validateClosureProfile(profile),host,expectedDigest)
}
/** Only for fixed SQL under D's independently validated configured participant. */
export function validateProgressAdvanceSyntax(before,after,expectedDigest) {
  return progressAdvance(before,after,undefined,undefined,expectedDigest)
}
export function parseClosureProgressBytes(input,profile,host) {
  requireValue(input&&typeof input==='object'&&!types.isProxy(input)
    &&(Object.getPrototypeOf(input)===Buffer.prototype||Object.getPrototypeOf(input)===Uint8Array.prototype),'progress-bytes')
  requireValue(Reflect.ownKeys(input).every(key=>typeof key==='string'&&/^(?:0|[1-9][0-9]*)$/.test(key)),'progress-bytes-properties')
  const bytes=Buffer.from(input)
  requireValue(bytes.length>0&&bytes.length<=MAX_JSON_BYTES,'progress-bytes-size')
  const text=UTF8.decode(bytes),value=parseStrictJson(text)
  requireValue(text===canonicalJson(value),'progress-canonical-bytes')
  return validateClosureProgress(value,profile,host)
}
function normalTransition(input,profile) {
  const value=closedClosureData(input,NORMAL_TRANSITION_FIELDS),reference=ref(value.reference),row=validateWorkflowRow(value.target_workflow)
  requireValue(value.version===3&&value.kind==='prime-runtime-workflow-mutation/v3'&&matches(value.memory_store_id,HEX)
    &&matches(value.expected_checkpoint_sha256,HEX)&&nullableDigest(value.previous_workflow_digest)
    &&nullableDigest(value.idempotency_key_sha256,true)&&REFERENCE_FIELDS.every(key=>row[key]===reference[key])
    &&row.idempotency_key_sha256===value.idempotency_key_sha256&&row.phase!=='known_unsent','normal-transition')
  if(profile)requireValue(value.memory_store_id===profile.expected_memory_store_id,'normal-transition-store')
  if(value.previous_workflow_digest===null)validateWorkflowAdvance(null,row)
  else if(['saved','forgotten'].includes(row.phase))requireValue(METADATA.every(key=>row[key]!==null),'normal-terminal-metadata')
  return value
}
export function validateNormalTransition(value,profile) {return normalTransition(value,validateClosureProfile(profile))}
export function validateNormalTransitionSyntax(value) {return normalTransition(value)}
export function normalTransitionDigest(value) {return hash('aukora-prime.runtime-workflow-mutation.v3\0',normalTransition(value))}
function journalTransition(input,profile) {
  const value=closedClosureData(input,JOURNAL_TRANSITION_FIELDS),reference=ref(value.reference),target=progress(value.target_progress,profile)
  requireValue(value.version===3&&value.kind==='prime-runtime-unsent-journal-transition/v3'&&matches(value.memory_store_id,HEX)
    &&matches(value.expected_checkpoint_sha256,HEX)&&nullableDigest(value.previous_progress_digest)
    &&nullableDigest(value.idempotency_key_sha256,true)&&same(reference,target.reference)
    &&target.idempotency_key_sha256===value.idempotency_key_sha256&&value.memory_store_id===target.expected_memory_store_id
    &&value.target_stage===target.stage&&(value.previous_progress_digest!==null||target.stage==='started'),'journal-transition')
  if(profile)requireValue(value.memory_store_id===profile.expected_memory_store_id,'journal-transition-store')
  return value
}
export function validateJournalTransition(value,profile) {return journalTransition(value,validateClosureProfile(profile))}
export function validateJournalTransitionSyntax(value) {return journalTransition(value)}
export function journalTransitionDigest(value) {return hash('aukora-prime.runtime-unsent-journal-transition.v3\0',journalTransition(value))}
