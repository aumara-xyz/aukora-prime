// SPDX-License-Identifier: AGPL-3.0-or-later
// Private closure contract v1, selected by closure-interface-decision-v002.
// Structural checks require replies from the protected C/D roles; they do not
// establish independent custody, database fencing or permission to act.
import {createHash} from 'node:crypto'
import {types} from 'node:util'
import {canonicalJson,parseStrictJson,validateContract,operationDigest,MAX_JSON_DEPTH} from '../../contracts/src/runtime.mjs'
import {closed,freeze} from './registry.mjs'
// D hashes its existing donor encoding. Do not substitute a different JSON
// canonicalizer or depend on an unaccepted C/D closure implementation.
import {canonicalJSON as memoryCanonicalJSON} from '../../memory/genesis/plugins/aukora-kira/lib/record.mjs'

export const UNSENT_CLOSURE_PRIVATE_VERSION=1
export const UNSENT_REFERENCE_FIELDS=Object.freeze(['owner_id','owner_subject','task_id','operation_id','operation_digest','action_type'])
export const AUTHORITY_UNCONSUMED_RESPONSE_FIELDS=Object.freeze(['ok','status','operation','closure','closure_digest','idempotent'])
export const AUTHORITY_UNCONSUMED_CLOSURE_FIELDS=Object.freeze(['version','kind','store_id','owner_id','owner_subject','task_id',
  'operation_id','operation_digest','authorization_epoch','closed_at','broker_revision','kernel_receipt_count','kernel_receipt_head'])
export const MEMORY_UNSENT_RESPONSE_FIELDS=Object.freeze(['status','closure','closure_digest','retention','idempotent','grants_authority'])
export const MEMORY_UNSENT_CLOSURE_FIELDS=Object.freeze(['version','kind','owner_id','owner_subject','task_id',
  'operation_id','operation_digest','action_type','authorization_epoch','closure_id','writer_closed','intent_absent','effect_absent','grants_authority'])

const DIGEST=/^sha256:[a-f0-9]{64}$/
const HEX=/^[a-f0-9]{64}$/
const SUBJECT=/^aukora:1:[a-f0-9]{64}$/
const UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/
const INSTANT=/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/
const ACTIONS=Object.freeze(['memory.save','memory.forget'])
const HOST_FIELDS=Object.freeze(['owner_id','owner_subject','task_id','authorization_epoch'])
const RETENTION_FIELDS=Object.freeze(['checkpoint_sha256','control_sha256','authorization_epoch'])
const certificates=new WeakMap()
const match=(value,pattern)=>typeof value==='string'&&pattern.test(value)
const uint=value=>Number.isSafeInteger(value)&&value>=0&&!Object.is(value,-0)
const identifier=value=>typeof value==='string'&&value.length>0&&Buffer.byteLength(value,'utf8')<=1024
  &&!(/[\x00-\x1f\x7f]/u.test(value))
const check=(value)=>{if(!value)throw new TypeError('Invalid private closure evidence')}
const hash=(prefix,body)=>'sha256:'+createHash('sha256').update(prefix,'utf8').update(body,'utf8').digest('hex')

function unknown(reason,cause) {
  return Object.assign(new Error(reason,cause?{cause}:undefined),{
    error_code:'OUTCOME_UNKNOWN',reason,reconciliation_required:true,automatic_retry:false,
  })
}
function guarded(reason,work) {
  try {return work()}
  catch(cause) {throw unknown(reason,cause)}
}
function detached(input) {
  // Refuse proxies before reflection, and accessors before canonicalization.
  const ancestors=new WeakSet();let count=0
  function inspect(value,depth) {
    check(depth<=MAX_JSON_DEPTH&&++count<=100000)
    if(value===null||typeof value!=='object')return
    check(!types.isProxy(value)&&!ancestors.has(value))
    const array=Array.isArray(value),prototype=Object.getPrototypeOf(value)
    check(array?prototype===Array.prototype:prototype===Object.prototype||prototype===null)
    ancestors.add(value)
    for(const key of Reflect.ownKeys(value)) {
      const descriptor=Object.getOwnPropertyDescriptor(value,key)
      check(typeof key==='string'&&descriptor&&Object.hasOwn(descriptor,'value')
        &&(descriptor.enumerable||array&&key==='length'))
      if(!(array&&key==='length'))inspect(descriptor.value,depth+1)
    }
    ancestors.delete(value)
  }
  inspect(input,0)
  return freeze(parseStrictJson(canonicalJson(input)))
}
function trustedHost(host) {
  // A memory host also carries source bytes. Retain only its authenticated
  // identity and epoch, without serializing or retaining its content.
  check(host&&typeof host==='object'&&!Array.isArray(host)&&!types.isProxy(host)
    &&[Object.prototype,null].includes(Object.getPrototypeOf(host)))
  const identity={}
  for(const key of HOST_FIELDS) {
    const descriptor=Object.getOwnPropertyDescriptor(host,key)
    check(descriptor&&descriptor.enumerable&&Object.hasOwn(descriptor,'value'))
    identity[key]=descriptor.value
  }
  check(['owner_id','owner_subject','task_id'].every(key=>identifier(identity[key]))
    &&match(identity.owner_subject,SUBJECT)&&uint(identity.authorization_epoch))
  return detached(identity)
}
function referenceData(input) {
  const reference=detached(input)
  closed(reference,UNSENT_REFERENCE_FIELDS)
  check(['owner_id','owner_subject','task_id','operation_id'].every(key=>identifier(reference[key]))
    &&match(reference.owner_subject,SUBJECT)&&match(reference.operation_digest,DIGEST)
    &&ACTIONS.includes(reference.action_type))
  return reference
}
function referenceForHost(input,host) {
  const reference=referenceData(input)
  check(['owner_id','owner_subject','task_id'].every(key=>reference[key]===host[key]))
  return reference
}
function retentionPolicy(options) {
  if(options===undefined)return true
  const policy=detached(options)
  check(policy&&typeof policy==='object'&&!Array.isArray(policy)
    &&Object.keys(policy).every(key=>key==='retentionRequired'))
  if(!Object.hasOwn(policy,'retentionRequired'))return true
  check(typeof policy.retentionRequired==='boolean')
  return policy.retentionRequired
}

/** Bind the six cold-journal lookup fields to an independently trusted host. */
export function validateUnsentReference(reference,host) {
  return guarded('UNSENT_REFERENCE_INVALID',()=>referenceForHost(reference,trustedHost(host)))
}

/** C's marker epoch belongs to its complete original retained operation. */
export function validateAuthorityUnconsumedClosure(inputReference,inputReply) {
  return guarded('AUTHORITY_UNCONSUMED_CLOSURE_INVALID',()=>{
    const reference=referenceData(inputReference),reply=detached(inputReply)
    closed(reply,AUTHORITY_UNCONSUMED_RESPONSE_FIELDS)
    check(reply.ok===true&&reply.status==='CLOSED_UNCONSUMED'&&typeof reply.idempotent==='boolean')
    const operation=reply.operation,marker=reply.closure
    validateContract('OperationProposal',operation)
    closed(operation.target_identity,['kind','owner_subject'])
    check(operationDigest(operation)===reference.operation_digest
      &&['owner_id','task_id','operation_id','action_type'].every(key=>operation[key]===reference[key])
      &&operation.audience==='aukora-prime.memory'
      &&operation.target_identity.kind==='prime-memory'
      &&operation.target_identity.owner_subject===reference.owner_subject)
    closed(marker,AUTHORITY_UNCONSUMED_CLOSURE_FIELDS)
    check(marker.version===1&&marker.kind==='prime-authority-never-consumed/v1'
      &&match(marker.store_id,HEX)
      &&['owner_id','owner_subject','task_id','operation_id','operation_digest'].every(key=>marker[key]===reference[key])
      &&uint(marker.authorization_epoch)&&marker.authorization_epoch===operation.authorization_epoch
      &&match(marker.closed_at,INSTANT)&&Number.isFinite(Date.parse(marker.closed_at))
      &&new Date(marker.closed_at).toISOString()===marker.closed_at
      &&uint(marker.broker_revision)&&marker.broker_revision>=1
      &&uint(marker.kernel_receipt_count)
      &&(marker.kernel_receipt_count===0?marker.kernel_receipt_head===null:match(marker.kernel_receipt_head,HEX))
      &&match(reply.closure_digest,DIGEST)
      &&reply.closure_digest===hash('aukora-prime.authority-never-consumed.v1\0',canonicalJson(marker)))
    return reply
  })
}

/** D and its retention bind the authenticated current closing host epoch.
 * Null retention requires an explicit internal non-retained source policy.
 */
export function validateMemoryUnsentClosure(inputHost,inputReference,inputReply,options) {
  return guarded('MEMORY_UNSENT_CLOSURE_INVALID',()=>{
    const host=trustedHost(inputHost),reference=referenceForHost(inputReference,host)
    const reply=detached(inputReply),required=retentionPolicy(options)
    closed(reply,MEMORY_UNSENT_RESPONSE_FIELDS)
    check(reply.status==='closed-unsent'&&typeof reply.idempotent==='boolean'&&reply.grants_authority===false)
    const marker=reply.closure
    closed(marker,MEMORY_UNSENT_CLOSURE_FIELDS)
    check(marker.version===1&&marker.kind==='prime-memory-writer-closure/v1'
      &&UNSENT_REFERENCE_FIELDS.every(key=>marker[key]===reference[key])
      &&uint(marker.authorization_epoch)&&marker.authorization_epoch===host.authorization_epoch
      &&match(marker.closure_id,UUID)&&marker.writer_closed===true
      &&marker.intent_absent===true&&marker.effect_absent===true&&marker.grants_authority===false
      &&match(reply.closure_digest,DIGEST)
      &&reply.closure_digest===hash('aukora-prime.memory-writer-closure.v1\0',memoryCanonicalJSON(marker)))
    if(reply.retention===null)check(!required)
    else {
      closed(reply.retention,RETENTION_FIELDS)
      check(match(reply.retention.checkpoint_sha256,HEX)&&match(reply.retention.control_sha256,HEX)
        &&uint(reply.retention.authorization_epoch)&&reply.retention.authorization_epoch===host.authorization_epoch)
    }
    return reply
  })
}

/** This brand records validation of both supplied protected-role results.
 * It is not an authority grant or an attestation of their deployment custody.
 */
export function certifyUnsentClosure(host,reference,authorityResult,memoryResult,options) {
  return guarded('UNSENT_CLOSURE_PAIR_INVALID',()=>{
    const identity=trustedHost(host),bound=referenceForHost(reference,identity)
    const authority=validateAuthorityUnconsumedClosure(bound,authorityResult)
    const memory=validateMemoryUnsentClosure(identity,bound,memoryResult,options)
    const certificate=Object.freeze({})
    certificates.set(certificate,freeze({host:identity,reference:bound,authority,memory}))
    return certificate
  })
}
export function isUnsentClosureCertificate(value) {return certificates.has(value)}
export function getUnsentClosureCertificate(value) {
  if(!certificates.has(value))throw unknown('UNSENT_CLOSURE_CERTIFICATE_REQUIRED')
  return certificates.get(value)
}
