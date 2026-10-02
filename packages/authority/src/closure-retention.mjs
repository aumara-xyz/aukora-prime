// SPDX-License-Identifier: AGPL-3.0-or-later
// Private v2 negative-retirement continuity over the original C witness. These
// hashes are local retained bindings, not a signature or independent custody.
import {createHash,randomBytes} from 'node:crypto'
import {openSync,closeSync,fsyncSync,fstatSync,lstatSync,renameSync,unlinkSync,constants as FS} from 'node:fs'
import {canonicalJson} from '../../contracts/src/runtime.mjs'
import {assertData} from './operation.mjs'
import {validateClosureRow,validateUnconsumedClosureRows} from './unconsumed-closure.mjs'
import {assertOperationUnconsumed,validatePreparationHistory} from './preparation-history.mjs'
import {readBytesStrict,parseStrictText,writeAllSync} from '../upstream/plugins/aukora-kira/lib/strict-read.mjs'
import {TrustedStoreCorruptError,TrustedStoreUnsafePathError,WriterLockedError} from '../upstream/scripts/aukora/trusted-state-store.mjs'

const HEX=/^[a-f0-9]{64}$/
const DIGEST=/^sha256:[a-f0-9]{64}$/
const PROFILE_FIELDS=['version','kind','expected_store_id']
const PENDING_FIELDS=['version','kind','store_id','previous_inclusion_digest','operation_key','closure_row','row_digest','pending_digest']
const PENDING_BODY_FIELDS=PENDING_FIELDS.filter(key=>key!=='pending_digest')
const PROFILE_DOMAIN='aukora-prime.authority-closure-profile.v2\0'
const ROW_DOMAIN='aukora-prime.authority-closure-row.v2\0'
const INCLUSION_DOMAIN='aukora-prime.authority-closure-inclusion.v2\0'
const SET_DOMAIN='aukora-prime.authority-closure-set.v2\0'
const PENDING_DOMAIN='aukora-prime.authority-closure-retirement-pending.v2\0'
// Fixed children of the already protected witness directory. No caller path is
// admitted, and the pending candidate lives outside the state restore boundary.
export const CLOSURE_PENDING_FILE='prime-authority-closure-retirement-pending-v2.json'
const NOFOLLOW=FS.O_NOFOLLOW??0
const NONBLOCK=FS.O_NONBLOCK??0
const hash=text=>createHash('sha256').update(text,'utf8').digest('hex')
const digest=(domain,value)=>'sha256:'+hash(domain+canonicalJson(value))
const operationKey=operation=>hash(canonicalJson([operation.owner_id,operation.operation_id]))
const same=(left,right)=>canonicalJson(left)===canonicalJson(right)
const uint=value=>Number.isSafeInteger(value)&&value>=0
const match=(value,pattern)=>typeof value==='string'&&pattern.test(value)
const fail=detail=>{throw new TrustedStoreCorruptError('RECONCILIATION_REQUIRED: '+detail)}
function exact(value,fields) {
  assertData(value)
  return value!==null&&typeof value==='object'&&!Array.isArray(value)
    &&Object.keys(value).length===fields.length&&fields.every(key=>Object.hasOwn(value,key))
}

export function validateClosureProfile(input) {
  if(!exact(input,PROFILE_FIELDS)||input.version!==2||input.kind!=='prime-authority-closure-retention/v2'
    ||!match(input.expected_store_id,HEX))fail('CLOSURE_PROFILE_REQUIRED')
  return Object.freeze(JSON.parse(canonicalJson(input)))
}
export function closureProfileKey(profile) {
  return hash(PROFILE_DOMAIN+canonicalJson(validateClosureProfile(profile)))
}
export function closureRowDigest(row) {
  assertData(row)
  return digest(ROW_DOMAIN,row)
}
export function closureInclusionKey(profile,rowDigest) {
  const selected=validateClosureProfile(profile)
  if(!match(rowDigest,DIGEST))fail('CLOSURE_ROW_DIGEST_INVALID')
  return hash(INCLUSION_DOMAIN+canonicalJson({store_id:selected.expected_store_id,row_digest:rowDigest}))
}

export function closureInclusionProjection(record,profile,{omitOperationKey=null}={}) {
  const selected=validateClosureProfile(profile)
  validatePreparationHistory(record)
  validateUnconsumedClosureRows(record)
  if(record.broker.store_id!==selected.expected_store_id)fail('CLOSURE_STORE_ID_MISMATCH')
  if(omitOperationKey!==null&&!match(omitOperationKey,HEX))fail('CLOSURE_OPERATION_KEY_INVALID')
  const entries=[]
  for(const [key,row]of Object.entries(record.broker.operations)) {
    if(!row||typeof row!=='object'||Array.isArray(row))fail('CLOSURE_OPERATION_HISTORY_INVALID')
    if(row.status!=='CLOSED_UNCONSUMED'||key===omitOperationKey)continue
    const row_digest=closureRowDigest(row)
    entries.push({operation_key:key,row_digest,inclusion_key:closureInclusionKey(selected,row_digest)})
  }
  entries.sort((left,right)=>left.operation_key<right.operation_key?-1:left.operation_key>right.operation_key?1:0)
  return {store_id:selected.expected_store_id,entries}
}
export function closureInclusionDigest(projection) {
  if(!exact(projection,['store_id','entries'])||!match(projection.store_id,HEX)||!Array.isArray(projection.entries))
    fail('CLOSURE_INCLUSION_PROJECTION_INVALID')
  let previous=null
  const keys=new Set()
  for(const entry of projection.entries) {
    if(!exact(entry,['operation_key','row_digest','inclusion_key'])||!match(entry.operation_key,HEX)
      ||!match(entry.row_digest,DIGEST)||!match(entry.inclusion_key,HEX)
      ||(previous!==null&&entry.operation_key<=previous)||keys.has(entry.inclusion_key)
      ||entry.inclusion_key!==hash(INCLUSION_DOMAIN+canonicalJson({store_id:projection.store_id,row_digest:entry.row_digest})))
      fail('CLOSURE_INCLUSION_PROJECTION_INVALID')
    previous=entry.operation_key;keys.add(entry.inclusion_key)
  }
  return digest(SET_DOMAIN,projection)
}

function pendingShape(pending,profile) {
  const selected=validateClosureProfile(profile)
  if(!exact(pending,PENDING_FIELDS)||pending.version!==2||pending.kind!=='prime-authority-closure-retirement-pending/v2'
    ||pending.store_id!==selected.expected_store_id||!match(pending.previous_inclusion_digest,DIGEST)
    ||!match(pending.operation_key,HEX)||!match(pending.row_digest,DIGEST)||!match(pending.pending_digest,DIGEST)
    ||pending.row_digest!==closureRowDigest(pending.closure_row))fail('CLOSURE_PENDING_INVALID')
  const body=Object.fromEntries(PENDING_BODY_FIELDS.map(key=>[key,pending[key]]))
  if(pending.pending_digest!==digest(PENDING_DOMAIN,body))fail('CLOSURE_PENDING_DIGEST_MISMATCH')
  return pending
}
export function createClosurePending(record,profile,key,closureRow) {
  const selected=validateClosureProfile(profile),previous=closureInclusionProjection(record,selected)
  if(!match(key,HEX)||record.broker.operations[key]?.status==='CLOSED_UNCONSUMED')fail('CLOSURE_PENDING_CONFLICT')
  const body={version:2,kind:'prime-authority-closure-retirement-pending/v2',store_id:selected.expected_store_id,
    previous_inclusion_digest:closureInclusionDigest(previous),operation_key:key,
    closure_row:JSON.parse(canonicalJson(closureRow)),row_digest:closureRowDigest(closureRow)}
  const pending={...body,pending_digest:digest(PENDING_DOMAIN,body)}
  validateClosurePending(pending,record,selected)
  return pending
}
export function validateClosurePending(input,record,profile) {
  const selected=validateClosureProfile(profile),pending=pendingShape(input,selected)
  validatePreparationHistory(record)
  validateUnconsumedClosureRows(record)
  if(record.broker.store_id!==selected.expected_store_id)fail('CLOSURE_STORE_ID_MISMATCH')
  const row=pending.closure_row,marker=row?.closure,key=pending.operation_key,original=record.broker.operations[key]
  if(!row?.operation||operationKey(row.operation)!==key||!original?.operation
    ||!same(original.operation,row.operation)||original.operation_digest!==row.operation_digest
    ||marker?.kernel_receipt_count!==record.state.receiptHead.count
    ||marker?.kernel_receipt_head!==record.state.receiptHead.headHash)fail('CLOSURE_PENDING_ORIGINAL_BINDING_MISMATCH')
  let stage,prospective
  if(original.status==='CLOSED_UNCONSUMED') {
    if(!same(original,row)||record.broker.revision!==marker.broker_revision)fail('CLOSURE_PENDING_COMMITTED_ROW_MISMATCH')
    validateClosureRow(row,record)
    stage='committed';prospective=record
  } else {
    if(record.broker.revision!==marker?.broker_revision-1)fail('CLOSURE_PENDING_REVISION_CONFLICT')
    assertOperationUnconsumed(record,row.operation)
    prospective={...record,broker:{...record.broker,revision:marker.broker_revision,
      operations:{...record.broker.operations,[key]:row}}}
    validateClosureRow(row,prospective)
    stage='precommit'
  }
  const previous_projection=closureInclusionProjection(record,selected,{omitOperationKey:key})
  if(pending.previous_inclusion_digest!==closureInclusionDigest(previous_projection))fail('CLOSURE_PENDING_PRIOR_INCLUSION_MISMATCH')
  const projection=closureInclusionProjection(prospective,selected)
  return {stage,previous_projection,projection,pending}
}

function locked(store) {
  if(!store?.locked||!store.witness?.locked||store.dirFd===null||store.witness.dirFd===null)
    throw new WriterLockedError('closure continuity requires both original protected writer locks')
  store.assertAncestors()
  store.assertWitnessOutside()
  store.assertDir()
  store.witness.assertDir()
}
function selectedProfile(store) {
  const profile=validateClosureProfile(store.closureRetentionProfile)
  if(store.store_id!==profile.expected_store_id)fail('CLOSURE_STORE_ID_MISMATCH')
  return profile
}
function expectedKeys(store,profile,projection) {
  if(!match(store.stateKey,HEX)||!match(store.brokerWitnessKey,HEX)||store.stateKey===store.brokerWitnessKey
    ||store.stateKey!==hash('aukora-prime.kernel-history.v1\0'+profile.expected_store_id)
    ||store.brokerWitnessKey!==hash('aukora-prime.broker-history.v1\0'+profile.expected_store_id))
    fail('CLOSURE_HISTORY_KEYS_MISMATCH')
  const keys=[store.stateKey,store.brokerWitnessKey,closureProfileKey(profile),...projection.entries.map(entry=>entry.inclusion_key)]
  if(new Set(keys).size!==keys.length)fail('CLOSURE_WITNESS_KEY_COLLISION')
  return keys.sort()
}
export function validateWitnessInclusion(store,record,{pending=null,allowPending=false}={}) {
  locked(store)
  const profile=selectedProfile(store),projection=closureInclusionProjection(record,profile)
  const witness=store.witnessRecord
  if(!exact(witness,['schema','heads'])||witness.schema!==1||!witness.heads||typeof witness.heads!=='object'
    ||Array.isArray(witness.heads)||Object.entries(witness.heads).some(([key,count])=>!match(key,HEX)||!uint(count)))
    fail('CLOSURE_WITNESS_INVALID')
  const actual=Object.keys(witness.heads).sort()
  let pendingState=null,inclusion_retained=true,acceptedProjection=projection
  if(pending!==null) {
    if(!allowPending)fail('CLOSURE_RETIREMENT_PENDING')
    pendingState=validateClosurePending(pending,record,profile)
    const priorKeys=expectedKeys(store,profile,pendingState.previous_projection)
    const finalKeys=expectedKeys(store,profile,pendingState.projection)
    if(same(actual,priorKeys)) {
      inclusion_retained=false;acceptedProjection=pendingState.previous_projection
    } else if(pendingState.stage==='committed'&&same(actual,finalKeys))acceptedProjection=pendingState.projection
    else fail('CLOSURE_WITNESS_INCLUSION_MISMATCH')
  } else if(!same(actual,expectedKeys(store,profile,projection)))fail('CLOSURE_WITNESS_INCLUSION_MISMATCH')
  const valueOne=[closureProfileKey(profile),...acceptedProjection.entries.map(entry=>entry.inclusion_key)]
  if(valueOne.some(key=>witness.heads[key]!==1))fail('CLOSURE_WITNESS_INCLUSION_VALUE_INVALID')
  const kernelCount=record.state.receiptHead.count,brokerRevision=record.broker.revision
  const retainedKernel=witness.heads[store.stateKey],retainedBroker=witness.heads[store.brokerWitnessKey]
  if(retainedKernel!==kernelCount)fail('CLOSURE_KERNEL_WITNESS_NOT_CONVERGED')
  const priorBroker=pendingState?.stage==='committed'?pendingState.pending.closure_row.closure.broker_revision-1:brokerRevision
  if(retainedBroker!==brokerRevision&&!(pendingState?.stage==='committed'&&retainedBroker===priorBroker))
    fail('CLOSURE_BROKER_WITNESS_NOT_CONVERGED')
  // The prescribed sequence retains the broker head before adding inclusion.
  // A final inclusion set with the old broker head is not a crash boundary of
  // that sequence and cannot authorize reconstruction or head repair.
  if(pendingState!==null&&inclusion_retained&&retainedBroker!==brokerRevision)
    fail('CLOSURE_PENDING_DURABILITY_ORDER_MISMATCH')
  // Only the explicit command may promote the precise pending commit's broker
  // head. Every ordinary/factual load requires equality; this helper never writes.
  return {projection,inclusion_digest:closureInclusionDigest(projection),
    pending_stage:pendingState?.stage??null,inclusion_retained,
    counters_converged:retainedBroker===brokerRevision,broker_retained_revision:retainedBroker}
}

function maxPendingBytes(store) {
  const maximum=store.maxStateBytes??16*1024*1024
  if(!Number.isSafeInteger(maximum)||maximum<1||maximum>Number.MAX_SAFE_INTEGER-8192)fail('CLOSURE_PENDING_SIZE_BOUND_INVALID')
  return maximum+8192
}
function regular(info) {
  if(!info.isFile()||(typeof process.getuid==='function'&&info.uid!==process.getuid())
    ||(info.mode&0o077)!==0||info.nlink!==1)
    throw new TrustedStoreUnsafePathError('closure pending must be one owner-only regular file')
}
function readPendingBytes(store) {
  locked(store)
  const file=store.witness.p(CLOSURE_PENDING_FILE)
  let result=null,pin=null
  try {result=readBytesStrict(file,{maxBytes:maxPendingBytes(store),validateStat(info) {regular(info);pin=info}})}
  catch(error) {if(error?.code!=='ENOENT')throw error}
  locked(store)
  if(result!==null) {
    const current=lstatSync(file);regular(current)
    if(current.dev!==pin.dev||current.ino!==pin.ino)throw new TrustedStoreUnsafePathError('closure pending inode changed during protected read')
    result.pin={dev:pin.dev,ino:pin.ino}
  }
  return result
}
export function readClosurePending(store) {
  const profile=selectedProfile(store),result=readPendingBytes(store)
  if(result===null)return null
  const pending=parseStrictText(result.text,store.witness.p(CLOSURE_PENDING_FILE))
  pendingShape(pending,profile)
  if(result.text!==canonicalJson(pending))fail('CLOSURE_PENDING_NONCANONICAL_BYTES')
  return pending
}
export function writeClosurePending(store,input) {
  locked(store)
  if(store.closureLoadMode!=='close')fail('CLOSURE_PENDING_REQUIRES_EXPLICIT_COMMAND')
  const profile=selectedProfile(store),pending=pendingShape(input,profile),body=canonicalJson(pending)
  const candidate=validateClosurePending(pending,store.currentRecord,profile)
  if(candidate.stage!=='precommit')fail('CLOSURE_PENDING_CREATION_REQUIRES_UNCOMMITTED_CANDIDATE')
  validateWitnessInclusion(store,store.currentRecord)
  if(Buffer.byteLength(body,'utf8')>maxPendingBytes(store))fail('CLOSURE_PENDING_SIZE_BOUND_EXCEEDED')
  const existing=readClosurePending(store)
  if(existing!==null) {
    if(!same(existing,pending))fail('CLOSURE_PENDING_ALREADY_EXISTS')
    return existing
  }
  const file=store.witness.p(CLOSURE_PENDING_FILE)
  const temporary=store.witness.p(CLOSURE_PENDING_FILE+'.tmp-'+process.pid+'-'+randomBytes(12).toString('hex'))
  let fd,renamed=false
  try {
    locked(store)
    fd=openSync(temporary,FS.O_CREAT|FS.O_EXCL|FS.O_WRONLY|NOFOLLOW|NONBLOCK,0o600)
    regular(fstatSync(fd))
    writeAllSync(fd,body)
    fsyncSync(fd)
    closeSync(fd);fd=undefined
    locked(store)
    // The original two writer locks serialize legitimate writers. Never
    // overwrite a discovered pending candidate, even if its bytes look valid.
    if(readClosurePending(store)!==null)fail('CLOSURE_PENDING_ALREADY_EXISTS')
    locked(store)
    renameSync(temporary,file);renamed=true
    locked(store)
    fsyncSync(store.witness.dirFd)
    const readback=readClosurePending(store)
    if(readback===null||!same(readback,pending))fail('CLOSURE_PENDING_READBACK_MISMATCH')
    return readback
  } finally {
    if(fd!==undefined)closeSync(fd)
    if(!renamed) {
      locked(store)
      try {unlinkSync(temporary);fsyncSync(store.witness.dirFd)} catch(error) {if(error?.code!=='ENOENT')throw error}
    }
  }
}
// Explicit close also reaches this boundary after a prior unlink succeeded but
// its directory fsync failed. No pending candidate is fabricated for that retry.
// The already committed exact row/inclusion stays unchanged; only absence is
// made durable and rechecked. Factual queries never invoke this function.
export function finishClosurePendingAbsence(store,operationKey,closureRow) {
  locked(store)
  if(store.closureLoadMode!=='close')fail('CLOSURE_PENDING_ABSENCE_REQUIRES_EXPLICIT_COMMAND')
  selectedProfile(store)
  if(!match(operationKey,HEX)||readClosurePending(store)!==null)fail('CLOSURE_PENDING_ABSENCE_REQUIRED')
  const retained=store.currentRecord?.broker?.operations?.[operationKey]
  if(!retained||!same(retained,closureRow))fail('CLOSURE_PENDING_REMOVAL_REQUIRES_EXACT_COMMITTED_ROW')
  validateClosureRow(retained,store.currentRecord)
  validateWitnessInclusion(store,store.currentRecord)
  locked(store)
  fsyncSync(store.witness.dirFd)
  locked(store)
  if(readClosurePending(store)!==null)fail('CLOSURE_PENDING_REMOVAL_NOT_DURABLE')
  validateWitnessInclusion(store,store.currentRecord)
}
export function removeClosurePending(store,input) {
  locked(store)
  if(store.closureLoadMode!=='close')fail('CLOSURE_PENDING_REMOVAL_REQUIRES_EXPLICIT_COMMAND')
  const profile=selectedProfile(store),pending=pendingShape(input,profile),existing=readClosurePending(store)
  if(existing===null) {
    finishClosurePendingAbsence(store,pending.operation_key,pending.closure_row);return
  }
  if(!same(existing,pending))fail('CLOSURE_PENDING_REMOVAL_CONFLICT')
  const inclusion=validateWitnessInclusion(store,store.currentRecord,{pending,allowPending:true})
  if(inclusion.pending_stage!=='committed'||!inclusion.inclusion_retained||!inclusion.counters_converged)
    fail('CLOSURE_PENDING_REMOVAL_REQUIRES_FULL_INCLUSION')
  // Explicit recovery may observe the exact witness rename from a command that
  // lost its directory-fsync reply. Retain that existing inclusion before
  // removing the candidate; factual readers never perform this convergence.
  fsyncSync(store.witness.dirFd)
  const file=store.witness.p(CLOSURE_PENDING_FILE)
  const readback=readPendingBytes(store)
  if(readback===null||readback.text!==canonicalJson(pending))fail('CLOSURE_PENDING_REMOVAL_CONFLICT')
  locked(store)
  // Check the exact path inode immediately before unlink; the lock and protected
  // directory pin carry the same trusted-operator syscall-window limit as donor IO.
  const info=lstatSync(file);regular(info)
  if(info.dev!==readback.pin.dev||info.ino!==readback.pin.ino)
    throw new TrustedStoreUnsafePathError('closure pending inode changed before removal')
  locked(store)
  unlinkSync(file)
  fsyncSync(store.witness.dirFd)
  if(readClosurePending(store)!==null)fail('CLOSURE_PENDING_REMOVAL_NOT_DURABLE')
}
