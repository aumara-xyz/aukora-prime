// SPDX-License-Identifier: AGPL-3.0-or-later
// Private C-only never-consumed retention grammar. This marker does not prove
// D absence, writer inability, an independent custodian, or permission to act.
import {createHash} from 'node:crypto'
import {canonicalJson} from '../../contracts/src/runtime.mjs'
import {assertData,detachContract,operationDigest} from './operation.mjs'

const HEX=/^[a-f0-9]{64}$/
const DIGEST=/^sha256:[a-f0-9]{64}$/
const SUBJECT=/^aukora:1:[a-f0-9]{64}$/
const INSTANT=/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/
const MARKER_FIELDS=['version','kind','store_id','owner_id','owner_subject','task_id','operation_id',
  'operation_digest','authorization_epoch','closed_at','broker_revision','kernel_receipt_count','kernel_receipt_head']
const ROW_FIELDS=['operation','operation_digest','status','review','approval','grant','pending_until','closure','closure_digest']
const sha=value=>createHash('sha256').update(value).digest('hex')
const operationKey=op=>sha(canonicalJson([op.owner_id,op.operation_id]))
const match=(value,pattern)=>typeof value==='string'&&pattern.test(value)
const uint=value=>Number.isSafeInteger(value)&&value>=0
const invalid=()=>{throw new TypeError('RECONCILIATION_REQUIRED: UNCONSUMED_CLOSURE_INCOHERENT')}
function exact(value,fields) {
  return value!==null&&typeof value==='object'&&!Array.isArray(value)
    &&Object.keys(value).length===fields.length&&fields.every(key=>Object.hasOwn(value,key))
}
function instant(value) {
  return match(value,INSTANT)&&Number.isFinite(Date.parse(value))&&new Date(value).toISOString()===value
}

export function closureDigest(marker) {
  assertData(marker)
  return 'sha256:'+sha('aukora-prime.authority-never-consumed.v1\0'+canonicalJson(marker))
}

// The caller validates the original complete kernel history while both original
// writer locks are held. Validation here adds no signature or independent proof.
export function validateClosureRow(row,record) {
  assertData(row)
  if(!exact(row,ROW_FIELDS)||row.status!=='CLOSED_UNCONSUMED'||row.review!==null||row.approval!==null
    ||row.grant!==null||row.pending_until!==null)invalid()
  const operation=detachContract('OperationProposal',row.operation),digest=operationDigest(operation),marker=row.closure
  if(row.operation_digest!==digest||!exact(marker,MARKER_FIELDS)||marker.version!==1
    ||marker.kind!=='prime-authority-never-consumed/v1'||!match(marker.store_id,HEX)
    ||!match(marker.owner_subject,SUBJECT)||marker.owner_id!==operation.owner_id||marker.task_id!==operation.task_id
    ||marker.operation_id!==operation.operation_id||marker.operation_digest!==digest
    ||!uint(marker.authorization_epoch)||marker.authorization_epoch!==operation.authorization_epoch
    ||!instant(marker.closed_at)||!Number.isSafeInteger(marker.broker_revision)||marker.broker_revision<1
    ||!uint(marker.kernel_receipt_count)||(marker.kernel_receipt_count===0?marker.kernel_receipt_head!==null
      :!match(marker.kernel_receipt_head,HEX))||!match(row.closure_digest,DIGEST)
    ||row.closure_digest!==closureDigest(marker))invalid()
  const broker=record?.broker,head=record?.state?.receiptHead,owner=broker?.owners?.[sha(operation.owner_id)]
  if(!match(broker?.store_id,HEX)||marker.store_id!==broker.store_id
    ||!Number.isSafeInteger(broker.revision)||broker.revision<marker.broker_revision
    ||!owner||owner.owner_id!==operation.owner_id||owner.subject!==marker.owner_subject
    ||!uint(head?.count)||(head.count===0?head.headHash!==null:!match(head.headHash,HEX))
    ||marker.kernel_receipt_count>head.count
    ||(marker.kernel_receipt_count===head.count&&marker.kernel_receipt_head!==head.headHash)
    ||!Array.isArray(record.prepared)||record.prepared.some(entry=>entry.contentHash===digest.slice(7)))invalid()
  return row
}

export function validateUnconsumedClosureRows(record) {
  assertData(record)
  const rows=record?.broker?.operations
  if(!rows||typeof rows!=='object'||Array.isArray(rows))invalid()
  for(const [key,row] of Object.entries(rows)) {
    if(row&&typeof row==='object'&&(row.status==='CLOSED_UNCONSUMED'
      ||Object.hasOwn(row,'closure')||Object.hasOwn(row,'closure_digest'))) {
      validateClosureRow(row,record)
      if(!match(key,HEX)||key!==operationKey(row.operation))invalid()
    }
  }
  return record
}
