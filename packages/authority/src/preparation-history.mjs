// SPDX-License-Identifier: AGPL-3.0-or-later
// A refusal-only prerequisite for exact-operation closure. This is not an
// unsent proof, a closure marker, an independent witness or effect permission.
import {assertTrustedState} from '../upstream/vendor/authority/lib/index.js'
import {createHash} from 'node:crypto'
import {canonicalJson} from '../../contracts/src/runtime.mjs'
import {assertData,detachContract,operationDigest} from './operation.mjs'
import {validateTerminalRecord} from './retention.mjs'

const HEX=/^[a-f0-9]{64}$/
const APPROVAL=/^approval:[a-f0-9]{64}$/
const FIELDS='consumptionId,contentHash,descriptorKind,effectId,preparedAtMs,receiptCountAfter,targetPath'
const operationKey=op=>createHash('sha256').update(canonicalJson([op.owner_id,op.operation_id])).digest('hex')
function refuse(reason) {throw new TypeError('RECONCILIATION_REQUIRED: '+reason)}
function text(value) {return typeof value==='string'&&value.length>0&&Buffer.byteLength(value,'utf8')<=1024}

/** Prime provisions an empty kernel history and its unchanged adapters append
 * exactly one PREPARED entry for each persisted allowed/consumed transition.
 * Broker-only writes never advance that head. Unknown or incomplete history
 * cannot establish absence; no migration, repair or counter reset is attempted. */
export function validatePreparationHistory(record) {
  assertData(record)
  assertTrustedState(record?.state)
  const prepared=record.prepared,consumed=record.state.consumedIds
  if(record.storeSchema!==1||!Array.isArray(prepared)||
     prepared.length!==record.state.receiptHead.count||consumed.length!==prepared.length)refuse('PREPARATION_HISTORY_INCOMPLETE')
  const effects=new Set(),ids=new Set(),durableIds=new Set(consumed)
  for(let i=0;i<prepared.length;i++) {
    const entry=prepared[i]
    if(!entry||Array.isArray(entry)||Object.keys(entry).sort().join(',')!==FIELDS||
       typeof entry.effectId!=='string'||!HEX.test(entry.effectId)||typeof entry.consumptionId!=='string'||!APPROVAL.test(entry.consumptionId)||
       typeof entry.contentHash!=='string'||!HEX.test(entry.contentHash)||
       !text(entry.descriptorKind)||!text(entry.targetPath)||
       !Number.isSafeInteger(entry.preparedAtMs)||entry.preparedAtMs<0||entry.receiptCountAfter!==i+1||
       effects.has(entry.effectId)||ids.has(entry.consumptionId)||!durableIds.has(entry.consumptionId))refuse('PREPARATION_HISTORY_INCOHERENT')
    effects.add(entry.effectId);ids.add(entry.consumptionId)
  }
  return record
}

/** Lock-held caller prerequisite only. The caller must additionally commit an
 * irreversible exact-operation writer fence and join D's retained no-intent /
 * no-effect writer-closure evidence before describing anything as known unsent.
 * This function returns no proof or permit and deliberately accepts no clock. */
export function assertOperationUnconsumed(record,operation) {
  validatePreparationHistory(record)
  const op=detachContract('OperationProposal',operation),digest=operationDigest(op)
  if(record.prepared.some(entry=>entry.contentHash===digest.slice(7)))refuse('EXACT_OPERATION_KERNEL_PREPARED')
  const rows=record.broker?.operations
  if(!rows||Array.isArray(rows)||typeof rows!=='object')refuse('OPERATION_HISTORY_UNAVAILABLE')
  const represented=new Set()
  // Validate every candidate binding before deciding which one belongs to this
  // operation. A corrupt/missing digest must not hide a consumed broker row.
  for(const [key,row] of Object.entries(rows)) {
    if(!HEX.test(key)||!row||Array.isArray(row)||typeof row!=='object'||
       typeof row.operation_digest!=='string'||!/^sha256:[a-f0-9]{64}$/.test(row.operation_digest))refuse('OPERATION_HISTORY_INCOHERENT')
    represented.add(row.operation_digest)
    if(Object.hasOwn(row,'schema'))validateTerminalRecord(row)
    else if(row.operation) {
      const bound=detachContract('OperationProposal',row.operation)
      if(operationDigest(bound)!==row.operation_digest||operationKey(bound)!==key)refuse('OPERATION_HISTORY_INCOHERENT')
      if(bound.owner_id===op.owner_id&&bound.operation_id===op.operation_id&&
         canonicalJson(bound)!==canonicalJson(op))refuse('EXACT_OPERATION_CHANGED')
    } else refuse('OPERATION_HISTORY_INCOHERENT')
    if(key===operationKey(op)&&row.operation_digest!==digest)refuse('EXACT_OPERATION_CHANGED')
    if(row.operation_digest!==digest)continue
    if(!row.operation||canonicalJson(row.operation)!==canonicalJson(op)||
       !['PROPOSED','APPROVED','DENIED'].includes(row.status)||row.grant||row.grant_digest||row.dispatch||row.retained_memory)refuse('EXACT_OPERATION_AUTHORITY_OR_EFFECT_RETAINED')
    const nonce=row.approval?.proof?.nonce??row.review?.template?.nonce
    if(nonce!==undefined&&(typeof nonce!=='string'||!HEX.test(nonce)||record.state.consumedIds.includes('approval:'+nonce)))refuse('EXACT_OPERATION_APPROVAL_CONSUMED_OR_INCOHERENT')
  }
  // Consumed rows are never pruned. A missing broker binding for any retained
  // kernel preparation makes absence claims unavailable, including after a
  // corrupt deletion that left the kernel counters and entries coherent.
  if(record.prepared.some(entry=>!represented.has('sha256:'+entry.contentHash)))refuse('PREPARED_BROKER_BINDING_MISSING')
}
