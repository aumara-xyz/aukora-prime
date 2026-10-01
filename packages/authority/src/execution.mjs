import { createHash } from 'node:crypto'
import { canonicalJson } from '../../contracts/src/runtime.mjs'
import { assertData, detachContract } from './operation.mjs'

export const DIGEST=/^sha256:[a-f0-9]{64}$/
export const UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i
const digest=(domain,value)=>'sha256:'+createHash('sha256').update(domain+'\0'+canonicalJson(value)).digest('hex')
export function executorRequestDigest(input) {
  if(!input||typeof input!=='object')throw new TypeError('INVALID: executor request')
  const data={}
  for(const k of Reflect.ownKeys(input)) {
    const d=Object.getOwnPropertyDescriptor(input,k)
    if(typeof k!=='string'||!d.enumerable||!Object.hasOwn(d,'value'))throw new TypeError('INVALID: executor request data')
    if(k!=='signal')data[k]=d.value
  }
  assertData(data)
  if(Object.keys(data).sort().join(',')!=='consumed_grant,image_digest,max_output_bytes,operation,policy_digest,request_id,wall_time_ms')throw new TypeError('INVALID: closed executor request')
  detachContract('OperationProposal',data.operation);detachContract('ConsumedGrant',data.consumed_grant)
  if(!UUID.test(data.request_id)||!DIGEST.test(data.policy_digest)||typeof data.image_digest!=='string'||!data.image_digest||
     !Number.isSafeInteger(data.wall_time_ms)||data.wall_time_ms<1||!Number.isSafeInteger(data.max_output_bytes)||data.max_output_bytes<1)throw new TypeError('INVALID: executor request bounds')
  return digest('aukora-prime.executor-request.v1',data)
}
export function executionReceiptDigest(input) {
  return digest('aukora-prime.execution-receipt.v1',validatedReceipt(input))
}
export function validatedReceipt(input) {
  const r=detachContract('ExecutionReceipt',input)
  if(!UUID.test(r.receipt_id)||!UUID.test(r.request_id)||!DIGEST.test(r.operation_digest)||typeof r.finished_at!=='string'||
     (r.started_at!==null&&typeof r.started_at!=='string')||Buffer.byteLength(r.stdout)>1048576||Buffer.byteLength(r.stderr)>1048576)throw new TypeError('INVALID: bounded execution receipt')
  if(r.sandbox!==null) {
    const s=r.sandbox
    if(!s||typeof s!=='object'||Array.isArray(s)||Object.keys(s).sort().join(',')!=='identity,image_digest,name,policy_digest,uid'||
       !UUID.test(s.uid)||[s.identity,s.image_digest,s.name].some(x=>typeof x!=='string'||!x.length)||!DIGEST.test(s.policy_digest))throw new TypeError('INVALID: exact sandbox receipt')
  }
  if(r.rpc_completion==='complete'&&r.exit_code===null)throw new TypeError('INVALID: complete RPC requires typed exit')
  if(r.rpc_completion==='not_started'&&(r.started_at!==null||r.exit_code!==null))throw new TypeError('INVALID: non-started receipt has execution evidence')
  if(r.cleanup==='not_created'&&(r.sandbox!==null||r.rpc_completion!=='not_started'||r.started_at!==null||r.exit_code!==null))throw new TypeError('INVALID: not_created contradicts execution')
  return r
}
export function settlementStatus(receipt,cancelRequested) {
  if(!['confirmed_absent','not_created'].includes(receipt.cleanup)||receipt.reconciliation_required)return 'OUTCOME_UNKNOWN'
  if(receipt.rpc_completion==='complete'&&receipt.exit_code!==null)return receipt.exit_code===0?'COMPLETED':'FAILED'
  if(cancelRequested&&receipt.rpc_completion==='not_started'&&receipt.started_at===null&&receipt.exit_code===null)return 'CANCELLED'
  if(receipt.status==='unavailable'&&receipt.rpc_completion==='not_started'&&receipt.cleanup==='not_created')return 'UNAVAILABLE'
  return 'OUTCOME_UNKNOWN'
}
