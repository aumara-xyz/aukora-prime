import { createHash } from 'node:crypto'
import { canonicalJson } from '../../contracts/src/runtime.mjs'
import { assertData } from './operation.mjs'
import { DIGEST, UUID } from './execution.mjs'
const hash=(domain,value)=>'sha256:'+createHash('sha256').update(domain+'\0'+canonicalJson(value)).digest('hex')
export function memoryResultDigest(result) {assertData(result);return hash('aukora-prime.memory-result.v1',result)}
export function memoryEffectReceipt(input) {
  assertData(input)
  if(!input||Array.isArray(input)||Object.keys(input).sort().join(',')!=='action_type,grant_id,kind,operation_digest,operation_id,owner_subject,request_digest,request_id,result,result_digest,status,version'||
     input.version!==1||input.kind!=='prime-memory-effect/v1'||input.status!=='applied'||!UUID.test(input.request_id)||
     !DIGEST.test(input.operation_digest)||!DIGEST.test(input.request_digest)||!DIGEST.test(input.result_digest)||
     ['action_type','grant_id','operation_id','owner_subject'].some(k=>typeof input[k]!=='string'||!input[k]||input[k].length>1024)||
     input.result_digest!==memoryResultDigest(input.result)||Buffer.byteLength(canonicalJson(input))>2*1024*1024)throw new TypeError('INVALID: exact committed memory effect receipt')
  return JSON.parse(canonicalJson(input))
}
export function memoryEffectReceiptDigest(input) {return hash('aukora-prime.memory-receipt.v1',memoryEffectReceipt(input))}
