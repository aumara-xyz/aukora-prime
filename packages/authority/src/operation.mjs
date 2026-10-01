import { validateContract, operationBytes, operationDigest, canonicalJson } from '../../contracts/src/runtime.mjs'
import { canonicalBytes } from '../upstream/vendor/authority/lib/index.js'

export { operationBytes, operationDigest }
export function assertData(value, depth = 0) {
  if (depth > 64) throw new TypeError('INVALID: data nesting limit')
  if (typeof value === 'number' && Object.is(value,-0)) throw new TypeError('INVALID: negative zero')
  if (!value || typeof value !== 'object') return
  if (!Array.isArray(value) && ![null,Object.prototype].includes(Object.getPrototypeOf(value))) throw new TypeError('INVALID: data prototype')
  const keys=Reflect.ownKeys(value)
  if (Array.isArray(value)) {
    if (Object.getPrototypeOf(value)!==Array.prototype || keys.length!==value.length+1) throw new TypeError('INVALID: dense plain arrays only')
    for (let i=0;i<value.length;i++) if (!Object.hasOwn(value,String(i))) throw new TypeError('INVALID: dense arrays only')
  }
  for(const k of keys) {
    if(typeof k!=='string') throw new TypeError('INVALID: symbol key')
    const d=Object.getOwnPropertyDescriptor(value,k)
    if(!Object.hasOwn(d,'value') || (!d.enumerable && !(Array.isArray(value)&&k==='length'))) throw new TypeError('INVALID: enumerable data only')
    assertData(d.value,depth+1)
  }
}
export function detachContract(kind, input) {
  // Ingress rejects accessor/symbol/prototype/array ambiguity before anything is read,
  // cloned, displayed or digested. The copied kernel validates canonical values too.
  assertData(input)
  canonicalBytes(input)
  validateContract(kind, input)
  const detached = JSON.parse(canonicalJson(input))
  if (kind === 'OperationProposal') {
    for (const key of ['operation_id','task_id','owner_id','agent_id','audience','action_type','expected_state_version','nonce','policy_version','expiry']) {
      if (typeof detached[key] !== 'string' || detached[key].length === 0) throw new TypeError(`INVALID: ${key} required`)
    }
    if (detached.target_identity === null || detached.canonical_parameters === null) throw new TypeError('INVALID: target and parameters required')
  }
  return detached
}
export function dollars(value) {
  if (value?.currency !== 'USD' || typeof value.amount !== 'string' || !/^\d+(\.\d{1,8})?$/.test(value.amount)) throw new TypeError('INVALID: USD decimal amount')
  const [whole, fraction=''] = value.amount.split('.')
  return BigInt(whole) * 100000000n + BigInt(fraction.padEnd(8,'0'))
}
export function deepFreeze(value) {
  if (value && typeof value === 'object') { Object.values(value).forEach(deepFreeze); Object.freeze(value) }
  return value
}
