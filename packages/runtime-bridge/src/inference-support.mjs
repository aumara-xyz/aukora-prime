// SPDX-License-Identifier: AGPL-3.0-or-later
// Private bridge glue. C owns the structural parser and durable authority path.
import {canonicalJson,operationDigest} from '../../contracts/src/runtime.mjs'
import {assertData} from '../../authority/src/operation.mjs'
import {closed,copy} from './registry.mjs'

export {canonicalJson,operationDigest,closed}
export const refusal = (code,reason) => Object.assign(new Error(reason),{error_code:code})
export function data(value) {assertData(value);return copy(value)}
export function configRecord(value,required,optional=[]) {
  if(!value||Object.getPrototypeOf(value)!==Object.prototype||Reflect.ownKeys(value).some(key=>
    typeof key!=='string'||![...required,...optional].includes(key)||!Object.hasOwn(Object.getOwnPropertyDescriptor(value,key),'value'))
    ||required.some(key=>!Object.hasOwn(value,key)))throw refusal('INVALID','INFERENCE_CLOSED_TRUSTED_CONFIG_REQUIRED')
}

let parserFlight
/** Fixed owned source only. Missing C implementation has no permissive fallback.
 * Loading is deferred so the existing memory/public exports keep their closure. */
export function loadInferenceContracts() {
  parserFlight??=import('../../authority/src/inference-admission.mjs').then(source=>{
    if(!['parseInferenceBinding','parseInferenceOperation','parseInferenceAdmission','inferenceRequestDigest']
      .every(name=>typeof source[name]==='function'))throw refusal('UNAVAILABLE','INFERENCE_C_PARSER_UNMOUNTED')
    return source
  }).catch(()=>{throw refusal('UNAVAILABLE','INFERENCE_C_PARSER_UNMOUNTED')})
  return parserFlight
}
export async function inferenceOperation(input) {
  const detached=data(input),source=await loadInferenceContracts()
  return source.parseInferenceOperation(detached)
}
export function ownerMappings(input) {
  const values=data(input)
  if(!Array.isArray(values)||!values.length)throw refusal('UNAVAILABLE','INFERENCE_C_OWNER_MAPPING_UNMOUNTED')
  const owners=new Map()
  for(const value of values) {
    closed(value,['owner_id','subject'])
    if(typeof value.owner_id!=='string'||!value.owner_id||value.owner_id.length>256
      ||typeof value.subject!=='string'||!/^aukora:1:[a-f0-9]{64}$/.test(value.subject)||owners.has(value.owner_id))
      throw refusal('INVALID','INFERENCE_C_OWNER_MAPPING_INVALID')
    owners.set(value.owner_id,value)
  }
  return owners
}
export function requireOwnedOperation(operation,registry,owners,{factualOnly=false}={}) {
  const owner=owners.get(operation.owner_id)
  if(!owner||operation.target_identity.owner_subject!==owner.subject)
    throw refusal('UNAUTHORIZED','INFERENCE_C_OWNER_TARGET_REQUIRED')
  if(!factualOnly) {
    const registered=registry.getOwned(operation.task_id,operation.owner_id)
    const binding=operation.canonical_parameters.binding
    if(registry.authorizeTask(operation)?.authenticated!==true||!registered
      ||registered.task.route_id!==operation.target_identity.route_id
      ||binding.owner_id!==registered.task.owner_id||binding.task_id!==registered.task.task_id
      ||binding.conversation_id!==registered.task.conversation_id)
      throw refusal('UNAUTHORIZED','INFERENCE_REGISTERED_TASK_BINDING_REQUIRED')
  }
  return owner
}
export const unavailableStatus = () => Object.freeze({state:'unavailable',qualification:'unqualified',
  reason:'INFERENCE_HOST_AND_C_E_LIFECYCLE_JOIN_PENDING'})
