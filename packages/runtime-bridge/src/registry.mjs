// SPDX-License-Identifier: AGPL-3.0-or-later
import {canonicalJson,validateContract} from '../../contracts/src/runtime.mjs'

export const freeze = value => {
  if(value && typeof value==='object') { for(const child of Object.values(value)) freeze(child);Object.freeze(value) }
  return value
}
export const copy = value => freeze(JSON.parse(canonicalJson(value)))
export function closed(value,fields) {
  canonicalJson(value)
  if(!value || Array.isArray(value) || typeof value!=='object' || Object.keys(value).length!==fields.length || fields.some(k=>!Object.hasOwn(value,k))) throw new TypeError('INVALID: closed bridge fields')
  return value
}

/** Provisioner-only registry. No public method registers or updates a task. */
export function createTrustedTaskRegistry(entries=[]) {
  if(!Array.isArray(entries)) throw new TypeError('INVALID: trusted registry entries')
  const tasks=new Map()
  for(const entry of entries) {
    closed(entry,['task','provider_and_region','audience','policy_version','data_scope'])
    validateContract('Task',entry.task)
    closed(entry.provider_and_region,['provider','region'])
    if(Object.values(entry.provider_and_region).some(x=>typeof x!=='string'||!x) || typeof entry.audience!=='string'||!entry.audience || typeof entry.policy_version!=='string'||!entry.policy_version || !Array.isArray(entry.data_scope)||entry.data_scope.some(x=>!entry.task.allowed_data_classes.includes(x))) throw new TypeError('INVALID: trusted registry binding')
    if(tasks.has(entry.task.task_id)) throw new TypeError('INVALID: duplicate trusted task')
    tasks.set(entry.task.task_id,copy(entry))
  }
  function getOwned(taskId,ownerId) {
    const entry=tasks.get(taskId)
    if(!entry || entry.task.owner_id!==ownerId || !['pending','running'].includes(entry.task.status)) return null
    return entry
  }
  function authorizeTask(operation) {
    validateContract('OperationProposal',operation)
    const entry=getOwned(operation.task_id,operation.owner_id)
    if(!entry || operation.agent_id!==entry.task.agent_id || operation.audience!==entry.audience || operation.policy_version!==entry.policy_version || canonicalJson(operation.provider_and_region)!==canonicalJson(entry.provider_and_region) || operation.data_scope.some(x=>!entry.data_scope.includes(x))) return {authenticated:false,task:null}
    return {authenticated:true,task:entry.task}
  }
  return Object.freeze({getOwned,authorizeTask,snapshot:()=>copy([...tasks.values()])})
}
