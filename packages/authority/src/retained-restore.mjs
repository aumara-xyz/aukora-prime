// SPDX-License-Identifier: AGPL-3.0-or-later
// Existing D restore parameter/result grammar; no permit or public schema added.
import {createHash} from 'node:crypto'
import {canonicalJson} from '../../contracts/src/runtime.mjs'
import {assertData,detachContract,deepFreeze,operationDigest} from './operation.mjs'

const HEX=/^[a-f0-9]{64}$/,DIGEST=/^sha256:[a-f0-9]{64}$/
// D's selected donor head vocabulary, unchanged at eafefb4.
const DOMAINS=['remembered','approved','legacy-presplit']
const ROOT='aukora:aura-record:v1'
const FIELDS=['manifest_sha256','mode','heads','retained_heads','control_anchor_sha256','retention_checkpoint_sha256','retention_epoch']
const fail=reason=>{throw Object.assign(new TypeError(reason),{error_code:'INVALID'})}
const need=(condition,reason)=>{if(!condition)fail(reason)}
const match=(value,pattern)=>typeof value==='string'&&pattern.test(value)
const same=(a,b)=>canonicalJson(a)===canonicalJson(b)
function exact(value,fields,reason) {
 assertData(value)
 need(value&&typeof value==='object'&&!Array.isArray(value)&&Reflect.ownKeys(value).length===fields.length
  &&fields.every(key=>Object.hasOwn(value,key)),reason)
 return value
}
function heads(value) {
 return value&&typeof value==='object'&&!Array.isArray(value)
  &&Object.entries(value).every(([domain,head])=>DOMAINS.includes(domain)&&(head===ROOT||match(head,HEX)))
}
export function validateRetainedRestoreOperation(input) {
 const op=detachContract('OperationProposal',input)
 need(op.action_type==='memory.restore'&&op.audience==='aukora-prime.memory','RETAINED_RESTORE_ACTION_REQUIRED')
 const target=exact(op.target_identity,['kind','owner_subject'],'RETAINED_RESTORE_TARGET_FIELDS')
 need(target.kind==='prime-memory'&&match(target.owner_subject,/^aukora:1:[a-f0-9]{64}$/)
  &&match(op.expected_state_version,DIGEST),'RETAINED_RESTORE_TARGET_INVALID')
 const p=exact(op.canonical_parameters,FIELDS,'RETAINED_RESTORE_PARAMETER_FIELDS')
 need(p.mode==='prime-restore'&&match(p.manifest_sha256,HEX)&&heads(p.heads)&&heads(p.retained_heads)
  &&same(p.heads,p.retained_heads)&&match(p.control_anchor_sha256,HEX)&&match(p.retention_checkpoint_sha256,HEX)
  &&Number.isSafeInteger(p.retention_epoch)&&p.retention_epoch>=0&&!Object.is(p.retention_epoch,-0)
  &&p.retention_epoch===op.authorization_epoch,'RETAINED_RESTORE_PARAMETERS_INVALID')
 // expected_state_version describes actual local A, while heads describes P.
 // Only the genuine D target observation/ancestry checks can relate them.
 return deepFreeze(p)
}
export function retainedRestoreRequestDigest(operation) {
 const p=validateRetainedRestoreOperation(operation)
 const request={version:1,action_type:operation.action_type,owner_subject:operation.target_identity.owner_subject,
  operation_id:operation.operation_id,operation_digest:operationDigest(operation),parameters:p}
 return 'sha256:'+createHash('sha256').update('aukora-prime.memory.effect.v1\0'+canonicalJson(request),'utf8').digest('hex')
}
export function validateRetainedRestoreResult(input,operation) {
 const p=validateRetainedRestoreOperation(operation)
 const value=exact(input,['state','manifest_sha256','heads','restored_records','grants_authority'],'RETAINED_RESTORE_RESULT_FIELDS')
 need(value.state==='restored'&&value.manifest_sha256===p.manifest_sha256&&same(value.heads,p.heads)
  &&Number.isSafeInteger(value.restored_records)&&value.restored_records>=0&&value.restored_records<=10000
  &&!Object.is(value.restored_records,-0)&&value.grants_authority===false,'RETAINED_RESTORE_RESULT_INVALID')
 return deepFreeze(JSON.parse(canonicalJson(value)))
}
