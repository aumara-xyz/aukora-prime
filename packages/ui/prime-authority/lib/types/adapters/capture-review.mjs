// SPDX-License-Identifier: AGPL-3.0-or-later
// Browser-safe display comparison only. The private capture digest is verified by D under its database lock.
export const CAPTURE_STATEMENT_MAX = 4096
export const CAPTURE_ATTRIBUTIONS = Object.freeze(['owner','owner-voice','owner-edit','backfill','lane-requester','dream','agent'])
export const CAPTURE_PARAMETER_FIELDS = Object.freeze(['capture_sha256','idempotency_key_sha256','heads','statement','attributed_to'])
const fail=()=>{throw new TypeError('memory:capture-review-invalid')}
const object=(value,fields)=>{
  if(!value || ![Object.prototype,null].includes(Object.getPrototypeOf(value))) fail()
  const keys=Reflect.ownKeys(value)
  if(keys.length!==fields.length || keys.some(k=>typeof k!=='string'||!fields.includes(k))) fail()
  for(const key of keys) {
    const descriptor=Object.getOwnPropertyDescriptor(value,key)
    if(!descriptor?.enumerable || !Object.hasOwn(descriptor,'value')) fail()
  }
}
function statement(value) {
  if(typeof value!=='string' || value.length===0 || value.length>CAPTURE_STATEMENT_MAX || !value.trim()
    || /[\u0000-\u0008\u000b-\u001f\u007f\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]/u.test(value)) fail()
  for(let i=0;i<value.length;i++) {
    const unit=value.charCodeAt(i)
    if(unit>=0xd800 && unit<=0xdbff) {
      const next=value.charCodeAt(++i);if(!(next>=0xdc00 && next<=0xdfff)) fail()
    } else if(unit>=0xdc00 && unit<=0xdfff) fail()
  }
}
export function validateCaptureDraft(draft) {
  object(draft,['statement','attributed_to']);statement(draft.statement)
  if(!CAPTURE_ATTRIBUTIONS.includes(draft.attributed_to)) fail()
  return Object.freeze({statement:draft.statement,attributed_to:draft.attributed_to})
}
export function validateCaptureReview(parameters,immutableDraft) {
  object(parameters,CAPTURE_PARAMETER_FIELDS)
  const draft=validateCaptureDraft(immutableDraft)
  if(typeof parameters.capture_sha256!=='string' || typeof parameters.idempotency_key_sha256!=='string'
    || !/^[0-9a-f]{64}$/.test(parameters.capture_sha256) || !/^[0-9a-f]{64}$/.test(parameters.idempotency_key_sha256)) fail()
  if(!parameters.heads || ![Object.prototype,null].includes(Object.getPrototypeOf(parameters.heads))) fail()
  object(parameters.heads,Object.keys(parameters.heads))
  for(const [domain,head] of Object.entries(parameters.heads)) if(!['remembered','approved','legacy-presplit'].includes(domain)
    || typeof head!=='string' || !(head==='aukora:aura-record:v1'||/^[0-9a-f]{64}$/.test(head))) fail()
  if(parameters.statement!==draft.statement || parameters.attributed_to!==draft.attributed_to) fail()
  return draft
}
