// SPDX-License-Identifier: AGPL-3.0-or-later
// Browser-safe comparison for NEW capture review. Historical/imported bytes never pass through this helper.
export const CAPTURE_STATEMENT_MAX = 4096
export const CAPTURE_EVIDENCE_QUOTE_MAX = 4096
export const CAPTURE_ATTRIBUTIONS = Object.freeze(['owner','owner-voice','owner-edit','backfill','lane-requester','dream','agent'])
export const PILOT_CAPTURE_PROFILE = 'prime-pilot-memory-capture/v1'
export const REDUCED_PILOT_CAPTURE_PROFILE = 'REDUCED-GUARANTEE/prime-pilot-memory-capture/v1'
export const CAPTURE_METADATA_PROFILES = Object.freeze([PILOT_CAPTURE_PROFILE,REDUCED_PILOT_CAPTURE_PROFILE])
export const CAPTURE_METADATA_FIELDS = Object.freeze(['profile','category','valid_from','observed_at','confidence_percent','sensitivity'])
export const CAPTURE_DRAFT_FIELDS = Object.freeze(['statement','attributed_to','capture_metadata','evidence_quote'])
export const CAPTURE_PARAMETER_FIELDS = Object.freeze(['capture_sha256','idempotency_key_sha256','heads',...CAPTURE_DRAFT_FIELDS])
export const CAPTURE_TEXT_POLICY = Object.freeze({
  scope:'new-capture-only',normal_form:'NFC-required-never-normalized',
  allowed_controls:Object.freeze(['U+0009','U+000A']),
  allowed_format_controls:Object.freeze(['U+200C','U+200D']),
  refused_fillers:Object.freeze(['U+034F','U+115F','U+1160','U+17B4','U+17B5','U+2800','U+3164','U+FFA0']),
  refused_line_separators:Object.freeze(['U+2028','U+2029']),
})
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
const FORMAT_CONTROL=/\p{Cf}/u
const UNSAFE=/[\u0000-\u0008\u000b-\u001f\u007f-\u009f\u034f\u115f\u1160\u17b4\u17b5\u2028\u2029\u2800\u3164\uffa0]/u
const BLANKISH=/^[\s\p{Cf}\p{Mn}\p{Me}\u115f\u1160\u2800\u3164\uffa0]*$/u
function text(value,maximum) {
  if(typeof value!=='string' || value.length===0 || value.length>maximum || !value.trim()
    || UNSAFE.test(value) || BLANKISH.test(value)) fail()
  for(let i=0;i<value.length;i++) {
    const unit=value.charCodeAt(i)
    if(unit>=0xd800 && unit<=0xdbff) {
      const next=value.charCodeAt(++i);if(!(next>=0xdc00 && next<=0xdfff)) fail()
    } else if(unit>=0xdc00 && unit<=0xdfff) fail()
  }
  // Comparison only: no replacement string is supplied to the caller or persisted.
  if(value.normalize('NFC')!==value) fail()
  for(const character of value) if(FORMAT_CONTROL.test(character) && character!=='\u200c' && character!=='\u200d') fail()
}
export function validateCaptureLiterals(draft) {
  object(draft,['statement','attributed_to']);text(draft.statement,CAPTURE_STATEMENT_MAX)
  if(!CAPTURE_ATTRIBUTIONS.includes(draft.attributed_to)) fail()
  return Object.freeze({statement:draft.statement,attributed_to:draft.attributed_to})
}
export function validateCaptureMetadata(metadata) {
  object(metadata,CAPTURE_METADATA_FIELDS)
  if(!CAPTURE_METADATA_PROFILES.includes(metadata.profile) || metadata.category!=='fact'
    || metadata.confidence_percent!==70 || metadata.sensitivity!=='none'
    || typeof metadata.valid_from!=='string' || typeof metadata.observed_at!=='string'
    || !/^\d{4}-\d{2}-\d{2}$/.test(metadata.valid_from)
    || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(metadata.observed_at)
    || !Number.isFinite(Date.parse(metadata.observed_at))
    || new Date(metadata.observed_at).toISOString().replace('.000Z','Z')!==metadata.observed_at
    || metadata.valid_from!==metadata.observed_at.slice(0,10)) fail()
  return Object.freeze(Object.fromEntries(CAPTURE_METADATA_FIELDS.map(key=>[key,metadata[key]])))
}
export function validateCaptureDraft(draft) {
  object(draft,CAPTURE_DRAFT_FIELDS)
  const literals=validateCaptureLiterals({statement:draft.statement,attributed_to:draft.attributed_to})
  const capture_metadata=validateCaptureMetadata(draft.capture_metadata)
  text(draft.evidence_quote,CAPTURE_EVIDENCE_QUOTE_MAX)
  return Object.freeze({...literals,capture_metadata,evidence_quote:draft.evidence_quote})
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
  const metadata=validateCaptureMetadata(parameters.capture_metadata)
  if(parameters.statement!==draft.statement || parameters.attributed_to!==draft.attributed_to
    || parameters.evidence_quote!==draft.evidence_quote
    || CAPTURE_METADATA_FIELDS.some(key=>metadata[key]!==draft.capture_metadata[key])) fail()
  return draft
}
