// SPDX-License-Identifier: AGPL-3.0-or-later
// The pilot accepts a literal statement. Source time and all note metadata are
// fixed by the trusted capture profile, never selected by a guest payload.
export const PILOT_CAPTURE_PROFILE='prime-pilot-memory-capture/v1'
export function validatePilotMetadata(metadata){
  if(!metadata||Object.keys(metadata).sort().join(',')!=='category,confidence_percent,observed_at,profile,sensitivity,valid_from'
    ||metadata.profile!==PILOT_CAPTURE_PROFILE||metadata.category!=='fact'||metadata.confidence_percent!==70||metadata.sensitivity!=='none'
    ||typeof metadata.observed_at!=='string'||!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(metadata.observed_at)
    ||!Number.isFinite(Date.parse(metadata.observed_at))||new Date(metadata.observed_at).toISOString()!==metadata.observed_at.slice(0,-1)+'.000Z'
    ||metadata.valid_from!==metadata.observed_at.slice(0,10))throw new TypeError('INVALID: pilot capture metadata')
  return Object.freeze({...metadata})
}
const fields=['statement','category','validFrom','observedAt','confidence','sensitivity']
export function preparePilotCapture(input,trustedSourceAt){
  if(!input||Object.getPrototypeOf(input)!==Object.prototype||Object.keys(input).some(key=>!fields.includes(key))
    ||typeof input.statement!=='string'||typeof trustedSourceAt!=='string'
    ||!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(trustedSourceAt)
    ||!Number.isFinite(Date.parse(trustedSourceAt))||new Date(trustedSourceAt).toISOString()!==trustedSourceAt.slice(0,-1)+'.000Z')throw new TypeError('INVALID: pilot capture profile')
  const capture={statement:input.statement,category:'fact',validFrom:trustedSourceAt.slice(0,10),observedAt:trustedSourceAt,confidence:0.7,sensitivity:'none'}
  // Older callers may supply these fields only when each is the fixed value.
  // Links and arbitrary metadata are outside this pilot input grammar.
  if(Object.keys(input).some(key=>input[key]!==capture[key]))throw new TypeError('INVALID: pilot capture metadata is fixed')
  return Object.freeze({capture:Object.freeze(capture),metadata:Object.freeze({profile:PILOT_CAPTURE_PROFILE,
    category:capture.category,valid_from:capture.validFrom,observed_at:capture.observedAt,confidence_percent:70,sensitivity:capture.sensitivity})})
}
