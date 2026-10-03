// SPDX-License-Identifier: AGPL-3.0-or-later
// Fixed factual scope for NEW captures only. It attests no enrollment or hardware presence.
import { types } from 'node:util'
import { PILOT_CAPTURE_PROFILE, REDUCED_PILOT_CAPTURE_PROFILE } from './capture-review.mjs'

export const REDUCED_PILOT_SCOPE = Object.freeze({
  version:1,kind:'prime-reduced-guarantee-pilot/v1',guarantee:'REDUCED-GUARANTEE',deployment:'same-host',
  owner_approval:'passkey-required',storage:'postgresql-required',authority_independence:false,hardware_display:false,
})
export const REDUCED_PILOT_CAPTURE_ORIGIN = Object.freeze({by:'prime.capture/v1',pilot_scope:REDUCED_PILOT_SCOPE})
const normalOrigin = Object.freeze({by:'prime.capture/v1'})
const scopeKeys = Object.freeze(Object.keys(REDUCED_PILOT_SCOPE))
const fail = () => {throw Object.assign(new TypeError('memory:reduced-pilot-scope-refused'),
  {code:'memory:reduced-pilot-scope-refused'})}
function fields(value,required,optional = []) {
  if(!value || types.isProxy(value) || ![Object.prototype,null].includes(Object.getPrototypeOf(value))) fail()
  const ds = Object.getOwnPropertyDescriptors(value), keys = Reflect.ownKeys(ds)
  if(required.some(key => !keys.includes(key)) || keys.some(key => typeof key !== 'string'
    || !required.includes(key) && !optional.includes(key))) fail()
  for(const key of keys) if(!ds[key].enumerable || !Object.hasOwn(ds[key],'value')) fail()
  return Object.fromEntries(keys.map(key => [key,ds[key].value]))
}
export function validateReducedPilotScope(input) {
  const scope = fields(input,scopeKeys)
  if(scopeKeys.some(key => scope[key] !== REDUCED_PILOT_SCOPE[key])) fail()
  return Object.freeze(Object.fromEntries(scopeKeys.map(key => [key,scope[key]])))
}
export function validateCaptureOrigin(input) {
  const origin = fields(input,['by'],['pilot_scope'])
  if(origin.by !== 'prime.capture/v1') fail()
  if(!Object.hasOwn(origin,'pilot_scope')) return normalOrigin
  return Object.freeze({by:origin.by,pilot_scope:validateReducedPilotScope(origin.pilot_scope)})
}
export function captureProfileForOrigin(input = normalOrigin) {
  return Object.hasOwn(validateCaptureOrigin(input),'pilot_scope')
    ? REDUCED_PILOT_CAPTURE_PROFILE : PILOT_CAPTURE_PROFILE
}
export function validateCaptureScopeParity(origin,profile) {
  if(profile !== captureProfileForOrigin(origin)) fail()
  return validateCaptureOrigin(origin)
}
