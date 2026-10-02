// SPDX-License-Identifier: AGPL-3.0-or-later
// Read-only host metadata for D's fixed new-capture pilot. This does not
// reconstruct the private capture hash or validate source evidence.
export function validateCaptureMetadata(value) {
  const fields = ['profile','category','valid_from','observed_at','confidence_percent','sensitivity']
  if (!value || ![Object.prototype,null].includes(Object.getPrototypeOf(value)) ||
      Reflect.ownKeys(value).length !== fields.length || Reflect.ownKeys(value).some(key => !fields.includes(key))) {
    throw new TypeError('ui:fixed-capture-metadata-required')
  }
  for (const key of fields) {
    const descriptor = Object.getOwnPropertyDescriptor(value,key)
    if (!descriptor?.enumerable || !Object.hasOwn(descriptor,'value')) throw new TypeError('ui:fixed-capture-metadata-required')
  }
  if (value.profile !== 'prime-pilot-memory-capture/v1' || value.category !== 'fact' ||
      value.confidence_percent !== 70 || value.sensitivity !== 'none' || typeof value.observed_at !== 'string' ||
      !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(value.observed_at) || !Number.isFinite(Date.parse(value.observed_at)) ||
      new Date(value.observed_at).toISOString().replace('.000Z','Z') !== value.observed_at ||
      value.valid_from !== value.observed_at.slice(0,10)) throw new TypeError('ui:fixed-capture-metadata-required')
  return Object.freeze({...value})
}
