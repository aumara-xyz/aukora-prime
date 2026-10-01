// SPDX-License-Identifier: AGPL-3.0-or-later
// Optional trusted localhost pilot profile. This is a request-origin check,
// never owner authentication, enrollment or deployment qualification.
import {closed,copy} from './registry.mjs'
export function createLocalhostPilotGuard(profile) {
  const pinned=copy(closed(profile,['profile','origin','rp_id']))
  if(pinned.profile!=='localhost-pilot-v1'||pinned.origin!=='http://localhost:18731'||pinned.rp_id!=='localhost')throw new TypeError('INVALID: exact localhost pilot profile required')
  return request=>{
    // The host adapter extracts these fields from the actual request. They are
    // never read from the proposal body or inferred to configure C.
    if(request?.host!=='localhost:18731'||request?.origin!==pinned.origin)throw Object.assign(new Error('PILOT_HOST_ORIGIN_REFUSED'),{error_code:'UNAUTHORIZED'})
    return pinned
  }
}
