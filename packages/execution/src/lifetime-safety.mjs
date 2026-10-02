// SPDX-License-Identifier: AGPL-3.0-or-later
// Local accounting and explicit refusal only. No background service, lease,
// SDK abort or policy readback supplies independent lifetime enforcement.
import { createHash } from 'node:crypto'
import { canonicalJson } from '../../contracts/src/runtime.mjs'
import { refused } from './policy.mjs'
import { executorRequestDigest } from './binding.mjs'

export const PINNED_EXECUTION_SAFETY=Object.freeze({
  independent_expiry:'unavailable',late_create_fence:'unavailable',
  atomic_configuration:'unavailable',owned_artifact_cleanup:'unavailable',
})
const KEYS=['version','request_id','request_digest','accepted_at','deadline_at','last_observed_at','wall_time_ms','enforcement']
const DIGEST=/^sha256:[a-f0-9]{64}$/u
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu
const clone=value=>JSON.parse(canonicalJson(value))
const closed=value=>value&&typeof value==='object'&&!Array.isArray(value)
  &&Object.keys(value).sort().join(',')===[...KEYS].sort().join(',')
const utc=ms=>new Date(ms).toISOString()
function instant(value) {
  if(typeof value!=='string')throw refused('canonical lifetime instant required','INVALID')
  const ms=Date.parse(value)
  if(!Number.isSafeInteger(ms)||utc(ms)!==value)throw refused('canonical lifetime instant required','INVALID')
  return ms
}
function nowInstant(ms) {
  if(!Number.isSafeInteger(ms))throw refused('trusted local observation instant required','INVALID')
  return instant(utc(ms))
}
function request(job) {
  if(!UUID.test(job?.request_id)||!DIGEST.test(job?.request_digest)
    ||job.request?.request_id!==job.request_id||!Number.isSafeInteger(job.request.wall_time_ms)
    ||job.request.wall_time_ms<1||job.request.wall_time_ms>30000
    ||executorRequestDigest(job.request)!==job.request_digest)throw refused('bound local lifetime request required','INVALID')
  // Frozen v1 permits valid UTC forms without fractional seconds. Preserve
  // operation bytes; canonical milliseconds belong only to this private record.
  const expiry=Date.parse(job.request.operation.expiry)
  if(!Number.isSafeInteger(expiry))throw refused('valid operation expiry required','INVALID')
  return {wall:job.request.wall_time_ms,expiry}
}

/** Saved before claim/create, includes provisioning, and is never recreated on
 * restart. Wall-clock accounting cannot qualify crash/rollback enforcement. */
export function createLocalLifetime(job,now=Date.now()) {
  const accepted=nowInstant(now),r=request(job),deadline=accepted+r.wall
  // Approval expiry gates launch separately. It cannot shorten the approved
  // execution wall bound or turn an expired approval into cancellation intent.
  if(r.expiry<=accepted)throw refused('operation expired before lifetime reservation','EXPIRED')
  return {version:1,request_id:job.request_id,request_digest:job.request_digest,
    accepted_at:utc(accepted),deadline_at:utc(deadline),last_observed_at:utc(accepted),
    wall_time_ms:r.wall,enforcement:'local_accounting_only'}
}

/** Private F evidence domain; frozen v1 request/receipt digests are unchanged. */
export function localLifetimeDigest(value) {
  const record=clone(value)
  if(!closed(record))throw refused('closed lifetime record required','INVALID')
  const {last_observed_at,...immutable}=record
  return 'sha256:'+createHash('sha256').update('aukora-prime.local-lifetime.v1\0'+canonicalJson(immutable)).digest('hex')
}

export function inspectLocalLifetime(job,now=Date.now()) {
  try {
    const record=clone(job.lifetime),r=request(job),observed=nowInstant(now)
    if(!closed(record)||record.version!==1||record.enforcement!=='local_accounting_only'
      ||record.request_id!==job.request_id||record.request_digest!==job.request_digest
      ||record.wall_time_ms!==r.wall||job.lifetime_digest!==localLifetimeDigest(record))throw refused('lifetime binding differs','INVALID')
    const accepted=instant(record.accepted_at),deadline=instant(record.deadline_at),last=instant(record.last_observed_at)
    if(last<accepted||r.expiry<=accepted||deadline<=accepted||deadline!==accepted+r.wall)throw refused('lifetime deadline differs','INVALID')
    if(observed<last)return {status:'clock_uncertain',remaining_ms:null,lifetime:record}
    record.last_observed_at=utc(observed)
    return {status:observed>=deadline?'expired':'active',remaining_ms:Math.max(0,deadline-observed),lifetime:record}
  } catch {return {status:'invalid',remaining_ms:null,lifetime:null}}
}

export function refuseIndependentLifetime() {
  throw refused('independent expiry owner and terminal late-create fence unavailable for pinned OpenShell','UNAVAILABLE')
}
export function refuseAtomicConfiguration() {
  throw refused('pinned ExecSandbox has no atomic expected configuration/generation condition; readbacks cannot authorize launch','UNAVAILABLE')
}
export function refuseOwnedArtifactCleanup() {
  throw refused('independent identity-bound late-create fence and complete owned artifact cleanup evidence unavailable','RECONCILIATION_REQUIRED')
}
