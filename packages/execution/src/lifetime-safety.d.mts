// SPDX-License-Identifier: AGPL-3.0-or-later
export const PINNED_EXECUTION_SAFETY:Readonly<{independent_expiry:'unavailable';late_create_fence:'unavailable';atomic_configuration:'unavailable';owned_artifact_cleanup:'unavailable'}>
export interface LocalLifetime {version:1;request_id:string;request_digest:string;accepted_at:string;deadline_at:string;last_observed_at:string;wall_time_ms:number;enforcement:'local_accounting_only'}
import type { OwnedExecutorRequest } from '../../contracts/src/index.ts'
export interface LocalLifetimeJob {request_id:string;request_digest:string;request:OwnedExecutorRequest;lifetime?:LocalLifetime;lifetime_digest?:string}
export function createLocalLifetime(job:LocalLifetimeJob,now?:number):LocalLifetime
export function localLifetimeDigest(record:LocalLifetime):`sha256:${string}`
export function inspectLocalLifetime(job:LocalLifetimeJob,now?:number):{status:'active'|'expired'|'clock_uncertain'|'invalid';remaining_ms:number|null;lifetime:LocalLifetime|null}
export function refuseIndependentLifetime():never
export function refuseAtomicConfiguration():never
export function refuseOwnedArtifactCleanup():never
