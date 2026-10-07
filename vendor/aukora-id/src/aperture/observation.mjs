import registry from '../../spec/layer0-v1/registry.json' with { type: 'json' };
import { applicationDigest, canonicalBytes, closed, h32, parseBytes, sha256, u64, uint, fail } from '../bytes/index.mjs';
import { trustedBytes, LOCAL_ADAPTER } from './local-profile.mjs';

// Proposed narrow public LOCAL metadata profile. Until the parent-owned registry
// and verifier recognize it, completion remains unavailable. No private payload,
// salt, encryption or general observation profile is introduced here.
export const STATEMENT_PROFILE = 'aukora.local.fixed-message.observation.v1';
export const OBSERVATION_SCHEMA = 'aukora.local.observation.v1';
const literal = expected => value => { if (value !== expected) fail('CLOSED_SCHEMA'); };
export function requireObservationProfile() {
  if (!registry.accepted_observation_statement_profiles.includes(STATEMENT_PROFILE)) fail('UNSUPPORTED_PROFILE');
}
export function observationBytes(intent, observer, observedAt) {
  const r = intent.record, b = r.body;
  return trustedBytes({ schema: OBSERVATION_SCHEMA, statement_profile: STATEMENT_PROFILE,
    adapter_profile: LOCAL_ADAPTER, subject_id: r.subject_id, chain_id: r.chain_id,
    epoch: r.epoch, operation_id: b.operation_id, intent_ref: intent.event.id,
    intent_record_digest: applicationDigest(canonicalBytes(r)).toString('hex'),
    actor_key_id: b.actor_key_id, observer_key_id: observer.key_id,
    observer_certificate_ref: observer.certificate_ref, observed_at: observedAt,
    received_bytes: 18, claim: 'completed' });
}
export function parseObservation(bytes) {
  requireObservationProfile();
  const value = parseBytes(bytes, { maxBytes: 8192 });
  closed(value, { schema: literal(OBSERVATION_SCHEMA), statement_profile: literal(STATEMENT_PROFILE),
    adapter_profile: literal(LOCAL_ADAPTER), subject_id: h32, chain_id: h32, epoch: u64,
    operation_id: h32, intent_ref: h32, intent_record_digest: h32, actor_key_id: h32,
    observer_key_id: h32, observer_certificate_ref: h32, observed_at: uint,
    received_bytes: literal(18), claim: literal('completed') });
  if (!canonicalBytes(value).equals(Buffer.from(bytes))) fail('CLOSED_SCHEMA');
  return value;
}
export function observationEvidence(artifactBytes, observerKeyId, observedAt) {
  return { kind: 'local_boundary_record', source_id: observerKeyId, source_role: 'aperture_observer',
    artifact_digest: sha256(artifactBytes).toString('hex'), statement_profile: STATEMENT_PROFILE,
    claim: 'completed', observed_at: observedAt };
}
