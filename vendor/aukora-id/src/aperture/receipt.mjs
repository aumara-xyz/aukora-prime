import { applicationDigest, canonicalBytes } from '../bytes/index.mjs';
import { trustedBytes, CLASSICAL_PROFILE, refuse } from './local-profile.mjs';

// Unsigned journal-position template only. The observer decides what it actually
// observed and supplies the application proof. The host has no observer secret.
export function receiptTemplate({ intent, snapshot, append, observer, policyRefs, reconcilesReceipt = null }) {
  if (snapshot.now_lower !== snapshot.now_upper) refuse('TIME_UNCERTAINTY');
  if (BigInt(snapshot.sequence) >= 18446744073709551615n) refuse('LIMIT_EXCEEDED');
  const r = intent.record, b = r.body;
  return trustedBytes({ schema: 'aukora.record.v1', profile: CLASSICAL_PROFILE,
    domain: 'aukora.receipt.v1', kind: 'receipt', subject_id: r.subject_id, chain_id: r.chain_id,
    epoch: snapshot.epoch, sequence: String(BigInt(snapshot.sequence) + 1n), previous_event: snapshot.head,
    issued_at: snapshot.now_lower, not_before: snapshot.now_lower, expires: null,
    authority_refs: [...new Set([intent.event.id, append.certificate_ref, observer.certificate_ref,
      ...policyRefs, ...(reconcilesReceipt ? [reconcilesReceipt] : [])])].sort(),
    outer_context: { pubkey: append.public_key, created_at: snapshot.now_lower, kind: 8790, tags: [['aukora', 'l0-v1']] },
    signer_plan: [{ role: 'aperture_observer', key_id: observer.key_id, key_source: 'certificate',
      certificate_ref: observer.certificate_ref, algorithms: ['bip340'] }], consent_context: null,
    body: { operation_id: b.operation_id, intent_ref: intent.event.id,
      intent_record_digest: applicationDigest(canonicalBytes(r)).toString('hex'), actor_key_id: b.actor_key_id,
      observer_key_id: observer.key_id, observer_certificate_ref: observer.certificate_ref,
      outcome: 'unknown', dispatch_state: 'dispatched_uncertain', observed_at: snapshot.now_lower,
      evidence: [], reconciles_receipt: reconcilesReceipt } });
}
