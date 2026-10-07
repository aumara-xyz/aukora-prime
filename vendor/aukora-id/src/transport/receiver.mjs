import { canonicalBytes, fail, parseBytes, parseEvent, snapshotBytes } from '../bytes/index.mjs';
import { verifyEvent, verifyOuterEvent } from '../verifier/index.mjs';
import { context as validateContext } from '../verifier/schema.mjs';
import registry from '../../spec/layer0-v1/registry.json' with { type: 'json' };
import { MAX_EVENT, MAX_EVIDENCE } from './framing.mjs';

export const DATA_KINDS = Object.freeze(['agent_card', 'revocation', 'vouch', 'vouch_accept']);
const allowedCodes = new Set(Object.values(registry.reason_codes).flat());
export const diagnosticCode = error => allowedCodes.has(error?.code) ? error.code : 'MALFORMED_BYTES';
const key = record => `${record.subject_id}:${record.chain_id}:${record.kind}`;
const failure = code => ({ verdict: registry.reason_codes.UNKNOWN.includes(code) ? 'UNKNOWN' : 'REJECT',
  reason_codes: [code], record_digest: null, event_id: null, validated_through: null,
  missing_evidence: [], conflicts: [] });

// Contexts are fixed by the trusted local controller before connecting peers.
// There is deliberately no context, anchor, clock or policy selection on the wire.
export function createEvidenceReceiver(contextsBytes) {
  const contexts = parseBytes(contextsBytes);
  if (!Array.isArray(contexts) || contexts.length < 1 || contexts.length > 16) fail('LIMIT_EXCEEDED');
  const pinned = new Map();
  for (const context of contexts) {
    validateContext(context);
    if (context.purpose !== 'historical_integrity' || context.control !== null || context.additional_control.length ||
        context.expected_profile !== registry.profile.id || !DATA_KINDS.includes(context.expected_kind) ||
        context.expected_signers.length === 0) fail('WRONG_AUTHORITY');
    const slot = `${context.expected_subject_id}:${context.expected_chain_id}:${context.expected_kind}`;
    if (pinned.has(slot)) fail('CLOSED_SCHEMA');
    pinned.set(slot, canonicalBytes(context));
  }
  return Object.freeze({
    receive(eventBytes, evidenceBytes) {
      let event, evidence, verification;
      try {
        event = Buffer.from(snapshotBytes(eventBytes, MAX_EVENT));
        evidence = Buffer.from(snapshotBytes(evidenceBytes, MAX_EVIDENCE));
        // Check signed outer bytes first, so timestamp tampering is BAD_SIGNATURE.
        verifyOuterEvent(event);
        const parsed = parseEvent(event), context = pinned.get(key(parsed.record));
        if (!context) fail('WRONG_AUTHORITY');
        // Complete W2 application/ancestry verification, not outer-only trust.
        verification = verifyEvent(event, context, evidence);
      } catch (error) { verification = failure(diagnosticCode(error)); }
      const accepted = verification.verdict === 'valid';
      return Object.freeze({ accepted, purpose: 'historical_integrity', grants_authority: false,
        verification, data: accepted ? Object.freeze({ eventBytes: event, evidenceBytes: evidence }) : null });
    },
  });
}
