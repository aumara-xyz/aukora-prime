import registry from '../../spec/layer0-v1/registry.json' with { type: 'json' };
import { applicationDigest, b64, canonicalBytes, closed, h32, keyId, parseBytes, parseEvent, parseRecord } from '../bytes/index.mjs';
import { descriptorBytes, signRecord } from '../keys/index.mjs';
import * as verifier from '../verifier/index.mjs';
import { isFixedPayload } from '../local-sink/index.mjs';
import { CLASSICAL_PROFILE, LOCAL_ADAPTER, LOCAL_SCOPE, equalData, refuse, trustedBytes } from '../aperture/local-profile.mjs';
import { observationBytes, observationEvidence, requireObservationProfile, STATEMENT_PROFILE } from './profile.mjs';

const anchorFields = { expected_subject_id: h32, expected_chain_id: h32, expected_genesis: h32, expected_root_key_id: h32 };
const policies = Object.values(registry.policy_documents).map(({ digest, document }) => ({ digest,
  document: trustedBytes(document).toString('base64url') })).sort((a, b) => a.digest.localeCompare(b.digest));
const evidenceBytes = value => canonicalBytes(parseBytes(Buffer.from(JSON.stringify(value)), { mode: 'evidence' }));

// Trusted receiver primitive, instantiated only in the separate observer child.
// A receipt signature attests this receiver's accepted fixed-message frame, never
// a caller-supplied dispatch boolean or an instrumentation notice.
export function createReceiptObserver(configBytes) {
  requireObservationProfile();
  const config = parseBytes(configBytes);
  closed(config, { schema: v => { if (v !== 'aukora.local-observer.v1') refuse('CLOSED_SCHEMA'); },
    mode: v => { if (v !== 'LOCAL_TEST') refuse('WRONG_AUTHORITY'); },
    anchor: v => closed(v, anchorFields),
    observer: v => closed(v, { certificate_ref: h32, secret_key: s => b64(s, 32) }) });
  const secret = Buffer.from(config.observer.secret_key, 'base64url');
  const key = keyId(descriptorBytes(secret)).toString('hex');
  const observer = { key_id: key, certificate_ref: config.observer.certificate_ref };
  const seen = new Set();
  let closedFlag = false, count = 0, prefix = null, observerCertificateBytes = null;
  const verify = (eventBytes, kind, signers, supplied) => {
    const target = parseEvent(eventBytes).event.id;
    const context = trustedBytes({ schema: 'aukora.verify-context.v1', purpose: 'historical_integrity',
      ...config.anchor, expected_profile: CLASSICAL_PROFILE, expected_kind: kind,
      expected_signers: signers, policy_pins: policies.map(p => p.digest), control: null,
      additional_anchors: [], additional_control: [] });
    if (prefix && supplied.events.length !== 0) refuse('CLOSED_SCHEMA');
    const evidence = evidenceBytes({ ...supplied,
      events: supplied.events.filter(value => parseEvent(Buffer.from(value, 'base64url')).event.id !== target) });
    const result = prefix ? prefix.verify(eventBytes, context, evidence) : verifier.verifyEvent(eventBytes, context, evidence);
    if (result.verdict !== 'valid') refuse(result.reason_codes[0] ?? 'MISSING_EVIDENCE');
  };
  const synchronize = (eventBytes, contextBytes, suppliedEvidence) => {
    const context = parseBytes(contextBytes), supplied = parseBytes(suppliedEvidence, { mode: 'evidence' });
    if (context.purpose !== 'historical_integrity' || context.control !== null ||
      context.expected_profile !== CLASSICAL_PROFILE || context.additional_anchors?.length !== 0 ||
      context.additional_control?.length !== 0 || !equalData(context.policy_pins, policies.map(p => p.digest)) ||
      !equalData(supplied.policies, policies) || supplied.events?.length !== 0 || supplied.control_state !== null ||
      Object.keys(anchorFields).some(field => context[field] !== config.anchor[field])) refuse('WRONG_AUTHORITY');
    // This closure is built only from raw authenticated events. No host verdict,
    // imported cache, parsed state, or dispatch claim can initialize it.
    if (!prefix) {
      if (typeof verifier.createPrefixVerifier !== 'function') refuse('MISSING_EVIDENCE');
      prefix = verifier.createPrefixVerifier();
    }
    const before = prefix.head(), parsed = parseEvent(eventBytes);
    const checked = prefix.append(eventBytes, contextBytes, suppliedEvidence);
    if (checked.verdict !== 'valid') refuse(checked.reason_codes[0] ?? 'MISSING_EVIDENCE');
    const after = prefix.head();
    if (after.closed || after.id !== parsed.event.id || after.sequence !== parsed.record.sequence || after.count !== before.count + 1) refuse('INCONSISTENT_HEAD');
    if (parsed.event.id === observer.certificate_ref) observerCertificateBytes = Buffer.from(eventBytes);
    return [trustedBytes({ schema: 'aukora.local.observer-prefix-ack.v1', event_id: after.id,
      sequence: after.sequence, count: after.count }), Buffer.alloc(0), Buffer.alloc(0), Buffer.alloc(0)];
  };
  return Object.freeze({
    publicBinding: Object.freeze(observer),
    receive(fields) {
      if (closedFlag) refuse('MISSING_EVIDENCE');
      const [intentBytes, templateBytes, suppliedEvidence, payload] = fields;
      if (payload.length === 0) return synchronize(intentBytes, templateBytes, suppliedEvidence);
      // Only a complete frame with the exact bytes can reach the signing path.
      if (!isFixedPayload(payload)) refuse('SCOPE_MISMATCH');
      const intent = parseEvent(intentBytes), r = intent.record, b = r.body;
      const template = parseRecord(templateBytes), t = template.body;
      const supplied = parseBytes(suppliedEvidence, { mode: 'evidence' });
      if (r.kind !== 'intent' || r.profile !== CLASSICAL_PROFILE || !equalData(b.scope, LOCAL_SCOPE) || b.adapter_profile !== LOCAL_ADAPTER) refuse('WRONG_AUTHORITY');
      if (seen.has(b.operation_id)) refuse('REPLAY');
      // No eviction: the streamed path is bounded by the authenticated session.
      if (seen.size >= (prefix ? 32768 : 256)) refuse('LIMIT_EXCEEDED');
      if (prefix && (prefix.head().closed || prefix.head().id !== intent.event.id)) refuse('INCONSISTENT_HEAD');
      if ([b.requester_key_id, b.actor_key_id, config.anchor.expected_root_key_id,
        keyId(trustedBytes({ profile: CLASSICAL_PROFILE, bip340_public_key: r.outer_context.pubkey })).toString('hex')].includes(key)) refuse('WRONG_AUTHORITY');
      if (template.kind !== 'receipt' || template.profile !== CLASSICAL_PROFILE ||
        template.subject_id !== r.subject_id || template.chain_id !== r.chain_id || template.epoch !== r.epoch ||
        template.previous_event !== intent.event.id || BigInt(template.sequence) !== BigInt(r.sequence) + 1n ||
        template.outer_context.pubkey !== r.outer_context.pubkey || template.outer_context.created_at !== template.issued_at ||
        template.not_before !== template.issued_at || template.expires !== null || template.consent_context !== null ||
        !equalData(template.signer_plan, [{ role: 'aperture_observer', key_id: key, key_source: 'certificate',
          certificate_ref: observer.certificate_ref, algorithms: ['bip340'] }]) ||
        t.operation_id !== b.operation_id || t.intent_ref !== intent.event.id ||
        t.intent_record_digest !== applicationDigest(canonicalBytes(r)).toString('hex') ||
        t.actor_key_id !== b.actor_key_id || t.observer_key_id !== key || t.observer_certificate_ref !== observer.certificate_ref ||
        t.observed_at !== template.issued_at || t.observed_at < r.issued_at ||
        t.outcome !== 'unknown' || t.dispatch_state !== 'dispatched_uncertain' || t.evidence.length !== 0 ||
        !template.authority_refs.includes(observer.certificate_ref) || !template.authority_refs.includes(intent.event.id)) refuse('WRONG_AUTHORITY');
      verify(intentBytes, 'intent', [{ role: 'aperture_authority', key_id: b.actor_key_id }], supplied);
      const certificateBytes = prefix ? observerCertificateBytes : supplied.events.map(v => Buffer.from(v, 'base64url'))
        .find(v => parseEvent(v).event.id === observer.certificate_ref);
      if (!certificateBytes) refuse('MISSING_EVIDENCE');
      verify(certificateBytes, 'key_binding', [{ role: 'root', key_id: config.anchor.expected_root_key_id }], supplied);
      const certificate = parseEvent(certificateBytes).record;
      if (certificate.body.key_id !== key || certificate.body.role !== 'aperture_observer' ||
        !equalData(certificate.body.restriction.adapter_profiles, [LOCAL_ADAPTER]) ||
        !equalData(certificate.body.restriction.statement_profiles, [STATEMENT_PROFILE]) ||
        certificate.body.custody_policy_digest !== registry.policy_documents.custody.digest ||
        template.issued_at < certificate.not_before || template.issued_at >= certificate.expires) refuse('WRONG_AUTHORITY');
      // Receiver acceptance is the harmless LOCAL effect. Mark it before signing;
      // no response/signing failure permits replaying the frame on this receiver.
      seen.add(b.operation_id); count += 1;
      const artifact = observationBytes(intent, observer, t.observed_at);
      const record = trustedBytes({ ...template, body: { ...t, outcome: 'done', dispatch_state: 'observed',
        evidence: [observationEvidence(artifact, key, t.observed_at)] } });
      const content = signRecord(record, trustedBytes([{ key_id: key, secret_key: secret.toString('base64url') }]));
      return [content, artifact, Buffer.alloc(0), Buffer.alloc(0)];
    },
    count: () => count,
    close() { closedFlag = true; prefix?.close(); observerCertificateBytes?.fill(0); secret.fill(0); },
  });
}
