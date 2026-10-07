import { types } from 'node:util';
import { copyBytes, copyBoundedBytes, freezeData, plainFields } from './bytes.mjs';
import { expandHead } from './expansion.mjs';
import { GEOMETRY, projectGeometry } from './geometry.mjs';

const RESULT_FIELDS = ['verdict', 'reason_codes', 'record_digest', 'event_id', 'validated_through', 'missing_evidence', 'conflicts'];
const BUNDLE_FIELDS = ['eventBytes', 'contextBytes', 'evidenceBytes'];
const HEX32 = /^[0-9a-f]{64}$/;
const MAX_PULSES_PER_RENDERER = 4096;

function isPlainArray(value, length) {
  if (types.isProxy(value) || !Array.isArray(value)) return false;
  const fields = Object.getOwnPropertyDescriptors(value);
  if (fields.length.value !== length || Reflect.ownKeys(fields).length !== length + 1) return false;
  for (let i = 0; i < length; i += 1) {
    if (!fields[i] || !Object.hasOwn(fields[i], 'value')) return false;
  }
  return true;
}

function verifiedHead(result, head) {
  const fields = plainFields(result, RESULT_FIELDS);
  return fields !== null && fields.verdict === 'valid'
    && fields.event_id === head && fields.validated_through === head
    && typeof fields.record_digest === 'string' && HEX32.test(fields.record_digest)
    && isPlainArray(fields.reason_codes, 1) && fields.reason_codes[0] === 'VERIFIED'
    && isPlainArray(fields.missing_evidence, 0) && isPlainArray(fields.conflicts, 0);
}

function withActivity(model, status, pulse = null) {
  return freezeData({ ...model, activity: { status, pulse } });
}

// The entire cell path has a single input: the raw public head. No metadata bag.
export function renderHead(raw32) {
  const head = copyBytes(raw32, 32, 'head');
  const projection = projectGeometry(expandHead(head));
  return freezeData({
    schema: 'aukora.pentora.render.v1',
    head: Buffer.from(head).toString('hex'),
    geometry: GEOMETRY,
    ...projection,
    activity: { status: 'unverified_head', pulse: null },
    coherence: { status: 'UNKNOWN', word: null, reason: 'production_policy_and_placement_unresolved' },
    grantsAuthority: false,
  });
}

// TRUSTED HOST COMPOSITION ONLY. Both functions are pinned by the host, never
// accepted through a renderer request, plugin message, event or metadata object.
// The source returns exact bytes only for a newly accepted signed exchange in its
// verified journal. It supplies independently anchored CLASSICAL BIP340 context
// and evidence for that event; null means no such accepted exchange. This module
// does not infer acceptance from a caller flag, reverify crypto itself, or inspect
// event content/keys/inviter to choose cells. See README for integration obligations.
export function createAcceptedExchangeRenderer(trustedVerifyEvent, trustedAcceptedExchangeSource) {
  for (const fn of [trustedVerifyEvent, trustedAcceptedExchangeSource]) {
    if (typeof fn !== 'function' || types.isProxy(fn)) throw new TypeError('explicit trusted linkage required');
  }
  const displayed = new Set();
  return async function renderAcceptedExchange(raw32) {
    const head = copyBytes(raw32, 32, 'head');
    const model = renderHead(head);
    if (displayed.has(model.head)) return withActivity(model, 'already_displayed');
    if (displayed.size >= MAX_PULSES_PER_RENDERER) return withActivity(model, 'pulse_capacity_exhausted');
    try {
      const supplied = await trustedAcceptedExchangeSource(head);
      if (supplied === null) return withActivity(model, 'no_accepted_exchange');
      const bundle = plainFields(supplied, BUNDLE_FIELDS);
      if (bundle === null) return withActivity(model, 'verification_unavailable');
      const event = copyBoundedBytes(bundle.eventBytes, 262144, 'event bytes');
      const context = copyBoundedBytes(bundle.contextBytes, 262144, 'context bytes');
      const evidence = copyBoundedBytes(bundle.evidenceBytes, 4194304, 'evidence bytes');
      const result = await trustedVerifyEvent(event, context, evidence);
      if (!verifiedHead(result, model.head)) return withActivity(model, 'not_verified');
      // Recheck after await: concurrent renders cannot repeat the pulse or exceed cap.
      if (displayed.has(model.head)) return withActivity(model, 'already_displayed');
      if (displayed.size >= MAX_PULSES_PER_RENDERER) return withActivity(model, 'pulse_capacity_exhausted');
      displayed.add(model.head);
      return withActivity(model, 'accepted_signed_exchange', { eventId: model.head });
    } catch {
      return withActivity(model, 'verification_unavailable');
    }
  };
}
