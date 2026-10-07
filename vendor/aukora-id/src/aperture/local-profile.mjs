import { parseBytes, canonicalBytes, hashDomain, ByteError, closed, h32, b64 } from '../bytes/index.mjs';
import { isFixedPayload } from './fixed-message.mjs';

export const CLASSICAL_PROFILE = 'aukora.classical.bip340.v1';
export const LOCAL_ADAPTER = 'aukora.local.fixed-message.v1';
export const LOCAL_SCOPE = Object.freeze({
  adapter_profile: LOCAL_ADAPTER,
  site: Object.freeze({ scheme: 'local', endpoint: 'aukora-test-sink-v1' }),
  resource: 'sink', operation: 'emit', payload_class: LOCAL_ADAPTER,
});
export const LOCAL_BUDGET = Object.freeze([
  Object.freeze({ unit: 'bytes', maximum: '18', currency: null }),
  Object.freeze({ unit: 'requests', maximum: '1', currency: null }),
]);

// JSON.stringify is confined to internally constructed, non-executable data.
// All canonicalization/hash semantics belong to W1.
export function trustedBytes(value) {
  return canonicalBytes(parseBytes(Buffer.from(JSON.stringify(value))));
}
export function equalData(a, b) {
  return Buffer.from(trustedBytes(a)).equals(Buffer.from(trustedBytes(b)));
}
export function refuse(code) {
  throw new ByteError(code, 'LOCAL aperture refused');
}
export function checkLocalRequest(record) {
  if (record.kind !== 'emission_request') refuse('WRONG_DOMAIN');
  if (record.profile !== CLASSICAL_PROFILE) refuse('UNSUPPORTED_PROFILE');
  if (!equalData(record.body.scope, LOCAL_SCOPE) || !equalData(record.body.budget, LOCAL_BUDGET)) {
    refuse('SCOPE_MISMATCH');
  }
}

function decodeB64(text, length) {
  b64(text, length);
  return Buffer.from(text, 'base64url');
}

export function openPayload(payloadEvidenceBytes, operationId, commitment) {
  const evidence = parseBytes(payloadEvidenceBytes, { maxBytes: 1024 });
  closed(evidence, { operation_id: h32, salt: value => b64(value, 32), payload: value => b64(value, 18) });
  if (evidence.operation_id !== operationId) refuse('WRONG_AUTHORITY');
  const salt = decodeB64(evidence.salt, 32);
  let payload;
  try {
    payload = decodeB64(evidence.payload, 18);
    const check = () => {
      if (!isFixedPayload(payload)) refuse('SCOPE_MISMATCH');
      const preimage = Buffer.concat([salt, payload]);
      try {
        if (Buffer.from(hashDomain('aukora.payload.v1', preimage)).toString('hex') !== commitment) {
          refuse('WRONG_AUTHORITY');
        }
      } finally { preimage.fill(0); }
    };
    check();
    return Object.freeze({ payload, check, destroy() { salt.fill(0); payload.fill(0); } });
  } catch (error) {
    salt.fill(0); payload?.fill(0);
    throw error;
  }
}

export function operationResult({ operationId = null, intentRef = null, receiptRef = null, state = 'refused', reasons = ['MISSING_EVIDENCE'] } = {}) {
  return Object.freeze({ operation_id: operationId, intent_ref: intentRef, receipt_ref: receiptRef,
    state, reason_codes: Object.freeze([...new Set(reasons)].sort()) });
}
