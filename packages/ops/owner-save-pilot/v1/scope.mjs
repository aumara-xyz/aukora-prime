// SPDX-License-Identifier: AGPL-3.0-or-later
// Scope metadata only. This module never verifies an approval or executes an effect.
import { createHash } from 'node:crypto';
import { canonicalJson, parseStrictJson, operationDigest } from '../../../contracts/src/runtime.mjs';
import profileInput from './profile.json' with { type: 'json' };

const HEX = /^[a-f0-9]{64}$/;
const DIGEST = /^sha256:[a-f0-9]{64}$/;
const COMMIT = /^[a-f0-9]{40}$/;
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i;
const MISSING = ['independent_witness', 'second_host_anchor', 'hardware_hash_display'];
const EXPECTED_PROFILE = {
  version: 1, kind: 'prime-owner-save-pilot-profile/v1',
  guarantee_profile: 'reduced-guarantee-owner-save-pilot/v1', scope_label: 'REDUCED-GUARANTEE',
  missing_guarantees: MISSING, intended_effect: 'memory.save', approval_material: 'passkey',
  storage_backend: 'postgresql', entry_surface: 'existing-owner-application',
  public_qualified_factory: 'closed', v03_conformance: 'NOT_CLAIMED',
  grok_review: 'PENDING_ACTUAL_BYTES_REVIEW', setup_mode: 'action-time-approved-only'
};
function requireValue(value, reason) { if (!value) throw new TypeError(`INVALID: ${reason}`); }
function detach(value, maxBytes = 8 * 1024 * 1024) {
  const bytes = canonicalJson(value); // Reject accessors/prototypes before reading fields.
  return parseStrictJson(bytes, { maxBytes });
}
function closed(value, fields, reason) {
  requireValue(value && !Array.isArray(value) && typeof value === 'object'
    && Object.keys(value).sort().join(',') === [...fields].sort().join(','), reason);
  return value;
}
function frozen(value) {
  if (value && typeof value === 'object') { Object.values(value).forEach(frozen); Object.freeze(value); }
  return value;
}
export function sha256Bytes(bytes) {
  requireValue(typeof bytes === 'string', 'UTF8_TEXT_REQUIRED');
  return 'sha256:' + createHash('sha256').update(bytes, 'utf8').digest('hex');
}
const hash = (domain, value) => sha256Bytes(domain + '\0' + canonicalJson(value));
requireValue(canonicalJson(profileInput) === canonicalJson(EXPECTED_PROFILE), 'PILOT_PROFILE_LITERAL_REQUIRED');
export const PILOT_PROFILE = frozen(detach(profileInput, 16 * 1024));
export const PILOT_PROFILE_DIGEST = hash('aukora-prime.owner-save-pilot-profile.v1', PILOT_PROFILE);

function deployment(input) {
  const value = closed(detach(input, 16 * 1024),
    ['source_commit', 'release_digest', 'deployment_manifest_sha256'], 'EXACT_EXTERNAL_DEPLOYMENT_REQUIRED');
  requireValue(COMMIT.test(value.source_commit) && HEX.test(value.release_digest)
    && HEX.test(value.deployment_manifest_sha256), 'EXTERNAL_DEPLOYMENT_PIN_REQUIRED');
  return value;
}
function operation(input) {
  if (input === null) return null;
  const value = detach(input, 2 * 1024 * 1024);
  const digest = operationDigest(value); // Frozen Prime structural contract/domain.
  closed(value.target_identity, ['kind', 'owner_subject'], 'PILOT_MEMORY_TARGET_REQUIRED');
  requireValue(value.action_type === 'memory.save' && value.audience === 'aukora-prime.memory'
    && value.target_identity.kind === 'prime-memory'
    && /^aukora:1:[a-f0-9]{64}$/.test(value.target_identity.owner_subject), 'PILOT_OWNER_SAVE_REQUIRED');
  return { value, digest };
}
function receipt(bytes, op) {
  if (bytes === null) return null;
  requireValue(op !== null, 'RECEIPT_OPERATION_REQUIRED');
  const value = closed(parseStrictJson(bytes, { maxBytes: 2 * 1024 * 1024 }),
    ['version', 'kind', 'operation_id', 'operation_digest', 'grant_id', 'request_id',
      'request_digest', 'owner_subject', 'action_type', 'status', 'result_digest', 'result'],
    'UNCHANGED_PUBLIC_RECEIPT_FIELDS_REQUIRED');
  requireValue(bytes === canonicalJson(value), 'EXACT_CANONICAL_RECEIPT_BYTES_REQUIRED');
  requireValue(value.version === 1 && value.kind === 'prime-memory-effect/v1' && value.status === 'applied'
    && value.action_type === 'memory.save' && UUID.test(value.request_id)
    && DIGEST.test(value.request_digest) && DIGEST.test(value.result_digest)
    && typeof value.grant_id === 'string' && value.grant_id.length > 0 && value.grant_id.length <= 1024,
  'PUBLIC_RECEIPT_SHAPE_REQUIRED');
  requireValue(value.operation_id === op.value.operation_id && value.operation_digest === op.digest
    && value.owner_subject === op.value.target_identity.owner_subject, 'RECEIPT_OPERATION_BINDING_REQUIRED');
  requireValue(value.result_digest === hash('aukora-prime.memory-result.v1', value.result), 'RECEIPT_RESULT_DIGEST_REQUIRED');
  return { digest: hash('aukora-prime.memory-receipt.v1', value), bytesDigest: sha256Bytes(bytes) };
}

// Caller must supply independently retained deployment pins and the unchanged
// receipt bytes already admitted by C/Bridge. Hash agreement is not admission.
export function createPilotScopeBinding(input) {
  const data = closed(detach(input), ['deployment', 'operation', 'canonical_receipt_bytes'], 'EXACT_SCOPE_INPUT_REQUIRED');
  const dep = deployment(data.deployment), op = operation(data.operation), rec = receipt(data.canonical_receipt_bytes, op);
  const scope = {
    version: 1, kind: 'prime-owner-save-pilot-scope/v1',
    guarantee_profile: PILOT_PROFILE.guarantee_profile, scope_label: PILOT_PROFILE.scope_label,
    missing_guarantees: [...MISSING], public_qualified_factory: 'closed',
    v03_conformance: 'NOT_CLAIMED', grok_review: 'PENDING_ACTUAL_BYTES_REVIEW',
    profile_digest: PILOT_PROFILE_DIGEST, ...dep,
    operation_id: op?.value.operation_id ?? null, operation_digest: op?.digest ?? null,
    receipt_digest: rec?.digest ?? null, canonical_receipt_bytes_sha256: rec?.bytesDigest ?? null
  };
  return frozen({ scope, scope_digest: hash('aukora-prime.owner-save-pilot-scope.v1', scope) });
}

export function verifyPilotScopeBinding(input) {
  const data = closed(detach(input), ['binding', 'expected_deployment', 'operation', 'canonical_receipt_bytes'], 'EXACT_SCOPE_VERIFICATION_REQUIRED');
  closed(data.binding, ['scope', 'scope_digest'], 'EXACT_SCOPE_BINDING_REQUIRED');
  const expected = createPilotScopeBinding({ deployment: data.expected_deployment,
    operation: data.operation, canonical_receipt_bytes: data.canonical_receipt_bytes });
  requireValue(canonicalJson(data.binding) === canonicalJson(expected), 'PILOT_SCOPE_BINDING_MISMATCH');
  return expected;
}

// This source-preparation status deliberately has no runtime PASS/DONE state.
// H/B must agree a separate actual application envelope/status integration.
export function createPilotPreparationStatus(input) {
  const data = closed(detach(input), ['phase', 'deployment', 'operation', 'canonical_receipt_bytes'], 'EXACT_PREPARATION_STATUS_REQUIRED');
  requireValue(['source_preparation', 'integration_pending', 'activation_pending', 'actual_bytes_review_pending'].includes(data.phase), 'PREPARATION_PHASE_REQUIRED');
  const binding = createPilotScopeBinding({ deployment: data.deployment, operation: data.operation,
    canonical_receipt_bytes: data.canonical_receipt_bytes });
  return frozen({ version: 1, kind: 'prime-owner-save-pilot-preparation-status/v1',
    qualification: 'UNPERFORMED', phase: data.phase, ...binding });
}
