// SPDX-License-Identifier: AGPL-3.0-or-later
// Synthetic HASH-METADATA ONLY; no signer, approver, database, C store or server.
import assert from 'node:assert/strict';
import { canonicalJson, operationDigest } from '../../../contracts/src/runtime.mjs';
import { createPilotScopeBinding, verifyPilotScopeBinding, createPilotPreparationStatus, sha256Bytes } from './scope.mjs';

const deployment = { source_commit: '1'.repeat(40), release_digest: '2'.repeat(64), deployment_manifest_sha256: '3'.repeat(64) };
const operation = {
  version: 1, operation_id: 'metadata-only-operation', task_id: 'metadata-only-task',
  owner_id: 'metadata-only-owner', agent_id: 'metadata-only-agent', audience: 'aukora-prime.memory',
  action_type: 'memory.save', target_identity: { kind: 'prime-memory', owner_subject: 'aukora:1:' + '4'.repeat(64) },
  canonical_parameters: { source_only: true }, data_scope: ['metadata-only'], expected_state_version: 'metadata-only',
  provider_and_region: { provider: 'none', region: 'local' }, maximum_cost: { currency: 'USD', amount: '0' },
  expiry: '2026-10-02T00:00:00Z', nonce: 'metadata-only-nonce', policy_version: 'metadata-only', authorization_epoch: 1
};
const result = { fixture: 'UNAUTHENTICATED_HASH_METADATA_ONLY', canonical_bytes: 'exact bytes: α\n' };
const receipt = {
  version: 1, kind: 'prime-memory-effect/v1', operation_id: operation.operation_id,
  operation_digest: operationDigest(operation), grant_id: 'no-real-grant',
  request_id: '11111111-1111-4111-8111-111111111111', request_digest: 'sha256:' + '5'.repeat(64),
  owner_subject: operation.target_identity.owner_subject, action_type: 'memory.save', status: 'applied',
  result_digest: sha256Bytes('aukora-prime.memory-result.v1\0' + canonicalJson(result)), result
};
const bytes = canonicalJson(receipt);
const args = { deployment, operation, canonical_receipt_bytes: bytes };
let checks = 0;
function check(fn) { fn(); checks++; }
function rejected(fn, reason) { check(() => assert.throws(fn, new RegExp(reason))); }
const binding = createPilotScopeBinding(args);
check(() => assert.deepEqual(verifyPilotScopeBinding({ binding, expected_deployment: deployment, operation, canonical_receipt_bytes: bytes }), binding));
check(() => assert.equal(binding.scope.scope_label, 'REDUCED-GUARANTEE'));
check(() => assert.deepEqual(binding.scope.missing_guarantees, ['independent_witness', 'second_host_anchor', 'hardware_hash_display']));
check(() => assert.equal(binding.scope.receipt_digest, sha256Bytes('aukora-prime.memory-receipt.v1\0' + bytes)));
check(() => assert.equal(binding.scope.canonical_receipt_bytes_sha256, sha256Bytes(bytes)));
check(() => assert.equal(bytes, canonicalJson(receipt))); // Input receipt never receives assurance fields.
check(() => assert(Object.isFrozen(binding.scope.missing_guarantees)));
const verify = edited => verifyPilotScopeBinding({ binding: edited, expected_deployment: deployment, operation, canonical_receipt_bytes: bytes });
rejected(() => verify({ ...binding, scope: { ...binding.scope, scope_label: 'QUALIFIED' } }), 'PILOT_SCOPE_BINDING_MISMATCH');
rejected(() => verify({ ...binding, scope: { ...binding.scope, missing_guarantees: [] } }), 'PILOT_SCOPE_BINDING_MISMATCH');
rejected(() => verify({ ...binding, scope: { ...binding.scope, grok_review: 'ACCEPTED' } }), 'PILOT_SCOPE_BINDING_MISMATCH');
rejected(() => verifyPilotScopeBinding({ binding, expected_deployment: { ...deployment, release_digest: '6'.repeat(64) }, operation, canonical_receipt_bytes: bytes }), 'PILOT_SCOPE_BINDING_MISMATCH');
rejected(() => createPilotScopeBinding({ ...args, operation: { ...operation, operation_id: 'other-operation' } }), 'RECEIPT_OPERATION_BINDING_REQUIRED');
rejected(() => createPilotScopeBinding({ ...args, operation: { ...operation, target_identity: { ...operation.target_identity, owner_subject: 'aukora:1:' + '7'.repeat(64) } } }), 'RECEIPT_OPERATION_BINDING_REQUIRED');
rejected(() => createPilotScopeBinding({ ...args, canonical_receipt_bytes: canonicalJson({ ...receipt, result: { fixture: 'changed' } }) }), 'RECEIPT_RESULT_DIGEST_REQUIRED');
rejected(() => createPilotScopeBinding({ ...args, canonical_receipt_bytes: bytes + '\n' }), 'EXACT_CANONICAL_RECEIPT_BYTES_REQUIRED');
rejected(() => createPilotScopeBinding({ ...args, canonical_receipt_bytes: bytes.replace('"version":1', '"version":1,"version":1') }), 'JSON_DUPLICATE_KEY');
rejected(() => createPilotScopeBinding({ ...args, canonical_receipt_bytes: canonicalJson({ ...receipt, pilot_scope: {} }) }), 'UNCHANGED_PUBLIC_RECEIPT_FIELDS_REQUIRED');
rejected(() => createPilotScopeBinding({ ...args, operation: null }), 'RECEIPT_OPERATION_REQUIRED');
rejected(() => createPilotScopeBinding({ ...args, operation: { ...operation, action_type: 'memory.forget' }, canonical_receipt_bytes: null }), 'PILOT_OWNER_SAVE_REQUIRED');
rejected(() => createPilotScopeBinding({ ...args, allow_unqualified: true }), 'EXACT_SCOPE_INPUT_REQUIRED');
let getterRead = false;
const getterInput = Object.defineProperty({}, 'deployment', { enumerable: true, get() { getterRead = true; return deployment; } });
rejected(() => createPilotScopeBinding(getterInput), 'JSON_DATA_PROPERTY');
check(() => assert.equal(getterRead, false));
const status = createPilotPreparationStatus({ ...args, phase: 'actual_bytes_review_pending' });
check(() => assert.equal(status.qualification, 'UNPERFORMED'));
check(() => assert.equal(status.scope.grok_review, 'PENDING_ACTUAL_BYTES_REVIEW'));
rejected(() => createPilotPreparationStatus({ ...args, phase: 'DONE' }), 'PREPARATION_PHASE_REQUIRED');
check(() => {
  const noReceipt = createPilotScopeBinding({ deployment, operation: null, canonical_receipt_bytes: null });
  assert.equal(noReceipt.scope.operation_digest, null); assert.equal(noReceipt.scope.receipt_digest, null);
  assert.equal(noReceipt.scope.canonical_receipt_bytes_sha256, null); assert.equal(noReceipt.scope.scope_label, 'REDUCED-GUARANTEE');
});
check(() => {
  // Near the existing receipt bound: escaping it into the outer input exceeds
  // 2 MiB, but does not change or shrink the admitted receipt byte limit.
  const largeResult = { fixture: 'UNAUTHENTICATED_HASH_METADATA_ONLY', bytes: '"'.repeat(1_040_000) };
  const largeReceipt = { ...receipt, result: largeResult,
    result_digest: sha256Bytes('aukora-prime.memory-result.v1\0' + canonicalJson(largeResult)) };
  const largeBytes = canonicalJson(largeReceipt);
  assert(Buffer.byteLength(largeBytes) < 2 * 1024 * 1024);
  const largeArgs = { deployment, operation, canonical_receipt_bytes: largeBytes };
  assert(Buffer.byteLength(canonicalJson(largeArgs)) > 2 * 1024 * 1024);
  const largeBinding = createPilotScopeBinding(largeArgs);
  assert.deepEqual(verifyPilotScopeBinding({ binding: largeBinding, expected_deployment: deployment,
    operation, canonical_receipt_bytes: largeBytes }), largeBinding);
});
rejected(() => createPilotScopeBinding({ ...args, canonical_receipt_bytes: 'x'.repeat(2 * 1024 * 1024 + 1) }), 'JSON_SIZE');
process.stdout.write(JSON.stringify({ kind: 'prime-owner-save-pilot-source-check/v1', scope_label: 'REDUCED-GUARANTEE',
  missing_guarantees: binding.scope.missing_guarantees, source_check: 'PASS', checks,
  qualification: 'UNPERFORMED', real_passkey_pg_save: 'UNPERFORMED',
  without_approval_decline: 'UNPERFORMED', tampered_approval_decline: 'UNPERFORMED',
  grok_review: 'PENDING_ACTUAL_BYTES_REVIEW', fake_approver: 'NONE' }) + '\n');
