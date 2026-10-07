// Byte-only preparation for the explicit V2 approval overlay. No key, writer,
// admission-session or dispatch handle enters this module. Success is a draft.
import { createHash } from 'node:crypto';
import { canonicalBytes, parseEvent, snapshotBytes } from '../bytes/index.mjs';
import { verifyOuterEvent } from '../verifier/index.mjs';
import { openPayload } from '../aperture/local-profile.mjs';
import { LOCAL_BUDGET, LOCAL_SCOPE, addReason, draftRecord, inspectTyped, insist, same, wrapDraft } from './index.mjs';

function requestEntry(eventBytes) {
  const bytes = snapshotBytes(eventBytes);
  // Reuse W2's raw-key outer verifier: a supplied ID alone cannot bind a request.
  verifyOuterEvent(bytes);
  const entry = parseEvent(bytes);
  insist(entry.record.kind === 'emission_request', 'WRONG_DOMAIN');
  return entry;
}

function matchRequest(approval, request) {
  const a = approval.body, r = request.record, b = r.body;
  insist(approval.schema === 'aukora.record.v2', 'UNSUPPORTED_SCHEMA');
  insist(approval.subject_id === r.subject_id && approval.chain_id === r.chain_id
    && approval.epoch === r.epoch && a.request_ref === request.event.id, 'WRONG_AUTHORITY');
  insist(approval.authority_refs.includes(request.event.id)
    && a.journal_head === approval.previous_event, 'WRONG_AUTHORITY');
  insist(a.operation_id === b.operation_id && a.nonce === b.nonce
    && a.requester_key_id === b.requester_key_id && a.payload_commitment === b.payload_commitment, 'WRONG_AUTHORITY');
  insist(same(a.scope, b.scope) && same(a.scope, LOCAL_SCOPE)
    && same(b.budget, LOCAL_BUDGET), 'SCOPE_MISMATCH');
  insist(approval.not_before >= r.not_before && approval.expires <= r.expires, 'SCOPE_MISMATCH');
}

function matchOpening(approval, openingBytes) {
  // Existing aperture code owns the exact fixed payload and salted commitment.
  const opening = openPayload(openingBytes, approval.body.operation_id, approval.body.payload_commitment);
  try {
    insist(createHash('sha256').update(opening.payload).digest('hex') === approval.body.payload_sha256, 'WRONG_AUTHORITY');
  } finally { opening.destroy(); }
}

function atHead(record, control) {
  insist(control !== null && control !== undefined, 'STALE_CONTROL');
  insist(record.epoch === control.epoch && record.previous_event === control.head
    && BigInt(record.sequence) === BigInt(control.sequence) + 1n, 'INCONSISTENT_HEAD');
  if (control.now_lower >= record.expires) insist(false, 'EXPIRED');
  if (control.now_upper < record.not_before) insist(false, 'NOT_YET_VALID');
  insist(control.now_lower >= record.not_before && control.now_upper < record.expires, 'TIME_UNCERTAINTY');
}

function prepared(inspection, build) {
  let verification = inspection.verification, draft = null;
  try {
    const candidate = build();
    if (verification.verdict === 'valid') draft = candidate;
  } catch (error) {
    verification = addReason(verification, typeof error?.code === 'string' ? error.code : 'CLOSED_SCHEMA');
  }
  return Object.freeze({ verification: inspection.verification,
    verdict: draft ? 'DRAFT' : verification.verdict,
    reason_codes: draft ? Object.freeze(['UNSIGNED_DRAFT']) : verification.reason_codes,
    draft, grants_authority: false });
}

// Construction checks exact byte bindings, not human consent or fresh authority.
// The trusted caller verifies current request authority/head under its source
// lock before explicit W1 signing; admission rechecks afterward. The prepare*
// wrappers below use bounded cold verification, not the host's incremental session.
export function createOwnerApprovalDraft(recordBytes, requestEventBytes, openingBytes) {
  const approval = draftRecord(recordBytes, 'owner_approval', ['root']);
  matchRequest(approval, requestEntry(requestEventBytes));
  matchOpening(approval, openingBytes);
  return wrapDraft(approval);
}

export function prepareOwnerApproval(recordBytes, requestEventBytes, openingBytes, contextBytes, evidenceBytes) {
  const inspection = inspectTyped(requestEventBytes, contextBytes, evidenceBytes, 'emission_request', true);
  return prepared(inspection, () => {
    insist(inspection.entry !== null, 'MISSING_EVIDENCE');
    const record = draftRecord(recordBytes, 'owner_approval', ['root']);
    atHead(record, inspection.context?.control);
    insist(record.signer_plan[0].key_id === inspection.context.expected_root_key_id
      && record.signer_plan[0].certificate_ref === inspection.context.expected_genesis, 'WRONG_SIGNER');
    return createOwnerApprovalDraft(canonicalBytes(record), canonicalBytes(inspection.entry.event), openingBytes);
  });
}

export function validateOwnerApproval(eventBytes, contextBytes, evidenceBytes) {
  return inspectTyped(eventBytes, contextBytes, evidenceBytes, 'owner_approval', true).verification;
}

// W2 validates the approval's referenced request/authority. This helper additionally
// binds the volatile opening and the exact unsigned intent before host signing.
// The host must reacquire current evidence and reserve durably through its shared
// admission/aperture path; this result is never an admission or dispatch token.
export function prepareApprovedIntent(recordBytes, approvalEventBytes, requestEventBytes, openingBytes, contextBytes, evidenceBytes) {
  const inspection = inspectTyped(approvalEventBytes, contextBytes, evidenceBytes, 'owner_approval', true);
  return prepared(inspection, () => {
    insist(inspection.entry !== null, 'MISSING_EVIDENCE');
    const approval = inspection.entry.record, reference = inspection.entry.event.id;
    const request = requestEntry(requestEventBytes);
    const intent = draftRecord(recordBytes, 'intent', ['aperture_authority']);
    matchRequest(approval, request);
    matchOpening(approval, openingBytes);
    atHead(intent, inspection.context?.control);
    const a = approval.body, b = intent.body, r = request.record;
    insist(intent.schema === 'aukora.record.v2', 'UNSUPPORTED_SCHEMA');
    insist(intent.subject_id === approval.subject_id && intent.chain_id === approval.chain_id
      && intent.epoch === approval.epoch && intent.previous_event === reference
      && BigInt(intent.sequence) === BigInt(approval.sequence) + 1n
      && intent.authority_refs.includes(reference), 'INCONSISTENT_HEAD');
    insist(b.request_ref === a.request_ref && b.operation_id === a.operation_id && b.nonce === a.nonce
      && b.requester_key_id === a.requester_key_id && b.payload_commitment === a.payload_commitment, 'WRONG_AUTHORITY');
    insist(b.authority_ref === (r.body.agent_card_ref ?? r.signer_plan[0].certificate_ref)
      && b.control_checkpoint_ref === r.body.expected_control_checkpoint, 'WRONG_AUTHORITY');
    insist(same(b.scope, a.scope) && same(b.budget, r.body.budget)
      && intent.not_before >= approval.not_before && intent.expires <= approval.expires, 'SCOPE_MISMATCH');
    return wrapDraft(intent);
  });
}
