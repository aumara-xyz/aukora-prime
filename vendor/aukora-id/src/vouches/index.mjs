import { parseBytes, parseEvent } from '../bytes/index.mjs';
import { evidence as validateEvidence } from '../verifier/schema.mjs';
import { draftRecord, encode, inspectTyped, insist, wrapDraft } from '../delegation/index.mjs';

export function createVouchDraft(recordBytes) {
  const record = draftRecord(recordBytes, 'vouch', ['root', 'gardener']);
  insist(record.body.inviter_subject === record.subject_id
    && record.body.invitee_subject !== record.subject_id, 'WRONG_AUTHORITY');
  return wrapDraft(record);
}

export function createVouchAcceptanceDraft(recordBytes, vouchEventBytes) {
  const record = draftRecord(recordBytes, 'vouch_accept', ['human_approval']);
  const vouch = parseEvent(vouchEventBytes);
  insist(vouch.record.kind === 'vouch', 'WRONG_DOMAIN');
  insist(record.body.vouch_ref === vouch.event.id && record.body.invitee_subject === record.subject_id, 'WRONG_AUTHORITY');
  for (const field of ['inviter_subject', 'invitee_subject', 'invitee_genesis']) {
    insist(record.body[field] === vouch.record.body[field], 'WRONG_AUTHORITY');
  }
  // consent_scope_digest is preserved verbatim. Its preimage/domain is not frozen;
  // neither this constructor nor an application signature invents that meaning.
  return wrapDraft(record);
}

export function validateVouch(eventBytes, contextBytes, evidenceBytes) {
  return inspectTyped(eventBytes, contextBytes, evidenceBytes, 'vouch').verification;
}

export function validateVouchAcceptance(eventBytes, contextBytes, evidenceBytes) {
  return inspectTyped(eventBytes, contextBytes, evidenceBytes, 'vouch_accept').verification;
}

// Structural projection of supplied claims, deliberately separate from W2
// authority validation. Uses the existing EvidenceBundle shape; every event
// re-enters W1. There is no traversal or path/cycle-based score to amplify.
export function projectVouchClaims(evidenceBytes) {
  const bundle = parseBytes(evidenceBytes, { mode: 'evidence' });
  validateEvidence(bundle);
  const entries = bundle.events.map(bytes => parseEvent(Buffer.from(bytes, 'base64url')));
  const byRef = new Map(), nodes = new Set(), edges = new Map();
  let previous = null;
  for (const entry of entries) {
    insist(previous === null || previous < entry.event.id, 'CLOSED_SCHEMA');
    previous = entry.event.id;
    byRef.set(entry.event.id, entry);
  }
  for (const { event, record } of byRef.values()) {
    if (record.kind !== 'vouch') continue;
    const b = record.body;
    const pair = `${b.inviter_subject}:${b.invitee_subject}`;
    if (!edges.has(pair)) edges.set(pair, { inviter_subject: b.inviter_subject, invitee_subject: b.invitee_subject, vouch_refs: [], acceptance_claims: [], withdrawal_claims: [] });
    edges.get(pair).vouch_refs.push(event.id);
    nodes.add(b.inviter_subject); nodes.add(b.invitee_subject);
  }
  insist(nodes.size <= 256 && edges.size <= 512, 'LIMIT_EXCEEDED');
  for (const { event, record } of byRef.values()) {
    const b = record.body;
    if (record.kind === 'vouch_accept') {
      const vouch = byRef.get(b.vouch_ref)?.record;
      if (vouch?.kind === 'vouch' && b.invitee_subject === record.subject_id
        && ['inviter_subject', 'invitee_subject', 'invitee_genesis'].every(field => b[field] === vouch.body[field])) {
        edges.get(`${b.inviter_subject}:${b.invitee_subject}`).acceptance_claims.push({ acceptance_ref: event.id, vouch_ref: b.vouch_ref });
      }
    } else if (record.kind === 'revocation' && b.target_type === 'vouch') {
      const vouch = byRef.get(b.target_id)?.record;
      if (vouch?.kind === 'vouch' && record.subject_id === vouch.body.inviter_subject && b.target_subject === record.subject_id) {
        edges.get(`${vouch.body.inviter_subject}:${vouch.body.invitee_subject}`).withdrawal_claims.push({
          vouch_ref: b.target_id, revocation_ref: event.id, admission_predicates: b.admission_predicates,
        });
      }
    }
  }
  const compare = (a, b) => a < b ? -1 : a > b ? 1 : 0;
  const sorted = [...edges.entries()].sort(([a], [b]) => compare(a, b)).map(([, edge]) => ({
    ...edge, vouch_refs: edge.vouch_refs.sort(),
    acceptance_claims: edge.acceptance_claims.sort((a, b) => compare(a.acceptance_ref, b.acceptance_ref)),
    withdrawal_claims: edge.withdrawal_claims.sort((a, b) => compare(a.revocation_ref, b.revocation_ref)),
  }));
  return parseBytes(encode({
    verification: 'unverified_claims_only',
    vertices: [...nodes].sort(), edges: sorted,
    independent_support: null, tier_verdict: 'UNKNOWN', reason_codes: ['UNSUPPORTED_PROFILE'],
    grants_authority: false, changes_identity_access: false, changes_kira_access: false,
    establishes_physical_presence: false, establishes_unique_humanity: false,
  }));
}
