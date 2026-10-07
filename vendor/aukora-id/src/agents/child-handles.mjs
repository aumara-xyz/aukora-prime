// Ephemeral restrictions on the original card, never a new signed delegation.
// Trusted host owns this instance and supplies freshly acquired current evidence.
import { randomBytes } from 'node:crypto';
import { applicationDigest, budgets, canonicalBytes, closed, h32, parseBytes, parseRecord, snapshotBytes, uint, validateScope } from '../bytes/index.mjs';
import * as verifier from '../verifier/index.mjs';
import { LOCAL_BUDGET, addReason, encode, inspectTyped, inspectPrefixTyped, insist, same } from '../delegation/index.mjs';
import { prepareAgentRequest, preparePrefixAgentRequest } from './index.mjs';

const unsigned = Object.freeze({ verdict: 'DRAFT', reason_codes: Object.freeze(['UNSIGNED_DRAFT']) });
const errorCode = error => typeof error?.code === 'string' ? error.code : 'CLOSED_SCHEMA';
const outcome = (verification, fields = {}) => Object.freeze({ ...verification,
  handle_bytes: null, effective_limits: null, draft: null, ...fields, grants_authority: false });

function limits(bytes) {
  const value = closed(parseBytes(bytes, { maxBytes: 2048 }), {
    schema: v => insist(v === 'aukora.local-child-restriction.v1', 'CLOSED_SCHEMA'),
    parent_card_ref: h32, scope: validateScope, budget: budgets, not_before: uint, expires: uint,
  });
  insist(value.not_before < value.expires, 'CLOSED_SCHEMA');
  insist(value.budget.length === 2 && value.budget.every(b =>
    ['bytes', 'requests'].includes(b.unit) && b.currency === null), 'SCOPE_MISMATCH');
  return value;
}

function handleID(bytes) {
  return closed(parseBytes(bytes, { maxBytes: 256 }), {
    schema: v => insist(v === 'aukora.local-child-handle.v1', 'CLOSED_SCHEMA'), handle_id: h32,
  }).handle_id;
}

export function createLocalChildHandles() {
  return createHandles(false, null);
}

export function createPrefixChildHandles(prefix) {
  // No fallback if the shared branded API has not landed. Never read prefix
  // properties, call prefix.verify, accept a verdict, or manufacture a session.
  insist(typeof verifier.verifyPrefixEvent === 'function', 'UNSUPPORTED_PROFILE');
  return createHandles(true, prefix);
}

function createHandles(prefixed, prefix) {
  // One level, at most 64 handles per host instance; no import or restore path.
  const handles = new Map();
  let stopped = false;
  const requireOpen = () => insist(!stopped, 'REVOKED');
  const lookup = bytes => {
    requireOpen();
    const child = handles.get(handleID(bytes));
    insist(child !== undefined, 'WRONG_AUTHORITY');
    insist(!child.revoked, 'REVOKED');
    return child;
  };
  const inspectCurrent = (event, context, evidence, kind) => prefixed
    ? inspectPrefixTyped(prefix, event, context, evidence, kind, true)
    : inspectTyped(event, context, evidence, kind, true);
  return Object.freeze({
    derive(cardEventBytes, restrictionBytes, contextBytes, evidenceBytes) {
      const inspected = inspectCurrent(cardEventBytes, contextBytes, evidenceBytes, 'agent_card');
      let verification = inspected.verification;
      try {
        requireOpen();
        const requested = limits(restrictionBytes), entry = inspected.entry;
        // A draft, UNKNOWN or bad card can never allocate a handle.
        if (verification.verdict !== 'valid' || !entry) return outcome(verification);
        insist(entry.record.schema === 'aukora.record.v2', 'UNSUPPORTED_SCHEMA');
        insist(requested.parent_card_ref === entry.event.id, 'WRONG_AUTHORITY');
        const parent = entry.record;
        insist(same(requested.scope, parent.body.scope), 'SCOPE_MISMATCH');
        const budget = requested.budget.map(b => {
          const ceiling = parent.body.budget.find(p => p.unit === b.unit && p.currency === b.currency);
          insist(ceiling !== undefined, 'SCOPE_MISMATCH');
          return { ...b, maximum: String(BigInt(b.maximum) < BigInt(ceiling.maximum) ? BigInt(b.maximum) : BigInt(ceiling.maximum)) };
        });
        const effective = parseBytes(encode({ ...requested, budget,
          not_before: Math.max(requested.not_before, parent.not_before), expires: Math.min(requested.expires, parent.expires) }));
        insist(effective.not_before < effective.expires, 'SCOPE_MISMATCH');
        for (const b of LOCAL_BUDGET) insist(BigInt(budget.find(p => p.unit === b.unit).maximum) >= BigInt(b.maximum), 'SCOPE_MISMATCH');
        insist(handles.size < 64, 'LIMIT_EXCEEDED');
        let id;
        do { id = randomBytes(32).toString('hex'); } while (handles.has(id));
        handles.set(id, { card: canonicalBytes(entry.event), effective,
          remaining: new Map(budget.map(b => [b.unit, BigInt(b.maximum)])), prepared: new Set(), revoked: false });
        return outcome(unsigned, { handle_bytes: encode({ schema: 'aukora.local-child-handle.v1', handle_id: id }),
          effective_limits: effective });
      } catch (error) { verification = addReason(verification, errorCode(error)); }
      return outcome(verification);
    },
    prepare(handleBytes, proposalBytes, requestRecordBytes, contextBytes, evidenceBytes) {
      let result = unsigned;
      try {
        const child = lookup(handleBytes), requestBytes = snapshotBytes(requestRecordBytes);
        // This existing helper rechecks the original card and its complete ancestry
        // with current W2 context on every preparation. No caller verdict/callback.
        result = prefixed
          ? preparePrefixAgentRequest(prefix, proposalBytes, requestBytes, child.card, contextBytes, evidenceBytes)
          : prepareAgentRequest(proposalBytes, requestBytes, child.card, contextBytes, evidenceBytes);
        if (result.draft === null) return outcome(result);
        const request = parseRecord(requestBytes), bound = child.effective;
        insist(request.body.agent_card_ref === bound.parent_card_ref && same(request.body.scope, bound.scope)
          && request.not_before >= bound.not_before && request.expires <= bound.expires, 'SCOPE_MISMATCH');
        const digest = applicationDigest(requestBytes).toString('hex');
        insist(!child.prepared.has(digest), 'REPLAY');
        insist(child.prepared.size < 64, 'LIMIT_EXCEEDED');
        for (const b of request.body.budget) insist(child.remaining.get(b.unit) >= BigInt(b.maximum), 'SCOPE_MISMATCH');
        // Burn preparation allowance before releasing a draft, including drafts
        // the caller discards. This is not the journal's durable effect budget.
        for (const b of request.body.budget) child.remaining.set(b.unit, child.remaining.get(b.unit) - BigInt(b.maximum));
        child.prepared.add(digest);
        return outcome(result, { draft: result.draft });
      } catch (error) { result = addReason(result, errorCode(error)); }
      return outcome(result, { draft: null });
    },
    check(handleBytes, signedRequestBytes, contextBytes, evidenceBytes) {
      let verification = unsigned;
      try {
        const child = lookup(handleBytes);
        const inspected = inspectCurrent(signedRequestBytes, contextBytes, evidenceBytes, 'emission_request');
        verification = inspected.verification;
        if (verification.verdict !== 'valid' || !inspected.entry) return outcome(verification);
        const record = inspected.entry.record;
        insist(record.body.agent_card_ref === child.effective.parent_card_ref
          && child.prepared.has(applicationDigest(canonicalBytes(record)).toString('hex')), 'WRONG_AUTHORITY');
        return outcome(verification);
      } catch (error) { verification = addReason(verification, errorCode(error)); }
      return outcome(verification);
    },
    revoke(handleBytes) { lookup(handleBytes).revoked = true; },
    close() { stopped = true; handles.clear(); },
  });
}
