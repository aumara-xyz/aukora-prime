import { canonicalBytes, closed, h32, keyId, parseBytes, parseRecord, validateScope } from '../bytes/index.mjs';
import { LOCAL_BUDGET, LOCAL_SCOPE, addReason, draftRecord, encode, inspectTyped, inspectPrefixTyped, insist, same, wrapDraft } from '../delegation/index.mjs';

export function createAgentCardDraft(recordBytes) {
  const parsed = parseRecord(recordBytes);
  const record = draftRecord(canonicalBytes(parsed), 'agent_card', parsed.schema === 'aukora.record.v2' ? ['root'] : ['human_approval']);
  insist(record.body.human_subject === record.subject_id, 'WRONG_AUTHORITY');
  insist(keyId(canonicalBytes(record.body.agent_key)).toString('hex') === record.body.agent_key_id, 'WRONG_SIGNER');
  insist(record.body.budget.length === 2 && record.body.budget.every(b =>
    ['bytes', 'requests'].includes(b.unit) && b.currency === null), 'SCOPE_MISMATCH');
  return wrapDraft(record);
}

export function validateAgentCard(eventBytes, contextBytes, evidenceBytes) {
  return inspectTyped(eventBytes, contextBytes, evidenceBytes, 'agent_card').verification;
}

// A descriptor is display/registration metadata only. No API accepts it instead
// of the original signed bytes plus newly acquired trusted current evidence.
export function registerAgentCard(eventBytes, contextBytes, evidenceBytes) {
  const { verification, entry } = inspectTyped(eventBytes, contextBytes, evidenceBytes, 'agent_card', true);
  const registration = verification.verdict === 'valid' && entry ? parseBytes(encode({
    card_ref: entry.event.id,
    human_subject: entry.record.body.human_subject,
    agent_subject: entry.record.body.agent_subject,
    agent_key_id: entry.record.body.agent_key_id,
    scope: entry.record.body.scope,
    budget: entry.record.body.budget,
    not_before: entry.record.not_before,
    expires: entry.record.expires,
    onward_delegation: false,
    grants_authority: false,
  })) : null;
  return Object.freeze({ verification, registration, grants_authority: false });
}

export function parseProposal(proposalBytes) {
  return closed(parseBytes(proposalBytes), {
    schema: v => insist(v === 'aukora.agent-proposal.v1', 'CLOSED_SCHEMA'),
    agent_card_ref: h32,
    operation_id: h32,
    nonce: h32,
    scope: validateScope,
  });
}

// Trusted-host preparation seam. The host supplies the unsigned frozen request,
// including the volatile payload commitment and journal position. The proposal
// never supplies signer, context, policy, control, payload-opening or sink handles.
// A valid return remains a draft; W3 must revalidate the signed event under its lock.
export function prepareAgentRequest(proposalBytes, requestRecordBytes, cardEventBytes, contextBytes, evidenceBytes) {
  return prepareRequest(proposalBytes, requestRecordBytes,
    inspectTyped(cardEventBytes, contextBytes, evidenceBytes, 'agent_card', true));
}

// Fixed verifier entrypoint only. A forged prefix cannot supply a verdict or
// callback. The constructor-owned handle goes through W2's brand gate each time.
export function preparePrefixAgentRequest(prefix, proposalBytes, requestRecordBytes, cardEventBytes, contextBytes, evidenceBytes) {
  return prepareRequest(proposalBytes, requestRecordBytes,
    inspectPrefixTyped(prefix, cardEventBytes, contextBytes, evidenceBytes, 'agent_card', true));
}

function prepareRequest(proposalBytes, requestRecordBytes, inspected) {
  let verification = inspected.verification, draft = null;
  try {
    const proposal = parseProposal(proposalBytes);
    const request = draftRecord(requestRecordBytes, 'emission_request', ['agent']);
    const card = inspected.entry?.record, reference = inspected.entry?.event.id;
    insist(request.body.agent_card_ref === proposal.agent_card_ref
      && request.body.operation_id === proposal.operation_id && request.body.nonce === proposal.nonce, 'WRONG_AUTHORITY');
    insist(same(request.body.scope, proposal.scope) && same(request.body.scope, LOCAL_SCOPE)
      && same(request.body.budget, LOCAL_BUDGET), 'SCOPE_MISMATCH');
    if (card) {
      insist(proposal.agent_card_ref === reference && request.body.agent_card_ref === reference, 'WRONG_AUTHORITY');
      insist(request.subject_id === card.subject_id && request.chain_id === card.chain_id
        && request.body.requester_subject === card.body.agent_subject, 'WRONG_AUTHORITY');
      insist(request.body.requester_key_id === card.body.agent_key_id
        && request.signer_plan[0].key_id === card.body.agent_key_id, 'WRONG_SIGNER');
      insist(request.signer_plan[0].certificate_ref === reference
        && request.authority_refs.length === 1 && request.authority_refs[0] === reference, 'WRONG_AUTHORITY');
      insist(same(request.body.scope, card.body.scope) && request.not_before >= card.not_before
        && request.expires <= card.expires, 'SCOPE_MISMATCH');
      for (const value of request.body.budget) {
        const ceiling = card.body.budget.find(b => b.unit === value.unit && b.currency === value.currency);
        insist(ceiling && BigInt(value.maximum) <= BigInt(ceiling.maximum), 'SCOPE_MISMATCH');
      }
    }
    const control = inspected.context?.control;
    if (control) {
      insist(request.epoch === control.epoch && request.previous_event === control.head
        && BigInt(request.sequence) === BigInt(control.sequence) + 1n, 'WRONG_AUTHORITY');
      insist(request.body.expected_control_checkpoint === control.checkpoint_ref, 'INCONSISTENT_HEAD');
      if (control.now_lower >= request.expires) verification = addReason(verification, 'EXPIRED');
      else if (control.now_upper < request.not_before) verification = addReason(verification, 'NOT_YET_VALID');
      else if (control.now_lower < request.not_before || control.now_upper >= request.expires) verification = addReason(verification, 'TIME_UNCERTAINTY');
    }
    if (verification.verdict === 'valid' && card) draft = wrapDraft(request);
  } catch (error) {
    verification = addReason(verification, typeof error?.code === 'string' ? error.code : 'CLOSED_SCHEMA');
  }
  return Object.freeze({
    card_verification: inspected.verification,
    verdict: draft ? 'DRAFT' : verification.verdict,
    reason_codes: draft ? Object.freeze(['UNSIGNED_DRAFT']) : verification.reason_codes,
    draft,
    grants_authority: false,
  });
}

export function validateAgentRequest(eventBytes, contextBytes, evidenceBytes) {
  const { verification, entry } = inspectTyped(eventBytes, contextBytes, evidenceBytes, 'emission_request', true);
  if (entry && (entry.record.body.agent_card_ref === null
    || entry.record.signer_plan.length !== 1 || entry.record.signer_plan[0].role !== 'agent')) {
    return addReason(verification, 'WRONG_AUTHORITY');
  }
  return verification;
}

export { createLocalChildHandles, createPrefixChildHandles } from './child-handles.mjs';
