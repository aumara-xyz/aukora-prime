// W6 is a byte-only preparation/inspection layer. It owns no authority state.
import { readFileSync } from 'node:fs';
import { canonicalBytes, closed, fail, parseBytes, parseEvent, parseRecord, snapshotBytes } from '../bytes/index.mjs';
import * as verifier from '../verifier/index.mjs';

const registry = parseBytes(readFileSync(new URL('../../spec/layer0-v1/registry.json', import.meta.url)));
export const LOCAL_SCOPE = registry.local_scope;
export const LOCAL_BUDGET = registry.local_budget;
export const POLICY_PINS = Object.freeze(Object.fromEntries(Object.entries(registry.policy_documents).map(([name, value]) => [name, value.digest])));
const rejectCodes = new Set(registry.reason_codes.REJECT);

// Only internally constructed data or W1-parsed trees reach this serializer.
export const encode = value => canonicalBytes(parseBytes(Buffer.from(JSON.stringify(value))));
export const same = (left, right) => canonicalBytes(left).equals(canonicalBytes(right));
export const insist = (condition, code) => { if (!condition) fail(code); };

export function addReason(result, code) {
  const reasons = [...new Set([...result.reason_codes.filter(r => r !== 'VERIFIED'), code])].sort();
  const verdict = reasons.some(r => rejectCodes.has(r)) ? 'REJECT'
    : reasons.some(r => registry.reason_codes.UNKNOWN.includes(r)) ? 'UNKNOWN' : 'DRAFT';
  return Object.freeze({ ...result, verdict, reason_codes: Object.freeze(reasons) });
}

// Snapshot each external byte input before it is used by more than one reader.
// All cryptographic, ancestry, current-control and proof checks belong to W2.
export function inspectTyped(eventBytes, contextBytes, evidenceBytes, kind, current = false) {
  return inspect(false, null, eventBytes, contextBytes, evidenceBytes, kind, current);
}

// The prefix is an opaque trusted-construction argument, never wire data. Only
// the verifier module's fixed brand gate can interpret it; no handle methods run.
export function inspectPrefixTyped(prefix, eventBytes, contextBytes, evidenceBytes, kind, current = false) {
  insist(typeof verifier.verifyPrefixEvent === 'function', 'UNSUPPORTED_PROFILE');
  return inspect(true, prefix, eventBytes, contextBytes, evidenceBytes, kind, current);
}

function inspect(prefixed, prefix, eventBytes, contextBytes, evidenceBytes, kind, current) {
  const verify = prefixed
    ? (event, context, evidence) => verifier.verifyPrefixEvent(prefix, event, context, evidence)
    : verifier.verifyEvent;
  let event, context, evidence;
  try {
    event = snapshotBytes(eventBytes);
    context = snapshotBytes(contextBytes, 4194304);
    evidence = snapshotBytes(evidenceBytes, 4194304);
  } catch {
    return { verification: verify(eventBytes, contextBytes, evidenceBytes), entry: null, context: null };
  }
  let verification = verify(event, context, evidence), entry = null, parsedContext = null;
  try {
    parsedContext = parseBytes(context, { mode: 'evidence' });
    if (parsedContext.expected_kind !== kind) verification = addReason(verification, 'WRONG_DOMAIN');
    if (current && parsedContext.purpose !== 'authorization_now') verification = addReason(verification, 'STALE_CONTROL');
    const input = parseBytes(event);
    const record = input.schema === 'aukora.draft.v1' ? parseRecord(canonicalBytes(input.record)) : (entry = parseEvent(event)).record;
    if (record.kind !== kind) verification = addReason(verification, 'WRONG_DOMAIN');
  } catch { /* W2 already reports malformed/unsupported input without effects. */ }
  return { verification, entry, context: parsedContext };
}

export function draftRecord(recordBytes, kind, roles) {
  const record = parseRecord(recordBytes);
  insist(record.kind === kind, 'WRONG_DOMAIN');
  insist(record.signer_plan.length === 1 && roles.includes(record.signer_plan[0].role)
    && record.signer_plan[0].key_source === 'certificate', 'WRONG_AUTHORITY');
  insist(record.authority_refs.includes(record.signer_plan[0].certificate_ref), 'WRONG_AUTHORITY');
  return record;
}

export const wrapDraft = record => encode({ schema: 'aukora.draft.v1', record, proofs: [] });

// W1's explicit trusted signing API consumes this output. This does not sign,
// decide consent or grant permission; malformed or committed wrappers refuse.
export function delegationRecordFromDraft(draftBytes) {
  const draft = parseBytes(draftBytes);
  closed(draft, {
    schema: value => insist(value === 'aukora.draft.v1', 'CLOSED_SCHEMA'),
    record: value => insist(value !== null && typeof value === 'object', 'CLOSED_SCHEMA'),
    proofs: value => insist(Array.isArray(value) && value.length === 0, 'CLOSED_SCHEMA'),
  });
  const roles = { vouch: ['root', 'gardener'], vouch_accept: ['human_approval'],
    agent_card: draft.record.schema === 'aukora.record.v2' ? ['root'] : ['human_approval'],
    emission_request: ['agent'], owner_approval: ['root'], intent: ['aperture_authority'] };
  insist(Object.hasOwn(roles, draft.record.kind), 'WRONG_DOMAIN');
  if (['owner_approval', 'intent'].includes(draft.record.kind)) insist(draft.record.schema === 'aukora.record.v2', 'UNSUPPORTED_SCHEMA');
  return canonicalBytes(draftRecord(canonicalBytes(draft.record), draft.record.kind, roles[draft.record.kind]));
}

export const CLAIMS = parseBytes(encode({
  profile: registry.profile.id,
  trusted_adapter: 'Node',
  cryptography: 'W1 bytes/keys and W2 verifier; no W6 signature kernel',
  registration: 'read-only inspection of an owner-issued card; no operational enrollment',
  proposals: 'untrusted data; trusted host must separately sign, admit and submitLocal',
  vouch_graph: 'unverified claims projection; no independent-support count or admission authority',
  consent_scope_digest: 'opaque signed H32; preimage/domain not frozen',
  custody: 'disposable LOCAL test keys in trusted test harness only',
  sandbox: false,
  network_confinement: false,
  key_custody: false,
  onward_delegation: false,
  live_dispatch: false,
  tier_unlock: false,
  receipt_creation: false,
  dependencies: ['W1 strict bytes and disposable signing', 'W2 pure verifier', 'trusted host submitLocal and protected current-control/durability boundary',
    'V2 owner approval requires shared schema/verifier/admission overlay; no local bypass'],
}));

export { createOwnerApprovalDraft, prepareOwnerApproval, validateOwnerApproval, prepareApprovedIntent } from './approval.mjs';
