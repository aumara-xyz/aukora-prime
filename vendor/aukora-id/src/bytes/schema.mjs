import { assertParsed, canonicalBytes, fail, hashDomain, parseBytes, snapshotBytes } from './parser.mjs';

export const CLASSICAL_PROFILE = 'aukora.classical.bip340.v1';
export const RECORD_V2_SCHEMA = 'aukora.record.v2';
export const RECORD_V2_DOMAINS = Object.freeze({ owner_approval: 'aukora.owner-approval.v2', agent_card: 'aukora.agent-card.v2', intent: 'aukora.intent.v2' });
export const RECORD_DOMAINS = Object.freeze(Object.fromEntries([
  'identity', 'key_binding', 'epoch_transition', 'policy_commitment', 'vouch', 'vouch_accept',
  'agent_card', 'emission_request', 'intent', 'receipt', 'kira_map', 'recovery_policy', 'coherence_checkpoint', 'revocation',
].map(kind => [kind, `aukora.${kind.replaceAll('_', '-')}.v1`])));
export const PROJECTION_ORDER = Object.freeze(['identity', 'delegation', 'actions', 'receipts', 'memory']);
const maxU64 = 18446744073709551615n;
const ok = condition => { if (!condition) fail('CLOSED_SCHEMA'); };
export const text = value => ok(typeof value === 'string');
export const h32 = value => ok(typeof value === 'string' && /^[0-9a-f]{64}$/.test(value));
export const uint = value => ok(Number.isSafeInteger(value) && value >= 0 && !Object.is(value, -0));
export const u64 = value => ok(typeof value === 'string' && /^(0|[1-9][0-9]{0,19})$/.test(value) && BigInt(value) <= maxU64);
const bool = value => ok(typeof value === 'boolean');
const literal = expected => value => ok(value === expected);
const oneOf = values => value => ok(values.includes(value));
const nullable = validator => value => { if (value !== null) validator(value); };
export function b64(value, length) {
  ok(typeof value === 'string' && /^[A-Za-z0-9_-]*$/.test(value));
  const bytes = Buffer.from(value, 'base64url');
  ok(bytes.toString('base64url') === value && (length === undefined || bytes.length === length));
}
export function closed(value, fields) {
  assertParsed(value);
  ok(value !== null && typeof value === 'object' && !Array.isArray(value));
  const keys = Object.keys(value);
  ok(keys.length === Object.keys(fields).length && keys.every(key => Object.hasOwn(fields, key)));
  for (const [key, validator] of Object.entries(fields)) validator(value[key]);
  return value;
}
const array = validator => value => { assertParsed(value); ok(Array.isArray(value)); value.forEach(validator); };
const set = (validator, order = value => canonicalBytes(value)) => value => {
  array(validator)(value);
  for (let i = 1; i < value.length; i++) ok(Buffer.compare(Buffer.from(order(value[i - 1])), Buffer.from(order(value[i]))) < 0);
};
const refs = set(h32);
const texts = set(text);
export function validateDescriptor(value) {
  assertParsed(value); ok(value !== null && typeof value === 'object');
  if (value.profile === 'aukora.device.p256.v1') {
    closed(value, { profile: literal('aukora.device.p256.v1'), public_key_sec1: v => b64(v, 65), credential_id: b64,
      rp_id: v => ok(typeof v === 'string' && /^[a-z0-9.-]+$/.test(v)), origins: texts });
    ok(Buffer.from(value.public_key_sec1, 'base64url')[0] === 4);
  } else {
    if (value.profile !== CLASSICAL_PROFILE) fail('UNSUPPORTED_PROFILE');
    closed(value, { profile: literal(CLASSICAL_PROFILE), bip340_public_key: h32 });
  }
  return value;
}
export function validateScope(value) {
  closed(value, { adapter_profile: text, site: v => closed(v, { scheme: text, endpoint: text }), resource: text, operation: text, payload_class: text });
  if (value.adapter_profile !== 'aukora.local.fixed-message.v1' || value.site.scheme !== 'local' ||
      value.site.endpoint !== 'aukora-test-sink-v1' || value.resource !== 'sink' || value.operation !== 'emit' ||
      value.payload_class !== 'aukora.local.fixed-message.v1') fail('SCOPE_MISMATCH');
}
const budget = value => {
  closed(value, { unit: oneOf(['requests', 'bytes', 'minor_currency']), maximum: u64, currency: nullable(v => ok(typeof v === 'string' && /^[A-Z]{3}$/.test(v))) });
  ok((value.unit === 'minor_currency') === (value.currency !== null));
};
export const budgets = set(budget, value => value.unit + '\0' + (value.currency ?? ''));
const targetType = oneOf(['root_key', 'device_key', 'agent_card', 'key_binding', 'vouch']);
const roles = ['root', 'human_approval', 'device_assertion', 'journal_append', 'aperture_authority', 'aperture_observer', 'storage', 'gardener', 'agent', 'recovery_operator', 'successor_possession'];
const certificateRoles = roles.filter(role => !['root', 'recovery_operator', 'successor_possession'].includes(role));
const restrictionFields = {
  human_approval: { record_kinds: set(oneOf(['agent_card', 'vouch_accept', 'emission_request'])), emission_scopes: set(validateScope), budget_ceiling: budgets },
  device_assertion: { assertion_policy_ref: h32 },
  journal_append: { append_epoch: u64 },
  aperture_authority: { adapter_profiles: texts, emission_scopes: set(validateScope), budget_ceiling: budgets },
  aperture_observer: { adapter_profiles: texts, statement_profiles: texts },
  storage: { namespace_id: h32, record_kinds: value => { array(literal('kira_map'))(value); ok(value.length === 1); } },
  gardener: { admission_policy_ref: h32, monthly_cap: uint },
  agent: { emission_scopes: set(validateScope), budget_ceiling: budgets, onward_delegation: literal(false) },
};
const observation = value => closed(value, { kind: oneOf(['provider_ack', 'provider_result', 'local_boundary_record', 'reconciliation']), source_id: h32, source_role: text, artifact_digest: h32, statement_profile: text, claim: oneOf(['accepted', 'completed', 'not_dispatched', 'uncertain']), observed_at: uint });
const location = value => closed(value, { scheme: oneOf(['https', 'content_addressed']), locator: text, ciphertext_digest: h32 });
const missing = value => closed(value, { type: oneOf(['event', 'certificate', 'revocation', 'consumption', 'time', 'witness']), reference: nullable(h32), reason: oneOf(['unavailable', 'unsupported', 'withheld']) });
const projection = value => { closed(value, { role: oneOf(PROJECTION_ORDER), event_id: nullable(h32), sequence: nullable(u64) }); ok((value.event_id === null) === (value.sequence === null)); };
const envelopeCipher = value => closed(value, { cipher_profile: text, key_ref: h32, nonce: b64, ciphertext: b64, aad_digest: h32 });
const bodyFields = {
  identity: { root_key: validateDescriptor, initial_append_key: validateDescriptor, succession_policy_digest: h32, recovery_policy_digest: h32, algorithm_policy_digest: h32, persona_policy_digest: h32 },
  key_binding: { key_id: h32, descriptor: validateDescriptor, role: oneOf(certificateRoles), parent_key_id: h32, parent_certificate_ref: h32, valid_from_epoch: u64, valid_through_epoch: u64, restriction: assertParsed, custody_policy_digest: h32, binding_purpose: oneOf(['enroll', 'renew']), device_assertion_policy_digest: nullable(h32) },
  epoch_transition: { from_epoch: u64, to_epoch: u64, prior_final_event: h32, next_append_key_id: h32, next_append_certificate: h32, next_root_key: nullable(validateDescriptor), control_checkpoint_ref: h32, consumption_anchor: h32, revocation_anchor: h32, transition_policy_ref: h32 },
  policy_commitment: { policy_type: oneOf(['admission', 'custody', 'scope', 'algorithm', 'succession', 'assertion', 'time', 'control']), policy_version: uint, policy_digest: h32, effective_sequence: u64 },
  vouch: { inviter_subject: h32, invitee_subject: h32, invitee_genesis: h32, ceremony_id: h32, ceremony_claim: oneOf(['remote', 'in_person']), ceremony_evidence_refs: refs, admission_policy_ref: h32, invite_slot: h32, visibility: oneOf(['one_hop', 'explicit_edges']), visible_to: refs },
  vouch_accept: { vouch_ref: h32, inviter_subject: h32, invitee_subject: h32, invitee_genesis: h32, consent_scope_digest: h32 },
  agent_card: { human_subject: h32, agent_subject: h32, agent_key: validateDescriptor, agent_key_id: h32, scope: validateScope, budget: budgets, revocation_handle: h32, onward_delegation: literal(false), custody_policy_digest: h32 },
  emission_request: { operation_id: h32, nonce: h32, requester_subject: h32, requester_key_id: h32, agent_card_ref: nullable(h32), scope: validateScope, payload_commitment: h32, budget: budgets, expected_control_checkpoint: h32 },
  intent: { operation_id: h32, nonce: h32, request_ref: h32, requester_key_id: h32, actor_key_id: h32, scope: validateScope, payload_commitment: h32, authority_ref: h32, budget: budgets, control_checkpoint_ref: h32, reservation_id: h32, consumption_commitment: h32, adapter_profile: text },
  receipt: { operation_id: h32, intent_ref: h32, intent_record_digest: h32, actor_key_id: h32, observer_key_id: h32, observer_certificate_ref: h32, outcome: oneOf(['done', 'refused', 'unknown']), dispatch_state: oneOf(['not_dispatched', 'dispatched_uncertain', 'observed']), observed_at: uint, evidence: set(observation), reconciles_receipt: nullable(h32) },
  kira_map: { map_id: h32, revision: u64, previous_map: nullable(h32), basis_journal_event: h32, storage_key_id: h32, manifest: envelopeCipher, manifest_ciphertext_digest: h32, public_location_hints: set(location), provenance_profile: text },
  recovery_policy: { policy_id: h32, recovery_epoch: u64, operators: set(value => closed(value, { operator_id: h32, certified_key_ref: h32, trust_domain_id: h32, jurisdiction: text, endpoint: text })), threshold: uint, attempt_limit: literal(5), ledger_profile: text, reset_policy_digest: h32, compromise_policy_digest: h32, succession_policy_digest: h32, bound_devices_exempt_from_lockout: literal(true), authority_restore_rule: literal('current_control_only'), protocol_status: literal('unreviewed') },
  coherence_checkpoint: { basis_event: h32, basis_sequence: u64, basis_epoch: u64, previous_checkpoint: nullable(h32), heads: value => { array(projection)(value); ok(value.length === 5 && value.every((head, i) => head.role === PROJECTION_ORDER[i])); }, control_state_digest: h32, evidence_complete: bool, missing_evidence: set(missing) },
  revocation: { target_type: targetType, target_id: h32, target_subject: h32, effective_sequence: u64, effective_epoch: u64, reason: oneOf(['compromise', 'rotation', 'withdrawal', 'termination']), admission_predicates: texts, successor_ref: nullable(h32), policy_ref: h32 },
};
const ownerApprovalFields = { operation_id: h32, nonce: h32, request_ref: h32, requester_key_id: h32,
  scope: validateScope, payload_sha256: h32, payload_commitment: h32, journal_head: h32 };
// Only immutable parser-owned trees enter these helpers. Envelope inspection may
// check tag shape without claiming that the content, role or authority is valid.
export function validateEventTags(tags) {
  array(array(text))(tags);
  if (tags.length === 1) {
    ok(tags[0].length === 2 && tags[0][0] === 'aukora' && tags[0][1] === 'l0-v1');
    return tags;
  }
  ok(tags.length === 3 || tags.length === 4);
  ok(tags[0].length === 2 && tags[0][0] === 'aukora' && tags[0][1] === 'l0-v2');
  ok(tags[1].length === 2 && tags[1][0] === 'prev'); h32(tags[1][1]);
  ok(tags[2].length === 2 && tags[2][0] === 'seq'); u64(tags[2][1]); ok(tags[2][1] !== '0');
  if (tags.length === 4) {
    const tag = tags[3];
    ok(tag.length === 12 && tag[0] === 'aukora-delegation-v1' && tag[11] === 'false');
    h32(tag[1]); h32(tag[10]);
    for (const index of [8, 9]) { uint(Number(tag[index])); ok(String(Number(tag[index])) === tag[index]); }
  }
  return tags;
}
function outerContext(value, version) {
  closed(value, { pubkey: h32, created_at: uint, kind: literal(8790), tags: validateEventTags });
  if (version !== null) ok(value.tags[0][1] === (version === RECORD_V2_SCHEMA ? 'l0-v2' : 'l0-v1'));
}
function bindV2Tags(record) {
  const tags = record.outer_context.tags;
  ok(tags[1][1] === record.previous_event && tags[2][1] === record.sequence);
  ok(tags.length === (record.kind === 'agent_card' ? 4 : 3));
  if (record.kind === 'agent_card') {
    const b = record.body, scope = b.scope;
    const expected = ['aukora-delegation-v1', b.agent_key_id, scope.adapter_profile, scope.site.scheme,
      scope.site.endpoint, scope.resource, scope.operation, scope.payload_class,
      String(record.not_before), String(record.expires), b.revocation_handle, 'false'];
    ok(tags[3].every((value, index) => value === expected[index]));
  }
}
const signerShape = value => closed(value, { role: text, key_id: h32,
  key_source: oneOf(['certificate', 'genesis_root', 'transition_next_root']),
  certificate_ref: nullable(h32), algorithms: array(text) });
const signer = value => {
  signerShape(value); oneOf(roles)(value.role);
  if (value.algorithms.length !== 1 || value.algorithms[0] !== 'bip340') fail('UNSUPPORTED_ALGORITHM');
  ok((value.key_source === 'certificate') === (value.certificate_ref !== null));
  if (value.key_source === 'genesis_root') ok(value.role === 'root');
  if (value.key_source === 'transition_next_root') ok(value.role === 'successor_possession');
};
function recordShape(record, validateBody, version, validateSigner = signer) {
  closed(record, { schema: text, profile: text, domain: text, kind: text,
    subject_id: h32, chain_id: h32, epoch: u64, sequence: u64, previous_event: nullable(h32), issued_at: uint, not_before: uint, expires: nullable(uint), authority_refs: refs,
    outer_context: value => outerContext(value, version), signer_plan: v => { array(validateSigner)(v); ok(v.length > 0); const seen = new Set();
      const tuple = s => s.role + '\0' + s.key_id + '\0' + (s.certificate_ref ?? '');
      for (let i = 0; i < v.length; i++) { const key = v[i].role + '\0' + v[i].key_id; ok(!seen.has(key)); seen.add(key); if (i) ok(tuple(v[i - 1]) < tuple(v[i])); }
    },
    consent_context: nullable(v => closed(v, { challenge_nonce: h32, ceremony_id: h32, assertion_policy_ref: h32, operation_id: nullable(h32) })), body: validateBody });
}
export function validateRecord(record) {
  assertParsed(record); ok(record !== null && typeof record === 'object');
  const v2 = record.schema === RECORD_V2_SCHEMA;
  if (record.schema !== 'aukora.record.v1' && !v2) fail('UNSUPPORTED_SCHEMA');
  // An unsupported V2 discriminator does not hide malformed common fields.
  // Defer version binding so the frozen V1 future-schema diagnostic survives.
  if (v2) recordShape(record, value => ok(value !== null && typeof value === 'object' && !Array.isArray(value)), null, signerShape);
  if (record.profile !== CLASSICAL_PROFILE) fail('UNSUPPORTED_PROFILE');
  const domains = v2 ? RECORD_V2_DOMAINS : RECORD_DOMAINS;
  // Frozen V1 future-schema vectors used a V1 identity with only its schema
  // changed to v2. That legacy shape is still not a V2 record. Preserve its
  // UNSUPPORTED_SCHEMA diagnosis; a new V2-tagged unknown kind is distinct.
  const tags = record.outer_context?.tags;
  if (v2 && !Object.hasOwn(domains, record.kind) && Array.isArray(tags) && tags.length === 1 &&
      Array.isArray(tags[0]) && tags[0].length === 2 && tags[0][0] === 'aukora' && tags[0][1] === 'l0-v1') fail('UNSUPPORTED_SCHEMA');
  if (!Object.hasOwn(domains, record.kind)) fail('UNSUPPORTED_KIND');
  recordShape(record, value => closed(value, v2 && record.kind === 'owner_approval' ? ownerApprovalFields : bodyFields[record.kind]), record.schema);
  if (record.domain !== domains[record.kind]) fail('WRONG_DOMAIN');
  ok(record.issued_at === record.outer_context.created_at && record.issued_at <= record.not_before && (record.expires === null || record.not_before < record.expires));
  if (!['identity', 'epoch_transition', 'policy_commitment', 'receipt', 'kira_map', 'recovery_policy', 'coherence_checkpoint', 'revocation'].includes(record.kind)) ok(record.expires !== null);
  const b = record.body;
  if (v2) {
    ok(record.expires !== null && record.consent_context === null);
    ok(record.signer_plan.length === 1);
    const proofRole = record.kind === 'intent' ? 'aperture_authority' : 'root';
    ok(record.signer_plan[0].role === proofRole && record.signer_plan[0].key_source === 'certificate');
    bindV2Tags(record);
    if (record.kind === 'owner_approval') ok(b.journal_head === record.previous_event);
  }
  if (record.kind === 'identity') {
    ok(record.epoch === '0' && record.sequence === '0' && record.previous_event === null && record.authority_refs.length === 0);
    ok(b.root_key.profile === CLASSICAL_PROFILE && b.initial_append_key.profile === CLASSICAL_PROFILE);
  } else { ok(record.previous_event !== null && record.sequence !== '0' && record.authority_refs.length > 0); }
  if (record.kind === 'key_binding') {
    closed(b.restriction, { subject_id: h32, chain_id: h32, ...restrictionFields[b.role] });
    ok(b.restriction.subject_id === record.subject_id && b.restriction.chain_id === record.chain_id);
    ok(BigInt(b.valid_from_epoch) <= BigInt(b.valid_through_epoch));
    ok(b.key_id === hashDomain('aukora.key.v1', canonicalBytes(b.descriptor)).toString('hex'));
    ok(b.role === 'device_assertion' || b.descriptor.profile === CLASSICAL_PROFILE);
  }
  if (record.kind === 'agent_card') ok(b.agent_key.profile === CLASSICAL_PROFILE && b.agent_key_id === hashDomain('aukora.key.v1', canonicalBytes(b.agent_key)).toString('hex'));
  if (record.kind === 'epoch_transition') ok(b.from_epoch === record.epoch && BigInt(b.to_epoch) === BigInt(b.from_epoch) + 1n && b.prior_final_event === record.previous_event);
  if (record.kind === 'policy_commitment') ok(b.effective_sequence === record.sequence);
  if (record.kind === 'revocation') ok(b.effective_sequence === record.sequence && b.effective_epoch === record.epoch);
  if (record.kind === 'recovery_policy') ok(b.threshold > 0 && b.threshold <= b.operators.length);
  return record;
}
export function validateParsedV2Record(record) {
  assertParsed(record); ok(record !== null && typeof record === 'object');
  if (record.schema !== RECORD_V2_SCHEMA) fail('UNSUPPORTED_SCHEMA');
  return validateRecord(record);
}
export function validateEnvelope(event) {
  closed(event, { id: h32, pubkey: h32, created_at: uint, kind: literal(8790), tags: validateEventTags, content: text, sig: v => ok(typeof v === 'string' && /^[0-9a-f]{128}$/.test(v)) });
  return event;
}
export function parseContent(contentBytes) {
  const snapshot = snapshotBytes(contentBytes, 196608);
  const content = parseBytes(snapshot, { maxBytes: 196608 });
  closed(content, { record: validateRecord, proofs: array(v => closed(v, { signer_index: uint, algorithm: literal('bip340'), signature: v => b64(v, 64) })) });
  if (content.proofs.length < content.record.signer_plan.length) fail('MISSING_REQUIRED_PROOF');
  ok(content.proofs.length === content.record.signer_plan.length && content.proofs.every((proof, i) => proof.signer_index === i));
  ok(Buffer.from(snapshot).equals(canonicalBytes(content)));
  return content;
}
