// Closed W0 schemas. Call only on data produced by the shared strict byte parser.
import { canonicalBytes } from './primitives.mjs';
import { assertParsed, RECORD_V2_SCHEMA, validateEventTags, validateParsedV2Record } from '../bytes/index.mjs';

export class Violation extends Error {
  constructor(code) { super(code); this.code = code; }
}
export const fail = (code = 'CLOSED_SCHEMA') => { throw new Violation(code); };
export const insist = (condition, code) => { if (!condition) fail(code); };
export const same = (a, b) => Buffer.compare(canonicalBytes(a), canonicalBytes(b)) === 0;
export const H = x => insist(typeof x === 'string' && /^[0-9a-f]{64}$/.test(x));
export const U = x => insist(Number.isSafeInteger(x) && x >= 0 && !Object.is(x, -0));
export const U64 = x => insist(typeof x === 'string' && /^(0|[1-9][0-9]{0,19})$/.test(x) && BigInt(x) <= 18446744073709551615n);
export const T = x => insist(typeof x === 'string');
const B = x => insist(typeof x === 'boolean');
export const nullable = v => x => { if (x !== null) v(x); };
export const one = (...values) => x => insist(values.includes(x));
export const literal = value => x => insist(x === value);
export const list = (v, maximum = 256) => x => { insist(Array.isArray(x)); insist(x.length <= maximum, 'LIMIT_EXCEEDED'); x.forEach(v); };
export function closed(value, fields) {
  insist(value !== null && typeof value === 'object' && !Array.isArray(value));
  insist(Object.keys(value).length === Object.keys(fields).length);
  for (const [name, validator] of Object.entries(fields)) {
    insist(Object.hasOwn(value, name)); validator(value[name]);
  }
}
export function sorted(values, key = x => x) {
  for (let i = 1; i < values.length; i++) {
    insist(Buffer.compare(canonicalBytes(key(values[i - 1])), canonicalBytes(key(values[i]))) < 0);
  }
}
const set = validator => x => { list(validator)(x); sorted(x); };
export function decode64(x, length) {
  insist(typeof x === 'string' && /^[A-Za-z0-9_-]*$/.test(x));
  const bytes = Buffer.from(x, 'base64url');
  insist(bytes.toString('base64url') === x);
  if (length !== undefined) insist(bytes.length === length);
  return bytes;
}
const b64 = x => { decode64(x); };
const hList = set(H);
export const PROFILE = 'aukora.classical.bip340.v1';
export const SOURCE = 'aukora.local-test-control.v1';
export const ROLES = ['root', 'human_approval', 'device_assertion', 'journal_append', 'aperture_authority', 'aperture_observer', 'storage', 'gardener', 'agent', 'recovery_operator', 'successor_possession'];
export const DOMAINS = Object.freeze({identity:'aukora.identity.v1',key_binding:'aukora.key-binding.v1',epoch_transition:'aukora.epoch-transition.v1',policy_commitment:'aukora.policy-commitment.v1',vouch:'aukora.vouch.v1',vouch_accept:'aukora.vouch-accept.v1',agent_card:'aukora.agent-card.v1',emission_request:'aukora.emission-request.v1',intent:'aukora.intent.v1',receipt:'aukora.receipt.v1',kira_map:'aukora.kira-map.v1',recovery_policy:'aukora.recovery-policy.v1',coherence_checkpoint:'aukora.coherence-checkpoint.v1',revocation:'aukora.revocation.v1'});
export const PROJECTIONS = ['identity', 'delegation', 'actions', 'receipts', 'memory'];
export const LOCAL_SCOPE = Object.freeze({adapter_profile:'aukora.local.fixed-message.v1',site:{scheme:'local',endpoint:'aukora-test-sink-v1'},resource:'sink',operation:'emit',payload_class:'aukora.local.fixed-message.v1'});
export const LOCAL_BUDGET = [{unit:'bytes',maximum:'18',currency:null},{unit:'requests',maximum:'1',currency:null}];
export const POLICY_PINS = Object.freeze({algorithm:'4d7b2b987d48db5eeaaa5a98450933875dfee5c0fa970a3b088ea45f919bbda5',scope:'a8fe61c89e957b1ac9b433795452505a947c9d633317a799416aac113e219acd',time:'43044e7df9bd820b2cb064be90ea92c0bd09d8f79f5fa9565c0432a8168aac44',control:'0f997602f4ec67af72bd34e30a633d38e2693aada2ceebb1e71df131632e10d4',custody:'fead2fbc14aa1fbc52e81bfd27dc2153165c1b5f68d71372bd790ba07f16d9ee',admission:'de34591b35cdd0aba870b281c4c95ef120f7ccf8b5aec2195378f78d5e532272',succession:'1b0d7fca96fe6de9f1ce84a86191ce61cc74fbd4aecef1fad56469b3fc8a1dec',recovery:'6459633cb1b906dc970789dbddb09a7c0291aab0f590fdd46e3d863e2b30f8e0',persona:'d2eebce0570eb1c549d9ff7f2d2b7b28e393b86e42b1c989f74ce9b51d92aee1',assertion:'1ad88cc6b36c3d9edbeb29216c6dcb4e157e885e97594c6fbc55633f2ba7bfb6'});
export function descriptor(d) {
  insist(d !== null && typeof d === 'object' && !Array.isArray(d)); T(d.profile);
  if (d.profile === PROFILE) closed(d, {profile:literal(PROFILE),bip340_public_key:H});
  else if (d.profile === 'aukora.device.p256.v1') {
    closed(d,{profile:T,public_key_sec1:x=>{insist(decode64(x,65)[0]===4);},credential_id:b64,rp_id:T,origins:set(T)});
  } else fail('UNSUPPORTED_PROFILE');
}
export function scope(s) {
  // Shape is distinct from semantic equality, so a wrong endpoint is SCOPE_MISMATCH.
  closed(s,{adapter_profile:T,site:x=>closed(x,{scheme:T,endpoint:T}),resource:T,operation:T,payload_class:T});
}
function budget(b) {
  closed(b,{unit:one('requests','bytes','minor_currency'),maximum:U64,currency:nullable(x=>insist(typeof x==='string'&&/^[A-Z]{3}$/.test(x)))});
  insist((b.unit==='minor_currency') === (b.currency!==null));
}
export function budgets(b) { list(budget)(b); sorted(b, x=>[x.unit,x.currency]); }
export const targetTypes = ['root_key','device_key','agent_card','key_binding','vouch'];
export function missing(m) { closed(m,{type:one('event','certificate','revocation','consumption','time','witness'),reference:nullable(H),reason:one('unavailable','unsupported','withheld')}); }
const observation = o=>closed(o,{kind:one('provider_ack','provider_result','local_boundary_record','reconciliation'),source_id:H,source_role:T,artifact_digest:H,statement_profile:T,claim:one('accepted','completed','not_dispatched','uncertain'),observed_at:U});
const envelope = o=>closed(o,{cipher_profile:T,key_ref:H,nonce:b64,ciphertext:b64,aad_digest:H});
function restriction(r, role) {
  const base = {subject_id:H,chain_id:H};
  const variants = {
    human_approval:{record_kinds:set(one('agent_card','vouch_accept','emission_request')),emission_scopes:set(scope),budget_ceiling:budgets},
    device_assertion:{assertion_policy_ref:H},journal_append:{append_epoch:U64},
    aperture_authority:{adapter_profiles:set(T),emission_scopes:set(scope),budget_ceiling:budgets},
    aperture_observer:{adapter_profiles:set(T),statement_profiles:set(T)},
    storage:{namespace_id:H,record_kinds:x=>insist(same(x,['kira_map']))},
    gardener:{admission_policy_ref:H,monthly_cap:U},agent:{emission_scopes:set(scope),budget_ceiling:budgets,onward_delegation:literal(false)}
  };
  insist(Object.hasOwn(variants,role)); closed(r,{...base,...variants[role]});
}
const bodies = {
  identity:b=>closed(b,{root_key:descriptor,initial_append_key:descriptor,succession_policy_digest:H,recovery_policy_digest:H,algorithm_policy_digest:H,persona_policy_digest:H}),
  key_binding:b=>{closed(b,{key_id:H,descriptor,role:one('human_approval','device_assertion','journal_append','aperture_authority','aperture_observer','storage','gardener','agent'),parent_key_id:H,parent_certificate_ref:H,valid_from_epoch:U64,valid_through_epoch:U64,restriction:x=>restriction(x,b.role),custody_policy_digest:H,binding_purpose:one('enroll','renew'),device_assertion_policy_digest:nullable(H)});insist(BigInt(b.valid_from_epoch)<=BigInt(b.valid_through_epoch));},
  epoch_transition:b=>closed(b,{from_epoch:U64,to_epoch:U64,prior_final_event:H,next_append_key_id:H,next_append_certificate:H,next_root_key:nullable(descriptor),control_checkpoint_ref:H,consumption_anchor:H,revocation_anchor:H,transition_policy_ref:H}),
  policy_commitment:b=>closed(b,{policy_type:one('admission','custody','scope','algorithm','succession','assertion','time','control'),policy_version:U,policy_digest:H,effective_sequence:U64}),
  vouch:b=>closed(b,{inviter_subject:H,invitee_subject:H,invitee_genesis:H,ceremony_id:H,ceremony_claim:one('remote','in_person'),ceremony_evidence_refs:hList,admission_policy_ref:H,invite_slot:H,visibility:one('one_hop','explicit_edges'),visible_to:hList}),
  vouch_accept:b=>closed(b,{vouch_ref:H,inviter_subject:H,invitee_subject:H,invitee_genesis:H,consent_scope_digest:H}),
  agent_card:b=>closed(b,{human_subject:H,agent_subject:H,agent_key:descriptor,agent_key_id:H,scope,budget:budgets,revocation_handle:H,onward_delegation:literal(false),custody_policy_digest:H}),
  emission_request:b=>closed(b,{operation_id:H,nonce:H,requester_subject:H,requester_key_id:H,agent_card_ref:nullable(H),scope,payload_commitment:H,budget:budgets,expected_control_checkpoint:H}),
  intent:b=>closed(b,{operation_id:H,nonce:H,request_ref:H,requester_key_id:H,actor_key_id:H,scope,payload_commitment:H,authority_ref:H,budget:budgets,control_checkpoint_ref:H,reservation_id:H,consumption_commitment:H,adapter_profile:T}),
  receipt:b=>closed(b,{operation_id:H,intent_ref:H,intent_record_digest:H,actor_key_id:H,observer_key_id:H,observer_certificate_ref:H,outcome:one('done','refused','unknown'),dispatch_state:one('not_dispatched','dispatched_uncertain','observed'),observed_at:U,evidence:list(observation),reconciles_receipt:nullable(H)}),
  kira_map:b=>closed(b,{map_id:H,revision:U64,previous_map:nullable(H),basis_journal_event:H,storage_key_id:H,manifest:envelope,manifest_ciphertext_digest:H,public_location_hints:set(x=>closed(x,{scheme:one('https','content_addressed'),locator:T,ciphertext_digest:H})),provenance_profile:T}),
  recovery_policy:b=>closed(b,{policy_id:H,recovery_epoch:U64,operators:set(x=>closed(x,{operator_id:H,certified_key_ref:H,trust_domain_id:H,jurisdiction:T,endpoint:T})),threshold:U,attempt_limit:literal(5),ledger_profile:T,reset_policy_digest:H,compromise_policy_digest:H,succession_policy_digest:H,bound_devices_exempt_from_lockout:literal(true),authority_restore_rule:literal('current_control_only'),protocol_status:literal('unreviewed')}),
  coherence_checkpoint:b=>{closed(b,{basis_event:H,basis_sequence:U64,basis_epoch:U64,previous_checkpoint:nullable(H),heads:list(h=>closed(h,{role:one(...PROJECTIONS),event_id:nullable(H),sequence:nullable(U64)}),5),control_state_digest:H,evidence_complete:B,missing_evidence:set(missing)});insist(b.heads.length===5);b.heads.forEach((h,i)=>{insist(h.role===PROJECTIONS[i]);insist((h.event_id===null)===(h.sequence===null));});},
  revocation:b=>closed(b,{target_type:one(...targetTypes),target_id:H,target_subject:H,effective_sequence:U64,effective_epoch:U64,reason:one('compromise','rotation','withdrawal','termination'),admission_predicates:set(T),successor_ref:nullable(H),policy_ref:H})
};
// Versioned tag shapes are envelope syntax, checked before domain/signature
// semantics. V1 records still require the exact original singleton tag.
const profileTags = validateEventTags;
const outerContext = x=>closed(x,{pubkey:H,created_at:U,kind:U,tags:v=>{profileTags(v);insist(same(v,[['aukora','l0-v1']]));}});
export function record(r) {
  assertParsed(r);
  if(r!==null&&typeof r==='object'&&r.schema===RECORD_V2_SCHEMA) return validateParsedV2Record(r);
  closed(r,{schema:T,profile:T,domain:T,kind:T,subject_id:H,chain_id:H,epoch:U64,sequence:U64,previous_event:nullable(H),issued_at:U,not_before:U,expires:nullable(U),authority_refs:hList,outer_context:outerContext,signer_plan:list(s=>closed(s,{role:T,key_id:H,key_source:one('certificate','genesis_root','transition_next_root'),certificate_ref:nullable(H),algorithms:list(T)})),consent_context:nullable(x=>closed(x,{challenge_nonce:H,ceremony_id:H,assertion_policy_ref:H,operation_id:nullable(H)})),body:x=>insist(x!==null&&typeof x==='object'&&!Array.isArray(x))});
  if(r.schema!=='aukora.record.v1') fail('UNSUPPORTED_SCHEMA');
  if(!Object.hasOwn(bodies,r.kind)) fail('UNSUPPORTED_KIND');
  if(r.profile!==PROFILE) fail('UNSUPPORTED_PROFILE');
  insist(r.domain===DOMAINS[r.kind],'WRONG_DOMAIN');
  bodies[r.kind](r.body);
  insist(r.issued_at<=r.not_before);
  insist(r.expires===null||r.not_before<r.expires);
  if(['key_binding','vouch','vouch_accept','agent_card','emission_request','intent'].includes(r.kind)) insist(r.expires!==null);
  insist(r.issued_at===r.outer_context.created_at);
  insist(r.outer_context.kind===8790,'WRONG_DOMAIN');
  for(let i=0;i<r.signer_plan.length;i++) {
    const s=r.signer_plan[i]; insist(ROLES.includes(s.role));
    insist((s.key_source==='certificate') === (s.certificate_ref!==null));
    if(s.key_source==='genesis_root') insist(r.kind==='identity'&&s.role==='root','WRONG_AUTHORITY');
    if(s.key_source==='transition_next_root') insist(r.kind==='epoch_transition'&&s.role==='successor_possession','WRONG_AUTHORITY');
    if(!same(s.algorithms,['bip340'])) fail('UNSUPPORTED_ALGORITHM');
    if(i>0) {
      const p=r.signer_plan[i-1];
      const cmp=(a,b)=>a===b?0:a===null?-1:b===null?1:a<b?-1:1;
      const order=cmp(p.role,s.role)||cmp(p.key_id,s.key_id)||cmp(p.certificate_ref,s.certificate_ref);
      insist(order<0);
      insist(p.role!==s.role||p.key_id!==s.key_id);
    }
  }
  if(r.kind==='identity') insist(r.epoch==='0'&&r.sequence==='0'&&r.previous_event===null&&r.authority_refs.length===0,'WRONG_AUTHORITY');
  else insist(r.previous_event!==null&&r.sequence!=='0'&&r.authority_refs.length>0,'WRONG_AUTHORITY');
}
export function outer(e) {
  assertParsed(e);
  insist(e!==null&&typeof e==='object'&&!Array.isArray(e));
  if(!Object.hasOwn(e,'sig')) fail('MISSING_REQUIRED_PROOF');
  closed(e,{id:H,pubkey:H,created_at:U,kind:U,tags:profileTags,content:T,sig:x=>insist(typeof x==='string'&&/^[0-9a-f]{128}$/.test(x))});
  insist(e.kind===8790,'WRONG_DOMAIN');
}
export function proofs(p, r) {
  list(x=>closed(x,{signer_index:U,algorithm:T,signature:b64}))(p);
  if(p.length<r.signer_plan.length) fail('MISSING_REQUIRED_PROOF');
  insist(p.length===r.signer_plan.length);
  p.forEach((proof,i)=>{insist(proof.signer_index===i);if(proof.algorithm!=='bip340') fail('UNSUPPORTED_ALGORITHM');decode64(proof.signature,64);});
}
const floor = x=>closed(x,{source_id:T,subject_id:H,chain_id:H,revision:U64,time_floor:U,epoch:U64,sequence:U64,head:H,control_state_digest:H});
export function snapshot(x) {
  closed(x,{source_id:T,mode:T,boot_id:H,revision:U64,time_policy_digest:H,control_policy_digest:H,now_lower:U,now_upper:U,subject_id:H,chain_id:H,epoch:U64,sequence:U64,head:H,checkpoint_ref:nullable(H),control_state_digest:H,floor});
  insist(x.now_lower<=x.now_upper);
}
export function context(c) {
  closed(c,{schema:literal('aukora.verify-context.v1'),purpose:one('historical_integrity','authorization_now'),expected_subject_id:H,expected_chain_id:H,expected_genesis:H,expected_root_key_id:H,expected_profile:T,expected_kind:T,expected_signers:list(s=>closed(s,{role:T,key_id:H})),policy_pins:hList,control:nullable(snapshot),additional_anchors:list(a=>closed(a,{subject_id:H,chain_id:H,genesis:H,root_key_id:H,profile:T})),additional_control:list(snapshot)});
  sorted(c.expected_signers,x=>[x.role,x.key_id]); sorted(c.additional_anchors,x=>[x.subject_id,x.chain_id]); sorted(c.additional_control,x=>[x.subject_id,x.chain_id]);
}
export function evidence(e) {
  closed(e,{schema:literal('aukora.evidence.v1'),events:list(b64),policies:list(p=>closed(p,{digest:H,document:b64})),control_state:nullable(b64),artifacts:list(a=>closed(a,{digest:H,blob:b64}))});
  sorted(e.policies,x=>x.digest); sorted(e.artifacts,x=>x.digest);
}
export function controlState(s) {
  closed(s,{schema:literal('aukora.control-state.v1'),subject_id:H,chain_id:H,epoch:U64,basis_event:H,active_root_key_id:H,active_append_key_id:H,revoked_targets:set(t=>closed(t,{target_type:one(...targetTypes),target_id:H})),spent_operations:set(o=>closed(o,{operation_id:H,nonce:H,reservation_id:H,intent_ref:H})),active_policy_refs:hList});
}
export function policyDocument(p) {
  closed(p,{schema:literal('aukora.policy.v1'),policy_type:one(...Object.keys(POLICY_PINS)),policy_version:literal(1),parameters:x=>insist(x!==null&&typeof x==='object'&&!Array.isArray(x))});
  const variants={
    algorithm:{profile:literal(PROFILE),application_algorithms:x=>insist(same(x,['bip340'])),outer_algorithm:literal('bip340'),ml_dsa_enabled:literal(false)},
    scope:{allowed_scopes:x=>insist(same(x,[LOCAL_SCOPE])),payload_hex:literal('41554b4f5241204c4f43414c20544553540a'),request_bytes:literal('18'),request_count:literal('1'),live_dispatch:literal(false)},
    time:{source_id:literal(SOURCE),mode:literal('LOCAL_TEST'),clock:literal('explicit_monotone_logical_unix_seconds'),skew_grace_seconds:literal(0),max_cached_revisions:literal('0')},
    control:{source_id:literal(SOURCE),mode:literal('LOCAL_TEST'),currentness:literal('same_lock_current_boot_revision'),floor:literal('retained_outside_import'),dispatch_gap_ticks:literal('0'),automatic_resend:literal(false),live_dispatch:literal(false)},
    custody:{mode:literal('LOCAL_TEST'),keys:literal('disposable_test_only'),signing:literal('trusted_node'),bridge:literal('proposal_only'),requester_observer_custody:literal('separate'),live_dispatch:literal(false)},
    admission:{invites_per_month:U,tier_vouches:U,tier_independent_paths:U,month_basis:literal('UTC'),path_predicate:literal('unreviewed'),subtree_predicate:literal('unreviewed'),visibility:literal('one_hop')},
    succession:{append_rotation:literal('current_root_and_next_append_possession'),allow_root_replacement:literal(false),allow_recovery_transition:literal(false)},
    recovery:{status:literal('unreviewed'),attempt_limit:literal(5),behavior:literal('always_refuse'),bound_devices_exempt_from_lockout:literal(true)},
    persona:{status:literal('unreviewed'),automatic_cross_linking:literal(false)},assertion:{status:literal('unreviewed'),behavior:literal('always_refuse')}
  };
  closed(p.parameters,variants[p.policy_type]);
}
