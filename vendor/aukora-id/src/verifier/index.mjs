import { parseBytes, canonicalBytes, sha256, hashDomain, verifyBip340, hex, digest, nostrPreimageParsed, ByteError } from './primitives.mjs';
import * as S from './schema.mjs';
import { validateMapCryptoProfile } from '../kira/crypto.mjs';
import { parseObservation, observationBytes, observationEvidence, STATEMENT_PROFILE, requireObservationProfile } from '../aperture/observation.mjs';
import { PrefixMap } from './prefix-state.mjs';
import { derivedControlBytes, derivedControlDigest } from '../journal/control-state.mjs';

const REJECT = new Set(['MALFORMED_BYTES','DUPLICATE_KEY','CLOSED_SCHEMA','LIMIT_EXCEEDED','BAD_SIGNATURE','WRONG_DOMAIN','WRONG_SIGNER','WRONG_AUTHORITY','SCOPE_MISMATCH','EXPIRED','NOT_YET_VALID','REVOKED','REPLAY','JOURNAL_CONFLICT','INCONSISTENT_HEAD','MISSING_REQUIRED_PROOF']);
const UNKNOWN = new Set(['UNSUPPORTED_SCHEMA','UNSUPPORTED_KIND','UNSUPPORTED_ALGORITHM','UNSUPPORTED_PROFILE','MISSING_EVIDENCE','STALE_CONTROL','UNTRUSTED_TIME','TIME_UNCERTAINTY','ROLLBACK_UNRESOLVED','RECOVERY_UNREVIEWED']);
const codes = new Set([...REJECT,...UNKNOWN,'UNSIGNED_DRAFT']);
const MAX_EVIDENCE = 4194304;
const textBytes = text => Buffer.from(text,'utf8');
const keyID = descriptor => digest('aukora.key.v1',descriptor);
const arraySorted = values => values.sort((a,b)=>Buffer.compare(canonicalBytes(a),canonicalBytes(b)));
const uniqueSorted = values => [...new Map(values.map(v=>[hex(canonicalBytes(v)),v])).values()].sort((a,b)=>Buffer.compare(canonicalBytes(a),canonicalBytes(b)));
const isSameChain = (a,b) => a.subject_id===b.subject_id && a.chain_id===b.chain_id;
const parse = (bytes,maxBytes=262144) => parseBytes(bytes,{mode:maxBytes>262144?'evidence':'event',maxBytes});

function signatureReason(signature,message,key,budget) {
  if(++budget.count>64)return 'LIMIT_EXCEEDED';
  try {return verifyBip340(signature,message,key)===true?null:'BAD_SIGNATURE';}
  catch {return 'BAD_SIGNATURE';}
}
// One outer-check routine for both public entry points. The envelope is already
// W1-branded; content stays an opaque signed string until full verification.
function inspectOuterEnvelope(event,budget) {
  S.outer(event);
  const eventHash=sha256(nostrPreimageParsed(event)),reasons=new Set();
  if(hex(eventHash)!==event.id)reasons.add('BAD_SIGNATURE');
  const signatureCode=signatureReason(Buffer.from(event.sig,'hex'),eventHash,Buffer.from(event.pubkey,'hex'),budget);
  if(signatureCode)reasons.add(signatureCode);
  return {event,reason_codes:[...reasons]};
}

/** Outer shape, ID and BIP340 only. No application or authority verification. */
export function verifyOuterEvent(eventBytes) {
  try {
    const checked=inspectOuterEnvelope(parse(eventBytes),{count:0});
    if(checked.reason_codes.length)throw new ByteError(checked.reason_codes[0]);
    return checked.event;
  } catch(error) {
    if(error instanceof ByteError)throw error;
    throw new ByteError(error instanceof S.Violation?error.code:'CLOSED_SCHEMA');
  }
}

/** Pure W0 verifier. Inputs are bytes; the result confers no permission or effects. */
export function verifyEvent(eventBytes, contextBytes, evidenceBytes) {
  return verifyInternal(eventBytes, contextBytes, evidenceBytes);
}

// Only this module can bind a handle to its real byte-verification closure.
// WeakMap lookup never consults properties, getters or methods on a supplied handle.
const prefixChecks = new WeakMap();
export function verifyPrefixEvent(prefix, eventBytes, contextBytes, evidenceBytes) {
  const check = prefixChecks.get(prefix);
  if (!check) throw new ByteError('WRONG_AUTHORITY');
  return check(eventBytes, contextBytes, evidenceBytes);
}

// A session is built exclusively by checking raw sequential events. No caller can
// supply a state object, successful verdict, checkpoint shortcut, or cache entry.
// Historical facts are immutable; authorization_now is never retained.
export function createPrefixVerifier() {
  const cache = { events: new Map(), positions: new Map(), successors: new Map(), binding: null,
    head: null, bytes: 0, closed: false, resultItem: null, controlDigests: new WeakMap() };
  const run = (append, eventBytes, contextBytes, evidenceBytes) => {
    cache.resultItem = null;
    const result = verifyInternal(eventBytes, contextBytes, evidenceBytes, cache, append);
    const item = cache.resultItem; cache.resultItem = null;
    if (append && result.verdict === 'valid' && item && !cache.events.has(item.event.id)) {
      cache.events.set(item.event.id, item); cache.bytes += Buffer.byteLength(JSON.stringify(item.event));
      cache.positions.set(item.record.sequence, item.event.id);
      if (item.record.previous_event !== null) cache.successors.set(item.record.previous_event, item.event.id);
      cache.head = item;
    }
    if (result.reason_codes.some(code => ['JOURNAL_CONFLICT', 'ROLLBACK_UNRESOLVED'].includes(code))) cache.closed = true;
    return result;
  };
  const verificationHandle = Object.freeze(Object.create(null));
  prefixChecks.set(verificationHandle, (event, context, evidence) => {
    if (cache.closed) throw new ByteError('ROLLBACK_UNRESOLVED');
    return run(false, event, context, evidence);
  });
  return Object.freeze({
    verificationHandle,
    append: (event, context, evidence) => run(true, event, context, evidence),
    verify: (event, context, evidence) => run(false, event, context, evidence),
    head: () => Object.freeze({ id: cache.head?.event.id ?? null, sequence: cache.head?.record.sequence ?? null,
      count: cache.events.size, bytes: cache.bytes, closed: cache.closed }),
    close() { cache.closed = true; cache.events.clear(); cache.positions.clear(); cache.successors.clear(); cache.head = null; },
  });
}

function verifyInternal(eventBytes, contextBytes, evidenceBytes, cache = null, appendToCache = false) {
  const allReasons = new Set(), missing = [], conflicts = [];
  const result = {verdict:'UNKNOWN',reason_codes:[],record_digest:null,event_id:null,validated_through:null,missing_evidence:missing,conflicts};
  let context, evidence, controlEvidence=null, target, draft=false, decodedTotal=0;
  const signatureBudget={count:0};
  const localEvents = new Map(), policies = new Map(), artifactDigests = new Set(), artifactBytes = new Map();
  const events = { get: id => localEvents.get(id) ?? cache?.events.get(id),
    set: (id, item) => localEvents.set(id, item), values: () => localEvents.values() };
  const reason = (code,item) => {
    if(!codes.has(code)) code='CLOSED_SCHEMA';
    allReasons.add(code); if(item) item.issues.add(code);
  };
  const caught = (error,item) => reason(error && typeof error.code==='string' ? error.code : 'CLOSED_SCHEMA',item);
  const demand = (condition,code,item) => { if(!condition) reason(code,item); return condition; };
  const absent = (type,reference,item,why='unavailable') => {
    missing.push({type,reference,reason:why}); reason('MISSING_EVIDENCE',item);
  };
  function verify(sig,message,key,item) {
    const code=signatureReason(sig,message,key,signatureBudget);
    if(code)reason(code,item);
    return code===null;
  }
  function boundedDecode(value) {
    const bytes=S.decode64(value); decodedTotal+=bytes.length;
    S.insist(decodedTotal<=MAX_EVIDENCE,'LIMIT_EXCEEDED'); return bytes;
  }
  function readEvent(bytes) {
    return readEventTree(parse(bytes));
  }
  function validateRecord(record,item) {
    try { S.record(record); }
    catch(error) {
      // Report both shape and exact-scope failures only on strict-parser output.
      // No scope inspection occurs on raw, duplicate-key or over-limit input.
      const body=record!==null&&typeof record==='object'&&!Array.isArray(record)?record.body:null;
      const scope=body!==null&&typeof body==='object'&&!Array.isArray(body)?body.scope:null;
      if(error instanceof S.Violation&&error.code==='CLOSED_SCHEMA'&&
         scope!==null&&typeof scope==='object'&&!Array.isArray(scope)&&
         record.schema==='aukora.record.v1'&&record.profile===S.PROFILE&&
         ['agent_card','emission_request','intent'].includes(record.kind)&&
         !S.same(scope,S.LOCAL_SCOPE))reason('SCOPE_MISMATCH',item);
      throw error;
    }
  }
  function readEventTree(event) {
    const item={event,record:null,proofs:null,digest:null,issues:new Set(),status:'new',state:null,activeRefs:new Set(),authorityDepth:0};
    try {
      for(const code of inspectOuterEnvelope(event,signatureBudget).reason_codes)reason(code,item);
      S.insist(Buffer.byteLength(event.content,'utf8')<=196608,'LIMIT_EXCEEDED');
      const content=parse(textBytes(event.content),196608);
      S.closed(content,{record:x=>S.insist(x!==null&&typeof x==='object'&&!Array.isArray(x)),proofs:S.list(x=>S.insist(x!==null&&typeof x==='object'&&!Array.isArray(x)))});
      demand(hex(canonicalBytes(content))===hex(textBytes(event.content)),'CLOSED_SCHEMA',item);
      item.record=content.record; item.proofs=content.proofs;
      validateRecord(item.record,item);
      item.digest=hashDomain(item.record.schema,canonicalBytes(item.record));
      demand(S.same(item.record.outer_context,{pubkey:event.pubkey,created_at:event.created_at,kind:event.kind,tags:event.tags}),'WRONG_AUTHORITY',item);
      S.proofs(item.proofs,item.record);
    } catch(error) { caught(error,item); }
    return item;
  }
  const anchorFor = r => {
    if(r.subject_id===context.expected_subject_id && r.chain_id===context.expected_chain_id)
      return {subject_id:r.subject_id,chain_id:r.chain_id,genesis:context.expected_genesis,root_key_id:context.expected_root_key_id,profile:context.expected_profile};
    return context.additional_anchors.find(a=>isSameChain(a,r));
  };
  const currentFor = r => {
    if(context.control && isSameChain(context.control,r)) return context.control;
    return context.additional_control.find(c=>isSameChain(c,r));
  };
  function window(record,lower,upper,item) {
    if(record.expires!==null && lower>=record.expires) reason('EXPIRED',item);
    else if(upper<record.not_before) reason('NOT_YET_VALID',item);
    else if(lower<record.not_before || (record.expires!==null && upper>=record.expires)) reason('TIME_UNCERTAINTY',item);
  }
  function pin(policyType,value,item) {
    if(!context.policy_pins.includes(value)) absent('witness',value,item);
    if(value!==S.POLICY_PINS[policyType]) {
      const policy=policies.get(value);
      if(policyType!=='admission'||!policy||policy.policy_type!=='admission') reason('UNSUPPORTED_PROFILE',item);
    }
  }
  function localScope(scope,item) { demand(S.same(scope,S.LOCAL_SCOPE),'SCOPE_MISMATCH',item); }
  function narrowBudget(child,ceiling,item) {
    for(const b of child) {
      const cap=ceiling.find(c=>c.unit===b.unit&&c.currency===b.currency);
      demand(cap && BigInt(b.maximum)<=BigInt(cap.maximum),'SCOPE_MISMATCH',item);
      demand(b.unit==='bytes'||b.unit==='requests','SCOPE_MISMATCH',item);
    }
    // Both dimensions are mandatory in every LOCAL grant used by an operation.
    demand(['bytes','requests'].every(unit=>child.some(b=>b.unit===unit&&b.currency===null)),'SCOPE_MISMATCH',item);
  }
  function narrowing(child,parent,item) {
    demand(child.not_before>=parent.not_before && parent.expires!==null && child.expires!==null && child.expires<=parent.expires,'SCOPE_MISMATCH',item);
  }
  function lookup(ref,item,type='event') {
    const dependency=events.get(ref);
    if(!dependency) { absent(type,ref,item); return null; }
    return dependency;
  }
  function prior(ref,item,depth,type='certificate') {
    const dep=lookup(ref,item,type); if(!dep) return null;
    if(dep===item) { reason('WRONG_AUTHORITY',item); return null; }
    check(dep,depth+1);
    if(!dep.record || dep.issues.size) { for(const code of dep.issues) reason(code,item); return null; }
    if(isSameChain(dep.record,item.record)) {
      // Without the predecessor, ancestry is unproved rather than contradicted.
      // Keep the anchored certificate available for checking the application
      // signature; missing state still prevents a valid authority verdict.
      if(!item.before) absent('event',item.record.previous_event,item);
      else if(!item.before.prefix.has(ref)) { reason('WRONG_AUTHORITY',item); return null; }
    } else if(!anchorFor(dep.record)) { absent('certificate',ref,item); return null; }
    return dep;
  }
  function activeDependency(item,dependency) {
    item.activeRefs.add(dependency.event.id);
    for(const ref of dependency.activeRefs)item.activeRefs.add(ref);
  }
  function revoked(state,ref,key,item) {
    if(!state) return;
    for(const target of state.revoked.values()) {
      if((ref && ['key_binding','agent_card'].includes(target.target_type)&&target.target_id===ref) ||
         (key && ['root_key','device_key'].includes(target.target_type)&&target.target_id===key)) reason('REVOKED',item);
    }
  }
  function resolveSigner(plan,item,depth) {
    const r=item.record;
    if(plan.key_source==='genesis_root') {
      demand(r.kind==='identity'&&plan.role==='root','WRONG_AUTHORITY',item);
      return {descriptor:r.body.root_key,certificate:null,role:'root'};
    }
    if(plan.key_source==='transition_next_root') { reason('UNSUPPORTED_PROFILE',item); return null; }
    const certificate=prior(plan.certificate_ref,item,depth);
    if(!certificate) return null;
    activeDependency(item,certificate);
    item.authorityDepth=Math.max(item.authorityDepth,certificate.authorityDepth+1);
    if(item.authorityDepth>8){reason('LIMIT_EXCEEDED',item);return null;}
    demand(r.authority_refs.includes(plan.certificate_ref),'WRONG_AUTHORITY',item);
    const cr=certificate.record, b=cr.body;
    let descriptor;
    if(cr.kind==='identity') {
      demand(isSameChain(cr,r),'WRONG_AUTHORITY',item);
      if(plan.role==='root') descriptor=b.root_key;
      else if(plan.role==='journal_append') {
        descriptor=b.initial_append_key;
        demand(r.epoch==='0','WRONG_AUTHORITY',item);
      } else reason('WRONG_AUTHORITY',item);
    } else if(cr.kind==='key_binding') {
      demand(isSameChain(cr,r),'WRONG_AUTHORITY',item);
      demand(b.role===plan.role,'WRONG_AUTHORITY',item);
      const signingEpoch=r.kind==='epoch_transition'&&plan.role==='journal_append'?r.body.to_epoch:r.epoch;
      demand(BigInt(signingEpoch)>=BigInt(b.valid_from_epoch)&&BigInt(signingEpoch)<=BigInt(b.valid_through_epoch),'WRONG_AUTHORITY',item);
      descriptor=b.descriptor;
      // A root certificate for an agent does not appoint that agent as human.
      if(plan.role==='agent') reason('WRONG_AUTHORITY',item);
    } else if(cr.kind==='agent_card'&&plan.role==='agent') {
      descriptor=b.agent_key;
      demand(r.kind==='emission_request'&&r.body.agent_card_ref===certificate.event.id,'WRONG_AUTHORITY',item);
      demand(isSameChain(cr,r)&&b.human_subject===r.subject_id,'WRONG_AUTHORITY',item);
    } else reason('WRONG_AUTHORITY',item);
    window(cr,r.issued_at,r.issued_at,item);
    revoked(item.before,certificate.event.id,plan.key_id,item);
    return descriptor?{descriptor,certificate,role:plan.role}:null;
  }
  function requiredRoles(r) {
    switch(r.kind) {
      case 'identity': case 'key_binding': case 'policy_commitment': case 'recovery_policy':return ['root'];
      case 'epoch_transition':return r.body.next_root_key===null?['journal_append','root']:['journal_append','root','successor_possession'];
      case 'vouch':return [r.signer_plan.some(s=>s.role==='root')?'root':'gardener'];
      case 'owner_approval':return ['root'];
      case 'agent_card':return [r.schema==='aukora.record.v2'?'root':'human_approval'];
      case 'vouch_accept':return ['human_approval'];
      case 'emission_request':return [r.body.agent_card_ref===null?'human_approval':'agent'];
      case 'intent':return ['aperture_authority'];case 'receipt':return ['aperture_observer'];
      case 'kira_map':return ['storage'];case 'coherence_checkpoint':return ['journal_append'];
      case 'revocation':return [r.body.target_type==='vouch'&&r.signer_plan.some(s=>s.role==='gardener')?'gardener':'root'];
      default:return [];
    }
  }
  function validateSigners(item,depth) {
    const r=item.record, required=requiredRoles(r), actual=r.signer_plan.map(s=>s.role);
    for(const role of required) if(!actual.includes(role)) reason('MISSING_REQUIRED_PROOF',item);
    demand(actual.length===required.length && actual.every(role=>required.includes(role)),'WRONG_AUTHORITY',item);
    item.signers=[];
    r.signer_plan.forEach((plan,index)=>{
      const resolved=resolveSigner(plan,item,depth); if(!resolved) return;
      const key=keyID(resolved.descriptor);
      demand(key===plan.key_id,'WRONG_SIGNER',item);
      const expectedRoot=item.before?.rootKey??contextRoot(r);
      if(plan.role==='root'&&expectedRoot!==undefined) demand(key===expectedRoot,'WRONG_AUTHORITY',item);
      if(resolved.descriptor.profile!==S.PROFILE) { reason('UNSUPPORTED_PROFILE',item); return; }
      const proof=item.proofs[index];
      if(proof && proof.algorithm==='bip340') verify(S.decode64(proof.signature,64),item.digest,Buffer.from(resolved.descriptor.bip340_public_key,'hex'),item);
      item.signers.push({...resolved,plan,key});
      restrictSigner(item,resolved,depth);
    });
  }
  const contextRoot=r=>anchorFor(r)?.root_key_id;
  function restrictSigner(item,signer) {
    const r=item.record,b=r.body, cert=signer.certificate;
    if(!cert||cert.record.kind!=='key_binding') return;
    const restriction=cert.record.body.restriction;
    demand(isSameChain(restriction,r),'WRONG_AUTHORITY',item);
    if(signer.role==='human_approval') {
      demand(restriction.record_kinds.includes(r.kind),'WRONG_AUTHORITY',item);
      if(b.scope) {
        demand(restriction.emission_scopes.some(s=>S.same(s,b.scope)),'SCOPE_MISMATCH',item);
        narrowBudget(b.budget,restriction.budget_ceiling,item); narrowing(r,cert.record,item);
      }
    } else if(signer.role==='journal_append') {
      const epoch=r.kind==='epoch_transition'?b.to_epoch:r.epoch;
      demand(restriction.append_epoch===epoch,'WRONG_AUTHORITY',item);
      if(r.kind==='coherence_checkpoint'&&item.before) demand(item.before.appendKey===keyID(signer.descriptor),'WRONG_AUTHORITY',item);
    } else if(signer.role==='aperture_authority') {
      demand(restriction.adapter_profiles.includes(b.adapter_profile),'SCOPE_MISMATCH',item);
      demand(restriction.emission_scopes.some(s=>S.same(s,b.scope)),'SCOPE_MISMATCH',item);
      narrowBudget(b.budget,restriction.budget_ceiling,item);narrowing(r,cert.record,item);
    } else if(signer.role==='aperture_observer') {
      demand(restriction.adapter_profiles.includes(S.LOCAL_SCOPE.adapter_profile),'SCOPE_MISMATCH',item);
      if(b.outcome==='unknown'&&b.evidence.length===0) demand(restriction.statement_profiles.length===0,'WRONG_AUTHORITY',item);
      else {
        requireObservationProfile();
        demand(S.same(restriction.adapter_profiles,[S.LOCAL_SCOPE.adapter_profile])&&
          S.same(restriction.statement_profiles,[STATEMENT_PROFILE]),'WRONG_AUTHORITY',item);
      }
    } else if(signer.role==='storage') {
      demand(restriction.record_kinds.includes(r.kind),'WRONG_AUTHORITY',item);
      if(r.kind==='kira_map')demand(restriction.namespace_id===b.map_id,'SCOPE_MISMATCH',item);
    }
  }
  function copyState(state) {
    const next = {...state, heads:state.heads.map(x=>({...x}))};
    for (const name of ['policies','revoked','spent','requests','prefix','invites','spentNonces','reservations','requestNonces','balances','controlSpent','controlRevoked','maps']) next[name] = new (cache ? PrefixMap : Map)(state[name]);
    return next;
  }
  function initialState(item) {
    const r=item.record,b=r.body;
    return {subject_id:r.subject_id,chain_id:r.chain_id,epoch:r.epoch,rootKey:keyID(b.root_key),root:b.root_key,appendKey:keyID(b.initial_append_key),append:b.initial_append_key,appendCertificate:item.event.id,policies:new (cache?PrefixMap:Map)(),revoked:new (cache?PrefixMap:Map)(),spent:new (cache?PrefixMap:Map)(),requests:new (cache?PrefixMap:Map)(),prefix:new (cache?PrefixMap:Map)(),heads:S.PROJECTIONS.map(role=>({role,event_id:null,sequence:null})),checkpoint:null,invites:new (cache?PrefixMap:Map)(),...Object.fromEntries(['spentNonces','reservations','requestNonces','balances','controlSpent','controlRevoked','maps'].map(name=>[name,new (cache?PrefixMap:Map)()]))};
  }
  function controlValue(state,basis) {
    return {schema:'aukora.control-state.v1',subject_id:state.subject_id,chain_id:state.chain_id,epoch:state.epoch,basis_event:basis,active_root_key_id:state.rootKey,active_append_key_id:state.appendKey,revoked_targets:arraySorted([...state.revoked.values()]),spent_operations:arraySorted([...state.spent.values()]),active_policy_refs:[...state.policies.values()].map(x=>x.event.id).sort()};
  }
  function controlDigest(state, basis) {
    if (!cache) return digest('aukora.control-state.v1', controlValue(state, basis));
    const remembered = cache.controlDigests.get(state);
    if (remembered?.basis === basis) return remembered.digest;
    const value = derivedControlDigest(derivedControlBytes({subject_id:state.subject_id,chain_id:state.chain_id,
      epoch:state.epoch,basis_event:basis,active_root_key_id:state.rootKey,active_append_key_id:state.appendKey},
      state.controlRevoked.keys(),state.controlSpent.keys(),[...state.policies.values()].map(x=>x.event.id)));
    cache.controlDigests.set(state, {basis,digest:value}); return value;
  }
  function check(item,depth=0) {
    if(item.status==='checked') return item.state;
    if(item.status==='checking') { reason('JOURNAL_CONFLICT',item); return null; }
    if(depth>256) { reason('LIMIT_EXCEEDED',item); return null; }
    item.status='checking';
    if(!item.record||!item.digest||item.issues.size) {item.status='checked';return null;}
    const r=item.record,anchor=anchorFor(r);
    if(!anchor) absent('certificate',r.kind==='identity'?item.event.id:r.previous_event,item);
    else if(r.profile!==anchor.profile) reason(anchor.profile==='aukora.hybrid.bip340.mldsa65.v1'?'WRONG_AUTHORITY':'UNSUPPORTED_PROFILE',item);
    let state;
    if(r.kind==='identity') {
      // Absence is missing evidence, not a conflicting independently supplied
      // identity. Still check the supported self-signatures below; no state can
      // validate while the MISSING_EVIDENCE issue is present.
      if(anchor) {
        demand(item.event.id===anchor.genesis,'WRONG_AUTHORITY',item);
        demand(keyID(r.body.root_key)===anchor.root_key_id,'WRONG_SIGNER',item);
      }
      demand(item.event.pubkey===r.body.root_key.bip340_public_key,'WRONG_SIGNER',item);
      state=initialState(item); item.before=null;
    } else {
      const prev=lookup(r.previous_event,item);
      if(prev) {
        check(prev,depth+1);
        for(const issue of prev.issues) reason(issue,item);
        if(prev.record) {
          demand(isSameChain(prev.record,r),'WRONG_AUTHORITY',item);
          demand(BigInt(r.sequence)===BigInt(prev.record.sequence)+1n,'INCONSISTENT_HEAD',item);
          demand(r.issued_at>=prev.record.issued_at,'WRONG_AUTHORITY',item);
        }
        if(prev.state) {
          state=copyState(prev.state);item.before=prev.state;
          demand(r.epoch===state.epoch,'WRONG_AUTHORITY',item);
          demand(item.event.pubkey===state.append.bip340_public_key,'WRONG_SIGNER',item);
          revoked(state,state.appendCertificate,state.appendKey,item);
          const appendCert=events.get(state.appendCertificate);
          if(appendCert?.record) window(appendCert.record,r.issued_at,r.issued_at,item);
        }
      }
    }
    // Even absent ancestry never produces a guessed role. Available supported
    // application proofs are evaluated only against resolved, anchored certificates.
    try {
      validateSigners(item,0);
      if(state) {
        for(const ref of r.authority_refs) prior(ref,item,0,'certificate');
        validateBody(item,state);
        if(!item.issues.size) {
          updateState(item,state);item.state=state;
        }
      }
    } catch(error) { caught(error,item); }
    item.status='checked'; return item.state;
  }
  function policyRef(ref,type,item) {
    const event=prior(ref,item,0,'event');
    if(!event) return null;
    demand(event.record.kind==='policy_commitment'&&event.record.body.policy_type===type,'WRONG_AUTHORITY',item);
    if(event.record.kind==='policy_commitment') pin(type,event.record.body.policy_digest,item);
    const latest=item.before?.policies.get(type);
    if(latest) demand(latest.event.id===ref,'WRONG_AUTHORITY',item);
    return event;
  }
  function checkCard(card,item,state) {
    const r=item.record,b=r.body,c=card.record,cb=c.body;
    demand(c.kind==='agent_card','WRONG_AUTHORITY',item); if(c.kind!=='agent_card')return;
    demand(isSameChain(c,r)&&cb.human_subject===r.subject_id,'WRONG_AUTHORITY',item);
    demand(cb.agent_key_id===b.requester_key_id,'WRONG_SIGNER',item);
    if(r.kind==='emission_request') demand(cb.agent_subject===b.requester_subject,'WRONG_AUTHORITY',item);
    demand(S.same(cb.scope,b.scope),'SCOPE_MISMATCH',item);narrowBudget(b.budget,cb.budget,item);narrowing(r,c,item);
    revoked(state,card.event.id,cb.agent_key_id,item);
  }
  function validateBody(item,state) {
    const r=item.record,b=r.body,signer=item.signers[0];
    if(r.consent_context!==null) reason('UNSUPPORTED_PROFILE',item);
    if(b.scope) localScope(b.scope,item);
    switch(r.kind) {
      case 'identity':
        for(const type of ['algorithm','succession','recovery','persona']) pin(type,b[`${type}_policy_digest`],item);
        break;
      case 'key_binding': {
        demand(keyID(b.descriptor)===b.key_id,'WRONG_SIGNER',item);
        demand(b.parent_key_id===state.rootKey,'WRONG_AUTHORITY',item);
        demand(isSameChain(b.restriction,r),'WRONG_AUTHORITY',item);
        const root=prior(b.parent_certificate_ref,item,0);
        demand(!root||root.record.kind==='identity','WRONG_AUTHORITY',item);
        if(root) demand(b.parent_certificate_ref===anchorFor(r)?.genesis,'WRONG_AUTHORITY',item);
        pin('custody',b.custody_policy_digest,item);
        if(b.role==='device_assertion'||b.device_assertion_policy_digest!==null) reason('UNSUPPORTED_PROFILE',item);
        if(b.role!=='device_assertion') demand(b.descriptor.profile===S.PROFILE,'WRONG_AUTHORITY',item);
        if(b.restriction.emission_scopes) b.restriction.emission_scopes.forEach(s=>localScope(s,item));
        if(b.restriction.budget_ceiling) narrowBudget(b.restriction.budget_ceiling,b.restriction.budget_ceiling,item);
        if(b.restriction.adapter_profiles) b.restriction.adapter_profiles.forEach(p=>demand(p===S.LOCAL_SCOPE.adapter_profile,'SCOPE_MISMATCH',item));
        if(b.role==='aperture_observer'&&b.restriction.statement_profiles.length) {
          requireObservationProfile();
          demand(S.same(b.restriction.statement_profiles,[STATEMENT_PROFILE])&&
            S.same(b.restriction.adapter_profiles,[S.LOCAL_SCOPE.adapter_profile]),'UNSUPPORTED_PROFILE',item);
        }
        if(b.role==='gardener') policyRef(b.restriction.admission_policy_ref,'admission',item);
        break;
      }
      case 'policy_commitment': {
        demand(b.effective_sequence===r.sequence,'WRONG_AUTHORITY',item);demand(b.policy_version===1,'UNSUPPORTED_PROFILE',item);
        pin(b.policy_type,b.policy_digest,item);
        const previous=state.policies.get(b.policy_type);
        demand(r.authority_refs.includes(previous?previous.event.id:anchorFor(r)?.genesis),'WRONG_AUTHORITY',item);
        break;
      }
      case 'epoch_transition': {
        demand(b.from_epoch===r.epoch&&BigInt(b.to_epoch)===BigInt(b.from_epoch)+1n&&b.prior_final_event===r.previous_event,'WRONG_AUTHORITY',item);
        if(b.next_root_key!==null) reason('UNSUPPORTED_PROFILE',item);
        const next=prior(b.next_append_certificate,item,0);
        if(next) {
          demand(next.record.kind==='key_binding'&&next.record.body.role==='journal_append','WRONG_AUTHORITY',item);
          demand(next.record.body.key_id===b.next_append_key_id&&b.next_append_key_id!==state.appendKey,'WRONG_SIGNER',item);
          demand(next.record.body.restriction.append_epoch===b.to_epoch,'WRONG_AUTHORITY',item);
          demand(BigInt(b.to_epoch)>=BigInt(next.record.body.valid_from_epoch)&&BigInt(b.to_epoch)<=BigInt(next.record.body.valid_through_epoch),'WRONG_AUTHORITY',item);
          window(next.record,r.issued_at,r.issued_at,item);
        }
        const append=item.signers.find(s=>s.role==='journal_append');
        demand(append&&append.key===b.next_append_key_id&&append.certificate?.event.id===b.next_append_certificate,'WRONG_SIGNER',item);
        policyRef(b.transition_policy_ref,'succession',item);
        demand(b.control_checkpoint_ref===state.checkpoint,'INCONSISTENT_HEAD',item);
        demand(b.consumption_anchor===digest('aukora.consumption-state.v1',arraySorted([...state.spent.values()])),'INCONSISTENT_HEAD',item);
        demand(b.revocation_anchor===digest('aukora.revocation-state.v1',arraySorted([...state.revoked.values()])),'INCONSISTENT_HEAD',item);
        break;
      }
      case 'agent_card':
        demand(b.human_subject===r.subject_id,'WRONG_AUTHORITY',item);demand(keyID(b.agent_key)===b.agent_key_id,'WRONG_SIGNER',item);
        pin('custody',b.custody_policy_digest,item);narrowBudget(b.budget,b.budget,item);checkGrantRefs(item);
        break;
      case 'emission_request': {
        demand(signer&&signer.key===b.requester_key_id,'WRONG_SIGNER',item);
        demand(S.same(b.budget,S.LOCAL_BUDGET),'SCOPE_MISMATCH',item);
        if(b.agent_card_ref!==null) { const card=prior(b.agent_card_ref,item,0);if(card)checkCard(card,item,state); }
        else demand(b.requester_subject===r.subject_id,'WRONG_AUTHORITY',item);
        if(state.spent.has(b.operation_id)||state.spentNonces.has(b.nonce)||state.requests.has(b.operation_id)||state.requestNonces.has(b.nonce)) reason('REPLAY',item);
        demand(b.expected_control_checkpoint===state.checkpoint,'INCONSISTENT_HEAD',item);
        requirePolicies(state,item);
        checkGrantRefs(item);
        break;
      }
      case 'owner_approval': {
        const request=prior(b.request_ref,item,0,'event');
        demand(b.journal_head===r.previous_event&&r.authority_refs.includes(b.request_ref),'WRONG_AUTHORITY',item);
        if(request) {
          demand(request.record.kind==='emission_request','WRONG_AUTHORITY',item);
          if(request.record.kind==='emission_request') {
            const q=request.record.body;
            demand(isSameChain(request.record,r)&&request.record.epoch===r.epoch,'WRONG_AUTHORITY',item);
            for(const field of ['operation_id','nonce','requester_key_id','scope','payload_commitment'])
              demand(S.same(b[field],q[field]),field==='scope'?'SCOPE_MISMATCH':'WRONG_AUTHORITY',item);
            narrowing(r,request.record,item);activeDependency(item,request);
            demand(q.expected_control_checkpoint===state.checkpoint,'INCONSISTENT_HEAD',item);
            checkBalances(request,state,item);
          }
        }
        if(state.spent.has(b.operation_id)||state.spentNonces.has(b.nonce))reason('REPLAY',item);
        checkGrantRefs(item);requirePolicies(state,item);
        break;
      }
      case 'intent': {
        if(r.schema==='aukora.record.v2') {
          const approvals=r.authority_refs.map(ref=>events.get(ref)).filter(dep=>dep?.record?.kind==='owner_approval');
          if(approvals.length>1||r.authority_refs.every(ref=>events.get(ref)?.record))
            demand(approvals.length===1,'WRONG_AUTHORITY',item);
          const approval=prior(r.previous_event,item,0,'event');
          if(approval) {
            demand(approval.record.schema==='aukora.record.v2'&&approval.record.kind==='owner_approval'&&
              r.authority_refs.includes(approval.event.id),'WRONG_AUTHORITY',item);
            if(approval.record.kind==='owner_approval') {
              demand(isSameChain(approval.record,r)&&approval.record.epoch===r.epoch,'WRONG_AUTHORITY',item);
              for(const field of ['operation_id','nonce','request_ref','requester_key_id','scope','payload_commitment'])
                demand(S.same(b[field],approval.record.body[field]),field==='scope'?'SCOPE_MISMATCH':'WRONG_AUTHORITY',item);
              narrowing(r,approval.record,item);activeDependency(item,approval);
            }
          }
        }
        demand(signer&&signer.key===b.actor_key_id,'WRONG_SIGNER',item);
        demand(b.adapter_profile===S.LOCAL_SCOPE.adapter_profile&&S.same(b.budget,S.LOCAL_BUDGET),'SCOPE_MISMATCH',item);
        const request=prior(b.request_ref,item,0,'event');
        if(request) {
          demand(request.record.kind==='emission_request','WRONG_AUTHORITY',item);
          if(request.record.kind==='emission_request') {
            const q=request.record.body;
            demand(request.record.epoch===r.epoch,'WRONG_AUTHORITY',item);
            for(const field of ['operation_id','nonce','requester_key_id','scope','payload_commitment','budget']) demand(S.same(b[field],q[field]),field==='scope'||field==='budget'?'SCOPE_MISMATCH':'WRONG_AUTHORITY',item);
            const authority=q.agent_card_ref??request.record.signer_plan[0]?.certificate_ref;
            demand(b.authority_ref===authority,'WRONG_AUTHORITY',item);
            demand(b.control_checkpoint_ref===q.expected_control_checkpoint,'INCONSISTENT_HEAD',item);narrowing(r,request.record,item);
          }
        }
        const authority=prior(b.authority_ref,item,0);
        if(authority) {
          activeDependency(item,authority);
          if(authority.record.kind==='agent_card')checkCard(authority,item,state);
          else if(authority.record.kind==='key_binding') {
            const restriction=authority.record.body.restriction;
            demand(authority.record.body.role==='human_approval'&&authority.record.body.key_id===b.requester_key_id,'WRONG_AUTHORITY',item);
            demand(restriction.emission_scopes?.some(s=>S.same(s,b.scope)),'SCOPE_MISMATCH',item);
            if(restriction.budget_ceiling)narrowBudget(b.budget,restriction.budget_ceiling,item);narrowing(r,authority.record,item);
          } else reason('WRONG_AUTHORITY',item);
        }
        demand(b.control_checkpoint_ref===state.checkpoint,'INCONSISTENT_HEAD',item);
        const reservation={subject_id:r.subject_id,chain_id:r.chain_id,epoch:r.epoch,operation_id:b.operation_id,nonce:b.nonce,reservation_id:b.reservation_id,request_ref:b.request_ref,actor_key_id:b.actor_key_id,authority_ref:b.authority_ref,scope:b.scope,payload_commitment:b.payload_commitment,budget:b.budget,control_checkpoint_ref:b.control_checkpoint_ref,not_before:r.not_before,expires:r.expires};
        demand(b.consumption_commitment===digest('aukora.reservation.v1',reservation),'WRONG_AUTHORITY',item);
        if(state.spent.has(b.operation_id)||(state.spentNonces.has(b.nonce)||state.reservations.has(b.reservation_id)))reason('REPLAY',item);
        checkGrantRefs(item);checkBalances(item,state);requirePolicies(state,item);
        break;
      }
      case 'receipt': {
        demand(signer&&signer.key===b.observer_key_id&&signer.certificate?.event.id===b.observer_certificate_ref,'WRONG_SIGNER',item);
        const intent=prior(b.intent_ref,item,0,'event');
        if(intent) {
          demand(intent.record.kind==='intent','WRONG_AUTHORITY',item);
          if(intent.record.kind==='intent') {
            const q=intent.record.body;
            demand(b.operation_id===q.operation_id&&b.actor_key_id===q.actor_key_id&&b.intent_record_digest===hex(intent.digest),'WRONG_AUTHORITY',item);
            demand(b.observer_key_id!==q.requester_key_id,'WRONG_AUTHORITY',item);
            demand(b.observed_at>=intent.record.issued_at&&b.observed_at<=r.issued_at,'WRONG_AUTHORITY',item);
          }
        }
        demand((b.outcome!=='done'||b.dispatch_state==='observed')&&(b.dispatch_state!=='not_dispatched'||b.outcome==='refused')&&(b.dispatch_state!=='dispatched_uncertain'||b.outcome==='unknown'),'WRONG_AUTHORITY',item);
        if(b.outcome==='done'&&b.dispatch_state==='observed') {
          requireObservationProfile();
          demand(b.evidence.length===1,'WRONG_AUTHORITY',item);
          if(intent?.record?.kind==='intent'&&b.evidence.length===1) {
            const entry=b.evidence[0],blob=artifactBytes.get(entry.artifact_digest);
            demand(![intent.record.body.requester_key_id,intent.record.body.actor_key_id,state.appendKey,state.rootKey].includes(b.observer_key_id),'WRONG_AUTHORITY',item);
            demand(intent.record.epoch===r.epoch&&isSameChain(intent.record,r),'WRONG_AUTHORITY',item);
            demand(S.same(entry,{...observationEvidence(blob??Buffer.alloc(0),b.observer_key_id,b.observed_at),artifact_digest:entry.artifact_digest}),'WRONG_AUTHORITY',item);
            if(blob) {
              parseObservation(blob);
              demand(blob.equals(observationBytes(intent,{key_id:b.observer_key_id,certificate_ref:b.observer_certificate_ref},b.observed_at)),'WRONG_AUTHORITY',item);
            }
          }
        } else if(!(b.outcome==='unknown'&&b.dispatch_state==='dispatched_uncertain'&&b.evidence.length===0))reason('UNSUPPORTED_PROFILE',item);
        for(const o of b.evidence) if(!artifactDigests.has(o.artifact_digest))absent('witness',o.artifact_digest,item);
        if(b.reconciles_receipt!==null){const previous=prior(b.reconciles_receipt,item,0,'event');if(previous)demand(previous.record.kind==='receipt'&&previous.record.body.operation_id===b.operation_id&&previous.record.body.intent_ref===b.intent_ref,'WRONG_AUTHORITY',item);}
        break;
      }
      case 'coherence_checkpoint': {
        const basis=prior(b.basis_event,item,0,'event');
        if(basis?.state) {
          demand(b.basis_sequence===basis.record.sequence&&b.basis_epoch===basis.record.epoch,'INCONSISTENT_HEAD',item);
          demand(S.same(b.heads,basis.state.heads),'INCONSISTENT_HEAD',item);
          demand(b.control_state_digest===controlDigest(basis.state,basis.event.id),'INCONSISTENT_HEAD',item);
          demand(b.previous_checkpoint===basis.state.checkpoint,'INCONSISTENT_HEAD',item);
        }
        demand(b.previous_checkpoint===state.checkpoint,'INCONSISTENT_HEAD',item);
        if(!b.evidence_complete||b.missing_evidence.length) {reason('MISSING_EVIDENCE',item);missing.push(...b.missing_evidence);}
        break;
      }
      case 'revocation':validateRevocation(item,state);break;
      case 'vouch':validateVouch(item,state);break;
      case 'vouch_accept': {
        demand(b.invitee_subject===r.subject_id&&b.invitee_genesis===anchorFor(r)?.genesis,'WRONG_AUTHORITY',item);
        const vouch=prior(b.vouch_ref,item,0,'event');
        if(vouch){activeDependency(item,vouch);demand(vouch.record.kind==='vouch','WRONG_AUTHORITY',item);for(const field of ['inviter_subject','invitee_subject','invitee_genesis'])demand(b[field]===vouch.record.body[field],'WRONG_AUTHORITY',item);window(vouch.record,r.issued_at,r.issued_at,item);}
        break;
      }
      case 'kira_map': {
        validateMapCryptoProfile(canonicalBytes(r));
        demand(signer&&signer.key===b.storage_key_id,'WRONG_SIGNER',item);
        const basis=prior(b.basis_journal_event,item,0,'event');
        if(basis)demand(isSameChain(basis.record,r),'WRONG_AUTHORITY',item);
        const latest=state.maps.get(b.map_id);
        if(b.previous_map===null)demand(b.revision==='0'&&!latest,'INCONSISTENT_HEAD',item);
        else {
          const previous=prior(b.previous_map,item,0,'event');
          if(previous) {
            demand(previous.record.kind==='kira_map'&&isSameChain(previous.record,r)&&previous.record.body.map_id===b.map_id,'WRONG_AUTHORITY',item);
            if(previous.record.kind==='kira_map')demand(BigInt(b.revision)===BigInt(previous.record.body.revision)+1n&&latest===previous.event.id,'INCONSISTENT_HEAD',item);
          }
        }
        break;
      }
      case 'recovery_policy':
        demand(b.threshold>0&&b.threshold<=b.operators.length,'CLOSED_SCHEMA',item);
        // This is a statement of an inert policy. No recovery implementation.
        break;
    }
  }
  function requirePolicies(state,item) {
    for(const type of ['time','control','scope','custody']) {
      const policy=state.policies.get(type);
      if(!policy)absent('event',null,item);else pin(type,policy.record.body.policy_digest,item);
    }
    if(state.checkpoint===null)absent('event',null,item);
  }
  function grantRefs(item) {
    // Only the exact semantic grant path constrains an operation. A checkpoint's
    // basis/history is evidence, not a union of every grant ever used in that past.
    // All key bindings in this profile have the anchored root as direct parent.
    const refs=new Set();
    const r=item.record,b=r.body;
    for(const signer of item.signers??[]) {
      const certificate=signer.certificate;
      if(certificate?.record.kind==='key_binding'&&certificate.record.body.restriction.budget_ceiling)refs.add(certificate.event.id);
    }
    const authority=r.kind==='intent'?b.authority_ref:r.kind==='emission_request'?b.agent_card_ref:null;
    if(authority) {
      const grant=events.get(authority);
      if(grant?.record.kind==='key_binding')refs.add(authority);
      if(grant?.record.kind==='agent_card') {
        refs.add(authority);
        for(const signer of grant.signers??[])if(signer.role==='human_approval'&&signer.certificate)refs.add(signer.certificate.event.id);
      }
    }
    return refs;
  }
  function checkGrantRefs(item) {
    const accepted=grantRefs(item);
    for(const ref of item.record.authority_refs) {
      const dependency=events.get(ref)?.record;
      if(dependency?.kind==='agent_card'||dependency?.kind==='key_binding'&&dependency.body.restriction.budget_ceiling)
        demand(accepted.has(ref),'WRONG_AUTHORITY',item);
    }
  }
  function checkBalances(item,state,reportItem=item) {
    for(const ref of grantRefs(item)) {
      const grant=events.get(ref).record;
      const ceiling=grant.kind==='agent_card'?grant.body.budget:grant.body.restriction.budget_ceiling;
      for(const b of item.record.body.budget) {
        const cap=ceiling.find(c=>c.unit===b.unit&&c.currency===b.currency);
        if(!cap){reason('SCOPE_MISMATCH',reportItem);continue;}
        const used=state.balances.get(`${ref}:${b.unit}:${b.currency}`)??0n;
        demand(used+BigInt(b.maximum)<=BigInt(cap.maximum),'SCOPE_MISMATCH',reportItem);
      }
    }
  }
  function validateRevocation(item,state) {
    const r=item.record,b=r.body;
    demand(b.target_subject===r.subject_id&&b.effective_sequence===r.sequence&&b.effective_epoch===r.epoch,'WRONG_AUTHORITY',item);
    if(b.target_type==='root_key') {reason('UNSUPPORTED_PROFILE',item);return;}
    if(b.target_type==='vouch') {
      const vouch=prior(b.target_id,item,0,'event');
      if(vouch)demand(vouch.record.kind==='vouch'&&vouch.record.body.inviter_subject===r.subject_id&&item.signers.some(s=>s.role==='root'||vouch.record.signer_plan.some(p=>p.key_id===s.key)),'WRONG_AUTHORITY',item);
      policyRef(b.policy_ref,'admission',item);
    } else {
      demand(b.admission_predicates.length===0,'WRONG_AUTHORITY',item);
      if(b.target_type==='agent_card'||b.target_type==='key_binding') {
        const target=prior(b.target_id,item,0);
        if(target)demand(target.record.kind===b.target_type,'WRONG_AUTHORITY',item);
      } else {
        demand([...state.prefix.values()].some(e=>e.record.kind==='key_binding'&&e.record.body.key_id===b.target_id),'WRONG_AUTHORITY',item);
      }
      prior(b.policy_ref,item,0,'event');
    }
    if(b.successor_ref!==null)prior(b.successor_ref,item,0);
  }
  function validateVouch(item,state) {
    const r=item.record,b=r.body;
    demand(b.inviter_subject===r.subject_id&&b.invitee_subject!==r.subject_id,'WRONG_AUTHORITY',item);
    const invitee=lookup(b.invitee_genesis,item,'certificate');
    if(invitee){check(invitee);demand(invitee.record?.kind==='identity'&&invitee.record.subject_id===b.invitee_subject,'WRONG_AUTHORITY',item);for(const code of invitee.issues)reason(code,item);}
    const p=policyRef(b.admission_policy_ref,'admission',item);
    const month=new Date(r.issued_at*1000).toISOString().slice(0,7);
    if(state.invites.has(b.invite_slot))reason('REPLAY',item);
    const used=[...state.invites.values()].filter(v=>v.month===month).length;
    const document=p&&policies.get(p.record.body.policy_digest);
    const visibility=document?.parameters.visibility??(p?.record.body.policy_digest===S.POLICY_PINS.admission?'one_hop':null);
    if(visibility!==null)demand(b.visibility===visibility,'SCOPE_MISMATCH',item);
    const cap=document?.parameters.invites_per_month??(p?.record.body.policy_digest===S.POLICY_PINS.admission?3:null);
    if(cap!==null)demand(used<cap,'SCOPE_MISMATCH',item);
    const gardener=item.signers.find(s=>s.role==='gardener');
    if(gardener) {
      demand(gardener.certificate.record.body.restriction.admission_policy_ref===b.admission_policy_ref,'WRONG_AUTHORITY',item);
      const own=[...state.invites.values()].filter(v=>v.month===month&&v.issuer===gardener.key).length;
      demand(own<gardener.certificate.record.body.restriction.monthly_cap,'SCOPE_MISMATCH',item);
    }
    for(const ref of b.ceremony_evidence_refs)prior(ref,item,0,'event');
  }
  function updateState(item,state) {
    const r=item.record,b=r.body;
    if(r.kind==='epoch_transition') {
      const next=events.get(b.next_append_certificate).record.body;
      state.epoch=b.to_epoch;state.appendKey=b.next_append_key_id;state.append=next.descriptor;state.appendCertificate=b.next_append_certificate;
    }
    if(r.kind==='policy_commitment')state.policies.set(b.policy_type,item);
    if(r.kind==='revocation') {
      const entry={target_type:b.target_type,target_id:b.target_id};
      state.revoked.set(`${b.target_type}:${b.target_id}`,entry);
      state.controlRevoked.set(canonicalBytes(entry).toString('utf8'),true);
    }
    if(r.kind==='emission_request'){state.requests.set(b.operation_id,item);state.requestNonces.set(b.nonce,true);}
    if(r.kind==='intent') {
      const entry={operation_id:b.operation_id,nonce:b.nonce,reservation_id:b.reservation_id,intent_ref:item.event.id};
      state.spent.set(b.operation_id,entry);state.spentNonces.set(b.nonce,true);state.reservations.set(b.reservation_id,true);
      state.controlSpent.set(canonicalBytes(entry).toString('utf8'),true);
      for(const ref of grantRefs(item))for(const budget of b.budget){
        const key=`${ref}:${budget.unit}:${budget.currency}`;
        state.balances.set(key,(state.balances.get(key)??0n)+BigInt(budget.maximum));
      }
    }
    if(r.kind==='kira_map')state.maps.set(b.map_id,item.event.id);
    if(r.kind==='coherence_checkpoint')state.checkpoint=item.event.id;
    if(r.kind==='vouch')state.invites.set(b.invite_slot,{month:new Date(r.issued_at*1000).toISOString().slice(0,7),issuer:item.signers[0]?.key});
    const role=r.kind==='coherence_checkpoint'?null:['vouch','vouch_accept','agent_card'].includes(r.kind)||r.kind==='revocation'&&['vouch','agent_card'].includes(b.target_type)?'delegation':['emission_request','owner_approval','intent'].includes(r.kind)?'actions':r.kind==='receipt'?'receipts':r.kind==='kira_map'?'memory':'identity';
    if(role)state.heads[S.PROJECTIONS.indexOf(role)]={role,event_id:item.event.id,sequence:r.sequence};
    state.prefix.set(item.event.id,item);
  }
  function detectForks() {
    const positions=new Map(),successors=new Map();
    for(const item of events.values()) {
      if(!item.state||item.issues.size)continue;
      const r=item.record;
      if(cache)for(const other of [cache.positions.get(r.sequence),cache.successors.get(r.previous_event)]) {
        if(other&&other!==item.event.id){conflicts.push([other,item.event.id].sort());reason('JOURNAL_CONFLICT',item);}
      }
      const key=`${r.subject_id}:${r.chain_id}:${r.epoch}:${r.sequence}`,prev=`${r.subject_id}:${r.chain_id}:${r.previous_event}`;
      for(const [map,k] of [[positions,key],...(r.previous_event===null?[]:[[successors,prev]])]) {
        const other=map.get(k);
        if(other && other!==item.event.id) { conflicts.push([other,item.event.id].sort());reason('JOURNAL_CONFLICT',item);reason('JOURNAL_CONFLICT',events.get(other)); }
        else map.set(k,item.event.id);
      }
    }
  }
  function currentSnapshot(snapshot,item) {
    if(!snapshot){reason('STALE_CONTROL',item);reason('UNTRUSTED_TIME',item);return null;}
    const f=snapshot.floor;
    if(snapshot.mode!=='LOCAL_TEST') {reason('WRONG_AUTHORITY',item);return null;}
    if(snapshot.source_id!==S.SOURCE || snapshot.time_policy_digest!==S.POLICY_PINS.time)reason('UNTRUSTED_TIME',item);
    if(snapshot.source_id!==S.SOURCE || snapshot.control_policy_digest!==S.POLICY_PINS.control)reason('STALE_CONTROL',item);
    for(const field of ['source_id','subject_id','chain_id','revision','epoch','sequence','head','control_state_digest'])demand(snapshot[field]===f[field],'ROLLBACK_UNRESOLVED',item);
    demand(f.time_floor<=snapshot.now_lower,'ROLLBACK_UNRESOLVED',item);
    const head=lookup(snapshot.head,item);if(!head)return null;
    check(head);if(!head.state){reason('STALE_CONTROL',item);return null;}
    demand(isSameChain(head.record,snapshot)&&head.record.sequence===snapshot.sequence&&head.state.epoch===snapshot.epoch,'INCONSISTENT_HEAD',item);
    demand(controlDigest(head.state,head.event.id)===snapshot.control_state_digest,'INCONSISTENT_HEAD',item);
    demand(snapshot.checkpoint_ref===head.state.checkpoint,'INCONSISTENT_HEAD',item);
    return head.state;
  }
  function authorizationNow(item) {
    if(!item.digest)return;
    const r=item.record,snapshot=currentFor(r),state=currentSnapshot(snapshot,item);
    if(snapshot) {
      const trustedTime=snapshot.source_id===S.SOURCE&&snapshot.mode==='LOCAL_TEST'&&snapshot.time_policy_digest===S.POLICY_PINS.time;
      if(trustedTime)window(r,snapshot.now_lower,snapshot.now_upper,item);
      if(state)demand(r.epoch===snapshot.epoch,'WRONG_AUTHORITY',item);
      if(r.kind!=='identity')demand(snapshot.checkpoint_ref!==null,'STALE_CONTROL',item);
    }
    if(!state||!snapshot)return;
    demand(state.prefix.has(item.event.id)||r.previous_event===snapshot.head,'INCONSISTENT_HEAD',item);
    // New admission uses the independently supplied source month, never a
    // caller-selected issuance month. Historical prefix entries keep their
    // original month; this pure check cannot attest supplied context freshness.
    if(r.kind==='vouch'&&!state.prefix.has(item.event.id)&&snapshot.source_id===S.SOURCE&&
       snapshot.mode==='LOCAL_TEST'&&snapshot.time_policy_digest===S.POLICY_PINS.time) {
      const month=new Date(snapshot.now_lower*1000).toISOString().slice(0,7);
      if(month!==new Date(snapshot.now_upper*1000).toISOString().slice(0,7))reason('TIME_UNCERTAINTY',item);
      else demand(new Date(r.issued_at*1000).toISOString().slice(0,7)===month,'WRONG_AUTHORITY',item);
    }
    if(evidence.control_state===null&&!cache)absent('revocation',snapshot.control_state_digest,item);
    else if(evidence.control_state!==null) {
      const value=controlEvidence;
      demand(S.same(value,controlValue(state,snapshot.head)),'INCONSISTENT_HEAD',item);
      demand(digest('aukora.control-state.v1',value)===snapshot.control_state_digest,'INCONSISTENT_HEAD',item);
    }
    const refs=new Set(item.activeRefs);refs.add(state.appendCertificate);
    revoked(state,null,state.rootKey,item);
    revoked(state,item.event.id,r.body.agent_key_id??r.body.key_id??null,item);
    for(const ref of refs) {
      const dep=events.get(ref);if(!dep?.record)continue;
      const dr=dep.record;
      if(['key_binding','agent_card','identity','vouch','owner_approval','emission_request'].includes(dr.kind)) {
        const ds=currentFor(dr);
        if(!ds){reason('STALE_CONTROL',item);continue;}
        const foreign=!isSameChain(dr,r);
        const dsState=foreign?currentSnapshot(ds,item):state;
        if(ds.source_id===S.SOURCE&&ds.mode==='LOCAL_TEST'&&ds.time_policy_digest===S.POLICY_PINS.time)window(dr,ds.now_lower,ds.now_upper,item);
        const key=dr.kind==='key_binding'?dr.body.key_id:dr.kind==='agent_card'?dr.body.agent_key_id:dr.kind==='identity'?keyID(dr.body.root_key):null;
        revoked(dsState,ref,key,item);
        if(dr.kind==='vouch'&&dsState?.revoked.has(`vouch:${ref}`))reason('REVOKED',item);
      }
    }
    for(const s of item.signers??[])revoked(state,s.certificate?.event.id,s.key,item);
    if(r.kind==='vouch'&&state.revoked.has(`vouch:${item.event.id}`))reason('REVOKED',item);
    if(r.kind==='owner_approval') {
      demand(item.event.id===snapshot.head||(!state.prefix.has(item.event.id)&&r.previous_event===snapshot.head),'INCONSISTENT_HEAD',item);
      if(state.spent.has(r.body.operation_id)||state.spentNonces.has(r.body.nonce))reason('REPLAY',item);
      const request=events.get(r.body.request_ref);
      if(request?.record?.kind==='emission_request') {
        demand(request.record.body.expected_control_checkpoint===snapshot.checkpoint_ref,'INCONSISTENT_HEAD',item);
        checkBalances(request,state,item);
      }
      requirePolicies(state,item);
    }
    if(['emission_request','intent'].includes(r.kind)) {
      const b=r.body;
      const spent=state.spent.get(b.operation_id);
      const exactReserved=r.kind==='intent'&&spent&&spent.nonce===b.nonce&&spent.reservation_id===b.reservation_id&&spent.intent_ref===item.event.id&&state.prefix.has(item.event.id);
      if(!exactReserved&&(spent||state.spentNonces.has(b.nonce)))reason('REPLAY',item);
      const checkpoint=b.expected_control_checkpoint??b.control_checkpoint_ref;
      if(exactReserved) {
        const basis=state.prefix.get(checkpoint);
        demand(basis?.record.kind==='coherence_checkpoint'&&BigInt(basis.record.sequence)<BigInt(r.sequence),'INCONSISTENT_HEAD',item);
      } else demand(checkpoint===snapshot.checkpoint_ref,'INCONSISTENT_HEAD',item);
      requirePolicies(state,item);
      if(!exactReserved)checkBalances(item,state);
    }
    if(r.kind==='recovery_policy')reason('RECOVERY_UNREVIEWED',item);
  }
  try {
    // No caller object is inspected here. All three boundaries use W1's byte gate.
    const first=parse(eventBytes);
    context=parse(contextBytes,MAX_EVIDENCE); S.context(context);
    evidence=parse(evidenceBytes,MAX_EVIDENCE); S.evidence(evidence);
    if(cache) {
      S.insist(!cache.closed,'ROLLBACK_UNRESOLVED');
      S.insist(context.additional_anchors.length===0&&context.additional_control.length===0,'UNSUPPORTED_PROFILE');
      S.insist(evidence.events.length===0,'CLOSED_SCHEMA');
      const binding=hex(canonicalBytes({subject:context.expected_subject_id,chain:context.expected_chain_id,
        genesis:context.expected_genesis,root:context.expected_root_key_id,profile:context.expected_profile,
        pins:context.policy_pins,policies:evidence.policies}));
      if(cache.binding!==null)S.insist(cache.binding===binding,'WRONG_AUTHORITY');
      if(appendToCache)S.insist(context.purpose==='historical_integrity','WRONG_AUTHORITY');
      if(cache.binding===null)cache.binding=binding;
      const added=appendToCache&&!cache.events.has(first?.id);
      S.insist(cache.events.size+(added?1:0)<=32768&&cache.bytes+(added?Buffer.byteLength(JSON.stringify(first)):0)<=134217728,'LIMIT_EXCEEDED');
    }
    if(evidence.control_state!==null) {
      controlEvidence=parse(boundedDecode(evidence.control_state),MAX_EVIDENCE);S.controlState(controlEvidence);
    }
    if(first && first.schema==='aukora.draft.v1') {
      S.closed(first,{schema:S.literal('aukora.draft.v1'),record:x=>validateRecord(x),proofs:x=>S.insist(Array.isArray(x)&&x.length===0)});
      draft=true;target={record:first.record,digest:hashDomain(first.record.schema,canonicalBytes(first.record)),issues:new Set()};
      result.record_digest=hex(target.digest);
      if(first.record.body.scope)localScope(first.record.body.scope,target);
      reason('UNSIGNED_DRAFT');
    } else {
      // The copied event was parsed once above; readEvent accepts that immutable tree.
      target=readEventTree(first);
      if(target.event?.id && /^[0-9a-f]{64}$/.test(target.event.id))result.event_id=target.event.id;
      if(target.digest)result.record_digest=hex(target.digest);
      if(target.event?.id)events.set(target.event.id,target);
    }
    for(const p of evidence.policies) {
      const bytes=boundedDecode(p.document),document=parse(bytes,MAX_EVIDENCE);S.policyDocument(document);
      demand(digest('aukora.policy.v1',document)===p.digest,'BAD_SIGNATURE');
      if(document.policy_type!=='admission')demand(p.digest===S.POLICY_PINS[document.policy_type],'UNSUPPORTED_PROFILE');
      policies.set(p.digest,document);
    }
    for(const a of evidence.artifacts) {
      const blob=boundedDecode(a.blob);demand(hex(sha256(blob))===a.digest,'BAD_SIGNATURE');artifactDigests.add(a.digest);artifactBytes.set(a.digest,blob);
    }
    let previousID=null;
    for(const value of evidence.events) {
      const bytes=boundedDecode(value),item=readEvent(bytes);
      if(!item.event?.id)continue;
      if(previousID!==null)S.insist(previousID<item.event.id);previousID=item.event.id;
      const existing=events.get(item.event.id);
      if(existing)demand(S.same(existing.event,item.event),'BAD_SIGNATURE',item);else events.set(item.event.id,item);
    }
    if(!draft&&target.digest) {
      const r=target.record;
      demand(r.subject_id===context.expected_subject_id&&r.chain_id===context.expected_chain_id,'WRONG_AUTHORITY',target);
      demand(r.kind===context.expected_kind,'WRONG_DOMAIN',target);
      if(r.profile!==context.expected_profile)reason(context.expected_profile==='aukora.hybrid.bip340.mldsa65.v1'?'WRONG_AUTHORITY':'UNSUPPORTED_PROFILE',target);
      for(const s of context.expected_signers) {
        // A substituted role is an authority failure even when the independent
        // expected signer mismatch already prevents further chain evaluation.
        demand(r.signer_plan.some(p=>p.role===s.role),'WRONG_AUTHORITY',target);
        demand(r.signer_plan.some(p=>p.role===s.role&&p.key_id===s.key_id),'WRONG_SIGNER',target);
      }
      check(target);
      if(cache&&appendToCache&&!cache.events.has(target.event.id)) {
        demand(r.previous_event===(cache.head?.event.id??null),'INCONSISTENT_HEAD',target);
      }
      // Validate every supplied branch so hidden malformed ancestry cannot be a
      // selectable winning head. No sorting rule chooses a branch.
      for(const item of events.values())check(item);
      detectForks();
      if(context.purpose==='authorization_now')authorizationNow(target);
    }
  } catch(error) { caught(error); }
  result.reason_codes=[...allReasons].sort();
  result.missing_evidence=uniqueSorted(missing);result.conflicts=uniqueSorted(conflicts);
  if(result.reason_codes.some(c=>REJECT.has(c)))result.verdict='REJECT';
  else if(result.reason_codes.some(c=>UNKNOWN.has(c)))result.verdict='UNKNOWN';
  else if(draft)result.verdict='DRAFT';
  else if(target?.state){result.verdict='valid';result.reason_codes=['VERIFIED'];result.validated_through=target.event.id;}
  else {result.verdict='UNKNOWN';result.reason_codes=['MISSING_EVIDENCE'];}
  if(cache&&result.verdict==='valid'&&appendToCache)cache.resultItem=target;
  return result;

}

/** Explicit refusal seam; this function never acquires keys or releases shares. */
export function recover(_requestBytes) {
  return {verdict:'UNKNOWN',reason_codes:['RECOVERY_UNREVIEWED']};
}
