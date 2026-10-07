import registry from '../../spec/layer0-v1/registry.json' with { type: 'json' };
import { parseEvent, snapshotBytes } from '../bytes/index.mjs';
import { createPrefixVerifier } from '../verifier/index.mjs';
import { CLASSICAL_PROFILE, trustedBytes, refuse } from './local-profile.mjs';

const policies = Object.values(registry.policy_documents).map(({digest,document}) => ({digest,
  document:trustedBytes(document).toString('base64url')})).sort((a,b)=>a.digest.localeCompare(b.digest));
const neededArtifacts = (writer,record) => writer.receiptArtifacts(record.kind==='receipt'?record.body.evidence.map(e=>e.artifact_digest):[]);
const evidence = artifacts => trustedBytes({schema:'aukora.evidence.v1',events:[],policies,
  control_state:null,artifacts:[...artifacts].sort((a,b)=>a.digest.localeCompare(b.digest))});

// Trusted source consumer, never a proposal-supplied verifier or state snapshot.
// Source lock possession is checked by every writer method. Restarts and external
// SQLite changes rebuild by checking retained bytes from the anchored genesis.
export function createJournalVerifier(anchor) {
  let session=createPrefixVerifier(), epoch=null, closed=false;
  const context = (record, signers, purpose, snapshot=null) => trustedBytes({schema:'aukora.verify-context.v1',purpose,
    ...anchor,expected_profile:CLASSICAL_PROFILE,expected_kind:record.kind,expected_signers:signers,
    policy_pins:policies.map(p=>p.digest),control:snapshot,additional_anchors:[],additional_control:[]});
  const reset = () => { session.close(); session=createPrefixVerifier(); };
  const sync = writer => {
    if(closed)refuse('ROLLBACK_UNRESOLVED');
    const nextEpoch=writer.cacheEpoch();
    if(epoch!==nextEpoch){reset();epoch=nextEpoch;}
    const retainedHead=session.head();
    if(retainedHead.closed)refuse('ROLLBACK_UNRESOLVED');
    if(retainedHead.id!==null&&!writer.eventBytes(retainedHead.id)){reset();refuse('ROLLBACK_UNRESOLVED');}
    for(;;){
      const batch=writer.eventsAfter(session.head().id);
      if(!batch.length)break;
      for(const bytes of batch){
        const {record}=parseEvent(bytes);
        const result=session.append(bytes,context(record,record.signer_plan.map(({role,key_id})=>({role,key_id})),'historical_integrity'),evidence(neededArtifacts(writer,record)));
        if(result.verdict!=='valid'){reset();refuse(result.reason_codes[0]);}
      }
    }
    const snapshot=writer.snapshot(),head=session.head();
    if(head.id!==snapshot.head||head.sequence!==snapshot.sequence){reset();refuse('ROLLBACK_UNRESOLVED');}
    return snapshot;
  };
  const references = (writer, record, snapshot, state) => {
    const found=new Map(),pending=[snapshot.head,...state.active_policy_refs,record.previous_event,...record.authority_refs,
      ...record.signer_plan.map(s=>s.certificate_ref),record.body.request_ref,record.body.authority_ref,
      record.body.control_checkpoint_ref,record.body.expected_control_checkpoint,record.body.agent_card_ref];
    while(pending.length){
      const id=pending.pop();if(!id||found.has(id))continue;
      if(found.size>=256)refuse('LIMIT_EXCEEDED');
      const bytes=writer.eventBytes(id);if(!bytes)continue;
      const parsed=parseEvent(bytes);found.set(id,{bytes,...parsed});
      // Certificate/grant dependencies, never the linear previous_event chain.
      pending.push(...parsed.record.authority_refs,...parsed.record.signer_plan.map(s=>s.certificate_ref));
    }
    return [...found.values()];
  };
  return Object.freeze({
    verify(writer,eventBytes,expectedKind,signers,{purpose='authorization_now',artifacts=[]}={}) {
      const bytes=snapshotBytes(eventBytes),parsed=parseEvent(bytes),snapshot=sync(writer);
      if(parsed.record.kind!==expectedKind)refuse('WRONG_DOMAIN');
      const state=writer.controlSummary(),proof=evidence([...new Map([...neededArtifacts(writer,parsed.record),...artifacts].map(a=>[a.digest,a])).values()]);
      const contextBytes=context(parsed.record,signers,purpose,purpose==='authorization_now'?snapshot:null);
      const result=session.verify(bytes,contextBytes,proof);
      // Private trusted-host material; never serialized to proposal/controller data.
      return {result,reasons:result.verdict==='valid'?null:result.reason_codes,snapshot,state,contextBytes,prefix:session.verificationHandle,
        capacity:{events:32768-session.head().count,bytes:134217728-session.head().bytes},
        events:references(writer,parsed.record,snapshot,state),evidence:proof};
    },
    acceptedBundle(writer, eventBytes) {
      const bytes=snapshotBytes(eventBytes),parsed=parseEvent(bytes);
      sync(writer);
      if(!Buffer.from(writer.eventBytes(parsed.event.id)??[]).equals(Buffer.from(bytes)))refuse('MISSING_EVIDENCE');
      const contextBytes=context(parsed.record,parsed.record.signer_plan.map(({role,key_id})=>({role,key_id})),'historical_integrity');
      const evidenceBytes=evidence(neededArtifacts(writer,parsed.record));
      const checked=session.verify(bytes,contextBytes,evidenceBytes);
      if(checked.verdict!=='valid')refuse(checked.reason_codes[0]);
      return {eventBytes:Buffer.from(bytes),contextBytes:Buffer.from(contextBytes),evidenceBytes:Buffer.from(evidenceBytes),prefix:session.verificationHandle};
    },
    synchronizeObserver(writer, channel) {
      const snapshot=sync(writer);
      let acknowledged=channel.head();
      if(acknowledged.id!==null&&!writer.eventBytes(acknowledged.id))refuse('ROLLBACK_UNRESOLVED');
      for(;;) {
        const batch=writer.eventsAfter(acknowledged.id);if(!batch.length)break;
        for(const bytes of batch) {
          const {record}=parseEvent(bytes);
          acknowledged=channel.synchronize(bytes,context(record,record.signer_plan.map(({role,key_id})=>({role,key_id})),'historical_integrity'),evidence(neededArtifacts(writer,record)));
        }
      }
      if(acknowledged.id!==snapshot.head||acknowledged.sequence!==snapshot.sequence)refuse('INCONSISTENT_HEAD');
    },
    // A competing signed branch is independently checked from genesis up to its
    // own predecessor before the protected source retains/freezes the conflict.
    verifyBranch(writer,eventBytes,signers) {
      const branch=createPrefixVerifier(),candidate=parseEvent(eventBytes);let cursor=null;
      try {
        outer:for(;;){const batch=writer.eventsAfter(cursor);if(!batch.length)break;
          for(const bytes of batch){const {event,record}=parseEvent(bytes);
            if(BigInt(record.sequence)>=BigInt(candidate.record.sequence))break outer;
            const result=branch.append(bytes,context(record,record.signer_plan.map(({role,key_id})=>({role,key_id})),'historical_integrity'),evidence(neededArtifacts(writer,record)));
            if(result.verdict!=='valid')return result;cursor=event.id;
          }
        }
        return branch.append(eventBytes,context(candidate.record,signers,'historical_integrity'),evidence(neededArtifacts(writer,candidate.record)));
      } finally {branch.close();}
    },
    close(){closed=true;session.close();},
  });
}
