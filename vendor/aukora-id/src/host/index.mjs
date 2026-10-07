import { isAbsolute } from 'node:path';
import registry from '../../spec/layer0-v1/registry.json' with { type: 'json' };
import { b64, closed, h32, keyId, parseBytes, parseEvent, snapshotBytes, uint } from '../bytes/index.mjs';
import { descriptorBytes } from '../keys/index.mjs';
import { openJournal } from '../journal/index.mjs';
import { verifyOuterEvent, verifyPrefixEvent } from '../verifier/index.mjs';
import { createJournalVerifier } from '../aperture/verification.mjs';
import { createLocalAperture } from '../aperture/index.mjs';
import { createFixedLocalSink, noticeSinkEntry } from '../local-sink/index.mjs';
import { createTestBarriers } from './barriers.mjs';
import { requireObservationProfile } from '../observer/profile.mjs';
import { createObserverChannel } from '../observer/channel.mjs';
import { CLASSICAL_PROFILE, refuse, trustedBytes } from '../aperture/local-profile.mjs';

const expectedAnchor = { expected_subject_id: h32, expected_chain_id: h32,
  expected_genesis: h32, expected_root_key_id: h32 };
const secretSpec = { certificate_ref: h32, secret_key: value => b64(value, 32) };
const signerList = value => {
  if (!Array.isArray(value) || value.length !== 1) refuse('CLOSED_SCHEMA');
  closed(value[0], { role: role => { if (!['human_approval', 'agent'].includes(role)) refuse('WRONG_AUTHORITY'); }, key_id: h32 });
};
const signerFrom = value => {
  const secret = Buffer.from(value.secret_key, 'base64url');
  const descriptor = descriptorBytes(secret);
  return { secret, certificate_ref: value.certificate_ref,
    key_id: Buffer.from(keyId(descriptor)).toString('hex'), public_key: parseBytes(descriptor).bip340_public_key };
};

// Opens an existing retained W1 store. Fresh genesis is a separate, explicitly
// trusted W1 operation; host restarts cannot initialize or import/reset authority.
// This API is for the trusted controller, never untrusted plugin execution.
export function createLocalHost(configBytes, { observerFd = 4, barrier = null, receiptObserverBytes = null, receiptObserverFd = null } = {}) {
  const config = parseBytes(configBytes);
  closed(config, {
    schema: value => { if (!['aukora.local-host.v1','aukora.local-host.v2'].includes(value)) refuse('CLOSED_SCHEMA'); },
    mode: value => { if (value !== 'LOCAL_TEST') refuse('WRONG_AUTHORITY'); },
    directory: value => { if (typeof value !== 'string' || !isAbsolute(value)) refuse('CLOSED_SCHEMA'); },
    anchor: value => closed(value, expectedAnchor), request_signers: signerList,
    append: value => closed(value, secretSpec), aperture: value => closed(value, secretSpec),
  });
  const verifier = createJournalVerifier(config.anchor), accepted = [];
  let acceptedBytes = 0, stopped = false;
  const release = entry => {for(const field of ['eventBytes','contextBytes','evidenceBytes'])entry[field].fill(0);};
  const clearAccepted = () => {for(const entry of accepted)release(entry);accepted.length=0;acceptedBytes=0;};
  const captureAccepted = (writer,eventBytes) => {
    if(stopped)return;
    const bundle=verifier.acceptedBundle(writer,eventBytes);
    // A genuine prefix is attached only when drained; no cache/handle is queued.
    const entry={eventBytes:bundle.eventBytes,contextBytes:bundle.contextBytes,evidenceBytes:bundle.evidenceBytes};
    const size=entry.eventBytes.length+entry.contextBytes.length+entry.evidenceBytes.length;
    if(size>8388608){release(entry);return;}
    while(accepted.length>=64||acceptedBytes+size>8388608){const old=accepted.shift();acceptedBytes-=old.eventBytes.length+old.contextBytes.length+old.evidenceBytes.length;release(old);}
    accepted.push(entry);acceptedBytes+=size;
  };
  let source, append, aperture, engine, receiptObserver = null;
  try {
    append = signerFrom(config.append);
    aperture = signerFrom(config.aperture);
    if (append.key_id === aperture.key_id || [append.key_id, aperture.key_id].includes(config.anchor.expected_root_key_id) ||
      config.request_signers.some(({ key_id }) => [append.key_id, aperture.key_id].includes(key_id))) refuse('WRONG_AUTHORITY');
    if (receiptObserverBytes !== null) {
      requireObservationProfile();
      const publicBinding = closed(parseBytes(receiptObserverBytes), { key_id: h32, certificate_ref: h32 });
      if ([append.key_id, aperture.key_id, config.anchor.expected_root_key_id, ...config.request_signers.map(s => s.key_id)].includes(publicBinding.key_id)) refuse('WRONG_AUTHORITY');
      receiptObserver = { ...publicBinding, channel: createObserverChannel(receiptObserverFd) };
    } else if (receiptObserverFd !== null) refuse('WRONG_AUTHORITY');
    source = openJournal({ directory: config.directory });
    source.withWriterLock(writer => {
      if (typeof writer.retainVerifiedConflict !== 'function') refuse('MISSING_EVIDENCE');
      const snapshot = writer.snapshot();
      if (snapshot.subject_id !== config.anchor.expected_subject_id || snapshot.chain_id !== config.anchor.expected_chain_id) refuse('WRONG_AUTHORITY');
    });
    engine = createLocalAperture({ source, anchor: config.anchor, requestSigners: config.request_signers,
      append, aperture, mode: config.mode, receiptObserver, requireOwnerApproval: config.schema === 'aukora.local-host.v2' }, Object.freeze({
      sink: createFixedLocalSink(observerFd),
      barriers: createTestBarriers({ name: barrier, observerFd }),
      receiptNotice: (operationId, intentRef) => noticeSinkEntry(observerFd, operationId, intentRef),
      durableEvent: captureAccepted,
    }));
  } catch (error) {
    clearAccepted();verifier.close();append?.secret.fill(0); aperture?.secret.fill(0); source?.close(); throw error;
  }

  return Object.freeze({
    submitLocal: engine.submitLocal,
    deriveChild: engine.deriveChild,
    prepareChild: engine.prepareChild,
    revokeChild: engine.revokeChild,
    submitChild: engine.submitChild,
    // Trusted in-process consumer only. Service IPC exposes takePulse(), never
    // this raw bundle or its opaque module-branded verification handle.
    takeAcceptedEvent() {
      if(stopped)return null;
      try {
        return source.withWriterLock(writer=>{
          const entry=accepted.shift();if(!entry)return null;
          acceptedBytes-=entry.eventBytes.length+entry.contextBytes.length+entry.evidenceBytes.length;
          try {return verifier.acceptedBundle(writer,entry.eventBytes);}
          finally {release(entry);}
        });
      } catch {clearAccepted();return null;}
    },
    // Trusted controller read: one operation from this configured subject only.
    // No selected path/head/signer/context and no journal or lifecycle mutation.
    readReceipt(queryBytes) {
      const query=closed(parseBytes(snapshotBytes(queryBytes,256)),{operation_id:h32});
      if(stopped)refuse('WRONG_AUTHORITY');
      return source.withWriterLock(writer=>{
        writer.snapshot();
        const operation=writer.operation(config.anchor.expected_subject_id,query.operation_id);
        const unavailable={operation_id:query.operation_id,receipt_ref:null,receipt:null,
          verification:{verdict:'UNKNOWN',reason_codes:['MISSING_EVIDENCE'],record_digest:null,
            event_id:null,validated_through:null,missing_evidence:[],conflicts:[]},grants_authority:false};
        if(!operation?.last_receipt_ref)return unavailable;
        const eventBytes=writer.eventBytes(operation.last_receipt_ref);
        if(eventBytes===null)return unavailable;
        const {record}=parseEvent(eventBytes);
        if(record.kind!=='receipt'||record.body.operation_id!==query.operation_id||
          record.body.intent_ref!==operation.intent_ref)refuse('WRONG_AUTHORITY');
        const bundle=verifier.acceptedBundle(writer,eventBytes);
        const verification=verifyPrefixEvent(bundle.prefix,bundle.eventBytes,bundle.contextBytes,bundle.evidenceBytes);
        if(verification.verdict!=='valid')return {...unavailable,verification};
        // W2 checked this exact receipt and every referenced public artifact.
        // Its prefix/context and unrelated retained rows never leave this method.
        return {operation_id:query.operation_id,receipt_ref:operation.last_receipt_ref,
          receipt:{event:Buffer.from(bundle.eventBytes).toString('base64url'),
            artifacts:writer.receiptArtifacts(record.body.evidence.map(item=>item.artifact_digest))},
          verification,grants_authority:false};
      });
    },
    snapshot() { if(stopped)refuse('WRONG_AUTHORITY'); return source.withWriterLock(writer=>writer.snapshot()); },
    inspect() {
      if (stopped) refuse('WRONG_AUTHORITY');
      const storage = source.inspect();
      return { storage, counters: engine.counters(),
        profile: CLASSICAL_PROFILE, mode: 'LOCAL_TEST', completion_evidence: storage.operations.some(o => o.state === 'settled') ? 'SIGNED_LOCAL_RECEIPT' : 'UNKNOWN',
        cordis_integration: 'UNKNOWN', os_isolation: 'UNKNOWN' };
    },
    advanceClock(now) {
      uint(now);
      if (stopped) refuse('WRONG_AUTHORITY');
      return source.withWriterLock(writer => { writer.advanceClock(now); return writer.snapshot(); });
    },
    // Independently signed controller-supplied control/journal data only; this
    // method is absent from the proposal pipe and never creates signatures.
    appendVerified(eventBytes, expectedSignersBytes) {
      eventBytes = snapshotBytes(eventBytes);
      if (stopped) refuse('WRONG_AUTHORITY');
      verifyOuterEvent(eventBytes);
      const candidate = parseEvent(eventBytes);
      const signers = parseBytes(expectedSignersBytes);
      return source.withWriterLock(writer => {
        const checked = verifier.verify(writer,eventBytes,candidate.record.kind,signers,{purpose:'historical_integrity'});
        const result = checked.result;
        if (result.verdict !== 'valid') {
          if (result.reason_codes.includes('JOURNAL_CONFLICT')) {
            const branch=verifier.verifyBranch(writer,eventBytes,signers);
            if(branch.verdict==='valid') {
              try {writer.retainVerifiedConflict(eventBytes);}
              catch(error){if(error?.code!=='JOURNAL_CONFLICT')throw error;}
            }
          }
          return {appended:false,verification:result};
        }
        writer.appendVerified(eventBytes);
        return { appended: true, verification: result };
      });
    },
    // Current admission is a trusted controller capability, separate from
    // historical import. Proposal bytes cannot choose a verification purpose.
    admitCurrent(eventBytes, expectedSignersBytes) {
      eventBytes = snapshotBytes(eventBytes);
      if (stopped) refuse('WRONG_AUTHORITY');
      verifyOuterEvent(eventBytes);
      const candidate = parseEvent(eventBytes), signers = parseBytes(expectedSignersBytes);
      return source.withWriterLock(writer => {
        const checked = verifier.verify(writer,eventBytes,candidate.record.kind,signers);
        if (checked.result.verdict !== 'valid') return {appended:false,verification:checked.result};
        if (candidate.record.previous_event !== checked.snapshot.head) refuse('INCONSISTENT_HEAD');
        writer.appendVerified(eventBytes);
        return {appended:true,verification:checked.result};
      });
    },
    close() {
      if (stopped) return;
      stopped = true; clearAccepted();verifier.close(); engine.close(); source.close();
    },
  });
}

export function recover(_requestBytes) {
  return { verdict: 'UNKNOWN', reason_codes: ['RECOVERY_UNREVIEWED'] };
}
