import registry from '../../spec/layer0-v1/registry.json' with { type: 'json' };
import { applicationDigest, canonicalBytes, parseBytes, parseContent, parseEvent, parseRecord, snapshotBytes, sha256, h32 } from '../bytes/index.mjs';
import { signRecord, constructEvent, verifyBip340 } from '../keys/index.mjs';
import { verifyOuterEvent } from '../verifier/index.mjs';
import { createJournalVerifier } from './verification.mjs';
import { createPrefixChildHandles } from '../agents/child-handles.mjs';
import { budgetCeilings, prepareIntent } from './intent.mjs';
import { preflightIntentWork } from './preflight.mjs';
import { receiptTemplate } from './receipt.mjs';
import { observationBytes, observationEvidence, parseObservation, STATEMENT_PROFILE } from './observation.mjs';
import { CLASSICAL_PROFILE, LOCAL_ADAPTER, LOCAL_SCOPE, trustedBytes, equalData,
  checkLocalRequest, openPayload, operationResult, refuse } from './local-profile.mjs';

const knownCodes = new Set(Object.values(registry.reason_codes).flat());
const policies = Object.values(registry.policy_documents).map(({ digest, document }) => ({
  digest, document: trustedBytes(document).toString('base64url'),
})).sort((a, b) => a.digest.localeCompare(b.digest));

// A trusted host assembly function; never passed across the proposal bridge.
// No dependency, key, callback, store path, mode or sink is proposal-selectable.
export function createLocalAperture({ source, anchor, requestSigners, append, aperture,
  mode = 'LOCAL_TEST', receiptObserver = null, requireOwnerApproval = false }, effects) {
  // Only the trusted host constructs these synchronous effect capabilities.
  // This second argument is never decoded from wire/proposal/config bytes.
  const { sink, barriers, receiptNotice, durableEvent = null } = effects;
  if (typeof sink?.enter !== 'function' || typeof sink?.count !== 'function' ||
      typeof barriers?.intentSigned !== 'function' || typeof barriers?.reach !== 'function' ||
      typeof receiptNotice !== 'function' || (durableEvent !== null && typeof durableEvent !== 'function')) throw new TypeError('trusted host effects required');
  // Notification is deliberately lossy and cannot change a committed authority
  // outcome. Never wrap the transaction itself in this exception boundary.
  const notifyDurable = (writer,bytes) => { try { durableEvent?.(writer,bytes); } catch { /* lost notification */ } };
  let closed = false, inSubmission = false, intentSignCalls = 0, observedSinkEntries = 0;

  const verifier = createJournalVerifier(anchor);
  const verifyCurrent = (writer, bytes, kind, signers, artifacts = []) => verifier.verify(writer, bytes, kind, signers, {artifacts});
  let children = null, childPrefix = null;
  const childRuntime = acquired => {
    if(childPrefix!==acquired.prefix){
      // External source writes/reset invalidate ephemeral handles; never restore
      // a prepared allowance into a replacement verification session.
      children?.close();children=createPrefixChildHandles(acquired.prefix);childPrefix=acquired.prefix;
    }
    return children;
  };
  const requireChildController = () => {
    if(closed||inSubmission||mode!=='LOCAL_TEST')refuse('WRONG_AUTHORITY');
    if(!requireOwnerApproval)refuse('UNSUPPORTED_PROFILE');
  };
  const acquireParent = (writer, reference) => {
    h32(reference);
    const cardBytes=writer.eventBytes(reference);
    if(!cardBytes)refuse('MISSING_EVIDENCE');
    const card=parseEvent(cardBytes).record;
    if(card.kind!=='agent_card'||requestSigners.length!==1||requestSigners[0].role!=='agent'||
      requestSigners[0].key_id!==card.body.agent_key_id)refuse('WRONG_AUTHORITY');
    return {cardBytes,acquired:verifyCurrent(writer,cardBytes,'agent_card',[{role:'root',key_id:anchor.expected_root_key_id}])};
  };
  const sourcePolicy = (acquired, request, requireLatestCheckpoint) => {
    const { snapshot, state } = acquired;
    if (snapshot.source_id !== 'aukora.local-test-control.v1' || snapshot.mode !== 'LOCAL_TEST') refuse('STALE_CONTROL');
    if (snapshot.subject_id !== anchor.expected_subject_id || snapshot.chain_id !== anchor.expected_chain_id) refuse('WRONG_AUTHORITY');
    if (snapshot.epoch !== request.epoch || state.active_append_key_id !== append.key_id) refuse('WRONG_AUTHORITY');
    if (!snapshot.checkpoint_ref) refuse('MISSING_EVIDENCE');
    if (requireLatestCheckpoint && snapshot.checkpoint_ref !== request.body.expected_control_checkpoint) refuse('STALE_CONTROL');
    if (snapshot.now_lower !== snapshot.now_upper) refuse('TIME_UNCERTAINTY');
    if (request.body.requester_key_id === aperture.key_id || request.body.requester_key_id === append.key_id) refuse('WRONG_AUTHORITY');
    // A LOCAL custody policy must actually be committed. The host accepts only
    // bytes; it does not run arbitrary proposal/plugin code with these handles.
    const committed = new Set(acquired.events.filter(({ event, record }) => record.kind === 'policy_commitment' &&
      state.active_policy_refs.includes(event.id))
      .map(({ record }) => record.body.policy_digest));
    for (const name of ['algorithm', 'scope', 'time', 'control', 'custody']) {
      if (!committed.has(registry.policy_documents[name].digest)) refuse('MISSING_EVIDENCE');
    }
  };
  const reservedOwnership = (writer, request, intent, expectedState) => {
    const op = writer.operation(request.subject_id, request.body.operation_id);
    if (!op || op.intent_ref !== intent.event.id || op.nonce !== request.body.nonce ||
      op.reservation_id !== intent.record.body.reservation_id ||
      op.reservation_commitment !== intent.record.body.consumption_commitment || op.state !== expectedState) {
      refuse('WRONG_AUTHORITY');
    }
  };
  const storedResult = (operation, reasons) => operationResult({ operationId: operation.operation_id,
    intentRef: operation.intent_ref,
    receiptRef: operation.last_receipt_ref,
    state: operation.state === 'settled' ? 'settled' : operation.state === 'reserved_not_dispatched' ? 'reserved_not_dispatched' : 'unknown', reasons });

  const submit = (requestEventBytes, payloadEvidenceBytes, childHandleBytes = null) => {
      if (closed || mode !== 'LOCAL_TEST' || inSubmission) return operationResult({ reasons: ['WRONG_AUTHORITY'] });
      inSubmission = true;
      let opening, operationId = null, intentRef = null, committed = false, commitAttempted = false, markAttempted = false, marked = false;
      try {
        // Snapshot before parsing/locking. Object/proxy inputs cannot call back.
        const requestBytes = snapshotBytes(requestEventBytes);
        const childHandle=childHandleBytes===null?null:snapshotBytes(childHandleBytes,256);
        const evidenceBytes = snapshotBytes(payloadEvidenceBytes, 1024);
        // Authenticate the outer envelope before content/context semantics so
        // timestamp tampering retains the frozen BAD_SIGNATURE diagnosis.
        verifyOuterEvent(requestBytes);
        const parsed = parseEvent(requestBytes), request = parsed.record;
        checkLocalRequest(request);
        operationId = request.body.operation_id;
        opening = openPayload(evidenceBytes, operationId, request.body.payload_commitment);
        evidenceBytes.fill(0);
        return source.withWriterLock(writer => {
          const old = writer.operation(request.subject_id, operationId);
          if (old && childHandle===null) return storedResult(old, ['REPLAY']);
          const acquired = verifyCurrent(writer, requestBytes, 'emission_request', requestSigners);
          acquired.events.push({bytes:requestBytes,...parsed});
          if(childHandle!==null){
            // Recheck the prepared digest, local revocation, parent ancestry and
            // current time inside this same lock. No await occurs before effect.
            const checked=childRuntime(acquired).check(childHandle,requestBytes,acquired.contextBytes,acquired.evidence);
            if(checked.verdict!=='valid')return operationResult({operationId,reasons:checked.reason_codes});
          }
          if (acquired.reasons) return operationResult({ operationId, reasons: acquired.reasons });
          sourcePolicy(acquired, request, true);
          // The bridge cannot admit a request or forge the journal envelope.
          if (!Buffer.from(writer.eventBytes(parsed.event.id) ?? []).equals(Buffer.from(requestBytes))) {
            refuse('MISSING_EVIDENCE');
          }
          let approval = null;
          if (requireOwnerApproval) {
            const approvalBytes = writer.eventBytes(acquired.snapshot.head);
            if (!approvalBytes) refuse('MISSING_EVIDENCE');
            approval = parseEvent(approvalBytes);
            if (approval.record.schema !== 'aukora.record.v2' || approval.record.kind !== 'owner_approval') refuse('MISSING_EVIDENCE');
            const checked = verifyCurrent(writer, approvalBytes, 'owner_approval', [{role:'root',key_id:anchor.expected_root_key_id}]);
            if (checked.reasons) return operationResult({operationId,reasons:checked.reasons});
            if (approval.record.body.request_ref !== parsed.event.id ||
              approval.record.body.payload_sha256 !== sha256(opening.payload).toString('hex')) refuse('WRONG_AUTHORITY');
            opening.check();
            acquired.events.push({bytes:approvalBytes,...approval});
          }
          const certificateBytes = writer.eventBytes(aperture.certificate_ref);
          const certificate = certificateBytes ? {bytes:certificateBytes,...parseEvent(certificateBytes)} : null;
          if (!certificate) refuse('MISSING_EVIDENCE');
          const certificateCheck = verifyCurrent(writer, certificate.bytes, 'key_binding', [
            { role: 'root', key_id: anchor.expected_root_key_id },
          ]);
          if (certificateCheck.reasons) return operationResult({ operationId, reasons: certificateCheck.reasons });
          acquired.events.push(certificate);
          const binding = certificate.record.body;
          if (binding.role !== 'aperture_authority' || binding.key_id !== aperture.key_id ||
            !binding.restriction.adapter_profiles.includes(LOCAL_ADAPTER) ||
            !binding.restriction.emission_scopes.some(scope => equalData(scope, LOCAL_SCOPE)) ||
            binding.custody_policy_digest !== registry.policy_documents.custody.digest) refuse('WRONG_AUTHORITY');
          let observerPublicKey = null;
          if (receiptObserver) {
            const observerBytes = writer.eventBytes(receiptObserver.certificate_ref);
            const observerCertificate = observerBytes ? {bytes:observerBytes,...parseEvent(observerBytes)} : null;
            if (!observerCertificate) refuse('MISSING_EVIDENCE');
            const checked = verifyCurrent(writer, observerCertificate.bytes, 'key_binding', [{ role: 'root', key_id: anchor.expected_root_key_id }]);
            if (checked.reasons) return operationResult({ operationId, reasons: checked.reasons });
            const observerBinding = observerCertificate.record.body;
            if (observerBinding.role !== 'aperture_observer' || observerBinding.key_id !== receiptObserver.key_id ||
              [request.body.requester_key_id, aperture.key_id, append.key_id, anchor.expected_root_key_id].includes(observerBinding.key_id) ||
              !equalData(observerBinding.restriction.adapter_profiles, [LOCAL_ADAPTER]) ||
              !equalData(observerBinding.restriction.statement_profiles, [STATEMENT_PROFILE]) ||
              observerBinding.custody_policy_digest !== registry.policy_documents.custody.digest) refuse('WRONG_AUTHORITY');
            observerPublicKey = observerBinding.descriptor.bip340_public_key;
          }
          const debits = budgetCeilings(request, aperture.certificate_ref,
            new Map(acquired.events.map(({ event, record }) => [event.id, record])));
          writer.checkBudgetDebits(trustedBytes(debits));
          if (writer.isNonceConsumed(request.subject_id, request.body.nonce)) refuse('REPLAY');
          const prepared = prepareIntent({ request, requestRef: parsed.event.id, snapshot: acquired.snapshot,
            aperture, append, policyRefs: acquired.state.active_policy_refs, approval });
          const requiredEvents=receiptObserver?2:1;
          if(acquired.capacity.events<requiredEvents||acquired.capacity.bytes<262144*requiredEvents)refuse('LIMIT_EXCEEDED');
          preflightIntentWork(prepared.recordBytes, acquired.events, { reserveReceipt: receiptObserver !== null, verifiedPrefix: true });
          const signed = signRecord(prepared.recordBytes, trustedBytes([
            { key_id: aperture.key_id, secret_key: aperture.secret.toString('base64url') },
          ]));
          intentSignCalls += 1;
          barriers.intentSigned(operationId);
          const intentBytes = constructEvent(signed, append.secret);
          const intent = parseEvent(intentBytes);
          const intentCheck = verifyCurrent(writer, intentBytes, 'intent', [{ role: 'aperture_authority', key_id: aperture.key_id }]);
          if (intentCheck.reasons) return operationResult({ operationId, reasons: intentCheck.reasons });
          barriers.reach('before_atomic_commit', operationId);
          intentRef = intent.event.id;
          commitAttempted = true;
          writer.reserveIntent(intentBytes, prepared.descriptorBytes, trustedBytes(debits));
          committed = true;
          notifyDurable(writer,intentBytes);
          barriers.reach('after_consume_intent_durable', operationId);
          let final = verifyCurrent(writer, intentBytes, 'intent', [{ role: 'aperture_authority', key_id: aperture.key_id }]);
          if (final.reasons) return operationResult({ operationId, intentRef, state: 'reserved_not_dispatched', reasons: final.reasons });
          sourcePolicy(final, request, false);
          reservedOwnership(writer, request, intent, 'reserved_not_dispatched');
          opening.check();
          // Synchronization contains public events only. An unavailable or
          // ambiguous acknowledgement prevents crossing the dispatch marker.
          if(receiptObserver)verifier.synchronizeObserver(writer,receiptObserver.channel);
          const beforeMarker = final.snapshot;
          markAttempted = true;
          writer.markDispatchStarted(operationId);
          marked = true;
          barriers.reach('after_dispatch_marker_durable', operationId);
          // Guard lock remains held through marker COMMIT, final verification,
          // and synchronous sink entry. No promises/timers/proposal callbacks.
          final = verifyCurrent(writer, intentBytes, 'intent', [{ role: 'aperture_authority', key_id: aperture.key_id }]);
          if (final.reasons) return operationResult({ operationId, intentRef, state: 'unknown', reasons: final.reasons });
          sourcePolicy(final, request, false);
          if (final.snapshot.boot_id !== beforeMarker.boot_id ||
              final.snapshot.revision !== (BigInt(beforeMarker.revision) + 1n).toString() ||
              final.snapshot.now_lower !== beforeMarker.now_lower) refuse('STALE_CONTROL');
          reservedOwnership(writer, request, intent, 'dispatch_started');
          opening.check();
          if (!receiptObserver) {
            sink.enter(opening.payload, operationId, intentRef);
            barriers.reach('after_sink_entry', operationId);
            return operationResult({ operationId, intentRef, state: 'unknown', reasons: ['MISSING_EVIDENCE'] });
          }
          const templateBytes = receiptTemplate({ intent, snapshot: final.snapshot, append, observer: receiptObserver,
            policyRefs: final.state.active_policy_refs,
            reconcilesReceipt: writer.operation(request.subject_id, operationId).last_receipt_ref });
          // The actual fixed message crosses the inherited channel once. Only a
          // separate receiver which consumed that complete frame can sign back.
          const response = receiptObserver.channel.exchange([intentBytes, templateBytes, final.evidence, opening.payload]);
          try {
            const [contentBytes, artifactBytes, extraA, extraB] = response;
            if (extraA.length || extraB.length) refuse('CLOSED_SCHEMA');
            parseObservation(artifactBytes);
            if (!Buffer.from(artifactBytes).equals(observationBytes(intent, receiptObserver, final.snapshot.now_lower))) refuse('WRONG_AUTHORITY');
            const template = parseBytes(templateBytes), content = parseContent(contentBytes);
            if (!equalData(content.record, { ...template, body: { ...template.body, outcome: 'done', dispatch_state: 'observed',
              evidence: [observationEvidence(artifactBytes, receiptObserver.key_id, final.snapshot.now_lower)] } })) refuse('WRONG_AUTHORITY');
            // Reject a substituted/false observer proof before using the append
            // key. W2 still independently checks the complete signed event.
            if (!verifyBip340(Buffer.from(content.proofs[0].signature, 'base64url'),
              applicationDigest(canonicalBytes(content.record)), Buffer.from(observerPublicKey, 'hex'))) refuse('BAD_SIGNATURE');
            const receiptBytes = constructEvent(contentBytes, append.secret);
            const artifacts = [{ digest: sha256(artifactBytes).toString('hex'), blob: Buffer.from(artifactBytes).toString('base64url') }];
            const checked = verifyCurrent(writer, receiptBytes, 'receipt', [{ role: 'aperture_observer', key_id: receiptObserver.key_id }], artifacts);
            if (checked.reasons) return operationResult({ operationId, intentRef, state: 'unknown', reasons: checked.reasons });
            observedSinkEntries += 1;
            receiptNotice(operationId, intentRef);
            // This fault boundary is after independent reception but before the
            // atomic receipt/artifact commit. Crash still retains UNKNOWN.
            barriers.reach('after_sink_entry', operationId);
            const receiptRef = writer.recordReceipt(receiptBytes, artifactBytes);
            notifyDurable(writer,receiptBytes);
            return operationResult({ operationId, intentRef, receiptRef, state: 'settled', reasons: [] });
          } finally { response.forEach(value => value.fill(0)); }
        });
      } catch (error) {
        const code = knownCodes.has(error?.code) ? error.code : 'MISSING_EVIDENCE';
        return operationResult({ operationId, intentRef,
          state: marked || markAttempted || (commitAttempted && !committed) ? 'unknown' : committed ? 'reserved_not_dispatched' : 'refused',
          reasons: [code] });
      } finally { opening?.destroy(); inSubmission = false; }
  };
  return Object.freeze({
    submitLocal: (request,opening) => submit(request,opening),
    submitChild: (handle,request,opening) => submit(request,opening,snapshotBytes(handle,256)),
    deriveChild(restrictionBytes) {
      requireChildController();
      const bytes=snapshotBytes(restrictionBytes,2048),requested=parseBytes(bytes);
      return source.withWriterLock(writer=>{
        const {cardBytes,acquired}=acquireParent(writer,requested.parent_card_ref);
        return childRuntime(acquired).derive(cardBytes,bytes,acquired.contextBytes,acquired.evidence);
      });
    },
    prepareChild(handleBytes,proposalBytes,requestRecordBytes) {
      requireChildController();
      const handle=snapshotBytes(handleBytes,256),proposal=snapshotBytes(proposalBytes,2048),request=snapshotBytes(requestRecordBytes);
      const record=parseRecord(request);
      if(record.kind!=='emission_request')refuse('WRONG_DOMAIN');
      return source.withWriterLock(writer=>{
        const {acquired}=acquireParent(writer,record.body.agent_card_ref);
        return childRuntime(acquired).prepare(handle,proposal,request,acquired.contextBytes,acquired.evidence);
      });
    },
    revokeChild(handleBytes) {
      requireChildController();const handle=snapshotBytes(handleBytes,256);
      return source.withWriterLock(()=>{
        if(!children)refuse('WRONG_AUTHORITY');
        children.revoke(handle);return {revoked:true,grants_authority:false};
      });
    },
    counters() { return Object.freeze({ intent_sign_calls: intentSignCalls, sink_entries: receiptObserver ? observedSinkEntries : sink.count() }); },
    close() { closed = true; children?.close(); verifier.close(); receiptObserver?.channel.close(); append.secret.fill(0); aperture.secret.fill(0); },
  });
}
