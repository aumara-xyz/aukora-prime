// Private worker lifecycle shared by the separated service and keyless fixtures.
// This is not a provider or an authority verifier; production supplies the existing vault/HTTP/Bridge.
import { canonicalJson, operationDigest, validateContract } from '../../contracts/src/runtime.mjs';
import { id, refuse, assertDispatchExpiry, InferenceRefusal } from './policy.mjs';
import { verifyWorkerContinuation } from './dispatch-policy.mjs';

const same = (a,b) => canonicalJson(a) === canonicalJson(b);
const admissionOf = intent => ({...intent.binding,operation:intent.operation,
  consumed_grant:intent.consumed_grant,request_digest:intent.request_digest});
const lookupOf = intent => ({owner_id:intent.task.owner_id,task_id:intent.task.task_id,
  operation_digest:operationDigest(intent.operation),request_uuid:intent.request_id,request_digest:intent.request_digest});

/** Fence BEFORE Bridge receives the reviewed pair and can call C reserve. No proof is persisted. */
export async function reviewedReserveAttempt(ledger, binding, getReviewedApproval) {
  let snapshot, reviewed;
  try { snapshot=structuredClone(binding);canonicalJson(snapshot); }
  catch { refuse('INVALID_RESERVE_ATTEMPT'); }
  reviewed=await getReviewedApproval(structuredClone(snapshot));
  try {
    canonicalJson(reviewed);
    if (!reviewed || Object.keys(reviewed).sort().join(',') !== 'approval_proof,operation') throw new Error();
    reviewed=structuredClone(reviewed);
    validateContract('OperationProposal',reviewed.operation);validateContract('ApprovalProof',reviewed.approval_proof);
  } catch { refuse('INVALID_REVIEWED_APPROVAL'); }
  const {operation,approval_proof:proof}=reviewed;
  if (proof.operation_id !== operation.operation_id || proof.operation_digest !== operationDigest(operation)
      || proof.owner_id !== operation.owner_id || proof.audience !== operation.audience
      || proof.authorization_epoch !== operation.authorization_epoch) refuse('INVALID_REVIEWED_APPROVAL');
  assertDispatchExpiry(operation.expiry);assertDispatchExpiry(proof.expiry);
  ledger.beginReserveAttempt(snapshot,operation);
  return reviewed;
}

/** Exact persisted outbox only. This callback is also available after restart/logout. */
export async function withCommittedWorkerSettlement(ledger, method, lookup, consume) {
  if (typeof consume !== 'function') refuse('WORKER_SETTLEMENT_CALLBACK_REQUIRED');
  const {intent}=ledger.workerIntent(lookup?.owner_id,lookup?.task_id,lookup?.request_uuid);
  const pending=ledger.pendingWorkerSettlement(intent.task.owner_id,intent.task.task_id,intent.request_id);
  if (!pending || pending.method !== method || !same(lookup,{...lookupOf(intent),receipt_digest:pending.payload.receipt_digest}))
    refuse('WORKER_SETTLEMENT_SCOPE_MISMATCH');
  return await consume(structuredClone(pending.payload));
}

export class WorkerDispatchContinuation {
  #ledger;#observe;#generate;#withDispatch;#retrySettlement;#slots=new Map();
  constructor({ledger,observe,generate,withDispatch,retrySettlement}) {
    if (![observe,generate,withDispatch,retrySettlement].every(fn=>typeof fn==='function')) refuse('CREDENTIAL_AUTHORITY_JOIN_UNAVAILABLE');
    this.#ledger=ledger;this.#observe=observe;this.#generate=generate;
    this.#withDispatch=withDispatch;this.#retrySettlement=retrySettlement;
  }
  get activeCount() { return this.#slots.size; }
  hasRequest(uuid) { return this.#slots.has(uuid); }
  hasOwner(owner) { return [...this.#slots.values()].some(slot=>slot.snapshot.owner_id===owner); }
  #live(slot) {
    if (!slot.open || this.#slots.get(slot.snapshot.request_uuid)!==slot || slot.signal?.aborted)
      refuse('WORKER_CONTINUATION_CLOSED');
  }
  #unknown(slot) {
    const {task,request_id}=slot.intent,scope=[task.owner_id,task.task_id,request_id];
    const stored=this.#ledger.get(...scope);
    if (stored?.status !== 'completed' && stored?.status !== 'outcome_unknown') {
      try { this.#ledger.recordWorkerEvidence(...scope,null,new Date().toISOString()); }
      catch { refuse('WORKER_EVIDENCE_COMMIT_REQUIRED'); }
    }
  }
  async dispatch(request,{signal}={}) {
    if (signal?.aborted) refuse('CANCELLED_BEFORE_DISPATCH');
    let snapshot;
    try { canonicalJson(request);snapshot=structuredClone(request); } catch { refuse('INVALID_PRIVATE_DISPATCH'); }
    if (![snapshot?.owner_id,snapshot?.task_id,snapshot?.request_uuid].every(id)) refuse('INVALID_PRIVATE_DISPATCH');
    const uuid=snapshot.request_uuid;
    if (this.#slots.has(uuid)) refuse('REQUEST_ALREADY_RESERVED');
    const controller=new AbortController();
    const slot={snapshot,open:true,entered:false,dispatchEntered:false,completed:false,controller,invocationPending:true,flightPending:false,
      signal:signal ? AbortSignal.any([signal,controller.signal]) : controller.signal};
    this.#slots.set(uuid,slot);
    let timer;
    try {
      const {intent,route}=await this.#observe(snapshot);this.#live(slot);
      slot.intent=intent;
      // A fresh Bridge connection cannot reconstruct an unfenced C reserve attempt.
      const attempt=this.#ledger.reserveAttempt(intent.task.owner_id,intent.task.task_id,uuid);
      if (!attempt || !same(attempt.binding,intent.binding) || attempt.operation_digest!==operationDigest(intent.operation)
          || attempt.request_digest!==intent.request_digest) refuse('RESERVE_ATTEMPT_REQUIRED');
      this.#ledger.reserveWorkerIntent(intent);
      try {
        const claim={operation:intent.operation,consumed_grant:intent.consumed_grant,
          request_id:uuid,request_digest:intent.request_digest};
        // One bounded original invocation. Revocation prevents late claims/custody/replies resuming HTTP.
        slot.flightPending=true;
        const flight=Promise.resolve().then(()=>{this.#live(slot);return this.#withDispatch(structuredClone(claim));}).finally(()=>{
          slot.flightPending=false;
          if (!slot.invocationPending) this.#slots.delete(uuid);
        });
        const timeout=new Promise((_,reject)=>{
          timer=setTimeout(()=>{slot.open=false;controller.abort();reject(new InferenceRefusal('CLAIM_OUTCOME_UNKNOWN'));},route.max_request_ms);
        });
        const result=await Promise.race([flight,timeout]);
        this.#live(slot);
        if (!slot.completed || !same(result,slot.reply)) refuse('WORKER_CONTINUATION_NOT_COMPLETED');
      } catch {
        slot.open=false;controller.abort();this.#unknown(slot);
      } finally { clearTimeout(timer);slot.open=false; }
      // Bridge observation has enclosed HTTP and durable evidence. Settlement is factual redelivery only.
      await this.#retrySettlement(intent.task.owner_id,intent.task.task_id,uuid);
      if (!slot.completed) refuse('PROVIDER_OUTCOME_UNKNOWN');
      return structuredClone(slot.reply);
    } finally {
      clearTimeout(timer);slot.open=false;controller.abort();slot.invocationPending=false;
      // A bounded caller wait is not proof of callback quiescence. Keep close/entry/recovery fenced.
      if (!slot.flightPending) this.#slots.delete(uuid);
    }
  }
  async withCommittedIntent(lookup,consume) {
    const slot=this.#slots.get(lookup?.request_uuid);
    if (!slot?.intent || typeof consume!=='function') refuse('WORKER_CONTINUATION_REQUIRED');
    this.#live(slot);
    if (slot.entered || !same(lookup,lookupOf(slot.intent))) refuse('WORKER_CONTINUATION_SCOPE_MISMATCH');
    slot.entered=true;
    const {task,request_id}=slot.intent;
    this.#ledger.beginWorkerClaim(task.owner_id,task.task_id,request_id);
    slot.consuming=true;
    try { return await consume(structuredClone(admissionOf(slot.intent))); }
    catch (error) { this.#unknown(slot);throw error; }
    finally { slot.consuming=false; }
  }
  async dispatchCommitted(admission,claim) {
    const slot=this.#slots.get(admission?.request_uuid);
    if (!slot?.intent) refuse('WORKER_CONTINUATION_REQUIRED');
    this.#live(slot);
    if (!slot.consuming || slot.dispatchEntered || !same(admission,admissionOf(slot.intent))) refuse('WORKER_CONTINUATION_SCOPE_MISMATCH');
    slot.dispatchEntered=true;
    const {task,route,request_id}=slot.intent,scope=[task.owner_id,task.task_id,request_id];
    try {
      this.#ledger.acceptWorkerClaim(...scope,claim);
      await verifyWorkerContinuation(slot.intent,()=>this.#observe(slot.snapshot),slot.signal);
      this.#live(slot);
      this.#ledger.beginWorkerHttp(...scope);
      const reply=await this.#generate({...slot.snapshot,served_version:route.served_version,signal:slot.signal});
      this.#live(slot);
      this.#ledger.recordWorkerEvidence(...scope,reply,new Date().toISOString());
      slot.reply=structuredClone(reply);slot.completed=true;
      return structuredClone(reply);
    } catch (error) {
      // Commit factual uncertainty while Bridge still holds its qualified observation.
      this.#unknown(slot);throw error;
    }
  }
}
