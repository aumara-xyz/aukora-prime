// Server-only. This module belongs in a separate non-root UID with private immutable policy and IPC.
import { randomBytes, createCipheriv, createDecipheriv } from 'node:crypto';
import { openPrivateDatabase, transaction } from './private-db.mjs';
import { hash, id, integer, refuse, InferenceRefusal } from './policy.mjs';
import { verifyPrivateDispatch } from './dispatch-policy.mjs';
import { SpendLedger } from './ledger.mjs';
import { DeepSeekHttpProvider } from './credential-http.mjs';
import { WorkerDispatchContinuation, reviewedReserveAttempt, withCommittedWorkerSettlement } from './worker-continuation.mjs';

async function boundedReply(call, milliseconds, code) {
  let timer;
  try {
    return await Promise.race([Promise.resolve().then(call),new Promise((_,reject) => {
      timer = setTimeout(() => reject(new InferenceRefusal(code)),milliseconds);
    })]);
  } finally { clearTimeout(timer); }
}

export class CredentialVault {
  #db; #withEncryptionKey;
  constructor({ path, withEncryptionKey }) {
    if (typeof withEncryptionKey !== 'function') refuse('VAULT_KEY_CUSTODY_UNAVAILABLE');
    this.#db = openPrivateDatabase(path); this.#withEncryptionKey = withEncryptionKey;
    this.#db.exec(`CREATE TABLE IF NOT EXISTS credentials(owner_id TEXT PRIMARY KEY,generation INTEGER NOT NULL,iv BLOB NOT NULL,tag BLOB NOT NULL,ciphertext BLOB NOT NULL);
      CREATE TABLE IF NOT EXISTS entry_tickets(ticket_hash TEXT PRIMARY KEY,owner_id TEXT NOT NULL,expected_generation INTEGER NOT NULL,expiry INTEGER NOT NULL,used INTEGER NOT NULL);`);
  }
  close() { this.#db.close(); }
  status(owner) {
    const row = this.#db.prepare('SELECT generation FROM credentials WHERE owner_id=?').get(owner);
    return { configured: !!row, generation: row?.generation ?? null };
  }
  createTicket(owner, expected_generation, expiry) {
    if (!id(owner) || !integer(expected_generation) || !integer(expiry,1)) refuse('INVALID_CREDENTIAL_TICKET');
    const ticket = randomBytes(32).toString('base64url');
    this.#db.prepare('INSERT INTO entry_tickets VALUES(?,?,?,?,0)').run(hash(ticket),owner,expected_generation,expiry);
    return ticket;
  }
  async submit({ owner_id, ticket, secret, now = Date.now() }) {
    if (typeof secret !== 'string' || secret.length < 8 || secret.length > 4096 || !/^[\x21-\x7e]+$/u.test(secret)
        || typeof ticket !== 'string' || !/^[A-Za-z0-9_-]{43}$/u.test(ticket)) refuse('INVALID_CREDENTIAL_ENTRY');
    // Supplied key custody must be stable across restart, held only by the worker, and separately provisioned.
    return this.#withEncryptionKey(key => {
      if (!Buffer.isBuffer(key) || key.byteLength !== 32) refuse('VAULT_KEY_CUSTODY_UNAVAILABLE');
      const iv = randomBytes(12), bytes = Buffer.from(secret);
      const cipher = createCipheriv('aes-256-gcm',key,iv);
      cipher.setAAD(Buffer.from(owner_id));
      let ciphertext;
      try { ciphertext = Buffer.concat([cipher.update(bytes),cipher.final()]); } finally { bytes.fill(0); }
      const tag = cipher.getAuthTag();
      return transaction(this.#db,() => {
        const ticketRow = this.#db.prepare('SELECT * FROM entry_tickets WHERE ticket_hash=?').get(hash(ticket));
        if (!ticketRow || ticketRow.used || ticketRow.owner_id !== owner_id || ticketRow.expiry <= now) refuse('CREDENTIAL_TICKET_INVALID');
        const prior = this.status(owner_id).generation ?? 0;
        if (prior !== ticketRow.expected_generation) refuse('CREDENTIAL_GENERATION_CHANGED');
        const generation = prior + 1;
        this.#db.prepare('INSERT INTO credentials VALUES(?,?,?,?,?) ON CONFLICT(owner_id) DO UPDATE SET generation=excluded.generation,iv=excluded.iv,tag=excluded.tag,ciphertext=excluded.ciphertext').run(owner_id,generation,iv,tag,ciphertext);
        this.#db.prepare('UPDATE entry_tickets SET used=1 WHERE ticket_hash=?').run(hash(ticket));
        return { configured: true, generation };
      });
    });
  }
  async use(owner, generation, callback) {
    const row = this.#db.prepare('SELECT * FROM credentials WHERE owner_id=?').get(owner);
    if (!row || row.generation !== generation) refuse('CREDENTIAL_GENERATION_CHANGED');
    return this.#withEncryptionKey(async key => {
      if (this.status(owner).generation !== generation) refuse('CREDENTIAL_GENERATION_CHANGED');
      const decipher = createDecipheriv('aes-256-gcm',key,row.iv);
      decipher.setAAD(Buffer.from(owner)); decipher.setAuthTag(row.tag);
      const bytes = Buffer.concat([decipher.update(row.ciphertext),decipher.final()]);
      try { return await callback(bytes.toString('utf8')); } finally { bytes.fill(0); }
    });
  }
}

export function assertSeparatedCredentialProcess(application_uid) {
  if (process.platform !== 'linux' || typeof process.getuid !== 'function' || !integer(application_uid,1)
      || process.getuid() === 0 || process.getuid() === application_uid) refuse('SEPARATE_CREDENTIAL_UID_REQUIRED');
}

/** No server is started here. H must supply qualified private transport, C callbacks and approved UID/custody. */
export class SeparatedCredentialService {
  #vault; #ledger; #options; #http; #continuation; #credentialEntries = new Set();
  constructor(options) {
    assertSeparatedCredentialProcess(options.application_uid);
    if (![options.authenticateOwner,options.approveCredentialEntry,options.getReviewedApproval,options.withDispatch,
      options.getQualifiedRoute,options.getAuthorizedTask,options.getOwnerIdentity,
      options.settleInference,options.reconcileInferenceSettlement].every(v => typeof v === 'function')) refuse('CREDENTIAL_AUTHORITY_JOIN_UNAVAILABLE');
    this.#options = options;
    if (!options.total_budget) refuse('TOTAL_BUDGET_REQUIRED');
    this.#ledger = new SpendLedger(options.spend_path,{ total_budget:options.total_budget });
    try { this.#vault = new CredentialVault(options); }
    catch (error) { this.#ledger.close(); throw error; }
    this.#http = new DeepSeekHttpProvider({ useCredential: (owner,generation,fn) => this.#vault.use(owner,generation,fn) });
    this.#continuation = new WorkerDispatchContinuation({ledger:this.#ledger,observe:request=>this.#verify(request),
      generate:request=>this.#http.generate(request),withDispatch:input=>this.#options.withDispatch(input),
      retrySettlement:(owner,task,uuid)=>this.retrySettlement(owner,task,uuid)});
  }
  close() {
    if (this.#continuation.activeCount || this.#credentialEntries.size) refuse('WORKER_DISPATCH_ACTIVE');
    this.#ledger.close(); this.#vault.close();
  }
  async createHandoff({ owner_id, expected_generation, approval_proof, context }) {
    const actor = await this.#options.authenticateOwner(context);
    if (actor?.owner_id !== owner_id || !integer(expected_generation)) refuse('OWNER_AUTH_REQUIRED');
    const approved = await this.#options.approveCredentialEntry({ owner_id, provider: 'externalDeepSeek',
      expected_generation, approval_proof, context });
    if (approved?.owner_id !== owner_id || approved.provider !== 'externalDeepSeek'
        || approved.expected_generation !== expected_generation || !id(approved.operation_id)) refuse('OWNER_APPROVAL_REQUIRED');
    const expiry = Date.now() + 60000, ticket = this.#vault.createTicket(owner_id,expected_generation,expiry);
    return { provider: 'externalDeepSeek', method: 'POST', path: '/api/prime/inference/credential-entry',
      ticket, expires_at: new Date(expiry).toISOString() };
  }
  async submitEntry(context, { ticket, secret }) {
    const actor = await this.#options.authenticateOwner(context);
    if (!id(actor?.owner_id)) refuse('OWNER_AUTH_REQUIRED');
    if (this.#continuation.hasOwner(actor.owner_id) || this.#credentialEntries.has(actor.owner_id)) refuse('CREDENTIAL_DISPATCH_ACTIVE');
    this.#credentialEntries.add(actor.owner_id);
    try { return await this.#vault.submit({ owner_id: actor.owner_id, ticket, secret }); }
    finally { this.#credentialEntries.delete(actor.owner_id); }
  }
  async status(owner_id, context) {
    const actor = await this.#options.authenticateOwner(context);
    if (actor?.owner_id !== owner_id) refuse('OWNER_AUTH_REQUIRED');
    return this.#vault.status(owner_id);
  }
  /** Private Bridge reserve adapter. The durable attempt survives failed/lost C reserve replies. */
  async getReviewedApproval(binding) {
    const snapshot=structuredClone(binding);
    const [route,task,owner]=await Promise.all([
      this.#options.getQualifiedRoute(snapshot.owner_id),
      this.#options.getAuthorizedTask(snapshot.owner_id,snapshot.task_id),
      this.#options.getOwnerIdentity(snapshot.owner_id),
    ]);
    const credential=this.#vault.status(snapshot.owner_id);
    if (!credential.configured || credential.generation!==route.credential_generation) refuse('CREDENTIAL_GENERATION_CHANGED');
    if (owner?.owner_id!==snapshot.owner_id || task.owner_id!==snapshot.owner_id || task.task_id!==snapshot.task_id)
      refuse('PRIVATE_DISPATCH_SCOPE_MISMATCH');
    this.#ledger.register(task,route);
    return reviewedReserveAttempt(this.#ledger,snapshot,async candidate=>{
      const reviewed=await this.#options.getReviewedApproval(candidate);
      if (reviewed?.operation?.target_identity?.owner_subject!==owner.subject) refuse('PRIVATE_DISPATCH_SCOPE_MISMATCH');
      return reviewed;
    });
  }
  async dispatch(request, options = {}) {
    if (this.#credentialEntries.has(request?.owner_id)) refuse('CREDENTIAL_DISPATCH_ACTIVE');
    return this.#continuation.dispatch(request,options);
  }
  withCommittedIntent(lookup,consume) { return this.#continuation.withCommittedIntent(lookup,consume); }
  dispatchCommitted(admission,claim) { return this.#continuation.dispatchCommitted(admission,claim); }
  withCommittedSettlement(method,lookup,consume) { return withCommittedWorkerSettlement(this.#ledger,method,lookup,consume); }
  async #verify(request) {
    const [route,task,owner] = await Promise.all([
      this.#options.getQualifiedRoute(request.owner_id),
      this.#options.getAuthorizedTask(request.owner_id,request.task_id),
      this.#options.getOwnerIdentity(request.owner_id),
    ]);
    const credential = this.#vault.status(request.owner_id);
    if (!credential.configured) refuse('CREDENTIAL_SERVICE_UNAVAILABLE');
    return verifyPrivateDispatch(request,route,task,{owner,total_budget:this.#ledger.storedTotalBudget(),
      credential_generation:credential.generation});
  }
  /** Trusted host read. No model text, key, proof or raw exception appears in this status. */
  settlementStatus(owner, task, uuid) {
    const {phase,claim_reply} = this.#ledger.workerIntent(owner,task,uuid);
    const row = this.#ledger.get(owner,task,uuid), pending = this.#ledger.pendingWorkerSettlement(owner,task,uuid);
    return {request_id:uuid,phase,outcome:row.status,claim_confirmed:claim_reply !== null,
      receipt_digest:row.result?.receipt_digest ?? null,settlement_pending:!!pending || phase !== 'outcome_recorded'};
  }
  pendingRequests(owner, options) { return this.#ledger.pendingWorkerRequests(owner,options); }
  /** Retry factual delivery only; never reserve, claim, recover provider text or issue HTTP. */
  async retrySettlement(owner, task, uuid) {
    const pending = this.#ledger.pendingWorkerSettlement(owner,task,uuid);
    if (pending) {
      try {
        const send = pending.method === 'settleInference' ? this.#options.settleInference : this.#options.reconcileInferenceSettlement;
        const {intent} = this.#ledger.workerIntent(owner,task,uuid);
        // A hung acknowledgement cannot indefinitely withhold the committed provider result.
        const reply = await boundedReply(() => send(structuredClone(pending.payload)),
          Math.min(1000,intent.route.max_request_ms),'SETTLEMENT_DELIVERY_PENDING');
        this.#ledger.acknowledgeWorkerSettlement(owner,task,uuid,pending.payload.receipt_digest,reply);
      } catch { /* Keep the exact pending evidence and original observed_at for later delivery. */ }
    }
    return this.settlementStatus(owner,task,uuid);
  }
  /** Explicit quiescent-worker recovery; no persisted phase is ever resumed as a claim or HTTP call. */
  async recoverUnknown(context, {owner_id,task_id,request_id}) {
    const actor = await this.#options.authenticateOwner(context);
    if (actor?.owner_id !== owner_id) refuse('OWNER_AUTH_REQUIRED');
    if (this.#continuation.hasRequest(request_id)) refuse('WORKER_DISPATCH_ACTIVE');
    const {phase} = this.#ledger.workerIntent(owner_id,task_id,request_id);
    if (phase !== 'outcome_recorded') this.#ledger.recordWorkerEvidence(owner_id,task_id,request_id,null,new Date().toISOString());
    return this.retrySettlement(owner_id,task_id,request_id);
  }
  /** Evidence is loaded by trusted worker policy; app-provided token/cost numbers cannot release holds. */
  async reconcileEvidence(context, {owner_id,task_id,request_id,evidence_id}) {
    const actor = await this.#options.authenticateOwner(context);
    if (actor?.owner_id !== owner_id || !id(evidence_id)) refuse('OWNER_AUTH_REQUIRED');
    if (typeof this.#options.getReconciliationEvidence !== 'function') refuse('WORKER_RECONCILIATION_UNAVAILABLE');
    if (this.#continuation.hasRequest(request_id)) refuse('WORKER_DISPATCH_ACTIVE');
    const {intent} = this.#ledger.workerIntent(owner_id,task_id,request_id);
    const reply = await this.#options.getReconciliationEvidence({evidence_id,intent:structuredClone(intent)});
    if (this.#continuation.hasRequest(request_id)) refuse('WORKER_DISPATCH_ACTIVE');
    this.#ledger.recordWorkerEvidence(owner_id,task_id,request_id,reply,new Date().toISOString(),{reconciliation:true});
    return this.retrySettlement(owner_id,task_id,request_id);
  }
  totalUsage(owner_id, budget_id) { return this.#ledger.totalUsage(owner_id,budget_id); }
}
