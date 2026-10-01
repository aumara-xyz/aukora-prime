// Server-only. This module belongs in a separate non-root UID with private immutable policy and IPC.
import { randomBytes, createCipheriv, createDecipheriv } from 'node:crypto';
import { openPrivateDatabase, transaction } from './private-db.mjs';
import { hash, id, integer, refuse } from './policy.mjs';
import { verifyPrivateDispatch } from './dispatch-policy.mjs';
import { SpendLedger } from './ledger.mjs';
import { DeepSeekHttpProvider } from './credential-http.mjs';

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
  #vault; #ledger; #options; #http;
  constructor(options) {
    assertSeparatedCredentialProcess(options.application_uid);
    if (![options.authenticateOwner,options.approveCredentialEntry,options.verifyDispatchAdmission,
      options.getQualifiedRoute,options.getAuthorizedTask].every(v => typeof v === 'function')) refuse('CREDENTIAL_AUTHORITY_JOIN_UNAVAILABLE');
    this.#options = options;
    this.#vault = new CredentialVault(options);
    this.#ledger = new SpendLedger(options.spend_path);
    this.#http = new DeepSeekHttpProvider({ useCredential: (owner,generation,fn) => this.#vault.use(owner,generation,fn) });
  }
  close() { this.#ledger.close(); this.#vault.close(); }
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
    return this.#vault.submit({ owner_id: actor.owner_id, ticket, secret });
  }
  async status(owner_id, context) {
    const actor = await this.#options.authenticateOwner(context);
    if (actor?.owner_id !== owner_id) refuse('OWNER_AUTH_REQUIRED');
    return this.#vault.status(owner_id);
  }
  async dispatch(request, { signal } = {}) {
    if (signal?.aborted) refuse('CANCELLED_BEFORE_DISPATCH');
    const { route, task, input_bound: input, token_reservation: tokens, cost_reservation: cost } = verifyPrivateDispatch(request,
      await this.#options.getQualifiedRoute(request.owner_id),
      await this.#options.getAuthorizedTask(request.owner_id,request.task_id));
    // The C-backed callback must verify and durably claim this exact admission outside the app UID.
    const verified = await this.#options.verifyDispatchAdmission(structuredClone(request));
    if (verified !== true) refuse('DISPATCH_APPROVAL_REQUIRED');
    this.#ledger.register(task,route);
    this.#ledger.reserve(task,request.request_uuid,{ binding_hash: request.binding_hash, body_hash: request.body_sha256,
      token_reservation: tokens, cost_reservation: cost },() => ({ request_uuid: request.request_uuid, body_sha256: request.body_sha256 }));
    this.#ledger.transition(task.owner_id,task.task_id,request.request_uuid,'reserved','dispatched');
    // Independent service timeout; app cancellation does not remove the persistent request fence.
    const timeout = AbortSignal.timeout(route.max_request_ms);
    const combined = signal ? AbortSignal.any([signal,timeout]) : timeout;
    try {
      const reply = await this.#http.generate({ ...request, served_version: route.served_version, signal: combined });
      if (reply.input_tokens > input || reply.output_tokens > request.body.max_tokens) refuse('INVALID_PROVIDER_USAGE');
      this.#ledger.settle(task.owner_id,task.task_id,request.request_uuid,reply.input_tokens + reply.output_tokens,
        reply.input_tokens * route.input_microusd_per_token + reply.output_tokens * route.output_microusd_per_token,
        { outcome: 'completed', request_uuid: request.request_uuid });
      return reply;
    } catch {
      this.#ledger.transition(task.owner_id,task.task_id,request.request_uuid,'dispatched','outcome_unknown');
      refuse('PROVIDER_OUTCOME_UNKNOWN');
    }
  }
}
