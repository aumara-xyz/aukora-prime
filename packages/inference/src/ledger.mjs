import { canonical, refuse, validateTask, validateRoute, integer } from './policy.mjs';
import { openPrivateDatabase } from './private-db.mjs';
import { normalizeTotalBudget, totalBudgetBinding } from './budget-binding.mjs';
import { canonicalJson } from '../../contracts/src/json.mjs';
import { createWorkerEvidence, validateWorkerClaimReply, validateWorkerSettlementReply } from './worker-evidence.mjs';
import { reserveAttemptRecord } from './reserve-attempt-binding.mjs';

/** Host-owned durable ledger. The model never receives this object or database credentials. */
export class SpendLedger {
  constructor(path, { total_budget } = {}) {
    const descriptor = total_budget === undefined ? undefined : normalizeTotalBudget(total_budget);
    this.db = openPrivateDatabase(path);
    this.db.exec(`PRAGMA busy_timeout=5000; PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;
      CREATE TABLE IF NOT EXISTS tasks (owner_id TEXT, task_id TEXT, spec TEXT NOT NULL, route TEXT NOT NULL, PRIMARY KEY(owner_id,task_id));
      CREATE TABLE IF NOT EXISTS requests (
        request_uuid TEXT PRIMARY KEY, owner_id TEXT NOT NULL, task_id TEXT NOT NULL, conversation_id TEXT NOT NULL,
        binding_hash TEXT NOT NULL, body_hash TEXT NOT NULL, status TEXT NOT NULL,
        reserved_tokens INTEGER NOT NULL, reserved_cost INTEGER NOT NULL, charged_tokens INTEGER NOT NULL,
        charged_cost INTEGER NOT NULL, receipt TEXT NOT NULL, result TEXT, reconciliation TEXT);
      CREATE INDEX IF NOT EXISTS request_task ON requests(owner_id,task_id);
      CREATE TABLE IF NOT EXISTS total_budget (singleton INTEGER PRIMARY KEY CHECK(singleton=1), spec TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS worker_intents (
        request_uuid TEXT PRIMARY KEY, intent TEXT NOT NULL, phase TEXT NOT NULL, claim_reply TEXT);
      CREATE TABLE IF NOT EXISTS worker_evidence (
        request_uuid TEXT NOT NULL, sequence INTEGER NOT NULL, receipt_digest TEXT NOT NULL UNIQUE,
        payload TEXT NOT NULL, method TEXT NOT NULL, delivery TEXT NOT NULL, acknowledgement TEXT,
        PRIMARY KEY(request_uuid,sequence));
      CREATE TABLE IF NOT EXISTS reserve_attempts (
        request_uuid TEXT PRIMARY KEY COLLATE NOCASE, operation_id TEXT NOT NULL UNIQUE,
        owner_id TEXT NOT NULL, task_id TEXT NOT NULL, record TEXT NOT NULL);`);
    if (descriptor) {
      try {
        this.transaction(() => {
          const row = this.db.prepare('SELECT spec FROM total_budget WHERE singleton=1').get();
          if (row && row.spec !== canonical(descriptor)) refuse('TOTAL_BUDGET_CONFIG_CHANGED');
          // A new descriptor also covers earlier held/completed requests; it cannot reset accounting.
          if (this.db.prepare('SELECT owner_id FROM tasks WHERE owner_id<>? LIMIT 1').get(descriptor.owner_id)) refuse('TOTAL_BUDGET_SCOPE_MISMATCH');
          this.db.prepare('INSERT OR IGNORE INTO total_budget VALUES(1,?)').run(canonical(descriptor));
        });
      } catch (error) { this.db.close(); throw error; }
    }
  }
  close() { this.db.close(); }
  transaction(fn) {
    this.db.exec('BEGIN IMMEDIATE');
    try { const result = fn(); this.db.exec('COMMIT'); return result; }
    catch (error) { this.db.exec('ROLLBACK'); throw error; }
  }
  register(task, route) {
    return this.transaction(() => this.#register(task,route));
  }
  #register(task, route) {
    const spec = canonical(validateTask(task));
    const routeSpec = canonical(validateRoute(route));
      const budget = this.storedTotalBudget();
      if (budget || route.mode === 'production' || route.total_budget_id !== undefined)
        this.requireTotalBudget(task.owner_id,route.total_budget_id ?? budget?.budget_id);
      const existing = this.db.prepare('SELECT spec,route FROM tasks WHERE owner_id=? AND task_id=?').get(task.owner_id,task.task_id);
      if (existing && (existing.spec !== spec || existing.route !== routeSpec)) refuse('TASK_CONFIG_CHANGED');
      this.db.prepare('INSERT OR IGNORE INTO tasks VALUES (?,?,?,?)').run(task.owner_id,task.task_id,spec,routeSpec);
  }
  task(owner, task) {
    const row = this.db.prepare('SELECT spec FROM tasks WHERE owner_id=? AND task_id=?').get(owner,task);
    if (!row) refuse('TASK_NOT_REGISTERED');
    return JSON.parse(row.spec);
  }
  route(owner, task) {
    const row = this.db.prepare('SELECT route FROM tasks WHERE owner_id=? AND task_id=?').get(owner,task);
    if (!row) refuse('TASK_NOT_REGISTERED');
    return JSON.parse(row.route);
  }
  usage(owner, task) {
    return this.db.prepare(`SELECT COUNT(*) AS requests, COALESCE(SUM(charged_tokens),0) AS tokens,
      COALESCE(SUM(charged_cost),0) AS cost_microusd FROM requests WHERE owner_id=? AND task_id=?`).get(owner,task);
  }
  storedTotalBudget() {
    const row = this.db.prepare('SELECT spec FROM total_budget WHERE singleton=1').get();
    return row ? JSON.parse(row.spec) : undefined;
  }
  totalBudgetBinding(owner, budget_id) {
    const descriptor = this.storedTotalBudget();
    if (!descriptor) refuse('TOTAL_BUDGET_REQUIRED');
    if (descriptor.owner_id !== owner || descriptor.budget_id !== budget_id) refuse('TOTAL_BUDGET_SCOPE_MISMATCH');
    return totalBudgetBinding(descriptor);
  }
  requireTotalBudget(owner, budget_id) {
    const budget = this.storedTotalBudget();
    if (!budget) refuse('TOTAL_BUDGET_REQUIRED');
    if (budget.owner_id !== owner || budget.budget_id !== budget_id) refuse('TOTAL_BUDGET_SCOPE_MISMATCH');
    const [whole,fraction] = budget.ceiling.amount.split('.');
    return { ...budget,ceiling_microusd:Number(whole)*1000000+Number(fraction) };
  }
  totalUsage(owner, budget_id) {
    const budget = this.requireTotalBudget(owner,budget_id);
    const usage = this.db.prepare(`SELECT COUNT(*) AS requests, COALESCE(SUM(charged_tokens),0) AS tokens,
      COALESCE(SUM(charged_cost),0) AS cost_microusd FROM requests WHERE owner_id=?`).get(owner);
    return { budget_id:budget.budget_id,ceiling_microusd:budget.ceiling_microusd,...usage,
      remaining_microusd:Math.max(0,budget.ceiling_microusd-usage.cost_microusd) };
  }
  get(owner, task, uuid) {
    const row = this.db.prepare('SELECT * FROM requests WHERE owner_id=? AND task_id=? AND request_uuid=?').get(owner,task,uuid);
    if (!row) return undefined;
    return { ...row, receipt: JSON.parse(row.receipt), result: row.result ? JSON.parse(row.result) : undefined };
  }
  /** Commit before returning a reviewed approval to C reserve. Even an identical retry refuses. */
  beginReserveAttempt(binding, operation) {
    let input;
    try { input = JSON.parse(canonicalJson({binding,operation})); }
    catch { refuse('INVALID_RESERVE_ATTEMPT'); }
    return this.transaction(() => {
      const b = input.binding, op = input.operation;
      if (!b || typeof b.request_uuid !== 'string' || typeof b.owner_id !== 'string' || typeof b.task_id !== 'string'
          || !op || typeof op.operation_id !== 'string') refuse('INVALID_RESERVE_ATTEMPT');
      // UUID is global, including case variants of its hexadecimal spelling. Operation IDs are exact C identities.
      if (this.db.prepare('SELECT request_uuid FROM reserve_attempts WHERE request_uuid=? OR operation_id=? LIMIT 1').get(b.request_uuid,op.operation_id)
          || this.db.prepare('SELECT request_uuid FROM requests WHERE request_uuid=? COLLATE NOCASE LIMIT 1').get(b.request_uuid)
          || this.db.prepare("SELECT request_uuid FROM worker_intents WHERE json_extract(intent,'$.operation.operation_id')=? LIMIT 1").get(op.operation_id)) {
        refuse('RESERVE_ATTEMPT_RETAINED');
      }
      const record = reserveAttemptRecord(b,op,this.task(b.owner_id,b.task_id),this.route(b.owner_id,b.task_id),this.storedTotalBudget());
      this.db.prepare('INSERT INTO reserve_attempts VALUES(?,?,?,?,?)')
        .run(b.request_uuid,op.operation_id,b.owner_id,b.task_id,canonicalJson(record));
      return record;
    });
  }
  /** Content-free inspection only. Reading a retained attempt never permits reserve to run again. */
  reserveAttempt(owner, task, uuid) {
    const row = this.db.prepare('SELECT record FROM reserve_attempts WHERE owner_id=? AND task_id=? AND request_uuid=?').get(owner,task,uuid);
    return row ? JSON.parse(row.record) : undefined;
  }
  reserve(task, uuid, prepared, record) {
    return this.transaction(() => this.#reserve(task,uuid,prepared,record));
  }
  #reserve(task, uuid, prepared, record) {
      // UUID lookup is global so cross-owner UUID reuse cannot dispatch twice or disclose the other request.
      const duplicate = this.db.prepare('SELECT request_uuid FROM requests WHERE request_uuid=?').get(uuid);
      if (duplicate) refuse('REQUEST_ALREADY_RESERVED');
      const stored = this.task(task.owner_id,task.task_id);
      if (canonical(stored) !== canonical(task)) refuse('TASK_CONFIG_CHANGED');
      if (!integer(prepared.token_reservation,1) || !integer(prepared.cost_reservation)) refuse('INVALID_USAGE');
      const used = this.usage(task.owner_id,task.task_id);
      if (used.requests >= task.max_requests) refuse('REQUEST_CAP');
      if (used.tokens + prepared.token_reservation > task.max_tokens) refuse('TASK_TOKEN_CAP');
      if (used.cost_microusd + prepared.cost_reservation > task.spend_cap_microusd) refuse('SPEND_CAP');
      const budget = this.storedTotalBudget(), route = this.route(task.owner_id,task.task_id);
      if (budget || route.mode === 'production' || route.total_budget_id !== undefined) {
        const total = this.totalUsage(task.owner_id,route.total_budget_id ?? budget?.budget_id);
        if (prepared.cost_reservation > total.remaining_microusd) refuse('TOTAL_SPEND_CAP');
      }
      const receipt = record(); // fsynced owned donor append before commit; failure refuses dispatch.
      this.db.prepare('INSERT INTO requests VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)').run(uuid,task.owner_id,task.task_id,
        task.conversation_id,prepared.binding_hash,prepared.body_hash,'reserved',prepared.token_reservation,
        prepared.cost_reservation,prepared.token_reservation,prepared.cost_reservation,JSON.stringify(receipt),null,null);
      return receipt;
  }
  transition(owner, task, uuid, from, to) {
    if (this.db.prepare('SELECT request_uuid FROM worker_intents WHERE request_uuid=?').get(uuid)) refuse('WORKER_EVIDENCE_REQUIRED');
    const result = this.db.prepare('UPDATE requests SET status=? WHERE owner_id=? AND task_id=? AND request_uuid=? AND status=?').run(to,owner,task,uuid,from);
    if (result.changes !== 1) refuse('REQUEST_STATE_CONFLICT');
  }
  settle(owner, task, uuid, tokens, cost, result, reconciliation = null) {
    if (!integer(tokens) || !integer(cost)) refuse('INVALID_USAGE');
    return this.transaction(() => {
      if (this.db.prepare('SELECT request_uuid FROM worker_intents WHERE request_uuid=?').get(uuid)) refuse('WORKER_EVIDENCE_REQUIRED');
      const row = this.get(owner,task,uuid);
      if (!row || !['reserved','dispatched','outcome_unknown'].includes(row.status)) refuse('REQUEST_STATE_CONFLICT');
      this.db.prepare(`UPDATE requests SET status='completed', charged_tokens=?, charged_cost=?, result=?, reconciliation=?
        WHERE owner_id=? AND task_id=? AND request_uuid=?`).run(tokens,cost,JSON.stringify(result),reconciliation,owner,task,uuid);
    });
  }
  /** Operator reconciliation requires evidence; unknown spend remains held until this explicit host call. */
  reconcile(owner, task, uuid, { tokens, cost_microusd, evidence_id }) {
    if (typeof evidence_id !== 'string' || !evidence_id.trim() || evidence_id.length > 256) refuse('RECONCILIATION_EVIDENCE_REQUIRED');
    const row = this.get(owner,task,uuid);
    if (!row || !['reserved','dispatched','outcome_unknown'].includes(row.status)) refuse('REQUEST_STATE_CONFLICT');
    this.settle(owner,task,uuid,tokens,cost_microusd,{ outcome: 'reconciled', request_uuid: uuid }, evidence_id);
  }

  /** Private worker only. Intent, original policy and all allowance are committed in ONE transaction. */
  reserveWorkerIntent(intent) {
    const snapshot = canonicalJson(intent), { task,route,binding,request_id } = intent;
    return this.transaction(() => {
      if (this.db.prepare('SELECT request_uuid FROM worker_intents WHERE request_uuid=?').get(request_id)) refuse('REQUEST_ALREADY_RESERVED');
      if (canonicalJson(this.storedTotalBudget()) !== canonicalJson(intent.total_budget)) refuse('TOTAL_BUDGET_CONFIG_CHANGED');
      this.#register(task,route);
      this.#reserve(task,request_id,{binding_hash:binding.binding_hash,body_hash:binding.body_sha256,
        token_reservation:binding.reserved_tokens,cost_reservation:binding.reserved_cost_microusd},
        () => ({request_uuid:request_id,body_sha256:binding.body_sha256}));
      this.db.prepare('INSERT INTO worker_intents VALUES(?,?,?,NULL)').run(request_id,snapshot,'intent_committed');
      return structuredClone(intent);
    });
  }
  workerIntent(owner, task, uuid) {
    const request = this.get(owner,task,uuid);
    const row = request && this.db.prepare('SELECT * FROM worker_intents WHERE request_uuid=?').get(uuid);
    if (!row) refuse('WORKER_INTENT_REQUIRED');
    return {intent:JSON.parse(row.intent),phase:row.phase,claim_reply:row.claim_reply ? JSON.parse(row.claim_reply) : null};
  }
  beginWorkerClaim(owner, task, uuid) {
    return this.transaction(() => {
      this.workerIntent(owner,task,uuid);
      const changed = this.db.prepare("UPDATE worker_intents SET phase='claim_started' WHERE request_uuid=? AND phase='intent_committed'").run(uuid);
      if (changed.changes !== 1) refuse('WORKER_PHASE_CONFLICT');
    });
  }
  acceptWorkerClaim(owner, task, uuid, reply) {
    return this.transaction(() => {
      const {intent} = this.workerIntent(owner,task,uuid);
      const verified = validateWorkerClaimReply(intent,reply);
      const changed = this.db.prepare("UPDATE worker_intents SET phase='claimed',claim_reply=? WHERE request_uuid=? AND phase='claim_started'")
        .run(canonicalJson(verified),uuid);
      if (changed.changes !== 1) refuse('WORKER_PHASE_CONFLICT');
    });
  }
  beginWorkerHttp(owner, task, uuid) {
    return this.transaction(() => {
      this.workerIntent(owner,task,uuid);
      const changed = this.db.prepare("UPDATE worker_intents SET phase='http_started' WHERE request_uuid=? AND phase='claimed'").run(uuid);
      if (changed.changes !== 1) refuse('WORKER_PHASE_CONFLICT');
      const request = this.db.prepare("UPDATE requests SET status='dispatched' WHERE request_uuid=? AND status='reserved'").run(uuid);
      if (request.changes !== 1) refuse('REQUEST_STATE_CONFLICT');
    });
  }
  /** reply is a validated provider result or null for uncertainty. Never stores its plaintext text. */
  recordWorkerEvidence(owner, task, uuid, reply, observed_at, { reconciliation = false } = {}) {
    return this.transaction(() => {
      const {intent,phase} = this.workerIntent(owner,task,uuid);
      const prior = this.db.prepare('SELECT * FROM worker_evidence WHERE request_uuid=? ORDER BY sequence DESC LIMIT 1').get(uuid);
      if (reconciliation) {
        if (phase !== 'outcome_recorded' || !prior || prior.delivery !== 'acknowledged'
            || JSON.parse(prior.payload).receipt.outcome !== 'outcome_unknown' || reply === null) refuse('WORKER_RECONCILIATION_REQUIRED');
      } else if (prior || !['intent_committed','claim_started','claimed','http_started'].includes(phase)
          || (reply !== null && phase !== 'http_started')) refuse('WORKER_PHASE_CONFLICT');
      const {receipt,payload} = createWorkerEvidence(intent,reply,observed_at);
      const sequence = prior ? prior.sequence + 1 : 1;
      const method = reconciliation ? 'reconcileInferenceSettlement' : 'settleInference';
      const tokens = receipt.usage ? receipt.usage.input_tokens + receipt.usage.output_tokens : intent.binding.reserved_tokens;
      const cost = receipt.usage ? receipt.usage.cost_microusd : intent.binding.reserved_cost_microusd;
      // Evidence, factual accounting and the delivery obligation are all durable before C is called.
      const changed = this.db.prepare(`UPDATE requests SET status=?,charged_tokens=?,charged_cost=?,result=?,reconciliation=?
        WHERE request_uuid=? AND status IN ('reserved','dispatched','outcome_unknown')`)
        .run(receipt.outcome,tokens,cost,canonicalJson({outcome:receipt.outcome,request_uuid:uuid,receipt_digest:payload.receipt_digest}),
          reconciliation ? payload.receipt_digest : null,uuid);
      if (changed.changes !== 1) refuse('REQUEST_STATE_CONFLICT');
      this.db.prepare('INSERT INTO worker_evidence VALUES(?,?,?,?,?,?,NULL)')
        .run(uuid,sequence,payload.receipt_digest,canonicalJson(payload),method,'pending');
      this.db.prepare("UPDATE worker_intents SET phase='outcome_recorded' WHERE request_uuid=?").run(uuid);
      return {sequence,method,payload};
    });
  }
  pendingWorkerSettlement(owner, task, uuid) {
    this.workerIntent(owner,task,uuid);
    const row = this.db.prepare("SELECT * FROM worker_evidence WHERE request_uuid=? AND delivery='pending' ORDER BY sequence LIMIT 1").get(uuid);
    return row ? {sequence:row.sequence,method:row.method,payload:JSON.parse(row.payload)} : null;
  }
  pendingWorkerRequests(owner, {after_request_id = '',limit = 100} = {}) {
    if (typeof owner !== 'string' || typeof after_request_id !== 'string' || !integer(limit,1) || limit > 100) refuse('INVALID_WORKER_QUERY');
    return this.db.prepare(`SELECT r.owner_id,r.task_id,r.request_uuid AS request_id,w.phase,r.status AS outcome
      FROM requests r JOIN worker_intents w ON w.request_uuid=r.request_uuid
      WHERE r.owner_id=? AND r.request_uuid>? AND (w.phase<>'outcome_recorded' OR r.status='outcome_unknown' OR
        EXISTS(SELECT 1 FROM worker_evidence e WHERE e.request_uuid=r.request_uuid AND e.delivery='pending'))
      ORDER BY r.request_uuid LIMIT ?`).all(owner,after_request_id,limit);
  }
  acknowledgeWorkerSettlement(owner, task, uuid, receipt_digest, reply) {
    return this.transaction(() => {
      this.workerIntent(owner,task,uuid);
      const row = this.db.prepare('SELECT * FROM worker_evidence WHERE request_uuid=? AND receipt_digest=?').get(uuid,receipt_digest);
      if (!row) refuse('WORKER_EVIDENCE_REQUIRED');
      const verified = validateWorkerSettlementReply(JSON.parse(row.payload),reply);
      if (row.delivery === 'acknowledged') return; // A delayed duplicate cannot acknowledge a newer receipt.
      const earlier = this.db.prepare("SELECT sequence FROM worker_evidence WHERE request_uuid=? AND sequence<? AND delivery<>'acknowledged' LIMIT 1").get(uuid,row.sequence);
      if (earlier) refuse('WORKER_SETTLEMENT_ORDER');
      const changed = this.db.prepare("UPDATE worker_evidence SET delivery='acknowledged',acknowledgement=? WHERE request_uuid=? AND receipt_digest=? AND delivery='pending'")
        .run(canonicalJson(verified),uuid,receipt_digest);
      if (changed.changes !== 1) refuse('WORKER_PHASE_CONFLICT');
    });
  }
}
