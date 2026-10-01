import { DatabaseSync } from 'node:sqlite';
import { mkdirSync, lstatSync, openSync, closeSync, fsyncSync } from 'node:fs';
import { dirname } from 'node:path';
import { canonical, refuse, validateTask, validateRoute, integer } from './policy.mjs';

/** Host-owned durable ledger. The model never receives this object or database credentials. */
export class SpendLedger {
  constructor(path) {
    if (typeof path !== 'string' || !path.startsWith('/') || path === ':memory:') refuse('DURABLE_STORE_REQUIRED');
    mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
    const directory = lstatSync(dirname(path));
    if (!directory.isDirectory() || (directory.mode & 0o077)) refuse('DURABLE_STORE_NOT_PRIVATE');
    try { const fd = openSync(path,'wx',0o600); fsyncSync(fd); closeSync(fd); }
    catch (error) { if (error.code !== 'EEXIST') throw error; }
    const file = lstatSync(path);
    if (!file.isFile() || (file.mode & 0o077)) refuse('DURABLE_STORE_NOT_PRIVATE');
    const directoryFd = openSync(dirname(path),'r');
    try { fsyncSync(directoryFd); } finally { closeSync(directoryFd); }
    this.db = new DatabaseSync(path);
    this.db.exec(`PRAGMA busy_timeout=5000; PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;
      CREATE TABLE IF NOT EXISTS tasks (owner_id TEXT, task_id TEXT, spec TEXT NOT NULL, route TEXT NOT NULL, PRIMARY KEY(owner_id,task_id));
      CREATE TABLE IF NOT EXISTS requests (
        request_uuid TEXT PRIMARY KEY, owner_id TEXT NOT NULL, task_id TEXT NOT NULL, conversation_id TEXT NOT NULL,
        binding_hash TEXT NOT NULL, body_hash TEXT NOT NULL, status TEXT NOT NULL,
        reserved_tokens INTEGER NOT NULL, reserved_cost INTEGER NOT NULL, charged_tokens INTEGER NOT NULL,
        charged_cost INTEGER NOT NULL, receipt TEXT NOT NULL, result TEXT, reconciliation TEXT);
      CREATE INDEX IF NOT EXISTS request_task ON requests(owner_id,task_id);`);
  }
  close() { this.db.close(); }
  transaction(fn) {
    this.db.exec('BEGIN IMMEDIATE');
    try { const result = fn(); this.db.exec('COMMIT'); return result; }
    catch (error) { this.db.exec('ROLLBACK'); throw error; }
  }
  register(task, route) {
    const spec = canonical(validateTask(task));
    const routeSpec = canonical(validateRoute(route));
    return this.transaction(() => {
      const existing = this.db.prepare('SELECT spec,route FROM tasks WHERE owner_id=? AND task_id=?').get(task.owner_id,task.task_id);
      if (existing && (existing.spec !== spec || existing.route !== routeSpec)) refuse('TASK_CONFIG_CHANGED');
      this.db.prepare('INSERT OR IGNORE INTO tasks VALUES (?,?,?,?)').run(task.owner_id,task.task_id,spec,routeSpec);
    });
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
  get(owner, task, uuid) {
    const row = this.db.prepare('SELECT * FROM requests WHERE owner_id=? AND task_id=? AND request_uuid=?').get(owner,task,uuid);
    if (!row) return undefined;
    return { ...row, receipt: JSON.parse(row.receipt), result: row.result ? JSON.parse(row.result) : undefined };
  }
  reserve(task, uuid, prepared, record) {
    return this.transaction(() => {
      // UUID lookup is global so cross-owner UUID reuse cannot dispatch twice or disclose the other request.
      const duplicate = this.db.prepare('SELECT request_uuid FROM requests WHERE request_uuid=?').get(uuid);
      if (duplicate) refuse('REQUEST_ALREADY_RESERVED');
      const stored = this.task(task.owner_id,task.task_id);
      if (canonical(stored) !== canonical(task)) refuse('TASK_CONFIG_CHANGED');
      const used = this.usage(task.owner_id,task.task_id);
      if (used.requests >= task.max_requests) refuse('REQUEST_CAP');
      if (used.tokens + prepared.token_reservation > task.max_tokens) refuse('TASK_TOKEN_CAP');
      if (used.cost_microusd + prepared.cost_reservation > task.spend_cap_microusd) refuse('SPEND_CAP');
      const receipt = record(); // fsynced owned donor append before commit; failure refuses dispatch.
      this.db.prepare('INSERT INTO requests VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)').run(uuid,task.owner_id,task.task_id,
        task.conversation_id,prepared.binding_hash,prepared.body_hash,'reserved',prepared.token_reservation,
        prepared.cost_reservation,prepared.token_reservation,prepared.cost_reservation,JSON.stringify(receipt),null,null);
      return receipt;
    });
  }
  transition(owner, task, uuid, from, to) {
    const result = this.db.prepare('UPDATE requests SET status=? WHERE owner_id=? AND task_id=? AND request_uuid=? AND status=?').run(to,owner,task,uuid,from);
    if (result.changes !== 1) refuse('REQUEST_STATE_CONFLICT');
  }
  settle(owner, task, uuid, tokens, cost, result, reconciliation = null) {
    if (!integer(tokens) || !integer(cost)) refuse('INVALID_USAGE');
    return this.transaction(() => {
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
}
