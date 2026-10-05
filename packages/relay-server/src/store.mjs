import { DatabaseSync } from 'node:sqlite';
import { createHash, randomUUID } from 'node:crypto';
import { constants, openSync, closeSync } from 'node:fs';
import { AUTHORS, STORAGE, RelayError, requireCondition, validateMessage, scopesFor, requireScope, bodyBytesFor, exactObject } from './contract.mjs';
import { checkPrivateParent, checkPrivateFile, samePrivateFile } from './custody.mjs';
import { POST_RATE_POLICY, POST_RATE_POLICY_JSON, validatePostRatePolicy } from './post-rate-policy.mjs';

const STORE_AUTHORS = AUTHORS.filter(author => scopesFor(author).some(scope => scope.startsWith('messages:post:')));
const TABLE_COLUMNS = {
  messages: 'seq, id, author, client_request_id, kind, body, refs, created_at',
  status: 'agent, doing, last_seen',
  storage_usage: 'author, bytes',
};
function tableSql(table, authors, name = table) {
  const names = authors.map(author => `'${author}'`).join(',');
  if (table === 'messages') return `CREATE TABLE ${name} (
    seq INTEGER PRIMARY KEY AUTOINCREMENT, id TEXT NOT NULL UNIQUE,
    author TEXT NOT NULL CHECK(author IN (${names})),
    client_request_id TEXT NOT NULL, kind TEXT NOT NULL CHECK(kind IN ('chat','claim','review','decision')),
    body TEXT NOT NULL, refs TEXT NOT NULL, created_at INTEGER NOT NULL,
    CHECK(kind != 'decision' OR author = 'peter'), UNIQUE(author, client_request_id)
  ) STRICT`;
  if (table === 'status') return `CREATE TABLE ${name} (
    agent TEXT PRIMARY KEY CHECK(agent IN (${names})),
    doing TEXT NOT NULL, last_seen INTEGER NOT NULL
  ) STRICT`;
  return `CREATE TABLE ${name} (
    author TEXT PRIMARY KEY CHECK(author IN (${names})),
    bytes INTEGER NOT NULL CHECK(bytes >= 0)
  ) STRICT`;
}
// SQLite removes IF NOT EXISTS and quotes a table name after ALTER TABLE RENAME.
// Only these formatting differences and whitespace are normalized.
const normalizeSql = sql => sql.replace(/IF NOT EXISTS\s+/g, '').replace(/\s+/g, ' ').replace(/CREATE TABLE "([a-z_]+)"/, 'CREATE TABLE $1').trim();
const RATE_TABLES = ['post_rate_metadata', 'post_attempts'];
function rateTableSql(table) {
  if (table === 'post_rate_metadata') return `CREATE TABLE post_rate_metadata (
    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
    version INTEGER NOT NULL CHECK(version = 1),
    store_id TEXT NOT NULL CHECK(length(store_id) = 36),
    policy TEXT NOT NULL,
    last_clock_ms INTEGER NOT NULL CHECK(last_clock_ms >= 0 AND last_clock_ms <= 9007199254740991),
    attempt_count INTEGER NOT NULL CHECK(attempt_count >= 0 AND attempt_count <= 9007199254740991)
  ) STRICT`;
  const names = STORE_AUTHORS.map(author => `'${author}'`).join(',');
  return `CREATE TABLE post_attempts (
    author TEXT NOT NULL CHECK(author IN (${names})),
    client_request_id TEXT NOT NULL,
    request_sha256 TEXT NOT NULL CHECK(length(request_sha256) = 64 AND request_sha256 NOT GLOB '*[^0-9a-f]*'),
    reserved_at INTEGER NOT NULL CHECK(reserved_at >= 0 AND reserved_at <= 9007199254740991),
    PRIMARY KEY(author, client_request_id)
  ) STRICT`;
}

function initializeSchema(db, allowNew = false) {
  const objects = db.prepare("SELECT type, name, sql FROM sqlite_schema WHERE name NOT GLOB 'sqlite_*'").all();
  const tables = Object.keys(TABLE_COLUMNS);
  requireCondition(objects.every(row => row.type === 'table' && [...tables, ...RATE_TABLES].includes(row.name)), 500, 'unsupported_database_schema');
  if (objects.length === 0) {
    requireCondition(allowNew, 503, 'storage_unconfigured');
    for (const table of tables) db.exec(tableSql(table, STORE_AUTHORS));
    return;
  }
  const rateObjects = objects.filter(row => RATE_TABLES.includes(row.name));
  requireCondition(objects.length === tables.length + rateObjects.length && (rateObjects.length === 0 || rateObjects.length === 2), 500, 'unsupported_database_schema');
  requireCondition(rateObjects.every(row => normalizeSql(row.sql) === normalizeSql(rateTableSql(row.name))), 500, 'unsupported_database_schema');
  const matches = authors => tables.every(table => normalizeSql(objects.find(row => row.name === table).sql) === normalizeSql(tableSql(table, authors)));
  requireCondition(matches(STORE_AUTHORS), 500, 'unsupported_database_schema');
}

export function createStore(path, lowerLimits = {}, rateOptions = {}) {
  return openStore(path, lowerLimits, rateOptions, false);
}

// Setup-only host API: absent pathname + approved policy. Never called by start,
// createStore, post or recovery. Failed setup retains its file and refuses reuse.
export function provisionNewRelayStore(path, { postRatePolicy } = {}) {
  validatePostRatePolicy(postRatePolicy);
  checkPrivateParent(path);
  const fd = openSync(path, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW, 0o600);
  closeSync(fd);
  const store = openStore(path, {}, { postRatePolicy }, true);
  try { return { status: 'PROVISIONED', version: 1 }; }
  finally { store.close(); }
}

function openStore(path, lowerLimits = {}, rateOptions = {}, provision = false) {
  requireCondition(rateOptions !== null && typeof rateOptions === 'object' && !Array.isArray(rateOptions) && Object.keys(rateOptions).every(key => ['postRatePolicy', 'now'].includes(key)), 500, 'invalid_rate_options');
  // Source checks lower budgets to exercise actual SQLite without a 256 MiB fill.
  // The executable uses the fixed production limits and exposes no HTTP override.
  requireCondition(Object.keys(lowerLimits).every(k => ['agentQuotaBytes', 'peterQuotaBytes', 'maxPages', 'reservedPeterPages'].includes(k)), 500, 'invalid_storage_limits');
  const limits = { ...STORAGE, ...lowerLimits };
  for (const key of ['agentQuotaBytes', 'peterQuotaBytes', 'maxPages', 'reservedPeterPages']) {
    requireCondition(Number.isSafeInteger(limits[key]) && limits[key] > 0 && limits[key] <= STORAGE[key], 500, 'invalid_storage_limits');
  }
  requireCondition(limits.maxPages >= 16 && limits.reservedPeterPages <= limits.maxPages - 8, 500, 'invalid_storage_limits');
  const fileIdentity = checkPrivateFile(path);
  const db = new DatabaseSync(path, { timeout: 2000, enableForeignKeyConstraints: true });
  samePrivateFile(path, fileIdentity);
  let policy = null;
  try { policy = validatePostRatePolicy(rateOptions.postRatePolicy); } catch { /* POST remains unavailable. */ }
  const clock = rateOptions.now ?? Date.now;
  requireCondition(typeof clock === 'function', 500, 'invalid_clock');
  let healthy = true;
  function transaction(operation, mode = 'IMMEDIATE') {
    requireCondition(healthy, 503, 'storage_unavailable');
    try {
      samePrivateFile(path, fileIdentity);
      db.exec(`BEGIN ${mode}`); const result = operation(); db.exec('COMMIT'); return result;
    } catch (error) {
      // SQLITE_FULL can auto-end the transaction. Do not mask its original error
      // with a second rollback failure, and refuse further work if rollback fails.
      try { if (db.isTransaction) db.exec('ROLLBACK'); } catch { healthy = false; }
      if (error?.code === 'ERR_SQLITE_ERROR' && (error.errcode & 0xff) === 13) throw new RelayError(507, 'storage_full');
      throw error;
    }
  }
  try {
    db.exec(`PRAGMA page_size=4096; PRAGMA journal_mode=PERSIST; PRAGMA synchronous=FULL; PRAGMA busy_timeout=2000; PRAGMA max_page_count=${limits.maxPages};`);
    requireCondition(db.prepare('PRAGMA page_size').get().page_size === 4096, 500, 'unexpected_database_page_size');
    // Rebuild accounting from retained rows, including pre-quota stores, without
    // deleting messages, retry identities or status. Startup reconciliation is atomic.
    transaction(() => {
      initializeSchema(db, provision);
      if (provision) {
        requireCondition(policy !== null, 503, 'post_rate_policy_unavailable');
        for (const table of RATE_TABLES) db.exec(rateTableSql(table));
        db.prepare('INSERT INTO post_rate_metadata(singleton, version, store_id, policy, last_clock_ms, attempt_count) VALUES (1, 1, ?, ?, 0, 0)').run(randomUUID(), POST_RATE_POLICY_JSON);
      }
      const hasAttempts = db.prepare("SELECT COUNT(*) AS count FROM sqlite_schema WHERE type = 'table' AND name = 'post_attempts'").get().count === 1;
      const principalRows = STORE_AUTHORS.map(author => `SELECT '${author}' AS author`).join(' UNION ALL ');
      db.exec(`INSERT INTO storage_usage(author, bytes)
        SELECT principals.author, COALESCE(totals.bytes, 0) FROM (${principalRows}) AS principals LEFT JOIN (
        SELECT author, SUM(bytes) AS bytes FROM (
          SELECT author, ${STORAGE.rowOverheadBytes} + length(CAST(author AS BLOB)) + length(CAST(client_request_id AS BLOB)) + length(CAST(kind AS BLOB)) + length(CAST(body AS BLOB)) + length(CAST(refs AS BLOB)) AS bytes FROM messages
          UNION ALL SELECT agent AS author, ${STORAGE.rowOverheadBytes} + length(CAST(agent AS BLOB)) + length(CAST(doing AS BLOB)) AS bytes FROM status
          ${hasAttempts ? `UNION ALL SELECT author, ${STORAGE.rowOverheadBytes} + length(CAST(author AS BLOB)) + length(CAST(client_request_id AS BLOB)) + length(CAST(request_sha256 AS BLOB)) + length(CAST(reserved_at AS BLOB)) AS bytes FROM post_attempts` : ''}
        ) GROUP BY author) AS totals ON totals.author = principals.author WHERE 1 ON CONFLICT(author) DO UPDATE SET bytes=excluded.bytes;`);
    });
    requireCondition(db.prepare('PRAGMA quick_check').all().every(row => row.quick_check === 'ok'), 503, 'storage_integrity_failed');
  } catch (error) { db.close(); throw error; }
  const existing = db.prepare('SELECT * FROM messages WHERE author = ? AND client_request_id = ?'); existing.setReadBigInts(true);
  const insert = db.prepare('INSERT INTO messages(id, author, client_request_id, kind, body, refs, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)');
  const page = db.prepare('SELECT * FROM messages WHERE seq > ? ORDER BY seq ASC LIMIT ?'); page.setReadBigInts(true);
  const tailPage = db.prepare('SELECT * FROM messages ORDER BY seq DESC LIMIT ?'); tailPage.setReadBigInts(true);
  const head = db.prepare('SELECT COALESCE(MAX(seq), 0) AS seq FROM messages'); head.setReadBigInts(true);
  const upsertStatus = db.prepare('INSERT INTO status(agent, doing, last_seen) VALUES (?, ?, ?) ON CONFLICT(agent) DO UPDATE SET doing=excluded.doing, last_seen=excluded.last_seen');
  const status = db.prepare('SELECT * FROM status');
  const ownStatus = db.prepare('SELECT * FROM status WHERE agent = ?');
  const usage = db.prepare('SELECT bytes FROM storage_usage WHERE author = ?');
  const setUsage = db.prepare('INSERT INTO storage_usage(author, bytes) VALUES (?, ?) ON CONFLICT(author) DO UPDATE SET bytes=excluded.bytes');
  const pageCount = db.prepare('PRAGMA page_count'); const freePages = db.prepare('PRAGMA freelist_count');
  const rateConfigured = db.prepare("SELECT COUNT(*) AS count FROM sqlite_schema WHERE type = 'table' AND name IN ('post_rate_metadata', 'post_attempts')").get().count === 2;
  const metadata = rateConfigured ? db.prepare('SELECT * FROM post_rate_metadata') : null;
  const attempt = rateConfigured ? db.prepare('SELECT * FROM post_attempts WHERE author = ? AND client_request_id = ?') : null;
  const attemptFacts = rateConfigured ? db.prepare('SELECT COUNT(*) AS count, COALESCE(MAX(reserved_at), 0) AS last FROM post_attempts') : null;
  const lastAttempt = rateConfigured ? db.prepare('SELECT MAX(reserved_at) AS last FROM post_attempts WHERE author = ?') : null;
  const windowAttempts = rateConfigured ? db.prepare('SELECT COUNT(*) AS count FROM post_attempts WHERE author = ? AND reserved_at > ? AND reserved_at <= ?') : null;
  const reserveAttempt = rateConfigured ? db.prepare('INSERT INTO post_attempts(author, client_request_id, request_sha256, reserved_at) VALUES (?, ?, ?, ?)') : null;
  const advanceClock = rateConfigured ? db.prepare('UPDATE post_rate_metadata SET last_clock_ms = ?, attempt_count = attempt_count + 1 WHERE singleton = 1') : null;
  function ledgerState() {
    requireCondition(policy !== null, 503, 'post_rate_policy_unavailable');
    requireCondition(rateConfigured, 503, 'post_rate_ledger_unconfigured');
    const rows = metadata.all(); const meta = rows[0]; const facts = attemptFacts.get();
    requireCondition(rows.length === 1 && meta.version === 1 && /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(meta.store_id) && meta.policy === POST_RATE_POLICY_JSON && Number.isSafeInteger(meta.last_clock_ms) && meta.last_clock_ms >= 0 && Number.isSafeInteger(meta.attempt_count) && meta.attempt_count === facts.count && facts.last <= meta.last_clock_ms, 503, 'post_rate_ledger_damaged');
    return meta;
  }
  const charge = (...fields) => STORAGE.rowOverheadBytes + fields.reduce((bytes, field) => bytes + Buffer.byteLength(field, 'utf8'), 0);
  function account(author, delta) {
    const next = (usage.get(author)?.bytes ?? 0) + delta;
    requireCondition(next <= (author === 'peter' ? limits.peterQuotaBytes : limits.agentQuotaBytes), 507, 'principal_storage_quota');
    setUsage.run(author, next);
  }
  function preserveHeadroom(author) {
    const usedPages = pageCount.get().page_count - freePages.get().freelist_count;
    requireCondition(author === 'peter' || usedPages <= limits.maxPages - limits.reservedPeterPages, 507, 'peter_headroom_reserved');
  }
  function message(row) {
    return { id: row.id, cursor: row.seq.toString(), author: row.author, kind: row.kind, body: row.body, refs: JSON.parse(row.refs), createdAt: Number(row.created_at) };
  }
  return {
    post(author, input) {
      requireCondition(AUTHORS.includes(author), 403, 'invalid_author');
      exactObject(input, ['clientRequestId', 'kind', 'body', 'refs']);
      const descriptors = Object.getOwnPropertyDescriptors(input);
      requireCondition(Object.values(descriptors).every(descriptor => Object.hasOwn(descriptor, 'value')), 400, 'invalid_object');
      const supplied = Object.fromEntries(Object.entries(descriptors).map(([key, descriptor]) => [key, descriptor.value]));
      validateMessage(supplied);
      // No clock or later callback can retarget the already validated bytes.
      input = Object.freeze({ ...supplied, refs: Object.freeze([...supplied.refs]) });
      validateMessage(input);
      requireCondition(input.kind !== 'decision' || author === 'peter', 403, 'peter_only_decision');
      requireScope(author, `messages:post:${input.kind}`);
      requireCondition(Buffer.byteLength(input.body, 'utf8') <= bodyBytesFor(author), 413, 'body_too_large_for_author');
      const refs = JSON.stringify(input.refs);
      const requestHash = createHash('sha256').update('relay-post-attempt/v1\0').update(JSON.stringify([author, input.clientRequestId, input.kind, input.body, refs])).digest('hex');
      const admission = transaction(() => {
        const meta = ledgerState();
        const prior = existing.get(author, input.clientRequestId);
        if (prior) {
          requireCondition(prior.kind === input.kind && prior.body === input.body && prior.refs === refs, 409, 'idempotency_conflict');
          requireCondition(attempt.get(author, input.clientRequestId)?.request_sha256 === requestHash, 503, 'post_rate_ledger_damaged');
          return { message: message(prior), replayed: true };
        }
        const previousAttempt = attempt.get(author, input.clientRequestId);
        if (previousAttempt) {
          requireCondition(previousAttempt.request_sha256 === requestHash, 409, 'idempotency_conflict');
          throw new RelayError(503, 'post_outcome_unresolved');
        }
        const now = clock();
        requireCondition(Number.isSafeInteger(now) && now >= meta.last_clock_ms, 503, 'post_rate_clock_refused');
        const priorTime = lastAttempt.get(author).last;
        requireCondition(priorTime === null || now - priorTime >= POST_RATE_POLICY.gapMs, 429, 'post_rate_gap');
        requireCondition(windowAttempts.get(author, now - POST_RATE_POLICY.windowMs, now).count < POST_RATE_POLICY.maxAttempts, 429, 'post_rate_hour');
        // Ledger reservations themselves consume the retained principal quota
        // and cannot use Peter's reserved physical pages on an agent's behalf.
        account(author, charge(author, input.clientRequestId, requestHash, String(now)));
        reserveAttempt.run(author, input.clientRequestId, requestHash, now);
        advanceClock.run(now);
        preserveHeadroom(author);
        return { reservedAt: now };
      });
      if (admission.replayed) return admission;
      // The admission transaction has COMMITTED before message effects. Failed
      // or uncertain storage cannot refund it or relaunch this request identity.
      return transaction(() => {
        ledgerState();
        requireCondition(attempt.get(author, input.clientRequestId)?.request_sha256 === requestHash, 503, 'post_rate_ledger_damaged');
        account(author, charge(author, input.clientRequestId, input.kind, input.body, refs));
        const id = createHash('sha256').update(JSON.stringify([author, input.clientRequestId])).digest('hex');
        insert.run(id, author, input.clientRequestId, input.kind, input.body, refs, admission.reservedAt);
        preserveHeadroom(author);
        return { message: message(existing.get(author, input.clientRequestId)), replayed: false };
      });
    },
    read({ after, limit, tail }) {
      if (tail !== undefined) return transaction(() => {
        const messages = tailPage.all(tail).reverse().map(message);
        return { messages, nextCursor: messages.at(-1)?.cursor ?? '0', hasMore: false };
      }, 'DEFERRED');
      return transaction(() => {
        requireCondition(BigInt(after) <= head.get().seq, 409, 'cursor_ahead_of_log');
        const rows = page.all(BigInt(after), limit + 1); const hasMore = rows.length > limit;
        const messages = rows.slice(0, limit).map(message);
        return { messages, nextCursor: messages.at(-1)?.cursor ?? after, hasMore };
      }, 'DEFERRED');
    },
    setStatus(agent, doing) {
      requireCondition(AUTHORS.includes(agent), 403, 'invalid_author');
      requireScope(agent, 'status:write:self');
      return transaction(() => {
        const prior = ownStatus.get(agent); const oldCharge = prior ? charge(agent, prior.doing) : 0;
        account(agent, charge(agent, doing) - oldCharge);
        const lastSeen = Date.now(); upsertStatus.run(agent, doing, lastSeen); preserveHeadroom(agent);
        return { agent, doing, lastSeen };
      });
    },
    status() {
      requireCondition(healthy, 503, 'storage_unavailable');
      const rows = status.all();
      return { status: AUTHORS.map(agent => {
        const row = rows.find(r => r.agent === agent);
        return row ? { agent, doing: row.doing, lastSeen: row.last_seen } : { agent, doing: '', lastSeen: null };
      }) };
    },
    close() { db.close(); },
  };
}
