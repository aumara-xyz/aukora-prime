import { DatabaseSync } from 'node:sqlite';
import { createHash } from 'node:crypto';
import { AUTHORS, STORAGE, RelayError, requireCondition } from './contract.mjs';

export function createStore(path, lowerLimits = {}) {
  // Source checks lower budgets to exercise actual SQLite without a 256 MiB fill.
  // The executable uses the fixed production limits and exposes no HTTP override.
  requireCondition(Object.keys(lowerLimits).every(k => ['agentQuotaBytes', 'peterQuotaBytes', 'maxPages', 'reservedPeterPages'].includes(k)), 500, 'invalid_storage_limits');
  const limits = { ...STORAGE, ...lowerLimits };
  for (const key of ['agentQuotaBytes', 'peterQuotaBytes', 'maxPages', 'reservedPeterPages']) {
    requireCondition(Number.isSafeInteger(limits[key]) && limits[key] > 0 && limits[key] <= STORAGE[key], 500, 'invalid_storage_limits');
  }
  requireCondition(limits.maxPages >= 16 && limits.reservedPeterPages <= limits.maxPages - 8, 500, 'invalid_storage_limits');
  const db = new DatabaseSync(path, { timeout: 2000, enableForeignKeyConstraints: true });
  let healthy = true;
  function transaction(operation, mode = 'IMMEDIATE') {
    requireCondition(healthy, 503, 'storage_unavailable');
    try {
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
    db.exec(`PRAGMA page_size=4096; PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL; PRAGMA busy_timeout=2000; PRAGMA max_page_count=${limits.maxPages};
    CREATE TABLE IF NOT EXISTS messages (
      seq INTEGER PRIMARY KEY AUTOINCREMENT, id TEXT NOT NULL UNIQUE,
      author TEXT NOT NULL CHECK(author IN ('peter','gpt','grok','claudecode_cloud','claudecode_local','muse','dot')),
      client_request_id TEXT NOT NULL, kind TEXT NOT NULL CHECK(kind IN ('chat','claim','review','decision')),
      body TEXT NOT NULL, refs TEXT NOT NULL, created_at INTEGER NOT NULL,
      CHECK(kind != 'decision' OR author = 'peter'), UNIQUE(author, client_request_id)
    ) STRICT;
    CREATE TABLE IF NOT EXISTS status (
      agent TEXT PRIMARY KEY CHECK(agent IN ('peter','gpt','grok','claudecode_cloud','claudecode_local','muse','dot')),
      doing TEXT NOT NULL, last_seen INTEGER NOT NULL
    ) STRICT;
    CREATE TABLE IF NOT EXISTS storage_usage (
      author TEXT PRIMARY KEY CHECK(author IN ('peter','gpt','grok','claudecode_cloud','claudecode_local','muse','dot')),
      bytes INTEGER NOT NULL CHECK(bytes >= 0)
    ) STRICT;`);
    requireCondition(db.prepare('PRAGMA page_size').get().page_size === 4096, 500, 'unexpected_database_page_size');
    // Rebuild accounting from retained rows, including pre-quota stores, without
    // deleting messages, retry identities or status. Startup reconciliation is atomic.
    transaction(() => {
      db.exec(`DELETE FROM storage_usage;
        INSERT INTO storage_usage(author, bytes)
        SELECT author, SUM(bytes) FROM (
          SELECT author, ${STORAGE.rowOverheadBytes} + length(CAST(author AS BLOB)) + length(CAST(client_request_id AS BLOB)) + length(CAST(kind AS BLOB)) + length(CAST(body AS BLOB)) + length(CAST(refs AS BLOB)) AS bytes FROM messages
          UNION ALL SELECT agent AS author, ${STORAGE.rowOverheadBytes} + length(CAST(agent AS BLOB)) + length(CAST(doing AS BLOB)) AS bytes FROM status
        ) GROUP BY author;`);
    });
  } catch (error) { db.close(); throw error; }
  const existing = db.prepare('SELECT * FROM messages WHERE author = ? AND client_request_id = ?'); existing.setReadBigInts(true);
  const insert = db.prepare('INSERT INTO messages(id, author, client_request_id, kind, body, refs, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)');
  const page = db.prepare('SELECT * FROM messages WHERE seq > ? ORDER BY seq ASC LIMIT ?'); page.setReadBigInts(true);
  const head = db.prepare('SELECT COALESCE(MAX(seq), 0) AS seq FROM messages'); head.setReadBigInts(true);
  const upsertStatus = db.prepare('INSERT INTO status(agent, doing, last_seen) VALUES (?, ?, ?) ON CONFLICT(agent) DO UPDATE SET doing=excluded.doing, last_seen=excluded.last_seen');
  const status = db.prepare('SELECT * FROM status');
  const ownStatus = db.prepare('SELECT * FROM status WHERE agent = ?');
  const usage = db.prepare('SELECT bytes FROM storage_usage WHERE author = ?');
  const setUsage = db.prepare('INSERT INTO storage_usage(author, bytes) VALUES (?, ?) ON CONFLICT(author) DO UPDATE SET bytes=excluded.bytes');
  const pageCount = db.prepare('PRAGMA page_count'); const freePages = db.prepare('PRAGMA freelist_count');
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
      requireCondition(input.kind !== 'decision' || author === 'peter', 403, 'peter_only_decision');
      const refs = JSON.stringify(input.refs);
      return transaction(() => {
        const prior = existing.get(author, input.clientRequestId);
        if (prior) {
          requireCondition(prior.kind === input.kind && prior.body === input.body && prior.refs === refs, 409, 'idempotency_conflict');
          return { message: message(prior), replayed: true };
        }
        account(author, charge(author, input.clientRequestId, input.kind, input.body, refs));
        const id = createHash('sha256').update(JSON.stringify([author, input.clientRequestId])).digest('hex');
        insert.run(id, author, input.clientRequestId, input.kind, input.body, refs, Date.now());
        preserveHeadroom(author);
        return { message: message(existing.get(author, input.clientRequestId)), replayed: false };
      });
    },
    read({ after, limit }) {
      return transaction(() => {
        requireCondition(BigInt(after) <= head.get().seq, 409, 'cursor_ahead_of_log');
        const rows = page.all(BigInt(after), limit + 1); const hasMore = rows.length > limit;
        const messages = rows.slice(0, limit).map(message);
        return { messages, nextCursor: messages.at(-1)?.cursor ?? after, hasMore };
      }, 'DEFERRED');
    },
    setStatus(agent, doing) {
      requireCondition(AUTHORS.includes(agent), 403, 'invalid_author');
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
