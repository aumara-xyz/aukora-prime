// SPDX-License-Identifier: AGPL-3.0-or-later
import { DatabaseSync } from 'node:sqlite'
import { lstatSync, realpathSync, chmodSync, existsSync } from 'node:fs'
import { join, resolve } from 'node:path'
import { refused } from './policy.mjs'

/** Local single-host owner. The lock DB holds a live SQLite RESERVED lock;
 * job checkpoints commit to a different FULL-sync DB. Process death releases
 * the lock without erasing unfinished jobs. Never steal using PID/TTL alone.
 * Host-owned private directory and local filesystem are prerequisites. */
export class OwnedLedger {
  constructor(root) {
    const stat = lstatSync(root)
    if (resolve(root) !== root || realpathSync(root) !== root || !stat.isDirectory()
      || (stat.mode & 0o077) || (process.getuid && stat.uid !== process.getuid())) {
      throw refused('ledger requires canonical private host-owned directory', 'UNAVAILABLE')
    }
    this.root = root
    for (const name of ['lease.sqlite','jobs.sqlite','jobs.sqlite-wal','jobs.sqlite-shm']) {
      const file = join(root, name)
      if (existsSync(file)) {
        const st = lstatSync(file)
        if (!st.isFile() || st.isSymbolicLink() || (st.mode & 0o077)
          || (process.getuid && st.uid !== process.getuid())) throw refused('unsafe ledger file', 'UNAVAILABLE')
      }
    }
    this.db = new DatabaseSync(join(root, 'jobs.sqlite'))
    chmodSync(join(root, 'jobs.sqlite'), 0o600)
    this.db.exec('PRAGMA busy_timeout=1000; PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;')
    this.db.exec(`CREATE TABLE IF NOT EXISTS calls (
      request_id TEXT PRIMARY KEY, operation_id TEXT NOT NULL UNIQUE,
      grant_id TEXT NOT NULL UNIQUE, reservation_id TEXT NOT NULL UNIQUE,
      cleanup TEXT NOT NULL, body TEXT NOT NULL
    ) STRICT`)
    for (const name of ['jobs.sqlite-wal','jobs.sqlite-shm']) if (existsSync(join(root,name))) chmodSync(join(root,name),0o600)
    this.leased = false
  }
  async withLease(work) {
    if (this.leased) throw refused('local executor is already leased', 'RECONCILIATION_REQUIRED')
    const lease = new DatabaseSync(join(this.root, 'lease.sqlite'))
    chmodSync(join(this.root, 'lease.sqlite'), 0o600)
    try {
      lease.exec('PRAGMA busy_timeout=0; BEGIN IMMEDIATE;')
    } catch {
      lease.close()
      throw refused('another process owns lifecycle lease', 'RECONCILIATION_REQUIRED')
    }
    this.leased = true
    try { return await work() }
    finally { this.leased = false; try { lease.exec('ROLLBACK') } finally { lease.close() } }
  }
  checkLease() { if (!this.leased) throw refused('lifecycle mutation requires exclusive lease', 'RECONCILIATION_REQUIRED') }
  reserve(job) {
    this.checkLease()
    try { this.db.prepare('INSERT INTO calls VALUES (?,?,?,?,?,?)').run(job.request_id,
      job.receipt.operation_id,job.receipt.grant_id,job.reservation_id,job.receipt.cleanup,JSON.stringify(job)) }
    catch (error) {
      if (String(error.code).includes('CONSTRAINT') || String(error.message).includes('UNIQUE')) {
        throw refused('operation/grant/request already fenced; never relaunch', 'REPLAYED')
      }
      throw error
    }
  }
  save(job) {
    this.checkLease()
    const result = this.db.prepare('UPDATE calls SET cleanup=?, body=? WHERE request_id=?')
      .run(job.receipt.cleanup,JSON.stringify(job),job.request_id)
    if (result.changes !== 1) throw refused('owned ledger checkpoint missing', 'RECONCILIATION_REQUIRED')
  }
  pending() { return this.db.prepare("SELECT body FROM calls WHERE cleanup NOT IN ('confirmed_absent','not_created') ORDER BY rowid").all().map(r=>JSON.parse(r.body)) }
  lookup(requestId) { const row=this.db.prepare('SELECT body FROM calls WHERE request_id=?').get(requestId); return row ? JSON.parse(row.body) : null }
  close() { if (this.leased) throw refused('cannot close active lifecycle owner'); this.db.close() }
}
