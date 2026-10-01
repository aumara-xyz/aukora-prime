// SPDX-License-Identifier: AGPL-3.0-or-later
import { DatabaseSync } from 'node:sqlite'
import { lstatSync, realpathSync, chmodSync, existsSync,readFileSync,openSync,writeFileSync,fsyncSync,closeSync } from 'node:fs'
import { randomUUID } from 'node:crypto'
import { join, resolve } from 'node:path'
import { refused } from './policy.mjs'

/** Local single-host owner. The lock DB holds a live SQLite RESERVED lock;
 * job checkpoints commit to a different FULL-sync DB. Process death releases
 * the lock without erasing unfinished jobs. Never steal using PID/TTL alone.
 * Host-owned private directory and local filesystem are prerequisites. */
export class OwnedLedger {
  constructor(root,{initialize=false,expected_identity=null}={}) {
    const stat = lstatSync(root)
    if (resolve(root) !== root || realpathSync(root) !== root || !stat.isDirectory()
      || (stat.mode & 0o077) || (process.getuid && stat.uid !== process.getuid())) {
      throw refused('ledger requires canonical private host-owned directory', 'UNAVAILABLE')
    }
    this.root = root
    const names=['ledger.json','lease.sqlite','jobs.sqlite','jobs.sqlite-wal','jobs.sqlite-shm']
    if(initialize&&names.some(name=>existsSync(join(root,name))))throw refused('ledger already provisioned or incomplete; never overwrite','RECONCILIATION_REQUIRED')
    if(!initialize&&['ledger.json','lease.sqlite','jobs.sqlite'].some(name=>!existsSync(join(root,name))))throw refused('owned ledger missing; trusted reconciliation required before initialization','RECONCILIATION_REQUIRED')
    for (const name of names) {
      const file = join(root, name)
      if (existsSync(file)) {
        const st = lstatSync(file)
        if (!st.isFile() || st.isSymbolicLink() || (st.mode & 0o077)
          || (process.getuid && st.uid !== process.getuid())) throw refused('unsafe ledger file', 'UNAVAILABLE')
      }
    }
    if(!initialize) {
      const marker=JSON.parse(readFileSync(join(root,'ledger.json'),'utf8'))
      if(Object.keys(marker).sort().join(',')!=='created_at,ledger_id,version'||marker.version!==1||typeof marker.ledger_id!=='string'||!marker.ledger_id
        ||(expected_identity&&marker.ledger_id!==expected_identity))throw refused('ledger identity differs','RECONCILIATION_REQUIRED')
      this.identity=marker.ledger_id
    } else {
      if(expected_identity)throw refused('new ledger cannot reuse prior identity','RECONCILIATION_REQUIRED')
      this.identity=randomUUID()
    }
    this.db = new DatabaseSync(join(root, 'jobs.sqlite'))
    chmodSync(join(root, 'jobs.sqlite'), 0o600)
    this.db.exec('PRAGMA busy_timeout=1000; PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;')
    if(initialize) {
      this.db.exec(`PRAGMA application_id=1096108870; PRAGMA user_version=1;
        CREATE TABLE identity (ledger_id TEXT PRIMARY KEY) STRICT;
        CREATE TABLE calls (
        request_id TEXT PRIMARY KEY, operation_id TEXT NOT NULL UNIQUE,
        grant_id TEXT NOT NULL UNIQUE, reservation_id TEXT NOT NULL UNIQUE,
        cleanup TEXT NOT NULL, body TEXT NOT NULL
      ) STRICT`)
      this.db.prepare('INSERT INTO identity VALUES (?)').run(this.identity)
    } else {
      try {
        if(this.db.prepare('PRAGMA application_id').get().application_id!==1096108870
          ||this.db.prepare('PRAGMA user_version').get().user_version!==1
          ||this.db.prepare('SELECT ledger_id FROM identity').get()?.ledger_id!==this.identity
          ||this.db.prepare('PRAGMA quick_check').get().quick_check!=='ok')throw refused('ledger database identity/integrity differs','RECONCILIATION_REQUIRED')
      } catch(error) {this.db.close();throw refused('owned ledger invalid; never initialize on reopen','RECONCILIATION_REQUIRED')}
    }
    if(initialize) {
      const lease=new DatabaseSync(join(root,'lease.sqlite'));lease.exec('CREATE TABLE owner (ledger_id TEXT PRIMARY KEY) STRICT');lease.prepare('INSERT INTO owner VALUES (?)').run(this.identity);lease.close();chmodSync(join(root,'lease.sqlite'),0o600)
      const fd=openSync(join(root,'ledger.json'),'wx',0o600)
      try {writeFileSync(fd,JSON.stringify({version:1,ledger_id:this.identity,created_at:new Date().toISOString()}));fsyncSync(fd)}finally {closeSync(fd)}
      const dir=openSync(root,'r');try {fsyncSync(dir)}finally {closeSync(dir)}
    }
    for (const name of ['jobs.sqlite-wal','jobs.sqlite-shm']) if (existsSync(join(root,name))) chmodSync(join(root,name),0o600)
    this.leased = false
  }
  async withLease(work) {
    if (this.leased) throw refused('local executor is already leased', 'RECONCILIATION_REQUIRED')
    const lease = new DatabaseSync(join(this.root, 'lease.sqlite'))
    chmodSync(join(this.root, 'lease.sqlite'), 0o600)
    try {
      if(lease.prepare('SELECT ledger_id FROM owner').get()?.ledger_id!==this.identity)throw refused('lease identity differs','RECONCILIATION_REQUIRED')
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
  recovery() {
    return this.db.prepare('SELECT body FROM calls ORDER BY rowid').all().map(r=>JSON.parse(r.body)).filter(job=>
      !['confirmed_absent','not_created'].includes(job.receipt.cleanup)
      ||job.receipt.reconciliation_required
      ||(job.claim_state!=='refused'&&(job.outbox?.some(v=>v.state!=='acked')||!job.outbox?.length)))
  }
  lookup(requestId) { const row=this.db.prepare('SELECT body FROM calls WHERE request_id=?').get(requestId); return row ? JSON.parse(row.body) : null }
  close() { if (this.leased) throw refused('cannot close active lifecycle owner'); this.db.close() }
}
