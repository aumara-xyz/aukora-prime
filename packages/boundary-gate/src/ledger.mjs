// Append-only, hash-chained, Ed25519-signed change ledger (SQLite, WAL, synchronous=FULL). Every gate event
// (propose, reject, decide, apply, expire, reconcile, start) is one entry; UPDATE/DELETE are refused by triggers.
import fs from 'node:fs'
import path from 'node:path'
import { createHash, generateKeyPairSync, createPrivateKey, createPublicKey, sign, verify } from 'node:crypto'
import { DatabaseSync } from 'node:sqlite'

export const sha256 = (b) => createHash('sha256').update(b).digest('hex')
export const SHA = /^[0-9a-f]{64}$/

export function keyFingerprint(pub) { return sha256(pub.export({ type: 'spki', format: 'der' })).slice(0, 16) }

// Receipt signing key, created once (0600, exclusive create) in the gate's private home.
export function loadOrCreateKey(home) {
  const kp = path.join(home, 'receipt-ed25519.pem')
  if (!fs.existsSync(kp)) fs.writeFileSync(kp, generateKeyPairSync('ed25519').privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600, flag: 'wx' })
  const priv = createPrivateKey(fs.readFileSync(kp)); const pub = createPublicKey(priv)
  return { priv, pub, pubPem: pub.export({ type: 'spki', format: 'pem' }).toString(), fp: keyFingerprint(pub) }
}

export function openDb(file, { readOnly = false } = {}) {
  const db = new DatabaseSync(file, readOnly ? { readOnly: true } : {})
  if (readOnly) return db
  db.exec(`PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;
    CREATE TABLE IF NOT EXISTS proposals(id TEXT PRIMARY KEY, kind TEXT, target TEXT, base_sha TEXT, new_sha TEXT, diff TEXT,
      why TEXT, session TEXT, call_id TEXT, created INTEGER, expires INTEGER, displayable INTEGER, state TEXT, note TEXT, updated INTEGER);
    CREATE TABLE IF NOT EXISTS blobs(sha TEXT PRIMARY KEY, target TEXT, bytes BLOB, first_seen TEXT);
    CREATE TABLE IF NOT EXISTS ledger(seq INTEGER PRIMARY KEY, at TEXT NOT NULL, event TEXT NOT NULL, proposal TEXT, target TEXT,
      base_sha TEXT, new_sha TEXT, detail TEXT, prev TEXT NOT NULL, hash TEXT NOT NULL, sig TEXT NOT NULL);
    CREATE TRIGGER IF NOT EXISTS ledger_no_update BEFORE UPDATE ON ledger BEGIN SELECT RAISE(ABORT, 'ledger is append-only'); END;
    CREATE TRIGGER IF NOT EXISTS ledger_no_delete BEFORE DELETE ON ledger BEGIN SELECT RAISE(ABORT, 'ledger is append-only'); END;`)
  return db
}

export const entryBody = (e) => JSON.stringify([e.seq, e.at, e.event, e.proposal ?? null, e.target ?? null, e.base_sha ?? null, e.new_sha ?? null, e.detail ?? null, e.prev])

// Preserve the original TEXT detail: parsing and reserializing it would change the signed ledger body.
export function signedEntryData(e) {
  return Object.fromEntries(['seq', 'at', 'event', 'proposal', 'target', 'base_sha', 'new_sha', 'detail', 'prev', 'hash', 'sig'].map(k => [k, e[k]]))
}

export function verifyLedger(db, pub) {
  let prev = 'GENESIS', n = 0; const errors = []
  for (const e of db.prepare('SELECT * FROM ledger ORDER BY seq').iterate()) {
    n++
    if (e.seq !== n) errors.push(`seq gap at ${e.seq} (expected ${n})`)
    if (e.prev !== prev) errors.push(`seq ${e.seq}: prev ${String(e.prev).slice(0, 12)} != ${prev.slice(0, 12)}`)
    if (sha256(entryBody(e)) !== e.hash) errors.push(`seq ${e.seq}: hash mismatch`)
    let good = false; try { good = verify(null, Buffer.from(e.hash, 'hex'), pub, Buffer.from(e.sig, 'base64')) } catch {}
    if (!good) errors.push(`seq ${e.seq}: bad signature`)
    prev = e.hash; if (errors.length > 20) break
  }
  return { ok: errors.length === 0, entries: n, head: prev, errors }
}

export function createLedger(db, key, iso = () => new Date().toISOString()) {
  function append(event, f = {}) {
    const last = db.prepare('SELECT seq, hash FROM ledger ORDER BY seq DESC LIMIT 1').get()
    const e = { seq: (last?.seq ?? 0) + 1, at: iso(), event, proposal: f.proposal ?? null, target: f.target ?? null,
      base_sha: f.base_sha ?? null, new_sha: f.new_sha ?? null, detail: f.detail === undefined ? null : JSON.stringify(f.detail), prev: last?.hash ?? 'GENESIS' }
    e.hash = sha256(entryBody(e)); e.sig = sign(null, Buffer.from(e.hash, 'hex'), key.priv).toString('base64')
    db.prepare('INSERT INTO ledger VALUES(?,?,?,?,?,?,?,?,?,?,?)').run(e.seq, e.at, e.event, e.proposal, e.target, e.base_sha, e.new_sha, e.detail, e.prev, e.hash, e.sig)
    return e
  }
  return { append, verify: () => verifyLedger(db, key.pub) }
}
