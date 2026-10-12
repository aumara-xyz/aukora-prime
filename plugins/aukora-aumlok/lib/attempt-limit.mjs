// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * Limits ONLINE guessing against a node; does nothing against offline guessing
 * with a signature or record made under the root key. Offline verification oracles:
 * local-control.json publicRoot (rootId, ed25519, mlDsa65, genesis.initialRootKeySetId),
 * its recordProjection/public-control activeControlDigest, approval-receipt:v1
 * activeControlDigest, handover:v3 root IDs/signatures, root-class act publicKeyHex
 * and signature plus signed bytes, machines[] index/ed25519, machine-answer:v3
 * by.machineIndex/ed25519/keyId, and Nostr identity bindings' machine signer key.
 * Machine keys are derived by the candidate root's HKDF and the published index.
 * Recognition of public bytes grants no authority and proves no key possession.
 */
import { timingSafeEqual } from 'node:crypto'
import { existsSync } from 'node:fs'
import { isAbsolute } from 'node:path'
import { DatabaseSync } from 'node:sqlite'
import { isSubject } from './subject.mjs'

export const ATTEMPT_REFUSE = Object.freeze({
  REFUSED: 'aumlok:enrollment-refused',
  CONFIG: 'aumlok:attempt-config-invalid',
  STORE: 'aumlok:attempt-store-unavailable',
})
const REFUSED = Object.freeze({ ok: false, reason: ATTEMPT_REFUSE.REFUSED })
const RECOGNIZED = Object.freeze({ ok: true, recognized: true, authority: 'none' })
const ROOT_ID = /^[0-9a-f]{64}$/u
const integer = value => Number.isSafeInteger(value) && value >= 0
const error = code => Object.assign(new Error(code), { code })

/**
 * Opens a dedicated SQLite file in a trusted node-owned directory. Initialization
 * is explicit; missing state on reopen refuses. One file must serve every worker.
 * rootForSubject is a synchronous, node-controlled lookup of the currently pinned
 * rootId, or undefined for absence. It must not expose a separate discovery route.
 * Options and clock are node configuration, never fields supplied by the device.
 * A failed presentation at/after the threshold locks for baseMs * 2^(failures-limit),
 * capped at maxMs. Locked requests do not extend the lock; success does not reset it.
 * No network endpoint, key derivation, proof-of-possession or enrollment is performed.
 */
export function openAttemptLimiter({ file, rootForSubject, now = Date.now,
  limit = 5, baseMs = 60_000, maxMs = 3_600_000, initialize = false } = {}) {
  if (typeof file !== 'string' || !isAbsolute(file) || typeof rootForSubject !== 'function'
    || typeof now !== 'function' || typeof initialize !== 'boolean'
    || !integer(limit) || limit < 1 || !integer(baseMs) || baseMs < 1
    || !integer(maxMs) || maxMs < baseMs) throw error(ATTEMPT_REFUSE.CONFIG)
  const policy = JSON.stringify({ limit, baseMs, maxMs })
  let db
  try {
    if (!initialize && !existsSync(file)) throw error(ATTEMPT_REFUSE.STORE)
    db = new DatabaseSync(file)
    db.exec('PRAGMA busy_timeout=5000; PRAGMA journal_mode=DELETE; PRAGMA synchronous=EXTRA; BEGIN IMMEDIATE')
    if (initialize) {
      db.exec(`CREATE TABLE IF NOT EXISTS attempt_policy (id INTEGER PRIMARY KEY CHECK(id=1), policy TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS attempts (subject TEXT PRIMARY KEY, failures INTEGER NOT NULL,
          locked_until INTEGER NOT NULL, last_seen INTEGER NOT NULL)`)
      db.prepare('INSERT OR IGNORE INTO attempt_policy VALUES (1, ?)').run(policy)
    }
    if (db.prepare('SELECT policy FROM attempt_policy WHERE id=1').get()?.policy !== policy) {
      throw error(ATTEMPT_REFUSE.CONFIG)
    }
    db.exec('COMMIT')
  } catch (cause) {
    try { db?.close() } catch { /* No verdict may use this store. */ }
    throw error(cause?.code === ATTEMPT_REFUSE.CONFIG ? ATTEMPT_REFUSE.CONFIG : ATTEMPT_REFUSE.STORE)
  }

  function present(input) {
    let transaction = false
    try {
      const { subject, rootId } = input ?? {}
      if (!isSubject(subject)) return REFUSED
      db.exec('BEGIN IMMEDIATE')
      transaction = true
      const state = db.prepare('SELECT * FROM attempts WHERE subject=?').get(subject)
        ?? { failures: 0, locked_until: 0, last_seen: 0 }
      if (![state.failures, state.locked_until, state.last_seen].every(integer)) throw error(ATTEMPT_REFUSE.STORE)
      const clock = now()
      if (!integer(clock)) throw error(ATTEMPT_REFUSE.CONFIG)
      const at = Math.max(clock, state.last_seen)
      if (at > Number.MAX_SAFE_INTEGER - maxMs) throw error(ATTEMPT_REFUSE.CONFIG)
      let recognized = false
      if (at >= state.locked_until) {
        let expected
        try { expected = rootForSubject(subject) } catch { /* Lookup failure is a failed presentation. */ }
        const known = typeof expected === 'string' && ROOT_ID.test(expected)
        const shaped = typeof rootId === 'string' && ROOT_ID.test(rootId)
        const equal = timingSafeEqual(Buffer.from(known ? expected : '0'.repeat(64), 'hex'),
          Buffer.from(shaped ? rootId : '0'.repeat(64), 'hex'))
        recognized = known && shaped && equal
        if (!recognized) {
          state.failures = Math.min(Number.MAX_SAFE_INTEGER, state.failures + 1)
          if (state.failures >= limit) {
            const delay = Math.min(maxMs, baseMs * 2 ** Math.min(53, state.failures - limit))
            state.locked_until = at + delay
          }
        }
      }
      db.prepare(`INSERT INTO attempts VALUES (?, ?, ?, ?)
        ON CONFLICT(subject) DO UPDATE SET failures=excluded.failures,
          locked_until=excluded.locked_until, last_seen=excluded.last_seen`)
        .run(subject, state.failures, state.locked_until, at)
      db.exec('COMMIT')
      transaction = false
      return recognized ? RECOGNIZED : REFUSED
    } catch {
      if (transaction) { try { db.exec('ROLLBACK') } catch { /* Still refused. */ } }
      return REFUSED
    }
  }
  return Object.freeze({ present, close: () => db.close() })
}
