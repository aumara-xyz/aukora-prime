// SPDX-License-Identifier: AGPL-3.0-or-later
// Read-only gate journal snapshots. Verification records observations; it grants no authority.
// Gate byte convention: packages/boundary-gate/src/ledger.mjs at Prime 7561a97.
import { createHash, createPublicKey, verify } from 'node:crypto'
import { DatabaseSync } from 'node:sqlite'

const HEX64 = /^[0-9a-f]{64}$/u
const SOURCE_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u
const FIELDS = Object.freeze(['seq', 'at', 'event', 'proposal', 'target', 'base_sha', 'new_sha', 'detail', 'prev', 'hash', 'sig'])
const OPTIONAL_TEXT = Object.freeze(['proposal', 'target', 'base_sha', 'new_sha', 'detail'])
const ZERO_HEAD = Object.freeze({ position: 0, hash: 'GENESIS' })
const MAX_ROWS = 50000
const MAX_BYTES = 16 * 1024 * 1024
const MAX_RECORD_BYTES = 48 * 1024
const reason = (name) => `gate-source:${name}`

function publicKeyOf(value) {
  if (typeof value === 'string') {
    if (value.length > 4096 || !/^-----BEGIN PUBLIC KEY-----\r?\n[A-Za-z0-9+/=\r\n]+-----END PUBLIC KEY-----\r?\n?$/u.test(value))
      throw new TypeError(reason('public-key-invalid'))
    value = createPublicKey({ key: value, format: 'pem', type: 'spki' })
  }
  if (value?.type !== 'public' || value?.asymmetricKeyType !== 'ed25519')
    throw new TypeError(reason('public-key-invalid'))
  return value
}

/** The exact gate-signed JSON array. detail remains its original TEXT, never reserialized. */
export function gateEntryBody(entry) {
  return JSON.stringify([entry.seq, entry.at, entry.event, entry.proposal ?? null, entry.target ?? null,
    entry.base_sha ?? null, entry.new_sha ?? null, entry.detail ?? null, entry.prev])
}

export function gateEntryHash(entryBody) {
  if (typeof entryBody !== 'string') throw new TypeError(reason('entry-body-invalid'))
  return createHash('sha256').update(entryBody, 'utf8').digest('hex')
}

/** Full SPKI identity; the gate's older 16-hex fingerprint is only an anchor label. */
export function gatePublicKeySha256(publicKey) {
  return createHash('sha256').update(publicKeyOf(publicKey).export({ type: 'spki', format: 'der' })).digest('hex')
}

/** Verify one source record. Chain membership is checked by readGateSnapshot/the cold verifier. */
export function verifyGateRecord(entry, publicKey) {
  try {
    if (!entry || typeof entry !== 'object' || Array.isArray(entry)
      || Object.keys(entry).length !== FIELDS.length || FIELDS.some((field) => !Object.hasOwn(entry, field)))
      return { ok: false, reason: reason('record-shape') }
    if (!Number.isSafeInteger(entry.seq) || entry.seq < 1
      || typeof entry.at !== 'string' || entry.at.length === 0
      || typeof entry.event !== 'string' || entry.event.length === 0
      || OPTIONAL_TEXT.some((field) => entry[field] !== null && typeof entry[field] !== 'string'))
      return { ok: false, reason: reason('record-types') }
    if (typeof entry.hash !== 'string' || !HEX64.test(entry.hash)
      || typeof entry.prev !== 'string' || (entry.seq === 1 ? entry.prev !== 'GENESIS' : !HEX64.test(entry.prev)))
      return { ok: false, reason: reason('record-hash-shape') }
    if (typeof entry.sig !== 'string' || !/^[A-Za-z0-9+/]{86}==$/u.test(entry.sig))
      return { ok: false, reason: reason('signature-shape') }
    const signature = Buffer.from(entry.sig, 'base64')
    if (signature.length !== 64 || signature.toString('base64') !== entry.sig)
      return { ok: false, reason: reason('signature-shape') }
    const entry_body = gateEntryBody(entry)
    if (gateEntryHash(entry_body) !== entry.hash) return { ok: false, reason: reason('hash-mismatch') }
    if (!verify(null, Buffer.from(entry.hash, 'hex'), publicKeyOf(publicKey), signature))
      return { ok: false, reason: reason('signature-invalid') }
    return { ok: true, entry_body }
  } catch {
    return { ok: false, reason: reason('record-verification-failed') }
  }
}

function validBound(value, ceiling) {
  return Number.isSafeInteger(value) && value > 0 && value <= ceiling
}

/**
 * Select and verify a complete prefix in one SQLite read transaction, including committed WAL rows.
 * No writes, checkpoints, immutable mode, source copies, key discovery or credential creation.
 * Bounds count UTF-8 bytes of each returned record's JSON, including the retained exact signed body.
 * Any refusal returns an incomplete result without records; verified_head is diagnostic only.
 */
export function readGateSnapshot({ dbPath, sourceId, publicKeyPem, expectedKeySha256,
  maxRows = MAX_ROWS, maxBytes = MAX_BYTES, maxRecordBytes = MAX_RECORD_BYTES } = {}) {
  let source = { journal_id: typeof sourceId === 'string' && SOURCE_ID.test(sourceId) ? sourceId : null, key_sha256: null }
  let selected_head = null
  let verified_head = { ...ZERO_HEAD }
  let db, transaction = false
  const incomplete = (name) => ({ ok: false, status: 'incomplete', reason: name.startsWith('gate-source:') ? name : reason(name),
    source, selected_head, verified_head })
  try {
    if (source.journal_id === null) return incomplete('source-id-invalid')
    if (typeof dbPath !== 'string' || dbPath.length === 0 || dbPath.length > 4096 || /[\u0000-\u001f\u007f]/u.test(dbPath))
      return incomplete('source-path-invalid')
    if (typeof publicKeyPem !== 'string') return incomplete('public-key-invalid')
    if (typeof expectedKeySha256 !== 'string' || !HEX64.test(expectedKeySha256)) return incomplete('key-pin-required')
    if (!validBound(maxRows, MAX_ROWS) || !validBound(maxBytes, MAX_BYTES) || !validBound(maxRecordBytes, MAX_RECORD_BYTES))
      return incomplete('bounds-invalid')
    let publicKey
    try {
      publicKey = publicKeyOf(publicKeyPem)
      source = { journal_id: sourceId, key_sha256: gatePublicKeySha256(publicKey) }
    } catch { return incomplete('public-key-invalid') }
    if (source.key_sha256 !== expectedKeySha256) return incomplete('key-pin-mismatch')

    db = new DatabaseSync(dbPath, { readOnly: true })
    db.exec('BEGIN')
    transaction = true
    // The first SELECT establishes the read snapshot; all subsequent queries use that same view.
    const top = db.prepare('SELECT seq, CASE WHEN length(CAST(hash AS BLOB)) = 64 THEN hash ELSE NULL END AS hash FROM ledger ORDER BY seq DESC LIMIT 1').get()
    if (!top) selected_head = { ...ZERO_HEAD }
    else if (Number.isSafeInteger(top.seq) && top.seq > 0 && typeof top.hash === 'string' && HEX64.test(top.hash))
      selected_head = { position: top.seq, hash: top.hash }
    else return incomplete('selected-head-invalid')
    const count = db.prepare('SELECT COUNT(*) AS count FROM ledger').get().count
    if (!Number.isSafeInteger(count) || count < 0) return incomplete('row-count-invalid')
    if (count > maxRows) return incomplete('row-bound-exceeded')
    // Bound raw TEXT before materializing a potentially huge row. The exact returned-record check follows.
    const oversized = db.prepare(`SELECT 1 FROM ledger WHERE
      COALESCE(length(CAST(at AS BLOB)),0) + COALESCE(length(CAST(event AS BLOB)),0)
      + COALESCE(length(CAST(proposal AS BLOB)),0) + COALESCE(length(CAST(target AS BLOB)),0)
      + COALESCE(length(CAST(base_sha AS BLOB)),0) + COALESCE(length(CAST(new_sha AS BLOB)),0)
      + COALESCE(length(CAST(detail AS BLOB)),0) + COALESCE(length(CAST(prev AS BLOB)),0)
      + COALESCE(length(CAST(hash AS BLOB)),0) + COALESCE(length(CAST(sig AS BLOB)),0) > ? LIMIT 1`).get(maxRecordBytes)
    if (oversized) return incomplete('record-bound-exceeded')
    const records = []
    let bytes = 0
    for (const raw of db.prepare(`SELECT ${FIELDS.join(',')} FROM ledger ORDER BY seq`).iterate()) {
      const entry = Object.fromEntries(FIELDS.map((field) => [field, raw[field]]))
      const checked = verifyGateRecord(entry, publicKey)
      if (!checked.ok) return incomplete(checked.reason)
      if (entry.seq !== verified_head.position + 1) return incomplete('sequence-gap')
      if (entry.prev !== verified_head.hash) return incomplete('chain-mismatch')
      const record = { position: entry.seq, hash: entry.hash, action_id: entry.proposal ?? null,
        entry, entry_body: checked.entry_body }
      const recordBytes = Buffer.byteLength(JSON.stringify(record), 'utf8')
      if (recordBytes > maxRecordBytes) return incomplete('record-bound-exceeded')
      if (bytes + recordBytes > maxBytes) return incomplete('byte-bound-exceeded')
      records.push(record)
      bytes += recordBytes
      verified_head = { position: entry.seq, hash: entry.hash }
    }
    if (records.length !== count || verified_head.position !== selected_head.position || verified_head.hash !== selected_head.hash)
      return incomplete('selected-head-mismatch')
    db.exec('COMMIT')
    transaction = false
    return { ok: true, status: 'complete', source, selected_head, records }
  } catch {
    return incomplete('snapshot-unavailable')
  } finally {
    if (transaction) { try { db.exec('ROLLBACK') } catch {} }
    if (db) { try { db.close() } catch {} }
  }
}
