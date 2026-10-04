// Append-only, hash-chained, Ed25519-signed change ledger (SQLite, WAL, synchronous=FULL). Every gate event
// (propose, reject, decide, apply, expire, reconcile, start) is one entry; UPDATE/DELETE are refused by triggers.
import fs from 'node:fs'
import path from 'node:path'
import { createHash, generateKeyPairSync, createPrivateKey, createPublicKey, sign, verify } from 'node:crypto'
import { DatabaseSync } from 'node:sqlite'

export const sha256 = (b) => createHash('sha256').update(b).digest('hex')
export const SHA = /^[0-9a-f]{64}$/

export const GATE_COMPLETED_RESULT_DOMAIN = 'aukora:gate-completed-result:v1\0'
export const GATE_CAPTURE_DOMAIN = 'aukora:gate-capture:v1\0'
export const GATE_COMPLETED_RESULT_FIELDS = Object.freeze(['applied', 'state', 'entry', 'receipt', 'receipt_sig', 'ledger_seq', 'ledger_hash', 'message'])
const CAPTURE_FIELDS = ['version', 'kind', 'source', 'proposal_id', 'gate_pubkey_sha256', 'completed_result_sha256']
const RECEIPT_FIELDS = ['v', 'kind', 'proposal', 'target', 'base_sha', 'new_sha', 'applied_at', 'approver', 'pubkey_fp',
  'gate_pubkey_sha256', 'owner_authorization', 'owner_accepted_at_ms', 'owner_consumption']
const hex64 = value => typeof value === 'string' && value.length === 64 && SHA.test(value)
const safeTime = value => Number.isSafeInteger(value) && !Object.is(value, -0) && value >= 0
const sequence = value => safeTime(value) && value > 0
const printable = value => typeof value === 'string' && value.length >= 1 && value.length <= 200 && !/[^\x20-\x7e]/u.test(value)
const journalIdentifier = value => typeof value === 'string' && value.length >= 1 && value.length <= 128
  && /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u.test(value) && !/[^A-Za-z0-9._:-]/u.test(value)
const uuid = value => typeof value === 'string' && value.length === 36 && /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u.test(value)
const captureFail = () => { throw new Error('gate-capture:unavailable-or-invalid') }
function closedCaptureRecord(value, fields, preserveOrder = false) {
  if (!value || typeof value !== 'object' || ![Object.prototype, null].includes(Object.getPrototypeOf(value))) captureFail()
  const descriptors = Object.getOwnPropertyDescriptors(value), keys = Reflect.ownKeys(descriptors)
  if (keys.length !== fields.length || keys.some(k => typeof k !== 'string' || !fields.includes(k))) captureFail()
  const out = Object.create(null)
  for (const field of preserveOrder ? keys : fields) {
    const d = descriptors[field]
    if (!d?.enumerable || !Object.hasOwn(d, 'value')) captureFail()
    out[field] = d.value
  }
  return out
}
function signatureBytes(text) {
  if (typeof text !== 'string' || text.length !== 88) captureFail()
  const bytes = Buffer.from(text, 'base64')
  if (bytes.length !== 64 || bytes.toString('base64') !== text) captureFail()
  return bytes
}
function completedResultCore(value) {
  const core = closedCaptureRecord(value, GATE_COMPLETED_RESULT_FIELDS)
  if (core.applied !== true || core.state !== 'applied' || core.message !== 'applied' || !printable(core.entry)
    || !sequence(core.ledger_seq) || !hex64(core.ledger_hash)) captureFail()
  signatureBytes(core.receipt_sig)
  const receipt = closedCaptureRecord(core.receipt, RECEIPT_FIELDS, true)
  const reference = closedCaptureRecord(receipt.owner_authorization, ['version', 'kind', 'authorization_id', 'proof_sha256'], true)
  const consumption = closedCaptureRecord(receipt.owner_consumption, ['ledger_seq', 'ledger_hash', 'review_issue'], true)
  const issue = closedCaptureRecord(consumption.review_issue, ['ledger_seq', 'ledger_hash'], true)
  if (receipt.v !== 3 || !['change', 'revert'].includes(receipt.kind) || !uuid(receipt.proposal)
    || !printable(receipt.target) || !(receipt.base_sha === 'absent' || hex64(receipt.base_sha)) || !hex64(receipt.new_sha)
    || receipt.base_sha === receipt.new_sha || typeof receipt.applied_at !== 'string' || receipt.applied_at.length > 32
    || !Number.isFinite(Date.parse(receipt.applied_at)) || typeof receipt.approver !== 'string'
    || !/^aukora:1:[0-9a-f]{64}$/u.test(receipt.approver) || receipt.approver.length !== 73
    || !hex64(receipt.gate_pubkey_sha256) || receipt.pubkey_fp !== receipt.gate_pubkey_sha256.slice(0, 16)
    || !safeTime(receipt.owner_accepted_at_ms) || reference.version !== 1 || reference.kind !== 'aukora-owner-authorization-ref/v1'
    || !hex64(reference.authorization_id) || !hex64(reference.proof_sha256)
    || !sequence(issue.ledger_seq) || !hex64(issue.ledger_hash) || !sequence(consumption.ledger_seq)
    || !hex64(consumption.ledger_hash) || issue.ledger_seq >= consumption.ledger_seq || consumption.ledger_seq >= core.ledger_seq) captureFail()
  // Detach every descriptor snapshot, preserving the receipt's original property order. Never
  // serialize a raw caller object: a Proxy/toJSON trap could substitute different signed bytes.
  consumption.review_issue = issue
  receipt.owner_authorization = reference
  receipt.owner_consumption = consumption
  core.receipt = receipt
  return core
}
export function gateCompletedResultDigest(result) {
  return sha256(Buffer.from(GATE_COMPLETED_RESULT_DOMAIN + JSON.stringify(completedResultCore(result)), 'utf8'))
}
export function gateCaptureSigningBytes(supplied) {
  const capture = closedCaptureRecord(supplied, CAPTURE_FIELDS)
  const source = closedCaptureRecord(capture.source, ['journal_id', 'position', 'hash'])
  if (capture.version !== 1 || capture.kind !== 'aukora-gate-capture/v1' || !journalIdentifier(source.journal_id)
    || !sequence(source.position) || !hex64(source.hash) || !uuid(capture.proposal_id)
    || !hex64(capture.gate_pubkey_sha256) || !hex64(capture.completed_result_sha256)) captureFail()
  capture.source = source
  return Buffer.from(GATE_CAPTURE_DOMAIN + JSON.stringify(capture), 'utf8')
}
function completedGateResult(supplied) {
  const full = closedCaptureRecord(supplied, [...GATE_COMPLETED_RESULT_FIELDS, 'gate_capture'])
  const core = completedResultCore(Object.fromEntries(GATE_COMPLETED_RESULT_FIELDS.map(field => [field, full[field]])))
  const envelope = closedCaptureRecord(full.gate_capture, ['capture', 'signature_base64'])
  const capture = closedCaptureRecord(envelope.capture, CAPTURE_FIELDS)
  capture.source = closedCaptureRecord(capture.source, ['journal_id', 'position', 'hash'])
  gateCaptureSigningBytes(capture)
  signatureBytes(envelope.signature_base64)
  return { ...core, gate_capture: { capture, signature_base64: envelope.signature_base64 } }
}

/** Public completion/capture verification only. Expectations are independent trusted public pins.
 * This projects a source pointer, not owner enrollment or archival owner-authorization acceptance. */
export function verifyCompletedGateCapture(supplied, expectations) {
  const full = completedGateResult(supplied)
  const core = completedResultCore(Object.fromEntries(GATE_COMPLETED_RESULT_FIELDS.map(field => [field, full[field]])))
  const e = closedCaptureRecord(expectations, ['journal_id', 'gate_public_key_pem', 'gate_pubkey_sha256'])
  if (!journalIdentifier(e.journal_id) || !hex64(e.gate_pubkey_sha256) || typeof e.gate_public_key_pem !== 'string'
    || Buffer.byteLength(e.gate_public_key_pem) > 1024) captureFail()
  const key = createPublicKey(e.gate_public_key_pem)
  if (key.asymmetricKeyType !== 'ed25519' || sha256(key.export({ format: 'der', type: 'spki' })) !== e.gate_pubkey_sha256) captureFail()
  const envelope = closedCaptureRecord(full.gate_capture, ['capture', 'signature_base64'])
  const capture = closedCaptureRecord(envelope.capture, CAPTURE_FIELDS)
  const source = closedCaptureRecord(capture.source, ['journal_id', 'position', 'hash'])
  if (source.journal_id !== e.journal_id || source.position !== core.ledger_seq || source.hash !== core.ledger_hash
    || capture.proposal_id !== core.receipt.proposal || capture.gate_pubkey_sha256 !== e.gate_pubkey_sha256
    || core.receipt.gate_pubkey_sha256 !== e.gate_pubkey_sha256 || capture.completed_result_sha256 !== gateCompletedResultDigest(core)
    || !verify(null, Buffer.from(JSON.stringify(core.receipt)), key, signatureBytes(core.receipt_sig))
    || !verify(null, gateCaptureSigningBytes(capture), key, signatureBytes(envelope.signature_base64))) captureFail()
  return Object.freeze({ source: Object.freeze({ journal_id: source.journal_id, position: source.position, hash: source.hash }) })
}

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
    CREATE TRIGGER IF NOT EXISTS ledger_no_delete BEFORE DELETE ON ledger BEGIN SELECT RAISE(ABORT, 'ledger is append-only'); END;
    -- Additive source migration: existing signed rows and positional inserts stay byte-identical.
    CREATE TABLE IF NOT EXISTS owner_authorization_reviews(
      gate TEXT NOT NULL, challenge TEXT NOT NULL, proposal_id TEXT NOT NULL,
      authorization_id TEXT NOT NULL UNIQUE, authorization_text TEXT NOT NULL, owner_state_text TEXT NOT NULL,
      issued_at_ms INTEGER NOT NULL, expires_at_ms INTEGER NOT NULL, issue_seq INTEGER NOT NULL, issue_hash TEXT NOT NULL,
      state TEXT NOT NULL CHECK(state IN ('live','spent','invalidated','expired')),
      spent_at_ms INTEGER, spend_seq INTEGER, PRIMARY KEY(gate,challenge));
    CREATE UNIQUE INDEX IF NOT EXISTS owner_authorization_live_review ON owner_authorization_reviews(proposal_id) WHERE state='live';
    CREATE TRIGGER IF NOT EXISTS owner_authorization_review_no_delete BEFORE DELETE ON owner_authorization_reviews
      BEGIN SELECT RAISE(ABORT, 'owner review facts are retained'); END;
    CREATE TRIGGER IF NOT EXISTS owner_authorization_review_facts BEFORE UPDATE ON owner_authorization_reviews
      WHEN OLD.gate IS NOT NEW.gate OR OLD.challenge IS NOT NEW.challenge OR OLD.proposal_id IS NOT NEW.proposal_id
        OR OLD.authorization_id IS NOT NEW.authorization_id OR OLD.authorization_text IS NOT NEW.authorization_text
        OR OLD.owner_state_text IS NOT NEW.owner_state_text OR OLD.issued_at_ms IS NOT NEW.issued_at_ms
        OR OLD.expires_at_ms IS NOT NEW.expires_at_ms OR OLD.issue_seq IS NOT NEW.issue_seq OR OLD.issue_hash IS NOT NEW.issue_hash
        OR OLD.state != 'live' OR NEW.state = 'live'
      BEGIN SELECT RAISE(ABORT, 'owner review facts are immutable; terminal reviews cannot revive'); END;
    CREATE TABLE IF NOT EXISTS owner_authorization_consumptions(
      authorization_id TEXT PRIMARY KEY, proof_sha256 TEXT NOT NULL UNIQUE, gate TEXT NOT NULL, challenge TEXT NOT NULL,
      proposal_id TEXT NOT NULL UNIQUE, proof_text TEXT NOT NULL, accepted_at_ms INTEGER NOT NULL,
      consume_seq INTEGER NOT NULL UNIQUE, consume_hash TEXT NOT NULL, issue_seq INTEGER NOT NULL, issue_hash TEXT NOT NULL,
      owner_state_text TEXT NOT NULL, UNIQUE(gate,challenge));
    CREATE TRIGGER IF NOT EXISTS owner_authorization_consumption_no_update BEFORE UPDATE ON owner_authorization_consumptions
      BEGIN SELECT RAISE(ABORT, 'owner consumption is immutable'); END;
    CREATE TRIGGER IF NOT EXISTS owner_authorization_consumption_no_delete BEFORE DELETE ON owner_authorization_consumptions
      BEGIN SELECT RAISE(ABORT, 'owner consumption is retained'); END;
    CREATE TABLE IF NOT EXISTS gate_completed_results(
      proposal_id TEXT PRIMARY KEY NOT NULL, apply_seq INTEGER NOT NULL UNIQUE, apply_hash TEXT NOT NULL,
      completed_result_sha256 TEXT NOT NULL, result_text TEXT NOT NULL, retained_at_ms INTEGER NOT NULL);
    CREATE TRIGGER IF NOT EXISTS gate_completed_result_no_update BEFORE UPDATE ON gate_completed_results
      BEGIN SELECT RAISE(ABORT, 'original gate completion is immutable'); END;
    CREATE TRIGGER IF NOT EXISTS gate_completed_result_no_delete BEFORE DELETE ON gate_completed_results
      BEGIN SELECT RAISE(ABORT, 'original gate completion is retained'); END;`)
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
  function checkedCompletion(supplied) {
    const result = completedGateResult(supplied)
    const core = Object.fromEntries(GATE_COMPLETED_RESULT_FIELDS.map(field => [field, result[field]]))
    verifyCompletedGateCapture(result, { journal_id: result.gate_capture.capture.source.journal_id,
      gate_public_key_pem: key.pub.export({ type: 'spki', format: 'pem' }).toString(),
      gate_pubkey_sha256: sha256(key.pub.export({ type: 'spki', format: 'der' })) })
    const row = db.prepare('SELECT * FROM ledger WHERE seq=?').get(result.ledger_seq)
    if (!row || row.proposal !== result.receipt.proposal || row.hash !== result.ledger_hash
      || row.event !== (result.receipt.kind === 'revert' ? 'revert-applied' : 'apply')
      || row.target !== result.receipt.target || row.base_sha !== result.receipt.base_sha || row.new_sha !== result.receipt.new_sha
      || sha256(entryBody(row)) !== row.hash || !verify(null, Buffer.from(row.hash, 'hex'), key.pub, signatureBytes(row.sig))) captureFail()
    const detail = JSON.parse(row.detail)
    if (JSON.stringify(detail.receipt) !== JSON.stringify(result.receipt) || detail.receipt_sig !== result.receipt_sig) captureFail()
    return { result, digest: gateCompletedResultDigest(core), text: JSON.stringify(result) }
  }
  // Called only after original apply COMMIT and capture mint. This never signs or reconstructs
  // a completion from target bytes, a current entry spec, a later row, or the current journal tip.
  function retainCompletedResult(supplied, retainedAtMs) {
    if (!safeTime(retainedAtMs)) captureFail()
    const { result, digest, text } = checkedCompletion(supplied)
    const proposal = db.prepare('SELECT state FROM proposals WHERE id=?').get(result.receipt.proposal)
    if (proposal?.state !== 'applied') captureFail()
    const written = db.prepare(`INSERT INTO gate_completed_results(proposal_id,apply_seq,apply_hash,completed_result_sha256,result_text,retained_at_ms)
      VALUES(?,?,?,?,?,?)`).run(result.receipt.proposal, result.ledger_seq, result.ledger_hash, digest, text, retainedAtMs)
    if (written.changes !== 1) throw new Error('gate-capture:original-completion-retention-unavailable')
    const retained = db.prepare('SELECT * FROM gate_completed_results WHERE proposal_id=?').get(result.receipt.proposal)
    if (!retained || retained.apply_seq !== result.ledger_seq || retained.apply_hash !== result.ledger_hash
      || retained.completed_result_sha256 !== digest || retained.result_text !== text || retained.retained_at_ms !== retainedAtMs)
      throw new Error('gate-capture:original-completion-retention-unavailable')
    return supplied
  }
  function retainedCompletedResult(proposalId) {
    const row = db.prepare('SELECT * FROM gate_completed_results WHERE proposal_id=?').get(proposalId)
    if (!row) return null
    const original = JSON.parse(row.result_text)
    const { result, digest, text } = checkedCompletion(original)
    if (result.receipt.proposal !== proposalId || row.apply_seq !== result.ledger_seq || row.apply_hash !== result.ledger_hash
      || row.completed_result_sha256 !== digest || row.result_text !== text) captureFail()
    return original
  }
  return { append, retainCompletedResult, retainedCompletedResult, verify: () => verifyLedger(db, key.pub) }
}
