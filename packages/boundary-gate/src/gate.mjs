// Boundary gate core: the approval and state authority, run as its own Linux user (aukora-gate).
//
// Two operation sets, served on two different sockets so the harness can PROPOSE and READ AUDIT but can
// NEVER APPROVE:
//   proposeOps  (PROPOSE socket, group skgate, 0660): ping/targets/read/propose/close(reject only)/state/
//               harness_start/selfcheck/log/verify/status. There is no approve operation on this channel;
//               `close` refuses every outcome except rejected/cancelled/unavailable/expired and records the try.
//   ownerOps    (OWNER socket 0600 gate-only, and the bearer-protected owner page): pending/approve/reject/review/decide_review/
//               rotate_bearer. The kernel's socket-file permission check is the enforcement (Node has no
//               SO_PEERCRED), hence split sockets.
// Approval is single use: pending -> applying (spent) BEFORE any write, base hash rechecked, bytes come from the
// gate's own version store, post-write hash verified, and an Ed25519-signed receipt carries the exact separate
// P-256 owner proof reference. Rate limits are global and per target, never per
// harness-chosen session label. Targets are injected; with an empty allowlist every proposal is refused.
import path from 'node:path'
import { ownerCardClarity } from './targets.mjs'
import { createHmac, randomUUID, randomBytes, sign, verify, timingSafeEqual } from 'node:crypto'
import { sha256, SHA, loadOrCreateKey, openDb, createLedger, signedEntryData,
  gateCompletedResultDigest, gateCaptureSigningBytes, entryBody } from './ledger.mjs'
import { loadOwnerSecret, rotateBearer } from './secrets.mjs'
import { lineDiff, cleanNote, noteMeta, cardWarnings, swatchText, noteDisplay } from './card.mjs'
// Concrete G protocol, not a caller-supplied verifier. Installed use requires an independently
// verified protected owner-key profile and installation; source fixtures do not qualify custody.
import { ownerRootPin } from '../../owner-key/src/index.mjs'
import { AUTHORIZATION_FIELDS, ownerAuthorization, ownerAuthorizationOwnerState, ownerAuthorizationText, ownerAuthorizationDigest,
  ownerAuthorizationProofText, verifyOwnerAuthorization } from '../../owner-key/src/authorization.mjs'

export const DEFAULT_LIMITS = Object.freeze({
  ttlMs: 5 * 60 * 1000, popupLimit: 12000, keepVersions: 50, whyMax: 4000,
  maxPendingGlobal: 1, maxPerWindow: 3, windowMs: 10 * 60 * 1000, rejectCooldownMs: 60 * 1000, dedupeMs: 10 * 60 * 1000,
  proposeMaxPerWindow: 32, proposeWindowMs: 60 * 1000,
})
const CLOSE_OUTCOMES = ['rejected', 'cancelled', 'unavailable', 'expired']
const APPLIED_EVENTS = "('apply','revert-applied','genesis-target')"
export const maskId = (id) => id ? String(id).slice(0, 8) + '…' : id

// targets: { [name]: { entry, maxBytes, schema, validate(text), accentOf?, plain?, after? } }
// store:   { read(name, spec) -> Buffer|null, write(name, spec, bytes, proposalId) }
export function createGate({ home, targets = {}, store, now = Date.now, limits = {}, key, owner, db, iso, readOwnerState, journalId } = {}) {
  const L = { ...DEFAULT_LIMITS, ...limits }
  if (!Number.isSafeInteger(L.proposeMaxPerWindow) || L.proposeMaxPerWindow < 1 || L.proposeMaxPerWindow > 1024
    || !Number.isSafeInteger(L.proposeWindowMs) || L.proposeWindowMs < 1000 || L.proposeWindowMs > 3600000)
    throw new Error('invalid trusted propose budget')
  key ??= loadOrCreateKey(home)
  owner ??= loadOwnerSecret(home)
  db ??= openDb(path.join(home, 'gate.db'))
  iso ??= () => new Date(now()).toISOString()
  const TARGETS = Object.freeze({ ...targets })
  const ledger = createLedger(db, key, iso)
  const append = ledger.append
  const synchronous = (value, label) => {
    if (value && (typeof value === 'object' || typeof value === 'function')) {
      for (let prototype = value; prototype !== null; prototype = Object.getPrototypeOf(prototype)) {
        const then = Object.getOwnPropertyDescriptor(prototype, 'then')
        if (then && (!Object.hasOwn(then, 'value') || typeof then.value === 'function')) throw new Error(`${label} must be synchronous`)
      }
    }
    return value
  }
  const tx = (fn, beforeCommit, refuseWithinLock) => { db.exec('BEGIN IMMEDIATE'); try {
    if (refuseWithinLock) db.exec('SAVEPOINT owner_claim')
    let r
    try {
      r = synchronous(fn(), 'gate transaction')
      if (beforeCommit) synchronous(beforeCommit(), 'gate commit guard')
    } catch (error) {
      if (!refuseWithinLock) throw error
      // Roll back all acceptance facts, but retain the same writer lock while durably burning
      // the attempted challenge. Releasing the lock first would let another process consume it.
      db.exec('ROLLBACK TO owner_claim; RELEASE owner_claim')
      r = synchronous(refuseWithinLock(error), 'gate refusal transaction')
    }
    db.exec('COMMIT'); return r
  } catch (e) { db.exec('ROLLBACK'); throw e } }
  const currentMs = () => {
    const value = synchronous(now(), 'gate clock')
    if (!Number.isSafeInteger(value) || Object.is(value, -0) || value < 0) throw new Error('invalid gate clock')
    return value
  }
  const gateId = sha256(key.pub.export({ type: 'spki', format: 'der' }))
  if (journalId !== undefined && (typeof journalId !== 'string' || journalId.length < 1 || journalId.length > 128
    || !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u.test(journalId) || /[^A-Za-z0-9._:-]/u.test(journalId)))
    throw new Error('trusted journalId must be a bounded public identifier')
  const OWNER_STATE_FIELDS = ['version', 'kind', 'owner_subject', 'owner_root_spki_base64', 'owner_root_id',
    'owner_epoch', 'registry_sha256', 'activation_sha256']
  // This callback is a trusted host registry source, never an RPC input or qualification boolean.
  // Configuring enforcement is durable; losing or corrupting the registry cannot restore legacy approval.
  function activeOwnerState() {
    if (typeof readOwnerState !== 'function') throw new Error('owner authorization unavailable: trusted owner state is unconfigured')
    const state = synchronous(readOwnerState(), 'trusted owner state')
    if (!state || typeof state !== 'object' || ![Object.prototype, null].includes(Object.getPrototypeOf(state))) throw new Error('invalid trusted owner state')
    const descriptors = Object.getOwnPropertyDescriptors(state), keys = Reflect.ownKeys(descriptors)
    if (keys.length !== OWNER_STATE_FIELDS.length || keys.some(k => typeof k !== 'string' || !OWNER_STATE_FIELDS.includes(k))) throw new Error('invalid trusted owner state')
    const out = Object.create(null)
    for (const field of OWNER_STATE_FIELDS) {
      const d = descriptors[field]
      if (!d?.enumerable || !Object.hasOwn(d, 'value')) throw new Error('invalid trusted owner state')
      out[field] = d.value
    }
    if (out.version !== 1 || out.kind !== 'aukora-owner-state/v1'
      || typeof out.owner_subject !== 'string' || !/^aukora:1:[0-9a-f]{64}$/u.test(out.owner_subject)
      || out.owner_subject.length !== 73 || !Number.isSafeInteger(out.owner_epoch) || out.owner_epoch < 1
      || !['owner_root_id', 'registry_sha256', 'activation_sha256'].every(k => typeof out[k] === 'string' && out[k].length === 64 && SHA.test(out[k]))
      || ownerRootPin(out.owner_root_spki_base64).owner_root_id !== out.owner_root_id) throw new Error('invalid trusted owner state')
    return Object.freeze(out)
  }
  function ownerAuthorizationRequired() {
    if (readOwnerState !== undefined) return true
    if (db.prepare('SELECT 1 FROM owner_authorization_required LIMIT 1').get()
      || db.prepare('SELECT 1 FROM owner_authorization_reviews LIMIT 1').get()
      || db.prepare('SELECT 1 FROM owner_authorization_consumptions LIMIT 1').get()
      || db.prepare("SELECT 1 FROM ledger WHERE event IN ('owner-authorization-required','owner-authorization-consumed') LIMIT 1").get()) return true
    // Older G issuance rows predate the marker. Signed history remains authoritative even if
    // a snapshot table is lost; unreadable history throws instead of selecting the legacy path.
    for (const row of db.prepare("SELECT detail FROM ledger WHERE event='review-issued'").iterate()) {
      const detail = JSON.parse(row.detail)
      if (!detail || typeof detail !== 'object' || Array.isArray(detail)) throw new Error('owner authorization history unavailable')
      if (['authorization_id', 'authorization_text', 'owner_state', 'gate_pubkey_sha256'].some(field => Object.hasOwn(detail, field))) return true
    }
    for (const row of db.prepare("SELECT detail FROM ledger WHERE event IN ('apply','revert-applied')").iterate()) {
      const detail = JSON.parse(row.detail)
      if (!detail || typeof detail !== 'object' || Array.isArray(detail)) throw new Error('owner authorization history unavailable')
      if (detail.receipt?.v === 3 || detail.receipt?.owner_authorization) return true
    }
    return false
  }
  function assertLegacyMode() {
    if (ownerAuthorizationRequired()) throw new Error('owner authorization required: legacy approval is permanently disabled')
  }
  // This enforcement latch does not enroll, activate, read or qualify an owner key. It is made
  // under the same writer lock used by legacy effects, so concurrent gates cannot downgrade it.
  if (ownerAuthorizationRequired()) tx(() => {
    if (!db.prepare('SELECT 1 FROM owner_authorization_required LIMIT 1').get()) {
      const e = append('owner-authorization-required', { detail: { version: 1, kind: 'aukora-owner-authorization-required/v1',
        gate_pubkey_sha256: gateId, reason: readOwnerState !== undefined ? 'trusted-reader-configured' : 'retained-G-history' } })
      const inserted = db.prepare('INSERT INTO owner_authorization_required VALUES(1,?,?,?)').run(gateId, e.seq, e.hash)
      if (inserted.changes !== 1) throw new Error('owner authorization enforcement latch unavailable')
    }
  })
  const spec = (target) => {
    if (typeof target !== 'string' || !Object.hasOwn(TARGETS, target))
      throw new Error(`target refused: ${JSON.stringify(String(target).slice(0, 120))} is not on the allowlist (${Object.keys(TARGETS).join(', ') || 'empty'}). Only declarative, schema-validated targets exist.`)
    return TARGETS[target]
  }
  const readCur = (target) => {
    const bytes = synchronous(store.read(target, TARGETS[target]), 'target read')
    if (bytes !== null && !Buffer.isBuffer(bytes)) throw new Error('target read must return Buffer or null')
    return bytes
  }
  const putBlob = (target, bytes) => db.prepare('INSERT OR IGNORE INTO blobs VALUES(?,?,?,?)').run(sha256(bytes), target, bytes, iso())
  const blobText = (sha) => { const b = db.prepare('SELECT bytes FROM blobs WHERE sha=?').get(sha); return b ? Buffer.from(b.bytes).toString('utf8') : '' }
  const setState = (id, from, to, note) => db.prepare('UPDATE proposals SET state=?, note=?, updated=? WHERE id=? AND state=?').run(to, note ?? null, now(), id, from).changes === 1

  const REVIEW_FACTS_UNAVAILABLE = 'UNAVAILABLE: release floor facts could not be read; owner approval is disabled.'
  function targetReviewSnapshot(s, oldText, newText, target, baseSha, finalizingApply = null) {
    if (typeof s?.reviewFacts !== 'function') return null
    try {
      const facts = synchronous(s.reviewFacts(oldText, newText), 'owner review facts')
      if (!facts || typeof facts.from_to !== 'string' || !/^[\x20-\x7e]{1,600}$/.test(facts.from_to)) throw new Error('owner preview unavailable')
      // Null is legitimate only for this gate's first approval. A deleted target must not
      // erase retained adopted/applied history and turn a lost floor into a fresh installation.
      const priorHistory = finalizingApply
        ? db.prepare(`SELECT 1 FROM ledger WHERE target=? AND event IN ${APPLIED_EVENTS}
          AND (seq!=? OR proposal IS NULL OR proposal!=? OR hash!=?) LIMIT 1`)
          .get(target, finalizingApply.seq, finalizingApply.proposal, finalizingApply.hash)
        : db.prepare(`SELECT 1 FROM ledger WHERE target=? AND event IN ${APPLIED_EVENTS} LIMIT 1`).get(target)
      if (facts.release_floor === null && (baseSha !== 'absent' || priorHistory))
        throw new Error('release floor is absent after prior target bytes or retained history; owner preview unavailable')
      // These are trusted target facts, never model/proof fields. Preserve the same readable
      // floor snapshot and visible ROLLBACK line in the original signed issuance row.
      return { available: true, from_to: facts.from_to, facts_text: JSON.stringify(facts) }
    } catch { return { available: false, from_to: null, facts_text: null } }
  }
  function proposalReviewSnapshot(p, finalizingApply = null) {
    if (finalizingApply) {
      const row = db.prepare('SELECT * FROM ledger WHERE seq=? AND hash=?').get(finalizingApply.seq, finalizingApply.hash)
      // Only the exact signed row just appended inside this effect transaction is current,
      // not prior history. Same-proposal rows at any other coordinate and genesis remain retained.
      if (!row || row.event !== (p.kind === 'revert' ? 'revert-applied' : 'apply') || row.proposal !== p.id
        || row.target !== p.target || row.base_sha !== p.base_sha || row.new_sha !== p.new_sha
        || sha256(entryBody(row)) !== row.hash
        || !verify(null, Buffer.from(row.hash, 'hex'), key.pub, Buffer.from(row.sig, 'base64')))
        throw new Error('owner review facts unavailable: exact finalizing apply row is invalid')
      finalizingApply = row
    }
    return targetReviewSnapshot(TARGETS[p.target], blobText(p.base_sha), blobText(p.new_sha), p.target, p.base_sha, finalizingApply)
  }
  function assertTargetReview(p, review, finalizingApply = null) {
    if (typeof TARGETS[p.target]?.reviewFacts !== 'function') return
    const issued = db.prepare('SELECT * FROM ledger WHERE seq=? AND hash=?').get(review.issue_seq, review.issue_hash)
    if (!issued || issued.event !== 'review-issued' || issued.proposal !== p.id || sha256(entryBody(issued)) !== issued.hash
      || !verify(null, Buffer.from(issued.hash, 'hex'), key.pub, Buffer.from(issued.sig, 'base64')))
      throw new Error('owner review facts unavailable: original signed review is missing or invalid')
    const retained = JSON.parse(issued.detail).target_review
    const current = proposalReviewSnapshot(p, finalizingApply)
    if (!retained?.available || !current?.available || JSON.stringify(current) !== JSON.stringify(retained))
      throw new Error('owner review facts unavailable or changed since review; a fresh review is required')
  }

  // LIVE EXPIRY SWEEP (2026-10-04). A pending proposal past its TTL is closed as expired the moment anyone looks
  // (propose rate check, OWNER pending list, owner page), not only at gate start: a stale row must neither block the
  // next proposal (max 1 pending) nor be put in front of the owner as if it were still decidable.
  function sweepExpired() {
    const legacy = !ownerAuthorizationRequired()
    for (const r of db.prepare(`SELECT id, target FROM proposals WHERE state='pending' AND expires ${legacy ? '<' : '<='} ?`).all(legacy ? now() : currentMs()))
      tx(() => { if (setState(r.id, 'pending', 'expired', 'expired (ttl elapsed, live sweep)')) append('expire', { proposal: r.id, target: r.target, detail: { reason: 'ttl elapsed' } }) })
  }
  function rateCheck(target, newSha) {
    sweepExpired()
    // ONE PENDING PER CLASS: agent targets share one slot; the operator-only plugin-set approval has its own, so a
    // 24 h owner-release wait never blocks the agent's theme and an agent proposal never blocks the owner's release.
    const cls = TARGETS[target]?.pendingClass ?? 'agent'
    const pend = db.prepare("SELECT target FROM proposals WHERE state IN ('pending','applying')").all().filter(r => (TARGETS[r.target]?.pendingClass ?? 'agent') === cls).length
    if (pend >= L.maxPendingGlobal) throw new Error(`refused (rate limit): ${pend} proposal already pending (max ${L.maxPendingGlobal} in total). Resolve it before proposing again.`)
    const winT = db.prepare('SELECT COUNT(*) n FROM proposals WHERE target=? AND created>?').get(target, now() - L.windowMs).n
    const winG = db.prepare('SELECT COUNT(*) n FROM proposals WHERE created>?').get(now() - L.windowMs).n
    if (winT >= L.maxPerWindow || winG >= L.maxPerWindow) throw new Error(`refused (rate limit): ${Math.max(winT, winG)} proposals in the last ${L.windowMs / 60000} min (max ${L.maxPerWindow} per target and in total).`)
    const lastRej = db.prepare("SELECT updated FROM proposals WHERE state='refused' ORDER BY updated DESC LIMIT 1").get()
    if (lastRej && now() - lastRej.updated < L.rejectCooldownMs) throw new Error(`refused (cooldown): a proposal was rejected ${Math.round((now() - lastRej.updated) / 1000)}s ago; wait ${Math.ceil((L.rejectCooldownMs - (now() - lastRej.updated)) / 1000)}s.`)
    if (db.prepare("SELECT 1 FROM proposals WHERE target=? AND new_sha=? AND state='refused' AND updated>? LIMIT 1").get(target, newSha, now() - L.dedupeMs))
      throw new Error(`refused (dedupe): an identical proposal (same target and result) was rejected in the last ${L.dedupeMs / 60000} min.`)
  }

  function buildPopup(p, oldText) {
    const s = TARGETS[p.target]
    const targetReview = targetReviewSnapshot(s, oldText || '', p.content, p.target, p.base_sha)
    return {
      marker: 'GATE-' + randomBytes(3).toString('hex'),
      after_apply: s.after ? s.after(p.content) : `AFTER APPLY: ${p.bytes} bytes`,
      plain_change: targetReview ? targetReview.available ? targetReview.from_to : REVIEW_FACTS_UNAVAILABLE
        : s.plain ? s.plain(oldText || '', p.content) : `${p.bytes} bytes change`,
      note: p.note_meta?.nonascii ? noteDisplay(p.why, p.note_meta) : (p.why ?? null),
      note_hexdump: p.note_meta?.hexdump ?? null,
      flags: [...cardWarnings(s, oldText || '', p.content, p.why, p.note_meta), ...(targetReview?.available === false ? [REVIEW_FACTS_UNAVAILABLE] : [])],
      swatch: swatchText(s, oldText || '', p.content),
      note_display: noteDisplay(p.why, p.note_meta),
      banner: 'Only the lines marked with the one-time code below are from the gate. The NOTE is text written by the model; it is not verified. This card does not approve - approval happens on the gate owner page.',
    }
  }

  function createProposal({ target, content, why, claimed_base, session, call_id }, kind, extra = {}) {
    const s = spec(target)
    if (typeof content !== 'string') throw new Error('content must be a string')
    if (!content.isWellFormed() || !/^[\x20-\x7e]*$/.test(content)) { append('reject', { target, detail: { reason: 'non-printable-ascii', kind } }); throw new Error('refused: content must be printable ASCII only (0x20-0x7e; no newlines, tabs, unicode or lone surrogates)') }
    const bytes = Buffer.from(content, 'utf8')
    if (bytes.length > s.maxBytes) { append('reject', { target, detail: { reason: 'oversized', bytes: bytes.length, max: s.maxBytes, kind } }); throw new Error(`refused: ${bytes.length} bytes exceeds the ${s.maxBytes}-byte limit for ${target}`) }
    try { synchronous(s.validate(content), 'target validation') } catch (e) { append('reject', { target, detail: { reason: 'schema', error: e.message, kind } }); throw new Error('refused (schema): ' + e.message) }
    if (why != null && String(why).length > L.whyMax) throw new Error('refused: why/summary too long')
    const cur = readCur(target); const baseSha = cur ? sha256(cur) : 'absent'
    if (kind !== 'revert') {
      if (typeof claimed_base !== 'string' || !(SHA.test(claimed_base) || claimed_base === 'absent')) { append('reject', { target, base_sha: baseSha, detail: { reason: 'no-base', kind } }); throw new Error(`refused as stale: base_sha256 is required (current sha256 is ${baseSha}). Blind overwrites are not accepted.`) }
      if (claimed_base !== baseSha) { append('reject', { target, base_sha: baseSha, detail: { reason: 'stale-base', claimed: claimed_base, kind } }); throw new Error(`refused as stale: you based this on ${claimed_base} but the current sha256 is ${baseSha}.`) }
    }
    const newSha = sha256(bytes)
    if (newSha === baseSha) throw new Error('refused: proposed content is identical to current content')
    rateCheck(target, newSha)
    const diff = lineDiff(cur ? cur.toString('utf8') : '', content, target)
    const displayable = diff.length + content.length <= L.popupLimit ? 1 : 0
    // Pending lifetime: the global TTL, or a target's own (only the operator-only plugin-set approval sets one). This is
    // how long the QUESTION waits for the owner; the decision window (review challenge, REVIEW_TTL_MS) is not lengthened.
    const ttl = Number.isInteger(s.ttlMs) && s.ttlMs > 0 && s.operatorOnly === true ? s.ttlMs : L.ttlMs
    const id = randomUUID(), created = now(), expires = created + ttl
    const w = cleanNote(why), meta = noteMeta(why)
    return tx(() => {
      if (cur) putBlob(target, cur); putBlob(target, bytes)
      db.prepare('INSERT INTO proposals VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)').run(id, kind, target, baseSha, newSha, diff, w, String(session ?? ''), String(call_id ?? ''), created, expires, displayable, 'pending', null, created)
      const e = append('propose', { proposal: id, target, base_sha: baseSha, new_sha: newSha, detail: { kind, note: w, note_meta: meta, session: String(session ?? ''), expires: new Date(expires).toISOString(), displayable: !!displayable, ...extra } })
      const p = { id, kind, target, entry: s.entry, base_sha: baseSha, new_sha: newSha, diff, content, bytes: bytes.length, why: w, note_meta: meta, created, expires, displayable: !!displayable, ledger_seq: e.seq }
      return { ...p, popup: buildPopup(p, cur ? cur.toString('utf8') : '') }
    })
  }

  // PROPOSE side may only reject/expire/cancel a pending proposal. It can NEVER approve.
  function close({ id, outcome }) {
    if (typeof id !== 'string') throw new Error('id required')
    const p = db.prepare('SELECT * FROM proposals WHERE id=?').get(id)
    // checked before the id lookup, so an approving close is refused (and recorded) even for unknown ids
    if (!CLOSE_OUTCOMES.includes(outcome)) {
      append('decide-refused', { proposal: p ? id : id.slice(0, 64), target: p?.target ?? null, detail: { reason: 'approval is not possible on the propose channel', outcome: String(outcome).slice(0, 40), via: 'propose-close', known_id: !!p } })
      throw new Error('refused: the harness channel cannot approve; approval happens only on the gate owner channel')
    }
    if (!p) return { applied: false, state: 'unknown', message: 'unknown proposal id' }
    if (!Object.hasOwn(TARGETS, p.target) || TARGETS[p.target].operatorOnly)
      throw new Error('refused: only the owner channel may close an operator-only proposal')
    const to = outcome === 'rejected' ? 'refused' : 'expired'
    return tx(() => {
      if (!setState(id, 'pending', to, String(outcome))) { append('decide-refused', { proposal: id, target: p.target, detail: { reason: 'not pending', state: p.state, outcome, via: 'propose-close' } }); return { applied: false, state: p.state, message: `proposal is ${p.state}` } }
      append('decide', { proposal: id, target: p.target, base_sha: p.base_sha, new_sha: p.new_sha, detail: { outcome: outcome === 'rejected' ? 'rejected' : 'cancelled', via: 'propose-close (harness); not an approval' } })
      return { applied: false, state: to, message: outcome }
    })
  }

  function prune(target) {
    const keep = db.prepare(`SELECT new_sha AS sha FROM ledger WHERE target=? AND event IN ${APPLIED_EVENTS} ORDER BY seq DESC LIMIT ?`).all(target, L.keepVersions).map(r => r.sha)
    const pendingShas = db.prepare("SELECT base_sha, new_sha FROM proposals WHERE target=? AND state IN ('pending','applying')").all(target).flatMap(r => [r.base_sha, r.new_sha])
    const live = new Set([...keep, ...pendingShas])
    for (const b of db.prepare('SELECT sha FROM blobs WHERE target=?').all(target))
      if (!live.has(b.sha) && !db.prepare(`SELECT 1 FROM ledger WHERE target=? AND new_sha=? AND event IN ${APPLIED_EVENTS} LIMIT 1`).get(target, b.sha)) db.prepare('DELETE FROM blobs WHERE sha=?').run(b.sha)
  }

  // Legacy approval remains the cached owner-channel ceremony until trusted G enforcement is configured.
  const legacyReviews = new Map()
  const legacyExactKeys = (a, keys) => a !== null && typeof a === 'object' && !Array.isArray(a)
    && Object.keys(a).length === keys.length && keys.every(k => Object.hasOwn(a, k))
  function legacyReview(args) {
    return tx(() => { assertLegacyMode(); return issueLegacyReview(args) }, () => {
      assertLegacyMode()
      const p = db.prepare('SELECT * FROM proposals WHERE id=?').get(args.id)
      if (typeof TARGETS[p?.target]?.reviewFacts !== 'function') return
      const reviewed = legacyReviews.get(args.id)
      const issue = reviewed && db.prepare('SELECT detail FROM ledger WHERE seq=? AND hash=?').get(reviewed.issue_seq, reviewed.issue_hash)
      if (!issue || JSON.stringify(proposalReviewSnapshot(p)) !== JSON.stringify(JSON.parse(issue.detail).target_review))
        throw new Error('owner review facts changed before legacy issuance commit')
    })
  }
  function legacyOwnerDecide({ id, outcome }, approver, reviewed) {
    if (typeof id !== 'string') throw new Error('id required')
    if (typeof approver !== 'string' || !approver) throw new Error('owner channel did not name the approver')
    const p = db.prepare('SELECT * FROM proposals WHERE id=?').get(id)
    if (!p) { append('decide-refused', { proposal: String(id).slice(0, 64), detail: { reason: 'unknown proposal', via: 'owner' } }); return { applied: false, state: 'unknown', message: 'unknown proposal id' } }
    if (outcome === 'rejected') return tx(() => {
      if (!setState(id, 'pending', 'refused', 'owner rejected')) return { applied: false, state: p.state, message: `proposal is ${p.state}` }
      append('decide', { proposal: id, target: p.target, base_sha: p.base_sha, new_sha: p.new_sha, detail: { outcome: 'rejected', via: 'owner', approver } })
      return { applied: false, state: 'refused', message: 'rejected' }
    })
    if (outcome !== 'allowed-once') throw new Error('unknown outcome')
    const s = spec(p.target)
    const pre = tx(() => {
      assertLegacyMode()
      const r = db.prepare('SELECT state, expires, displayable FROM proposals WHERE id=?').get(id)
      if (r.state !== 'pending') { append('decide-refused', { proposal: id, target: p.target, detail: { reason: 'replay: not pending', state: r.state, via: 'owner' } }); return { applied: false, state: r.state, message: `refused: already used or closed (state ${r.state}) — replay refused` } }
      if (now() > r.expires) { setState(id, 'pending', 'expired', 'approved after expiry'); append('decide-refused', { proposal: id, target: p.target, detail: { reason: 'approved after expiry', via: 'owner' } }); return { applied: false, state: 'expired', message: 'refused: approval arrived after expiry' } }
      if (!r.displayable) { setState(id, 'pending', 'refused', 'too large for popup'); append('decide-refused', { proposal: id, target: p.target, detail: { reason: 'TRUNCATED: approval disabled', via: 'owner' } }); return { applied: false, state: 'refused', message: 'refused: proposal too large to show in full; approval disabled' } }
      const cur = readCur(p.target); const curSha = cur ? sha256(cur) : 'absent'
      if (curSha !== p.base_sha) { setState(id, 'pending', 'stale', `base changed to ${curSha}`); append('decide-refused', { proposal: id, target: p.target, base_sha: p.base_sha, detail: { reason: 'stale base at approval', current: curSha, via: 'owner' } }); return { applied: false, state: 'stale', message: `refused as stale: target changed since proposal (now ${curSha})` } }
      if (typeof s.reviewFacts === 'function') assertTargetReview(p, reviewed)
      if (!setState(id, 'pending', 'applying', 'spent')) throw new Error('legacy spend compare-and-set failed')
      append('decide', { proposal: id, target: p.target, base_sha: p.base_sha, new_sha: p.new_sha, detail: { outcome: 'allowed-once', via: 'owner', approver, spent: true } })
      return null
    }, () => {
      assertLegacyMode()
      if (typeof s.reviewFacts === 'function' && db.prepare('SELECT state FROM proposals WHERE id=?').get(id)?.state === 'applying')
        assertTargetReview(p, reviewed)
    })
    if (pre) return pre
    let completed, finalizingApply = null
    try {
      completed = tx(() => {
        assertLegacyMode()
        // Startup recovery can acquire the writer between spend and effect. A lost applying
        // fence or changed base refuses here; the earlier durable spend is never retried.
        if (db.prepare('SELECT state FROM proposals WHERE id=?').get(id)?.state !== 'applying')
          throw new Error('legacy applying fence lost before write; replay refused')
        const current = readCur(p.target), currentSha = current ? sha256(current) : 'absent'
        if (currentSha !== p.base_sha) throw new Error('legacy base changed after spend; write refused')
        const bytes = db.prepare('SELECT bytes FROM blobs WHERE sha=?').get(p.new_sha)?.bytes
        if (!bytes || sha256(Buffer.from(bytes)) !== p.new_sha) throw new Error('approved bytes missing from version store')
        if (typeof s.reviewFacts === 'function') assertTargetReview(p, reviewed)
        synchronous(store.write(p.target, s, Buffer.from(bytes), id), 'target write')
        const after = readCur(p.target); const got = after ? sha256(after) : 'absent'
        if (got !== p.new_sha) throw new Error('post-write hash mismatch ' + got)
        assertLegacyMode()
        const evidence = createHmac('sha256', Buffer.from(owner.hmacKey, 'hex')).update(`${id}\n${p.base_sha}\n${p.new_sha}\n${approver}`).digest('base64')
        const receipt = { v: 2, kind: p.kind, proposal: id, target: p.target, base_sha: p.base_sha, new_sha: p.new_sha, applied_at: iso(), approver, approval_evidence_hmac: evidence, pubkey_fp: key.fp }
        const rsig = signReceipt(receipt)
        if (!setState(id, 'applying', 'applied', 'applied')) throw new Error('legacy apply compare-and-set failed')
        const e = append(p.kind === 'revert' ? 'revert-applied' : 'apply', { proposal: id, target: p.target, base_sha: p.base_sha, new_sha: p.new_sha, detail: { receipt, receipt_sig: rsig } })
        finalizingApply = e
        prune(p.target)
        return { applied: true, state: 'applied', entry: s.entry, receipt, receipt_sig: rsig, ledger_seq: e.seq, ledger_hash: e.hash, message: 'applied' }
      }, () => { assertLegacyMode(); if (typeof s.reviewFacts === 'function') assertTargetReview(p, reviewed, finalizingApply) })
    } catch (e) {
      let cur = null; try { const b = readCur(p.target); cur = b ? sha256(b) : 'absent' } catch {}
      tx(() => { const st = cur === p.new_sha ? 'applied' : 'failed'; setState(id, 'applying', st, String(e.message)); append(st === 'applied' ? 'apply' : 'apply-failed', { proposal: id, target: p.target, base_sha: p.base_sha, new_sha: p.new_sha, detail: { error: String(e.message), via: 'owner' } }) })
      throw e
    }
    return captureCompletedResult(completed)
  }
  function issueLegacyReview(args) {
    if (!legacyExactKeys(args, ['id']) || typeof args.id !== 'string') throw new Error('review takes exactly {id}')
    const p = db.prepare('SELECT * FROM proposals WHERE id=?').get(args.id)
    if (!p) throw new Error('unknown proposal id')
    if (p.state !== 'pending') throw new Error(`proposal is ${p.state}; only a pending proposal can be reviewed`)
    if (now() > p.expires) throw new Error('proposal expired')
    const target_review = proposalReviewSnapshot(p)
    const review_challenge = randomBytes(32).toString('hex')
    const review_expires = Math.min(p.expires, now() + REVIEW_TTL_MS)
    const e = append('review-issued', { proposal: p.id, target: p.target, base_sha: p.base_sha, new_sha: p.new_sha, detail: { via: 'owner', review_expires: new Date(review_expires).toISOString(), ...(target_review ? { target_review } : {}) } })
    legacyReviews.set(p.id, { challenge: review_challenge, expires: review_expires, base_sha: p.base_sha, new_sha: p.new_sha, issue_seq: e.seq, issue_hash: e.hash })
    // v2 (owner card, 2026-10-04): the GATE'S OWN from->to line (computed here from the stored base and new bytes by the
    // target's spec, never from model text) and the model's note, returned SEPARATELY and labelled as model-authored, so the
    // card can put the gate's facts and diff first and fence the model's words. The note is the sanitised why (<=120 ASCII).
    const s = TARGETS[p.target], newText = blobText(p.new_sha)
    let oldText = ''
    if (p.base_sha !== 'absent') { try { oldText = blobText(p.base_sha) } catch { oldText = '' } }
    let from_to = null
    try { from_to = target_review ? target_review.from_to : s?.plain ? String(s.plain(oldText, newText)) : null } catch { from_to = null }
    if (from_to !== null && !/^[\x20-\x7e]{1,600}$/.test(from_to)) from_to = null
    return { version: 2, id: p.id, kind: p.kind, target: p.target, base_sha: p.base_sha, new_sha: p.new_sha, content: newText, diff: p.diff,
      from_to, ...ownerCardClarity(s, p.kind), ...(target_review?.available === false ? { what_this_does: REVIEW_FACTS_UNAVAILABLE } : {}), model_note: p.why ?? null,
      displayable: !!p.displayable && target_review?.available !== false, created: p.created, expires: p.expires, review_challenge, review_expires, pubkey_fp: key.fp }
  }
  function legacyDecideReview(args, approver) {
    const id = args && typeof args === 'object' && typeof args.id === 'string' ? args.id : null
    const stored = id === null ? undefined : legacyReviews.get(id)
    if (id !== null) legacyReviews.delete(id)
    const refuse = (reason) => { append('decide-refused', { proposal: id === null ? null : id.slice(0, 64), detail: { reason, via: 'owner-review' } }); throw new Error(`refused: ${reason}`) }
    if (!legacyExactKeys(args, ['id', 'base_sha', 'new_sha', 'review_challenge', 'outcome'])) refuse('decide_review takes exactly {id, base_sha, new_sha, review_challenge, outcome}')
    if (!['allowed-once', 'rejected'].includes(args.outcome)) refuse('outcome must be allowed-once or rejected')
    if (!stored) refuse('no live review challenge for this id (review first; a challenge is single use)')
    if (typeof args.review_challenge !== 'string' || !/^[0-9a-f]{64}$/.test(args.review_challenge) ||
        !timingSafeEqual(Buffer.from(args.review_challenge, 'hex'), Buffer.from(stored.challenge, 'hex'))) refuse('review challenge mismatch')
    if (now() > stored.expires) refuse('review challenge expired')
    const p = db.prepare('SELECT * FROM proposals WHERE id=?').get(id)
    if (!p) refuse('unknown proposal id')
    if (args.base_sha !== stored.base_sha || args.new_sha !== stored.new_sha || p.base_sha !== stored.base_sha || p.new_sha !== stored.new_sha) refuse('base/new do not match the reviewed proposal')
    if (p.state !== 'pending') refuse(`proposal is ${p.state}`)
    if (now() > p.expires) refuse('proposal expired')
    if (!p.displayable) refuse('proposal too large to show in full; approval disabled')
    assertLegacyMode()
    return legacyOwnerDecide({ id, outcome: args.outcome }, approver, stored)
  }

  // Rejection needs no owner signature. Every G effect follows durable proof consumption.
  function ownerDecide({ id, outcome }, approver) {
    if (typeof id !== 'string') throw new Error('id required')
    if (outcome !== 'rejected') throw new Error('allowed-once requires an owner authorization proof through decide_review')
    const p = db.prepare('SELECT * FROM proposals WHERE id=?').get(id)
    if (!p) return { applied: false, state: 'unknown', message: 'unknown proposal id' }
    return tx(() => {
      if (!setState(id, 'pending', 'refused', 'owner rejected')) return { applied: false, state: p.state, message: `proposal is ${p.state}` }
      db.prepare("UPDATE owner_authorization_reviews SET state='invalidated', spent_at_ms=? WHERE proposal_id=? AND state='live'").run(currentMs(), id)
      append('decide', { proposal: id, target: p.target, base_sha: p.base_sha, new_sha: p.new_sha,
        detail: { outcome: 'rejected', via: 'owner', approver: String(approver ?? '') } })
      return { applied: false, state: 'refused', message: 'rejected' }
    })
  }

  function retainedReceipt(p, consumption, appliedAt = iso()) {
    const state = JSON.parse(consumption.owner_state_text)
    return { v: 3, kind: p.kind, proposal: p.id, target: p.target, base_sha: p.base_sha, new_sha: p.new_sha,
      applied_at: appliedAt, approver: state.owner_subject, pubkey_fp: key.fp, gate_pubkey_sha256: consumption.gate,
      owner_authorization: { version: 1, kind: 'aukora-owner-authorization-ref/v1',
        authorization_id: consumption.authorization_id, proof_sha256: consumption.proof_sha256 },
      owner_accepted_at_ms: consumption.accepted_at_ms,
      owner_consumption: { ledger_seq: consumption.consume_seq, ledger_hash: consumption.consume_hash,
        review_issue: { ledger_seq: consumption.issue_seq, ledger_hash: consumption.issue_hash } } }
  }
  function recordApplied(p, consumption, note, extra = {}) {
    const receipt = retainedReceipt(p, consumption), receipt_sig = signReceipt(receipt)
    if (!setState(p.id, 'applying', 'applied', note)) throw new Error('apply state compare-and-set failed')
    const e = append(p.kind === 'revert' ? 'revert-applied' : 'apply', { proposal: p.id, target: p.target,
      base_sha: p.base_sha, new_sha: p.new_sha, detail: { receipt, receipt_sig, ...extra } })
    return { applied: true, state: 'applied', entry: TARGETS[p.target]?.entry, receipt, receipt_sig,
      ledger_seq: e.seq, ledger_hash: e.hash, message: 'applied' }
  }
  // Consumption commits first and remains spent if this process dies. Dispatch
  // must then win the SAME writer fence as startup reconciliation; a prior
  // applying snapshot is not permission to write after another gate closes it.
  function assertRetainedConsumption(p, c, review) {
    const consumed = db.prepare('SELECT * FROM ledger WHERE seq=? AND hash=?').get(c.consume_seq, c.consume_hash)
    const issue = db.prepare('SELECT * FROM ledger WHERE seq=? AND hash=?').get(c.issue_seq, c.issue_hash)
    if (!p || c.gate !== gateId || !review || review.state !== 'spent' || review.proposal_id !== p.id
      || review.authorization_id !== c.authorization_id || review.owner_state_text !== c.owner_state_text
      || review.spend_seq !== c.consume_seq || review.spent_at_ms !== c.accepted_at_ms
      || review.issue_seq !== c.issue_seq || review.issue_hash !== c.issue_hash
      || !consumed || consumed.event !== 'owner-authorization-consumed' || !issue || issue.event !== 'review-issued'
      || [consumed, issue].some(row => row.proposal !== p.id || row.target !== p.target
        || row.base_sha !== p.base_sha || row.new_sha !== p.new_sha))
      throw new Error('original consumed-effect binding unavailable')
    const detail = JSON.parse(consumed.detail), issued = JSON.parse(issue.detail)
    const state = ownerAuthorizationOwnerState(JSON.parse(c.owner_state_text))
    const authorization = ownerAuthorization(JSON.parse(review.authorization_text))
    if (ownerAuthorizationText(authorization) !== review.authorization_text
      || authorization.gate !== c.gate || authorization.challenge !== c.challenge || authorization.proposal_id !== p.id
      || authorization.operation !== p.kind || authorization.target !== p.target
      || authorization.before_sha256 !== p.base_sha || authorization.after_sha256 !== p.new_sha
      || authorization.issued_at_ms !== review.issued_at_ms || authorization.expires_at_ms !== review.expires_at_ms
      || authorization.owner_subject !== state.owner_subject || authorization.owner_root_id !== state.owner_root_id
      || authorization.owner_epoch !== state.owner_epoch
      || issued.authorization_text !== review.authorization_text || issued.authorization_id !== c.authorization_id
      || issued.gate_pubkey_sha256 !== c.gate || issued.issued_at_ms !== review.issued_at_ms
      || issued.expires_at_ms !== review.expires_at_ms || JSON.stringify(issued.owner_state) !== c.owner_state_text
      || detail.outcome !== 'allowed-once' || detail.operation !== p.kind || detail.spent !== true
      || detail.accepted_at_ms !== c.accepted_at_ms || detail.proof_text !== c.proof_text
      || detail.owner_authorization?.authorization_id !== c.authorization_id
      || detail.owner_authorization?.proof_sha256 !== c.proof_sha256
      || JSON.stringify(detail.owner_state) !== c.owner_state_text
      || detail.review_issue?.ledger_seq !== c.issue_seq || detail.review_issue?.ledger_hash !== c.issue_hash)
      throw new Error('original signed consumption or issuance differs from retained facts')
    // Historical proof validation uses its original accepted instant/root. A current
    // epoch change never revives it and must not invalidate factual old outcomes.
    const verified = verifyOwnerAuthorization(JSON.parse(c.proof_text), {
      owner_root_spki_base64: state.owner_root_spki_base64, authorization_digest: c.authorization_id,
      ...Object.fromEntries(AUTHORIZATION_FIELDS.map(field => [field, authorization[field]])) }, c.accepted_at_ms)
    if (verified.reference.proof_sha256 !== c.proof_sha256 || ownerAuthorizationProofText(verified.proof) !== c.proof_text)
      throw new Error('original owner proof differs from retained consumption')
  }
  function retainedConsumptions() {
    const rows = db.prepare('SELECT * FROM owner_authorization_consumptions').all()
    if (db.prepare("SELECT count(*) AS n FROM ledger WHERE event='owner-authorization-consumed'").get().n !== rows.length)
      throw new Error('original consumption retention unavailable')
    for (const c of rows) assertRetainedConsumption(
      db.prepare('SELECT * FROM proposals WHERE id=?').get(c.proposal_id), c,
      db.prepare('SELECT * FROM owner_authorization_reviews WHERE gate=? AND challenge=?').get(c.gate, c.challenge))
    return rows
  }
  function assertConsumedEffect(p, consumption) {
    const current = db.prepare('SELECT * FROM proposals WHERE id=?').get(p.id)
    const retained = db.prepare('SELECT * FROM owner_authorization_consumptions WHERE proposal_id=?').get(p.id)
    const review = db.prepare('SELECT * FROM owner_authorization_reviews WHERE gate=? AND challenge=?')
      .get(consumption.gate, consumption.challenge)
    if (!current || current.state !== 'applying'
      || ['kind', 'target', 'base_sha', 'new_sha', 'created', 'expires', 'displayable'].some(field => current[field] !== p[field])
      || !retained || JSON.stringify(retained) !== JSON.stringify(consumption)
      || !review || review.state !== 'spent' || review.proposal_id !== p.id
      || review.authorization_id !== consumption.authorization_id || review.owner_state_text !== consumption.owner_state_text
      || review.spend_seq !== consumption.consume_seq || review.issue_seq !== consumption.issue_seq
      || review.issue_hash !== consumption.issue_hash || !ledger.verify().ok)
      throw new Error('owner effect fence unavailable: original applying consumption changed')
    assertRetainedConsumption(p, consumption, review)
    const before = readCur(p.target)
    if ((before ? sha256(before) : 'absent') !== p.base_sha)
      throw new Error('owner effect fence unavailable: stale base before dispatch')
    const ownerState = activeOwnerState(), at = currentMs()
    if (JSON.stringify(ownerState) !== consumption.owner_state_text
      || at < consumption.accepted_at_ms || at >= review.expires_at_ms || at >= p.expires)
      throw new Error('owner effect fence unavailable: owner state or expiry changed before dispatch')
  }
  function applyConsumed(p, consumption) {
    const s = spec(p.target)
    let completed
    try {
      completed = tx(() => {
        const bytes = db.prepare('SELECT bytes FROM blobs WHERE sha=?').get(p.new_sha)?.bytes
        if (!bytes || sha256(Buffer.from(bytes)) !== p.new_sha) throw new Error('approved bytes missing from version store')
        synchronous(s.validate(Buffer.from(bytes).toString('utf8')), 'target validation')
        assertTargetReview(p, consumption)
        assertConsumedEffect(p, consumption)
        synchronous(store.write(p.target, s, Buffer.from(bytes), p.id), 'target write')
        const after = readCur(p.target); const got = after ? sha256(after) : 'absent'
        if (got !== p.new_sha) throw new Error('post-write hash mismatch ' + got)
        const result = recordApplied(p, consumption, 'applied'); prune(p.target); return result
      }, () => {
        const review = db.prepare('SELECT * FROM owner_authorization_reviews WHERE gate=? AND challenge=?')
          .get(consumption.gate, consumption.challenge)
        const ownerState = activeOwnerState(), at = currentMs()
        if (!review || review.state !== 'spent' || JSON.stringify(ownerState) !== consumption.owner_state_text
          || at < consumption.accepted_at_ms || at >= review.expires_at_ms || at >= p.expires)
          throw new Error('owner state or expiry changed before effect commit; spent outcome requires reconciliation')
      })
    } catch (error) {
      // Preserve original proof/spend through every failure. Reconciliation never repeats the effect.
      // If a write happened but receipt finalization failed, leave applying as a durable recovery fence.
      let cur = null, readable = false
      try { const bytes = readCur(p.target); cur = bytes ? sha256(bytes) : 'absent'; readable = true } catch {}
      try { tx(() => {
        if (!readable || cur !== p.base_sha) append('apply-incomplete', { proposal: p.id, target: p.target, base_sha: p.base_sha,
          new_sha: p.new_sha, detail: { error: String(error.message), owner_authorization: retainedReceipt(p, consumption).owner_authorization,
            consumption_seq: consumption.consume_seq, current: readable ? cur : null,
            result: readable && cur === p.new_sha ? 'bytes present; receipt incomplete; no retry'
              : readable ? 'unexpected bytes; effect unresolved; no retry' : 'target unreadable; effect unknown; no retry' } })
        else {
          if (!setState(p.id, 'applying', 'failed', String(error.message))) throw new Error('failed state compare-and-set failed')
          append('apply-failed', { proposal: p.id, target: p.target, base_sha: p.base_sha, new_sha: p.new_sha,
            detail: { error: String(error.message), consumption_seq: consumption.consume_seq, result: 'spent; no retry' } })
        }
      }) } catch { /* A failed audit write leaves the already committed applying/spend fence intact. */ }
      throw error
    }
    return captureCompletedResult(completed)
  }
  function captureCompletedResult(completed) {
    // Separate post-COMMIT capture avoids a circular apply-ledger hash. No model/request value
    // chooses this journal; unconfigured, failed or reconstructed completions have no capture.
    if (journalId === undefined) return completed
    const capture = Object.freeze({ version: 1, kind: 'aukora-gate-capture/v1',
      source: Object.freeze({ journal_id: journalId, position: completed.ledger_seq, hash: completed.ledger_hash }),
      proposal_id: completed.receipt.proposal, gate_pubkey_sha256: gateId,
      completed_result_sha256: gateCompletedResultDigest(completed) })
    const gate_capture = Object.freeze({ capture, signature_base64: sign(null, gateCaptureSigningBytes(capture), key.priv).toString('base64') })
    const original = Object.freeze({ ...completed, gate_capture })
    // Retain the ORIGINAL completed result after apply COMMIT/capture mint and before returning.
    // Failure here leaves applied intact but polling cannot invent or re-sign the lost completion.
    tx(() => ledger.retainCompletedResult(original, currentMs()))
    return original
  }

  const REVIEW_TTL_MS = 120000
  const exactKeys = (a, keys) => {
    if (!a || typeof a !== 'object' || ![Object.prototype, null].includes(Object.getPrototypeOf(a))) return false
    const descriptors = Object.getOwnPropertyDescriptors(a), found = Reflect.ownKeys(descriptors)
    return found.length === keys.length && found.every(k => typeof k === 'string' && keys.includes(k))
      && keys.every(k => descriptors[k]?.enumerable && Object.hasOwn(descriptors[k], 'value'))
  }
  function reviewAuthorized(args) {
    if (!exactKeys(args, ['id']) || typeof args.id !== 'string') throw new Error('review takes exactly {id}')
    const issued = tx(() => {
      const p = db.prepare('SELECT * FROM proposals WHERE id=?').get(args.id)
      if (!p || p.state !== 'pending') throw new Error('only a pending proposal can be reviewed')
      const state = activeOwnerState(), issued_at_ms = currentMs()
      if (issued_at_ms >= p.expires) throw new Error('proposal expired')
      const target_review = proposalReviewSnapshot(p)
      const expires_at_ms = Math.min(p.expires, issued_at_ms + REVIEW_TTL_MS)
      const authorization = ownerAuthorization({ version: 1, kind: 'aukora-owner-authorization/v1', operation: p.kind,
        proposal_id: p.id, target: p.target, before_sha256: p.base_sha, after_sha256: p.new_sha,
        gate: gateId, challenge: randomBytes(32).toString('hex'), issued_at_ms, expires_at_ms,
        owner_subject: state.owner_subject, owner_root_id: state.owner_root_id, owner_epoch: state.owner_epoch })
      const authorization_text = ownerAuthorizationText(authorization), authorization_id = ownerAuthorizationDigest(authorization)
      const owner_state_text = JSON.stringify(state)
      db.prepare("UPDATE owner_authorization_reviews SET state='invalidated', spent_at_ms=? WHERE proposal_id=? AND state='live'").run(issued_at_ms, p.id)
      const e = append('review-issued', { proposal: p.id, target: p.target, base_sha: p.base_sha, new_sha: p.new_sha,
        detail: { via: 'owner', authorization_text, authorization_id, owner_state: state,
          issued_at_ms, expires_at_ms, gate_pubkey_sha256: gateId, ...(target_review ? { target_review } : {}) } })
      db.prepare(`INSERT INTO owner_authorization_reviews(gate,challenge,proposal_id,authorization_id,authorization_text,
        owner_state_text,issued_at_ms,expires_at_ms,issue_seq,issue_hash,state) VALUES(?,?,?,?,?,?,?,?,?,?,'live')`)
        .run(gateId, authorization.challenge, p.id, authorization_id, authorization_text, owner_state_text,
          issued_at_ms, expires_at_ms, e.seq, e.hash)
      return { p, authorization, authorization_id, owner_state_text, target_review, issue_seq: e.seq, issue_hash: e.hash }
    }, () => {
      const live = db.prepare("SELECT * FROM owner_authorization_reviews WHERE proposal_id=? AND state='live'").get(args.id)
      if (!live || JSON.stringify(activeOwnerState()) !== live.owner_state_text)
        throw new Error('owner state or review validity changed before issuance commit')
      const p = db.prepare('SELECT * FROM proposals WHERE id=?').get(args.id)
      const issue = db.prepare('SELECT detail FROM ledger WHERE seq=? AND hash=?').get(live.issue_seq, live.issue_hash)
      if (!p || !issue || JSON.stringify(proposalReviewSnapshot(p)) !== JSON.stringify(JSON.parse(issue.detail).target_review ?? null))
        throw new Error('owner review facts changed before issuance commit')
      const at = currentMs()
      if (at < live.issued_at_ms || at >= live.expires_at_ms) throw new Error('review validity changed at final issuance clock')
    })
    const { p, authorization, target_review } = issued
    const s = TARGETS[p.target], newText = blobText(p.new_sha)
    let oldText = ''
    if (p.base_sha !== 'absent') { try { oldText = blobText(p.base_sha) } catch {} }
    let from_to = null
    try { from_to = target_review ? target_review.from_to : s?.plain ? String(synchronous(s.plain(oldText, newText), 'owner preview')) : null } catch {}
    if (from_to !== null && !/^[\x20-\x7e]{1,600}$/.test(from_to)) from_to = null
    return { version: 3, id: p.id, kind: p.kind, target: p.target, base_sha: p.base_sha, new_sha: p.new_sha, content: newText, diff: p.diff,
      from_to, ...ownerCardClarity(s, p.kind), ...(target_review?.available === false ? { what_this_does: REVIEW_FACTS_UNAVAILABLE } : {}),
      model_note: p.why ?? null, displayable: !!p.displayable && target_review?.available !== false,
      created: p.created, expires: p.expires, review_challenge: authorization.challenge,
      review_expires: authorization.expires_at_ms, review_issued_at_ms: authorization.issued_at_ms,
      pubkey_fp: key.fp, gate_pubkey_sha256: gateId, owner_authorization: authorization,
      authorization_digest: issued.authorization_id, review_issue: { ledger_seq: issued.issue_seq, ledger_hash: issued.issue_hash } }
  }

  function decideAuthorized(args, approver) {
    // An owner-channel attempt invalidates its current review even when malformed. No proof is
    // retained as accepted and no proposal becomes applying unless the complete transaction commits.
    const idDescriptor = args && typeof args === 'object' ? Object.getOwnPropertyDescriptor(args, 'id') : null
    const id = idDescriptor && Object.hasOwn(idDescriptor, 'value') && typeof idDescriptor.value === 'string' ? idDescriptor.value : null
    const consumed = tx(() => {
        const fields = ['id', 'base_sha', 'new_sha', 'review_challenge', 'outcome']
        const outcome = args && typeof args === 'object' ? Object.getOwnPropertyDescriptor(args, 'outcome') : null
        if (outcome && Object.hasOwn(outcome, 'value') && outcome.value === 'allowed-once') fields.push('owner_authorization_proof')
        if (!exactKeys(args, fields)) throw new Error('decide_review requires exact review fields and an owner proof for allowed-once')
        if (!['allowed-once', 'rejected'].includes(args.outcome)) throw new Error('outcome must be allowed-once or rejected')
        const r = db.prepare("SELECT * FROM owner_authorization_reviews WHERE proposal_id=? AND state='live'").get(id)
        if (!r) throw new Error('no live durable review challenge (single use)')
        if (typeof args.review_challenge !== 'string' || !/^[0-9a-f]{64}$/u.test(args.review_challenge)
          || args.review_challenge.length !== 64 || !timingSafeEqual(Buffer.from(args.review_challenge, 'hex'), Buffer.from(r.challenge, 'hex')))
          throw new Error('review challenge mismatch')
        const p = db.prepare('SELECT * FROM proposals WHERE id=?').get(id)
        const a = JSON.parse(r.authorization_text)
        if (!p || p.state !== 'pending') throw new Error('proposal is not pending; replay refused')
        if (args.base_sha !== a.before_sha256 || args.new_sha !== a.after_sha256 || p.base_sha !== a.before_sha256
          || p.new_sha !== a.after_sha256 || p.kind !== a.operation || p.target !== a.target || a.gate !== gateId)
          throw new Error('proposal does not match the durable review')
        const at = currentMs()
        if (at < r.issued_at_ms || at >= r.expires_at_ms || at >= p.expires) throw new Error('review or proposal expired')
        if (args.outcome === 'rejected') {
          const spent = db.prepare("UPDATE owner_authorization_reviews SET state='invalidated', spent_at_ms=? WHERE gate=? AND challenge=? AND state='live'").run(at, gateId, r.challenge)
          if (spent.changes !== 1 || !setState(id, 'pending', 'refused', 'owner rejected')) throw new Error('rejection compare-and-set failed')
          append('decide', { proposal: id, target: p.target, base_sha: p.base_sha, new_sha: p.new_sha,
            detail: { outcome: 'rejected', via: 'owner-review', approver: String(approver ?? ''), review_issue: { ledger_seq: r.issue_seq, ledger_hash: r.issue_hash } } })
          return { rejected: true }
        }
        const state = activeOwnerState()
        if (JSON.stringify(state) !== r.owner_state_text) throw new Error('active owner state changed since review')
        const expectations = { owner_root_spki_base64: state.owner_root_spki_base64, authorization_digest: r.authorization_id,
          ...Object.fromEntries(AUTHORIZATION_FIELDS.map(field => [field, a[field]])) }
        const verified = verifyOwnerAuthorization(args.owner_authorization_proof, expectations, currentMs())
        if (!p.displayable) throw new Error('proposal too large to show in full; approval disabled')
        const s = spec(p.target)
        const cur = readCur(p.target), curSha = cur ? sha256(cur) : 'absent'
        if (curSha !== p.base_sha) throw new Error('stale base at owner authorization')
        const stored = db.prepare('SELECT bytes FROM blobs WHERE sha=?').get(p.new_sha)?.bytes
        if (!stored || sha256(Buffer.from(stored)) !== p.new_sha) throw new Error('approved bytes missing from version store')
        synchronous(s.validate(Buffer.from(stored).toString('utf8')), 'target validation')
        assertTargetReview(p, r)
        const accepted_at_ms = currentMs(), proof_text = ownerAuthorizationProofText(verified.proof)
        if (accepted_at_ms < r.issued_at_ms || accepted_at_ms >= r.expires_at_ms || accepted_at_ms >= p.expires) throw new Error('owner authorization expired before consumption')
        if (journalId !== undefined) {
          let existing
          try { existing = db.prepare('SELECT 1 FROM gate_completed_results WHERE proposal_id=?').get(id) }
          catch { throw new Error('owner authorization unavailable: original completion store is unavailable') }
          if (existing) throw new Error('original completed result already retained; replay refused')
        }
        const e = append('owner-authorization-consumed', { proposal: id, target: p.target, base_sha: p.base_sha, new_sha: p.new_sha,
          detail: { outcome: 'allowed-once', operation: p.kind, via: 'owner-review', approver: state.owner_subject,
            channel: String(approver ?? ''), spent: true, accepted_at_ms, owner_authorization: verified.reference,
            proof_text, owner_state: state, review_issue: { ledger_seq: r.issue_seq, ledger_hash: r.issue_hash } } })
        db.prepare(`INSERT INTO owner_authorization_consumptions(authorization_id,proof_sha256,gate,challenge,proposal_id,
          proof_text,accepted_at_ms,consume_seq,consume_hash,issue_seq,issue_hash,owner_state_text) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`)
          .run(verified.reference.authorization_id, verified.reference.proof_sha256, gateId, r.challenge, id, proof_text,
            accepted_at_ms, e.seq, e.hash, r.issue_seq, r.issue_hash, r.owner_state_text)
        const spent = db.prepare("UPDATE owner_authorization_reviews SET state='spent', spent_at_ms=?, spend_seq=? WHERE gate=? AND challenge=? AND authorization_id=? AND state='live'")
          .run(accepted_at_ms, e.seq, gateId, r.challenge, verified.reference.authorization_id)
        if (spent.changes !== 1 || !setState(id, 'pending', 'applying', 'owner authorization spent')) throw new Error('owner consumption compare-and-set failed')
        return { p, review: r, consumption: db.prepare('SELECT * FROM owner_authorization_consumptions WHERE proposal_id=?').get(id) }
      }, () => {
        const c = db.prepare('SELECT * FROM owner_authorization_consumptions WHERE proposal_id=?').get(id)
        if (!c) return // Rejection has no proof consumption.
        const r = db.prepare('SELECT * FROM owner_authorization_reviews WHERE gate=? AND challenge=?').get(c.gate, c.challenge)
        const p = db.prepare('SELECT * FROM proposals WHERE id=?').get(id)
        if (!r || r.state !== 'spent' || !p || p.state !== 'applying' || JSON.stringify(activeOwnerState()) !== c.owner_state_text)
          throw new Error('owner state or spent transition changed before commit')
        assertTargetReview(p, c)
        const at = currentMs()
        if (at < c.accepted_at_ms || at >= r.expires_at_ms || at >= p.expires) throw new Error('owner authorization expired at final commit clock')
      }, error => {
        if (id !== null) db.prepare("UPDATE owner_authorization_reviews SET state='invalidated', spent_at_ms=? WHERE proposal_id=? AND state='live'").run(currentMs(), id)
        append('decide-refused', { proposal: id === null ? null : id.slice(0, 64),
          detail: { reason: String(error.message), via: 'owner-review', result: 'no accepted consumption; no effect' } })
        return { refused_error: error }
      })
    if (consumed.refused_error) throw consumed.refused_error
    if (consumed.rejected) return { applied: false, state: 'refused', message: 'rejected' }
    return applyConsumed(consumed.p, consumed.consumption)
  }
  function review(args) {
    return ownerAuthorizationRequired() ? reviewAuthorized(args) : legacyReview(args)
  }
  function decideReview(args, approver) {
    return ownerAuthorizationRequired() ? decideAuthorized(args, approver) : legacyDecideReview(args, approver)
  }
  const signReceipt = (receipt) => sign(null, Buffer.from(JSON.stringify(receipt)), key.priv).toString('base64')

  // Version history of a target from the ledger (applied, reverted and adopted versions, newest first).
  function history(target) {
    spec(target); const cur = readCur(target); const curSha = cur ? sha256(cur) : 'absent'
    const rows = db.prepare(`SELECT seq, at, event, proposal, new_sha FROM ledger WHERE target=? AND event IN ${APPLIED_EVENTS} ORDER BY seq DESC LIMIT ?`).all(target, L.keepVersions)
    const seen = new Set(), versions = []
    for (const r of rows) {
      if (seen.has(r.new_sha)) continue; seen.add(r.new_sha); const b = db.prepare('SELECT bytes FROM blobs WHERE sha=?').get(r.new_sha)
      versions.push({ sha256: r.new_sha, last_applied_at: r.at, ledger_seq: r.seq, event: r.event, current: r.new_sha === curSha, available: !!b, content: b ? Buffer.from(b.bytes).toString('utf8') : null })
    }
    return { target, current_sha256: curSha, versions }
  }
  // Revert = a new proposal of an earlier applied version's exact bytes; it needs the same owner approval.
  function revert({ target, to_sha, why, session, call_id }) {
    spec(target); let to = to_sha
    if (to === 'previous' || to == null) { const prev = history(target).versions.find(v => !v.current); if (!prev) throw new Error('nothing to revert: no earlier applied version recorded'); to = prev.sha256 }
    if (typeof to !== 'string' || !SHA.test(to)) throw new Error('to_sha256 must be a 64-hex sha256 from change_log / read_target history')
    if (!db.prepare(`SELECT 1 FROM ledger WHERE target=? AND new_sha=? AND event IN ${APPLIED_EVENTS} LIMIT 1`).get(target, to)) throw new Error(`refused: ${to} was never an applied version of ${target}`)
    const b = db.prepare('SELECT bytes FROM blobs WHERE sha=?').get(to); if (!b) throw new Error(`refused: version ${to} is no longer kept`)
    const stored = Buffer.from(b.bytes), text = stored.toString('utf8')
    if (sha256(stored) !== to || !Buffer.from(text, 'utf8').equals(stored)) throw new Error(`refused: stored version ${to} does not round-trip byte-for-byte`)
    return createProposal({ target, content: text, why: why ?? `revert ${target} to ${to}`, session, call_id }, 'revert', { revert_to: to })
  }

  // Start-up: adopt valid current target bytes as revertable versions, reconcile approvals interrupted by a
  // crash (never replayed), expire stale pending proposals, and record a gate-start entry with the ledger state.
  function legacyStartup({ pid = process.pid, bearerInfo = null, extra = {} } = {}) {
    const startupTx = fn => synchronous(fn(), 'legacy startup transaction')
    for (const [t, s] of Object.entries(TARGETS)) {
      const cur = readCur(t); let validCur = true
      try { if (cur) { const txt = cur.toString('utf8'); if (!/^[\x20-\x7e]*$/.test(txt)) throw new Error('non-ASCII'); s.validate(txt) } }
      catch (e) { validCur = false; append('genesis-target-invalid', { target: t, new_sha: sha256(cur), detail: { error: String(e.message).slice(0, 200) } }) }
      if (cur && validCur && !db.prepare(`SELECT 1 FROM ledger WHERE target=? AND new_sha=? AND event IN ${APPLIED_EVENTS} LIMIT 1`).get(t, sha256(cur)))
        startupTx(() => { putBlob(t, cur); append('genesis-target', { target: t, new_sha: sha256(cur), detail: { note: 'current bytes adopted at gate start' } }) })
    }
    for (const r of db.prepare("SELECT * FROM proposals WHERE state='applying'").all()) {
      let cur = null; try { const b = Object.hasOwn(TARGETS, r.target) ? readCur(r.target) : null; cur = b ? sha256(b) : 'absent' } catch {}
      startupTx(() => {
        if (cur === r.new_sha) { setState(r.id, 'applying', 'applied', 'reconciled after crash: bytes present'); append('reconcile', { proposal: r.id, target: r.target, base_sha: r.base_sha, new_sha: r.new_sha, detail: { result: 'applied' } }) }
        else if (cur === r.base_sha) { setState(r.id, 'applying', 'failed', 'reconciled: not written; spent; NOT re-applied'); append('reconcile', { proposal: r.id, target: r.target, base_sha: r.base_sha, new_sha: r.new_sha, detail: { result: 'failed: not written, spent, NOT replayed' } }) }
        else { setState(r.id, 'applying', 'conflict', `file ${cur} matches neither`); append('reconcile', { proposal: r.id, target: r.target, detail: { result: 'conflict', current: cur } }) }
      })
    }
    for (const r of db.prepare("SELECT id, target FROM proposals WHERE state='pending' AND expires < ?").all(now()))
      startupTx(() => { setState(r.id, 'pending', 'expired', 'expired (gate start)'); append('expire', { proposal: r.id, target: r.target, detail: { reason: 'ttl elapsed' } }) })
    const v = ledger.verify()
    append('gate-start', { detail: { pid, ledger_ok_before_start: v.ok, entries: v.entries, pubkey_fp: key.fp, owner_bearer: bearerInfo ? { rotated: true, fp8: bearerInfo.fp, expires: bearerInfo.expires } : null, ...extra } })
    return v
  }

  function startup({ pid = process.pid, bearerInfo = null, extra = {} } = {}) {
    if (!ownerAuthorizationRequired()) {
      let selected = false
      const legacy = tx(() => {
        if (ownerAuthorizationRequired()) return null
        selected = true
        return legacyStartup({ pid, bearerInfo, extra })
      }, () => { if (selected) assertLegacyMode() })
      if (legacy) return legacy
    }
    tx(() => {
      if (!ledger.verify().ok) throw new Error('startup refused: signed ledger unavailable')
      activeOwnerState()
      retainedConsumptions()
    })
    for (const [t, s] of Object.entries(TARGETS)) {
      // An interrupted effect cannot become a genesis adoption or acquire a fabricated apply time.
      tx(() => {
        if (db.prepare(`SELECT 1 FROM proposals p LEFT JOIN owner_authorization_consumptions c ON c.proposal_id=p.id
          WHERE p.target=? AND (p.state IN ('applying','incomplete','conflict')
            OR (c.proposal_id IS NOT NULL AND p.state!='applied')) LIMIT 1`).get(t)) return
        const cur = readCur(t); let validCur = true
        try { if (cur) { const txt = cur.toString('utf8'); if (!/^[\x20-\x7e]*$/.test(txt)) throw new Error('non-ASCII'); synchronous(s.validate(txt), 'target validation') } }
        catch (e) { validCur = false; append('genesis-target-invalid', { target: t, new_sha: sha256(cur), detail: { error: String(e.message).slice(0, 200) } }) }
        if (cur && validCur && !db.prepare(`SELECT 1 FROM ledger WHERE target=? AND new_sha=? AND event IN ${APPLIED_EVENTS} LIMIT 1`).get(t, sha256(cur))) {
          putBlob(t, cur); append('genesis-target', { target: t, new_sha: sha256(cur), detail: { note: 'current bytes adopted at gate start' } })
        }
      })
    }
    for (const selected of db.prepare("SELECT id FROM proposals WHERE state='applying'").all()) {
      tx(() => {
        const r = db.prepare("SELECT * FROM proposals WHERE id=? AND state='applying'").get(selected.id)
        if (!r) return // Another effect completed while startup waited for the writer.
        let cur = null, readable = false
        try { if (Object.hasOwn(TARGETS, r.target)) {
          const bytes = readCur(r.target); cur = bytes ? sha256(bytes) : 'absent'; readable = true
        } } catch {}
        const c = db.prepare('SELECT * FROM owner_authorization_consumptions WHERE proposal_id=?').get(r.id)
        const retained = c ? { owner_authorization: retainedReceipt(r, c).owner_authorization,
          consumption_seq: c.consume_seq, consumption_hash: c.consume_hash } : { owner_authorization: null }
        if (!readable) {
          append('reconcile', { proposal: r.id, target: r.target, base_sha: r.base_sha, new_sha: r.new_sha,
            detail: { result: 'incomplete: target unreadable; effect unknown; applying fence retained; no retry', ...retained } })
        } else if (cur === r.new_sha) {
          if (!setState(r.id, 'applying', 'incomplete', 'bytes present; signed receipt incomplete; spent; no retry')) throw new Error('reconcile compare-and-set failed')
          append('reconcile', { proposal: r.id, target: r.target, base_sha: r.base_sha, new_sha: r.new_sha,
            detail: { result: 'incomplete: bytes present; no fabricated receipt or apply time; no retry', ...retained } })
        } else if (cur === r.base_sha) {
          if (!setState(r.id, 'applying', 'failed', 'reconciled: not written; spent; NOT re-applied')) throw new Error('reconcile compare-and-set failed')
          append('reconcile', { proposal: r.id, target: r.target, base_sha: r.base_sha, new_sha: r.new_sha,
            detail: { result: 'failed: not written, spent, NOT replayed', ...retained } })
        } else {
          if (!setState(r.id, 'applying', 'conflict', `file ${cur} matches neither`)) throw new Error('reconcile compare-and-set failed')
          append('reconcile', { proposal: r.id, target: r.target, detail: { result: 'conflict', current: cur, ...retained } })
        }
      })
    }
    for (const r of db.prepare("SELECT id, target FROM proposals WHERE state='pending' AND expires <= ?").all(currentMs()))
      tx(() => { if (setState(r.id, 'pending', 'expired', 'expired (gate start)')) append('expire', { proposal: r.id, target: r.target, detail: { reason: 'ttl elapsed' } }) })
    return tx(() => {
      activeOwnerState()
      const v = ledger.verify()
      if (!v.ok) throw new Error('startup refused: signed ledger unavailable')
      retainedConsumptions()
      append('gate-start', { detail: { pid, ledger_ok_before_start: v.ok, entries: v.entries, pubkey_fp: key.fp, owner_bearer: bearerInfo ? { rotated: true, fp8: bearerInfo.fp, expires: bearerInfo.expires } : null, ...extra } })
      return v
    })
  }

  // Recovery observes the current G authority under the effect writer fence.
  // This signs/appends nothing and never starts, reconciles or retries an effect;
  // a live socket or valid ledger alone is insufficient readiness evidence.
  function readiness() {
    return tx(() => {
      const state = activeOwnerState(), checked = ledger.verify()
      if (!checked.ok) throw new Error('readiness refused: signed ledger unavailable')
      const consumptions = retainedConsumptions()
      let unresolvedConsumptions = 0
      for (const c of consumptions) {
        const p = db.prepare('SELECT * FROM proposals WHERE id=?').get(c.proposal_id)
        if (!['applied', 'failed'].includes(p.state)) unresolvedConsumptions++
        else {
          const terminal = db.prepare("SELECT * FROM ledger WHERE proposal=? AND seq>? AND event IN ('apply','revert-applied','apply-failed','reconcile') ORDER BY seq DESC LIMIT 1")
            .get(p.id, c.consume_seq)
          const outcome = terminal ? JSON.parse(terminal.detail) : null
          const binding = terminal && terminal.target === p.target && terminal.base_sha === p.base_sha && terminal.new_sha === p.new_sha
          const applied = p.state === 'applied' && binding && ['apply', 'revert-applied'].includes(terminal.event)
            && outcome?.receipt?.v === 3 && typeof outcome.receipt.applied_at === 'string'
            && JSON.stringify(outcome.receipt) === JSON.stringify(retainedReceipt(p, c, outcome.receipt.applied_at))
            && verify(null, Buffer.from(JSON.stringify(outcome.receipt)), key.pub, Buffer.from(outcome.receipt_sig ?? '', 'base64'))
          const failed = p.state === 'failed' && binding && outcome?.consumption_seq === c.consume_seq
            && (terminal.event === 'apply-failed' || terminal.event === 'reconcile' && outcome.result === 'failed: not written, spent, NOT replayed')
          if (!applied && !failed) throw new Error('readiness refused: original terminal outcome unavailable')
        }
      }
      const counts = Object.fromEntries(['applying', 'incomplete', 'conflict'].map(value =>
        [value, db.prepare('SELECT count(*) AS n FROM proposals WHERE state=?').get(value).n]))
      if (JSON.stringify(activeOwnerState()) !== JSON.stringify(state))
        throw new Error('readiness refused: owner state changed during observation')
      return { version: 1, kind: 'aukora-boundary-gate-readiness/v1',
        ready: unresolvedConsumptions === 0 && Object.values(counts).every(n => n === 0),
        checked_at_ms: currentMs(), gate_pubkey_sha256: gateId, owner_state_sha256: sha256(JSON.stringify(state)),
        owner_subject: state.owner_subject, owner_root_id: state.owner_root_id, owner_epoch: state.owner_epoch,
        registry_sha256: state.registry_sha256, activation_sha256: state.activation_sha256,
        ledger: { entries: checked.entries, head: checked.head },
        consumed_effects: { retained: consumptions.length, unresolved: unresolvedConsumptions, ...counts } }
    })
  }

  // everything the owner sees about one proposal, computed by the gate (same function as the popup flags)
  function cardView(p) {
    const oldText = blobText(p.base_sha), newText = blobText(p.new_sha), s = TARGETS[p.target]
    let meta = { nonascii: 0 }
    try { const d = db.prepare("SELECT detail FROM ledger WHERE proposal=? AND event='propose' ORDER BY seq LIMIT 1").get(p.id); meta = JSON.parse(d?.detail || '{}').note_meta || meta } catch {}
    const targetReview = targetReviewSnapshot(s, oldText, newText, p.target, p.base_sha)
    return { plain: targetReview ? targetReview.available ? targetReview.from_to : REVIEW_FACTS_UNAVAILABLE : s?.plain ? s.plain(oldText, newText) : '',
      after_apply: s?.after ? s.after(newText) : '', warnings: [...cardWarnings(s, oldText, newText, p.why, meta), ...(targetReview?.available === false ? [REVIEW_FACTS_UNAVAILABLE] : [])],
      note_display: noteDisplay(p.why, meta), note_meta: meta, swatch: swatchText(s, oldText, newText), base_accent: s?.accentOf?.(oldText) ?? null, new_accent: s?.accentOf?.(newText) ?? null }
  }
  // OPERATOR-ONLY TARGETS (the plugin-set approval) are never raised from the PROPOSE channel: an agent cannot put a
  // release admission in front of the owner. They are raised on the OWNER socket (root/gate user only) by `raise`.
  function refuseOperatorOnly(target, op) {
    if (typeof target === 'string' && Object.hasOwn(TARGETS, target) && TARGETS[target].operatorOnly === true) {
      append('reject', { target, detail: { reason: 'operator-only target', via: `propose-channel ${op}` } })
      throw new Error(`refused: ${target} is operator-only; it is raised on the owner channel, never proposed by an agent`)
    }
  }
  // RAISE (owner channel): create the pending question for an operator-only target. It approves NOTHING: the same
  // review -> decide_review ceremony is the only way it can apply. The base is the current bytes (rechecked at decide).
  function raise(args) {
    if (!exactKeys(args, ['target', 'content', 'why'])) throw new Error('raise takes exactly {target, content, why}')
    const s = spec(args.target)
    if (s.operatorOnly !== true) throw new Error('raise is only for operator-only targets; agent targets are proposed on the propose channel')
    const cur = readCur(args.target)
    return createProposal({ target: args.target, content: args.content, why: args.why, claimed_base: cur ? sha256(cur) : 'absent', session: 'owner-raise' }, 'change')
  }
  const pendingRows = () => { sweepExpired(); return db.prepare("SELECT id,kind,target,base_sha,new_sha,why,session,created,expires FROM proposals WHERE state='pending' ORDER BY created DESC").all() }

  function relayRecord(a) {
    const hex64 = v => typeof v === 'string' && /^[0-9a-f]{64}$/u.test(v)
    const phase = a && typeof a === 'object' ? Object.getOwnPropertyDescriptor(a, 'phase')?.value : undefined
    if (phase === 'intent') {
      if (!exactKeys(a, ['phase', 'author', 'client_request_id', 'body_sha256', 'bytes'])) throw new Error('relay_record intent takes exactly {phase, author, client_request_id, body_sha256, bytes}')
    } else if (phase === 'posted') {
      if (!exactKeys(a, ['phase', 'author', 'client_request_id', 'body_sha256', 'bytes', 'message_id', 'cursor'])) throw new Error('relay_record posted takes exactly {phase, author, client_request_id, body_sha256, bytes, message_id, cursor}')
      if (!hex64(a.message_id) || typeof a.cursor !== 'string' || !/^[1-9][0-9]{0,18}$/u.test(a.cursor)) throw new Error('relay_record: message_id must be 64-hex and cursor a positive decimal string')
    } else throw new Error('relay_record phase must be intent or posted')
    if (a.author !== 'auma') throw new Error('relay_record records only the auma principal')
    if (typeof a.client_request_id !== 'string' || !/^[A-Za-z0-9_-]{1,128}$/u.test(a.client_request_id)) throw new Error('relay_record: bad client_request_id')
    if (!hex64(a.body_sha256) || !Number.isSafeInteger(a.bytes) || a.bytes < 1 || a.bytes > 2000) throw new Error('relay_record: body_sha256 must be 64-hex and bytes 1..2000')
    if (phase === 'posted' && !db.prepare("SELECT 1 FROM ledger WHERE event='relay-intent' AND json_extract(detail,'$.client_request_id')=? AND json_extract(detail,'$.body_sha256')=? LIMIT 1").get(a.client_request_id, a.body_sha256))
      throw new Error('relay_record: posted without a matching recorded intent')
    const detail = { author: 'auma', client_request_id: a.client_request_id, body_sha256: a.body_sha256, bytes: a.bytes, ...(phase === 'posted' ? { message_id: a.message_id, cursor: a.cursor } : {}) }
    const e = tx(() => append(phase === 'intent' ? 'relay-intent' : 'relay-posted', { detail }))
    return { ok: true, seq: e.seq, hash: e.hash }
  }

  const proposeOps = {
    ping: () => ({ ok: true, pubkey_fp: key.fp, pubkey_pem: key.pubPem }),
    targets: () => Object.entries(TARGETS).map(([t, s]) => ({ target: t, schema: s.schema, entry: s.entry, maxBytes: s.maxBytes })),
    read: ({ target }) => { const s = spec(target); const b = readCur(target); return { target, sha256: b ? sha256(b) : 'absent', bytes: b ? b.length : 0, content: b ? b.toString('utf8') : null, schema: s.schema } },
    propose: (a) => { refuseOperatorOnly(a?.target, 'propose'); return createProposal({ ...a }, 'change') },
    revert: (a) => { refuseOperatorOnly(a?.target, 'revert'); return revert(a) },
    history: ({ target }) => history(target),
    close,
    state: ({ id }) => {
      const r = db.prepare('SELECT state, expires, updated FROM proposals WHERE id=?').get(String(id)); if (!r) return { state: 'unknown' }
      if (r.state === 'applied') {
        try {
          const original = ledger.retainedCompletedResult(String(id))
          if (original) return Object.freeze(original)
        } catch { /* Missing, damaged or unauthenticated retention is unavailable, never rebuilt. */ }
      }
      const out = { state: r.state, expires: r.expires, updated: r.updated }
      if (r.state === 'applied' && (journalId !== undefined || ownerAuthorizationRequired())) out.gate_capture_status = 'UNAVAILABLE'
      const d = db.prepare("SELECT seq, detail FROM ledger WHERE proposal=? AND event IN ('apply','revert-applied','decide') ORDER BY seq DESC LIMIT 1").get(String(id))
      if (d) { const j = JSON.parse(d.detail || '{}'); out.approver = j.receipt?.approver ?? j.approver ?? j.via ?? null; if (j.receipt) { out.ledger_seq = d.seq; out.pubkey_fp = j.receipt.pubkey_fp } }
      return out
    },
    harness_start: ({ pid }) => tx(() => {
      if (pid !== undefined && (!Number.isSafeInteger(pid) || pid <= 0)) throw new Error('invalid harness pid')
      const count = db.prepare("SELECT count(*) AS n FROM proposals WHERE state='pending'").get().n
      // A harness restart is a caller report, never authority to burn an owner intent.
      // Gate-clock TTL checks and the existing gate recovery path still apply.
      append('harness-start', { detail: { source: 'propose-socket/harness', verification: 'caller-reported-unverified',
        pid: pid ?? null, expired_pending: 0, preserved_pending: count } })
      return { expired: 0, preserved_pending: count }
    }),
    // RELAY RECORD (harness only): every AUMA relay post is written to this signed ledger, and therefore into Aura, twice:
    // an intent (body digest and size) BEFORE the harness sends it, and the server-assigned message id AFTER. It records
    // nothing else, grants nothing, and accepts only these closed shapes. Bodies are never stored here, only digests.
    relay_record: (a) => relayRecord(a),
    selfcheck: ({ result }) => {
      append('selfcheck', { detail: { source: 'propose-socket/harness', verification: 'caller-reported-unverified', result: result ?? null } })
      return { ok: true, verification: 'caller-reported-unverified' }
    },
    log: ({ limit, target }) => {
      const n = Math.max(1, Math.min(200, Number(limit) || 30))
      const rows = target ? db.prepare('SELECT seq,at,event,proposal,target,base_sha,new_sha,detail,hash FROM ledger WHERE target=? ORDER BY seq DESC LIMIT ?').all(String(target), n)
        : db.prepare('SELECT seq,at,event,proposal,target,base_sha,new_sha,detail,hash FROM ledger ORDER BY seq DESC LIMIT ?').all(n)
      const pendingIds = new Set(db.prepare("SELECT id FROM proposals WHERE state='pending'").all().map(r => r.id))
      return { verify: ledger.verify(), pubkey_fp: key.fp, entries: rows.map(r => ({ ...r,
        proposal: pendingIds.has(r.proposal) ? maskId(r.proposal) : r.proposal,
        detail: r.event === 'review-issued' && pendingIds.has(r.proposal) && JSON.parse(r.detail || '{}').authorization_id
          ? { via: 'owner', review: 'pending; owner channel only' } : r.detail ? JSON.parse(r.detail) : null })) }
    },
    verify: () => ledger.verify(),
    readiness: () => readiness(),
    status: () => ({ pubkey_fp: key.fp, verify: ledger.verify(),
      proposals: db.prepare('SELECT id,kind,target,base_sha,new_sha,state,note,created,expires FROM proposals ORDER BY created DESC LIMIT 20').all().map(r => r.state === 'pending' ? { ...r, id: maskId(r.id) } : r) }),
  }
  const ownerOps = {
    pending: () => ({ pubkey_fp: key.fp, pending: pendingRows().map(p => ({ ...p, ...cardView(p) })) }),
    rotate_bearer: () => { const r = rotateBearer(home, owner, now); append('owner-bearer-rotated', { detail: { fp8: r.fp, expires: r.expires, via: 'owner.sock' } }); return { rotated: true, expires: r.expires } },
    reject: ({ id }, approver) => ownerAuthorizationRequired() ? ownerDecide({ id, outcome: 'rejected' }, approver)
      : legacyOwnerDecide({ id, outcome: 'rejected' }, approver),
    raise: (a) => raise(a),
    review: (a) => review(a),
    decide_review: (a, approver) => decideReview(a, approver),
    status: proposeOps.status,
    log: ({ limit, target }) => {
      const checked = ledger.verify()
      if (!checked.ok) throw new Error('signed-ledger-export-unverified')
      const n = Math.max(1, Math.min(200, Number(limit) || 30))
      const rows = target ? db.prepare('SELECT * FROM ledger WHERE target=? ORDER BY seq DESC LIMIT ?').all(String(target), n)
        : db.prepare('SELECT * FROM ledger ORDER BY seq DESC LIMIT ?').all(n)
      return { verify: checked, pubkey_fp: key.fp, entries: rows.map(r => ({ ...r, detail: r.detail ? JSON.parse(r.detail) : null, signed_entry: signedEntryData(r) })) }
    },
    verify: proposeOps.verify,
    readiness: proposeOps.readiness,
  }
  // Charge every append-capable propose RPC BEFORE entering its handler. This separate
  // committed transaction survives refusals, multiple gate processes, and restarts.
  // There is one counter, never one per caller/session. Exhaustion signs nothing.
  // Owner operations retain the original handlers and do not share this admission limit.
  function chargePropose() {
    tx(() => {
      const t = currentMs(), row = db.prepare('SELECT window_start_ms,used FROM propose_budget WHERE singleton=1').get()
      if (row && (!Number.isSafeInteger(row.window_start_ms) || !Number.isSafeInteger(row.used)
        || row.used < 0 || row.window_start_ms > t)) throw new Error('propose budget unavailable: invalid retained clock/counter')
      const expired = !row || t - row.window_start_ms >= L.proposeWindowMs
      if (!expired && row.used >= L.proposeMaxPerWindow) throw new Error('propose budget exhausted; owner channel remains available')
      db.prepare('INSERT INTO propose_budget VALUES(1,?,?) ON CONFLICT(singleton) DO UPDATE SET window_start_ms=excluded.window_start_ms,used=excluded.used')
        .run(expired ? t : row.window_start_ms, expired ? 1 : row.used + 1)
    })
  }
  for (const op of ['propose', 'revert', 'close', 'harness_start', 'selfcheck', 'relay_record']) {
    const handler = proposeOps[op]
    proposeOps[op] = (...args) => { chargePropose(); return handler(...args) }
  }
  if (['approve', 'decide', 'review', 'decide_review', 'raise'].some(op => Object.hasOwn(proposeOps, op))) throw new Error('invariant: the propose channel must not expose approval')
  // ONE approval ceremony: review (fresh single-use challenge over exact base/new) -> decide_review. No direct approve.
  if (['approve', 'decide'].some(op => Object.hasOwn(ownerOps, op))) throw new Error('invariant: the owner channel approves only through review -> decide_review')

  return Object.freeze({
    proposeOps: Object.freeze(proposeOps), ownerOps: Object.freeze(ownerOps), startup, readiness, cardView, pendingRows, blobText, spec,
    targets: TARGETS, owner, pub: key.pub, pubPem: key.pubPem, fp: key.fp, home, now, db, append, verify: ledger.verify,
    close: () => { try { db.close() } catch {} },
  })
}
