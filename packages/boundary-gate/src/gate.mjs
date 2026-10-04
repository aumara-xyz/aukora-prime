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
// gate's own version store, post-write hash verified, and an Ed25519-signed receipt carries an HMAC over
// (id, base, new, approver) as approval evidence. Rate limits are global and per target, never per
// harness-chosen session label. Targets are injected; with an empty allowlist every proposal is refused.
import path from 'node:path'
import { createHmac, randomUUID, randomBytes, sign, timingSafeEqual } from 'node:crypto'
import { sha256, SHA, loadOrCreateKey, openDb, createLedger } from './ledger.mjs'
import { loadOwnerSecret, rotateBearer } from './secrets.mjs'
import { lineDiff, cleanNote, noteMeta, cardWarnings, swatchText, noteDisplay } from './card.mjs'

export const DEFAULT_LIMITS = Object.freeze({
  ttlMs: 5 * 60 * 1000, popupLimit: 12000, keepVersions: 50, whyMax: 4000,
  maxPendingGlobal: 1, maxPerWindow: 3, windowMs: 10 * 60 * 1000, rejectCooldownMs: 60 * 1000, dedupeMs: 10 * 60 * 1000,
})
const CLOSE_OUTCOMES = ['rejected', 'cancelled', 'unavailable', 'expired']
const APPLIED_EVENTS = "('apply','revert-applied','genesis-target')"
export const maskId = (id) => id ? String(id).slice(0, 8) + '…' : id

// targets: { [name]: { entry, maxBytes, schema, validate(text), accentOf?, plain?, after? } }
// store:   { read(name, spec) -> Buffer|null, write(name, spec, bytes, proposalId) }
export function createGate({ home, targets = {}, store, now = Date.now, limits = {}, key, owner, db, iso } = {}) {
  const L = { ...DEFAULT_LIMITS, ...limits }
  key ??= loadOrCreateKey(home)
  owner ??= loadOwnerSecret(home)
  db ??= openDb(path.join(home, 'gate.db'))
  iso ??= () => new Date(now()).toISOString()
  const TARGETS = Object.freeze({ ...targets })
  const ledger = createLedger(db, key, iso)
  const append = ledger.append
  const tx = (fn) => { db.exec('BEGIN IMMEDIATE'); try { const r = fn(); db.exec('COMMIT'); return r } catch (e) { db.exec('ROLLBACK'); throw e } }
  const spec = (target) => {
    if (typeof target !== 'string' || !Object.hasOwn(TARGETS, target))
      throw new Error(`target refused: ${JSON.stringify(String(target).slice(0, 120))} is not on the allowlist (${Object.keys(TARGETS).join(', ') || 'empty'}). Only declarative, schema-validated targets exist.`)
    return TARGETS[target]
  }
  const readCur = (target) => store.read(target, TARGETS[target])
  const putBlob = (target, bytes) => db.prepare('INSERT OR IGNORE INTO blobs VALUES(?,?,?,?)').run(sha256(bytes), target, bytes, iso())
  const blobText = (sha) => { const b = db.prepare('SELECT bytes FROM blobs WHERE sha=?').get(sha); return b ? Buffer.from(b.bytes).toString('utf8') : '' }
  const setState = (id, from, to, note) => db.prepare('UPDATE proposals SET state=?, note=?, updated=? WHERE id=? AND state=?').run(to, note ?? null, now(), id, from).changes === 1

  // LIVE EXPIRY SWEEP (2026-10-04). A pending proposal past its TTL is closed as expired the moment anyone looks
  // (propose rate check, OWNER pending list, owner page), not only at gate start: a stale row must neither block the
  // next proposal (max 1 pending) nor be put in front of the owner as if it were still decidable.
  function sweepExpired() {
    for (const r of db.prepare("SELECT id, target FROM proposals WHERE state='pending' AND expires < ?").all(now()))
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
    return {
      marker: 'GATE-' + randomBytes(3).toString('hex'),
      after_apply: s.after ? s.after(p.content) : `AFTER APPLY: ${p.bytes} bytes`,
      plain_change: s.plain ? s.plain(oldText || '', p.content) : `${p.bytes} bytes change`,
      note: p.note_meta?.nonascii ? noteDisplay(p.why, p.note_meta) : (p.why ?? null),
      note_hexdump: p.note_meta?.hexdump ?? null,
      flags: cardWarnings(s, oldText || '', p.content, p.why, p.note_meta),
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
    try { s.validate(content) } catch (e) { append('reject', { target, detail: { reason: 'schema', error: e.message, kind } }); throw new Error('refused (schema): ' + e.message) }
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

  // APPROVE: owner channel only. Records HMAC approval evidence and the approver principal in a signed receipt.
  function ownerDecide({ id, outcome }, approver) {
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
      const r = db.prepare('SELECT state, expires, displayable FROM proposals WHERE id=?').get(id)
      if (r.state !== 'pending') { append('decide-refused', { proposal: id, target: p.target, detail: { reason: 'replay: not pending', state: r.state, via: 'owner' } }); return { applied: false, state: r.state, message: `refused: already used or closed (state ${r.state}) — replay refused` } }
      if (now() > r.expires) { setState(id, 'pending', 'expired', 'approved after expiry'); append('decide-refused', { proposal: id, target: p.target, detail: { reason: 'approved after expiry', via: 'owner' } }); return { applied: false, state: 'expired', message: 'refused: approval arrived after expiry' } }
      if (!r.displayable) { setState(id, 'pending', 'refused', 'too large for popup'); append('decide-refused', { proposal: id, target: p.target, detail: { reason: 'TRUNCATED: approval disabled', via: 'owner' } }); return { applied: false, state: 'refused', message: 'refused: proposal too large to show in full; approval disabled' } }
      const cur = readCur(p.target); const curSha = cur ? sha256(cur) : 'absent'
      if (curSha !== p.base_sha) { setState(id, 'pending', 'stale', `base changed to ${curSha}`); append('decide-refused', { proposal: id, target: p.target, base_sha: p.base_sha, detail: { reason: 'stale base at approval', current: curSha, via: 'owner' } }); return { applied: false, state: 'stale', message: `refused as stale: target changed since proposal (now ${curSha})` } }
      setState(id, 'pending', 'applying', 'spent')
      append('decide', { proposal: id, target: p.target, base_sha: p.base_sha, new_sha: p.new_sha, detail: { outcome: 'allowed-once', via: 'owner', approver, spent: true } })
      return null
    })
    if (pre) return pre
    try {
      const bytes = db.prepare('SELECT bytes FROM blobs WHERE sha=?').get(p.new_sha)?.bytes
      if (!bytes || sha256(Buffer.from(bytes)) !== p.new_sha) throw new Error('approved bytes missing from version store')
      store.write(p.target, s, Buffer.from(bytes), id)
      const after = readCur(p.target); const got = after ? sha256(after) : 'absent'
      if (got !== p.new_sha) throw new Error('post-write hash mismatch ' + got)
      return tx(() => {
        const evidence = createHmac('sha256', Buffer.from(owner.hmacKey, 'hex')).update(`${id}\n${p.base_sha}\n${p.new_sha}\n${approver}`).digest('base64')
        const receipt = { v: 2, kind: p.kind, proposal: id, target: p.target, base_sha: p.base_sha, new_sha: p.new_sha, applied_at: iso(), approver, approval_evidence_hmac: evidence, pubkey_fp: key.fp }
        const rsig = signReceipt(receipt)
        setState(id, 'applying', 'applied', 'applied')
        const e = append(p.kind === 'revert' ? 'revert-applied' : 'apply', { proposal: id, target: p.target, base_sha: p.base_sha, new_sha: p.new_sha, detail: { receipt, receipt_sig: rsig } })
        prune(p.target)
        return { applied: true, state: 'applied', entry: s.entry, receipt, receipt_sig: rsig, ledger_seq: e.seq, ledger_hash: e.hash, message: 'applied' }
      })
    } catch (e) {
      let cur = null; try { const b = readCur(p.target); cur = b ? sha256(b) : 'absent' } catch {}
      tx(() => { const st = cur === p.new_sha ? 'applied' : 'failed'; setState(id, 'applying', st, String(e.message)); append(st === 'applied' ? 'apply' : 'apply-failed', { proposal: id, target: p.target, base_sha: p.base_sha, new_sha: p.new_sha, detail: { error: String(e.message), via: 'owner' } }) })
      throw e
    }
  }
  // OWNER REVIEW (L2 popup, 2026-10-04). review() hands the owner the FULL stored bytes and diff plus a fresh
  // gate-made challenge; decide_review() approves or refuses only with that exact challenge for the same immutable
  // id/base/new. The challenge lives in gate memory (one latest per id), is never on the PROPOSE channel, and is
  // CONSUMED BEFORE VALIDATION, so a failed or replayed decision cannot be retried with it. Approval still goes
  // through ownerDecide (spent-before-write, base recheck, version-store bytes, post-hash, signed receipt).
  const REVIEW_TTL_MS = 120000
  const reviews = new Map()
  const exactKeys = (a, keys) => a !== null && typeof a === 'object' && !Array.isArray(a) && Object.keys(a).length === keys.length && keys.every(k => Object.hasOwn(a, k))
  function review(args) {
    if (!exactKeys(args, ['id']) || typeof args.id !== 'string') throw new Error('review takes exactly {id}')
    const p = db.prepare('SELECT * FROM proposals WHERE id=?').get(args.id)
    if (!p) throw new Error('unknown proposal id')
    if (p.state !== 'pending') throw new Error(`proposal is ${p.state}; only a pending proposal can be reviewed`)
    if (now() > p.expires) throw new Error('proposal expired')
    const review_challenge = randomBytes(32).toString('hex')
    const review_expires = Math.min(p.expires, now() + REVIEW_TTL_MS)
    reviews.set(p.id, { challenge: review_challenge, expires: review_expires, base_sha: p.base_sha, new_sha: p.new_sha })
    append('review-issued', { proposal: p.id, target: p.target, base_sha: p.base_sha, new_sha: p.new_sha, detail: { via: 'owner', review_expires: new Date(review_expires).toISOString() } })
    // v2 (owner card, 2026-10-04): the GATE'S OWN from->to line (computed here from the stored base and new bytes by the
    // target's spec, never from model text) and the model's note, returned SEPARATELY and labelled as model-authored, so the
    // card can put the gate's facts and diff first and fence the model's words. The note is the sanitised why (<=120 ASCII).
    const s = TARGETS[p.target], newText = blobText(p.new_sha)
    let oldText = ''
    if (p.base_sha !== 'absent') { try { oldText = blobText(p.base_sha) } catch { oldText = '' } }
    let from_to = null
    try { from_to = s?.plain ? String(s.plain(oldText, newText)) : null } catch { from_to = null }
    if (from_to !== null && !/^[\x20-\x7e]{1,600}$/.test(from_to)) from_to = null
    return { version: 2, id: p.id, kind: p.kind, target: p.target, base_sha: p.base_sha, new_sha: p.new_sha, content: newText, diff: p.diff,
      from_to, model_note: p.why ?? null,
      displayable: !!p.displayable, created: p.created, expires: p.expires, review_challenge, review_expires, pubkey_fp: key.fp }
  }
  function decideReview(args, approver) {
    const id = args && typeof args === 'object' && typeof args.id === 'string' ? args.id : null
    const stored = id === null ? undefined : reviews.get(id)
    if (id !== null) reviews.delete(id)
    const refuse = (reason) => { append('decide-refused', { proposal: id === null ? null : id.slice(0, 64), detail: { reason, via: 'owner-review' } }); throw new Error(`refused: ${reason}`) }
    if (!exactKeys(args, ['id', 'base_sha', 'new_sha', 'review_challenge', 'outcome'])) refuse('decide_review takes exactly {id, base_sha, new_sha, review_challenge, outcome}')
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
    return ownerDecide({ id, outcome: args.outcome }, approver)
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
  function startup({ pid = process.pid, bearerInfo = null, extra = {} } = {}) {
    for (const [t, s] of Object.entries(TARGETS)) {
      const cur = readCur(t); let validCur = true
      try { if (cur) { const txt = cur.toString('utf8'); if (!/^[\x20-\x7e]*$/.test(txt)) throw new Error('non-ASCII'); s.validate(txt) } }
      catch (e) { validCur = false; append('genesis-target-invalid', { target: t, new_sha: sha256(cur), detail: { error: String(e.message).slice(0, 200) } }) }
      if (cur && validCur && !db.prepare(`SELECT 1 FROM ledger WHERE target=? AND new_sha=? AND event IN ${APPLIED_EVENTS} LIMIT 1`).get(t, sha256(cur)))
        tx(() => { putBlob(t, cur); append('genesis-target', { target: t, new_sha: sha256(cur), detail: { note: 'current bytes adopted at gate start' } }) })
    }
    for (const r of db.prepare("SELECT * FROM proposals WHERE state='applying'").all()) {
      let cur = null; try { const b = Object.hasOwn(TARGETS, r.target) ? readCur(r.target) : null; cur = b ? sha256(b) : 'absent' } catch {}
      tx(() => {
        if (cur === r.new_sha) { setState(r.id, 'applying', 'applied', 'reconciled after crash: bytes present'); append('reconcile', { proposal: r.id, target: r.target, base_sha: r.base_sha, new_sha: r.new_sha, detail: { result: 'applied' } }) }
        else if (cur === r.base_sha) { setState(r.id, 'applying', 'failed', 'reconciled: not written; spent; NOT re-applied'); append('reconcile', { proposal: r.id, target: r.target, base_sha: r.base_sha, new_sha: r.new_sha, detail: { result: 'failed: not written, spent, NOT replayed' } }) }
        else { setState(r.id, 'applying', 'conflict', `file ${cur} matches neither`); append('reconcile', { proposal: r.id, target: r.target, detail: { result: 'conflict', current: cur } }) }
      })
    }
    for (const r of db.prepare("SELECT id, target FROM proposals WHERE state='pending' AND expires < ?").all(now()))
      tx(() => { setState(r.id, 'pending', 'expired', 'expired (gate start)'); append('expire', { proposal: r.id, target: r.target, detail: { reason: 'ttl elapsed' } }) })
    const v = ledger.verify()
    append('gate-start', { detail: { pid, ledger_ok_before_start: v.ok, entries: v.entries, pubkey_fp: key.fp, owner_bearer: bearerInfo ? { rotated: true, fp8: bearerInfo.fp, expires: bearerInfo.expires } : null, ...extra } })
    return v
  }

  // everything the owner sees about one proposal, computed by the gate (same function as the popup flags)
  function cardView(p) {
    const oldText = blobText(p.base_sha), newText = blobText(p.new_sha), s = TARGETS[p.target]
    let meta = { nonascii: 0 }
    try { const d = db.prepare("SELECT detail FROM ledger WHERE proposal=? AND event='propose' ORDER BY seq LIMIT 1").get(p.id); meta = JSON.parse(d?.detail || '{}').note_meta || meta } catch {}
    return { plain: s?.plain ? s.plain(oldText, newText) : '', after_apply: s?.after ? s.after(newText) : '', warnings: cardWarnings(s, oldText, newText, p.why, meta),
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
      const out = { state: r.state, expires: r.expires, updated: r.updated }
      const d = db.prepare("SELECT seq, detail FROM ledger WHERE proposal=? AND event IN ('apply','revert-applied','decide') ORDER BY seq DESC LIMIT 1").get(String(id))
      if (d) { const j = JSON.parse(d.detail || '{}'); out.approver = j.receipt?.approver ?? j.approver ?? j.via ?? null; if (j.receipt) { out.ledger_seq = d.seq; out.pubkey_fp = j.receipt.pubkey_fp } }
      return out
    },
    harness_start: ({ pid }) => tx(() => {
      const rows = db.prepare("SELECT id, target FROM proposals WHERE state='pending'").all()
      for (const r of rows) { setState(r.id, 'pending', 'expired', 'harness restarted before decision'); append('expire', { proposal: r.id, target: r.target, detail: { reason: 'harness restarted before decision' } }) }
      append('harness-start', { detail: { pid: Number(pid) || null, expired_pending: rows.length } }); return { expired: rows.length }
    }),
    selfcheck: ({ result }) => { append('selfcheck', { detail: result && typeof result === 'object' ? result : { raw: String(result).slice(0, 2000) } }); return { ok: true } },
    log: ({ limit, target }) => {
      const n = Math.max(1, Math.min(200, Number(limit) || 30))
      const rows = target ? db.prepare('SELECT seq,at,event,proposal,target,base_sha,new_sha,detail,hash FROM ledger WHERE target=? ORDER BY seq DESC LIMIT ?').all(String(target), n)
        : db.prepare('SELECT seq,at,event,proposal,target,base_sha,new_sha,detail,hash FROM ledger ORDER BY seq DESC LIMIT ?').all(n)
      const pendingIds = new Set(db.prepare("SELECT id FROM proposals WHERE state='pending'").all().map(r => r.id))
      return { verify: ledger.verify(), pubkey_fp: key.fp, entries: rows.map(r => ({ ...r, proposal: pendingIds.has(r.proposal) ? maskId(r.proposal) : r.proposal, detail: r.detail ? JSON.parse(r.detail) : null })) }
    },
    verify: () => ledger.verify(),
    status: () => ({ pubkey_fp: key.fp, verify: ledger.verify(),
      proposals: db.prepare('SELECT id,kind,target,base_sha,new_sha,state,note,created,expires FROM proposals ORDER BY created DESC LIMIT 20').all().map(r => r.state === 'pending' ? { ...r, id: maskId(r.id) } : r) }),
  }
  const ownerOps = {
    pending: () => ({ pubkey_fp: key.fp, pending: pendingRows().map(p => ({ ...p, ...cardView(p) })) }),
    rotate_bearer: () => { const r = rotateBearer(home, owner, now); append('owner-bearer-rotated', { detail: { fp8: r.fp, expires: r.expires, via: 'owner.sock' } }); return { rotated: true, expires: r.expires } },
    reject: ({ id }, approver) => ownerDecide({ id, outcome: 'rejected' }, approver),
    raise: (a) => raise(a),
    review: (a) => review(a),
    decide_review: (a, approver) => decideReview(a, approver),
    status: proposeOps.status, log: proposeOps.log, verify: proposeOps.verify,
  }
  if (['approve', 'decide', 'review', 'decide_review', 'raise'].some(op => Object.hasOwn(proposeOps, op))) throw new Error('invariant: the propose channel must not expose approval')
  // ONE approval ceremony: review (fresh single-use challenge over exact base/new) -> decide_review. No direct approve.
  if (['approve', 'decide'].some(op => Object.hasOwn(ownerOps, op))) throw new Error('invariant: the owner channel approves only through review -> decide_review')

  return Object.freeze({
    proposeOps: Object.freeze(proposeOps), ownerOps: Object.freeze(ownerOps), startup, cardView, pendingRows, blobText, spec,
    targets: TARGETS, owner, pub: key.pub, pubPem: key.pubPem, fp: key.fp, home, now, db, append, verify: ledger.verify,
    close: () => { try { db.close() } catch {} },
  })
}
