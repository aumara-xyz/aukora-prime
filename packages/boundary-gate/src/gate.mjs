// Boundary gate core: the approval and state authority, run as its own Linux user (aukora-gate).
//
// Two operation sets, served on two different sockets so the harness can PROPOSE and READ AUDIT but can
// NEVER APPROVE:
//   proposeOps  (PROPOSE socket, group skgate, 0660): ping/targets/read/propose/close(reject only)/state/
//               harness_start/selfcheck/log/verify/status. There is no approve operation on this channel;
//               `close` refuses every outcome except rejected/cancelled/unavailable/expired and records the try.
//   ownerOps    (OWNER socket 0600 gate-only, and the bearer-protected owner page): pending/approve/reject/
//               rotate_bearer. The kernel's socket-file permission check is the enforcement (Node has no
//               SO_PEERCRED), hence split sockets.
// Approval is single use: pending -> applying (spent) BEFORE any write, base hash rechecked, bytes come from the
// gate's own version store, post-write hash verified, and an Ed25519-signed receipt carries an HMAC over
// (id, base, new, approver) as approval evidence. Rate limits are global and per target, never per
// harness-chosen session label. Targets are injected; with an empty allowlist every proposal is refused.
import path from 'node:path'
import { createHmac, randomUUID, randomBytes, sign } from 'node:crypto'
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

  function rateCheck(target, newSha) {
    const pend = db.prepare("SELECT COUNT(*) n FROM proposals WHERE state IN ('pending','applying')").get().n
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
    const id = randomUUID(), created = now(), expires = created + L.ttlMs
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
    if (!p) return { applied: false, state: 'unknown', message: 'unknown proposal id' }
    if (!CLOSE_OUTCOMES.includes(outcome)) {
      append('decide-refused', { proposal: id, target: p.target, detail: { reason: 'approval is not possible on the propose channel', outcome: String(outcome).slice(0, 40), via: 'propose-close' } })
      throw new Error('refused: the harness channel cannot approve; approval happens only on the gate owner channel')
    }
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
  const signReceipt = (receipt) => sign(null, Buffer.from(JSON.stringify(receipt)), key.priv).toString('base64')

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
  const pendingRows = () => db.prepare("SELECT id,kind,target,base_sha,new_sha,why,session,created,expires FROM proposals WHERE state='pending' ORDER BY created DESC").all()

  const proposeOps = {
    ping: () => ({ ok: true, pubkey_fp: key.fp, pubkey_pem: key.pubPem }),
    targets: () => Object.entries(TARGETS).map(([t, s]) => ({ target: t, schema: s.schema, entry: s.entry, maxBytes: s.maxBytes })),
    read: ({ target }) => { const s = spec(target); const b = readCur(target); return { target, sha256: b ? sha256(b) : 'absent', bytes: b ? b.length : 0, content: b ? b.toString('utf8') : null, schema: s.schema } },
    propose: (a) => createProposal({ ...a }, 'change'),
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
    approve: ({ id }, approver) => ownerDecide({ id, outcome: 'allowed-once' }, approver),
    reject: ({ id }, approver) => ownerDecide({ id, outcome: 'rejected' }, approver),
    status: proposeOps.status, log: proposeOps.log, verify: proposeOps.verify,
  }
  if (Object.hasOwn(proposeOps, 'approve') || Object.hasOwn(proposeOps, 'decide')) throw new Error('invariant: the propose channel must not expose approval')

  return Object.freeze({
    proposeOps: Object.freeze(proposeOps), ownerOps: Object.freeze(ownerOps), startup, cardView, pendingRows, blobText, spec,
    targets: TARGETS, owner, pub: key.pub, pubPem: key.pubPem, fp: key.fp, home, now, db, append, verify: ledger.verify,
    close: () => { try { db.close() } catch {} },
  })
}
