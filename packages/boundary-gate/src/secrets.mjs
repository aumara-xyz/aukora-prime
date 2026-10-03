// Owner secret held only by the gate user: an HMAC key for approval evidence (never rotated, so old receipts
// stay verifiable) and the owner-page bearer (rotated on every gate start and on request; expires after 12 h).
// Written atomically (tmp + rename), 0600. The bearer value is never logged; only an 8-char fingerprint is.
import fs from 'node:fs'
import path from 'node:path'
import { randomBytes, timingSafeEqual } from 'node:crypto'
import { sha256 } from './ledger.mjs'

export const BEARER_TTL_MS = 12 * 60 * 60 * 1000

export function loadOwnerSecret(home) {
  const f = path.join(home, 'owner-secret.json')
  if (!fs.existsSync(f)) fs.writeFileSync(f, JSON.stringify({ hmacKey: randomBytes(32).toString('hex'), bearer: randomBytes(32).toString('base64url') }), { mode: 0o600, flag: 'wx' })
  const o = JSON.parse(fs.readFileSync(f, 'utf8'))
  if (!/^[0-9a-f]{64}$/.test(String(o.hmacKey))) throw new Error('owner secret: invalid hmacKey')
  return o
}

export function rotateBearer(home, o, now = Date.now, ttl = BEARER_TTL_MS) {
  const f = path.join(home, 'owner-secret.json'), tmp = `${f}.tmp-${process.pid}`
  const t = now()
  const next = { ...o, bearer: randomBytes(32).toString('base64url'), bearer_issued: t, bearer_expires: t + ttl }
  fs.writeFileSync(tmp, JSON.stringify(next), { mode: 0o600, flag: 'w' }); fs.renameSync(tmp, f)
  Object.assign(o, next)
  return { issued: new Date(t).toISOString(), expires: new Date(next.bearer_expires).toISOString(), fp: sha256(next.bearer).slice(0, 8) }
}

export function bearerOk(o, given, now = Date.now) {
  try {
    if (!o.bearer_expires || now() > o.bearer_expires) return false
    const a = Buffer.from(String(given ?? '')), b = Buffer.from(String(o.bearer))
    return a.length === b.length && timingSafeEqual(a, b)
  } catch { return false }
}
