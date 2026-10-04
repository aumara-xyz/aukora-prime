// MONOTONIC RELEASE FLOOR (Kimi/GPT review of 524b8f5, Peter 2026-10-04 14:52 WITA).
//
// Before: an old plugin-set approval plus its own old release still booted (point the unit back at the old release and
// approval root), so a downgrade needed no owner decision. Now a root-owned floor file names the NEWEST owner approval
// ever installed, by the GATE-SIGNED `applied_at` on its receipt. The unit's ExecStartPre (bin/release-floor.mjs check,
// trusted root-owned code) refuses to start any release whose installed approval was applied before the floor.
//
// ROLLBACK = A FRESH OWNER CARD. Re-raising the old release (plugin-set-approval.mjs raise --release-dir <old>) produces a
// new gate receipt with a new applied_at; the owner approves it with one click; `install` then moves the floor to it.
// The gate states on that card, as a gate fact, that it is a ROLLBACK (the release is in the floor's history).
// The floor only moves forward: install never lowers it, and nothing but root can write it.
import fs from 'node:fs'
import path from 'node:path'

export const FLOOR_FILE = '/etc/aukora-approvals/release-floor.json'
export const FLOOR_KIND = 'aukora-release-floor/v1'
const HISTORY_MAX = 64

const ms = (iso) => { const t = Date.parse(iso); if (!Number.isFinite(t) || new Date(t).toISOString() !== iso) throw new Error(`not an ISO timestamp: ${String(iso).slice(0, 40)}`); return t }

/** Parse a floor; null when the file is absent. Malformed is an error, never "no floor". */
export function readFloor(file = FLOOR_FILE, { requireRoot = false } = {}) {
  let st
  try { st = fs.lstatSync(file) } catch (e) { if (e.code === 'ENOENT') return null; throw e }
  if (!st.isFile()) throw new Error(`release floor ${file} is not a regular file`)
  if (requireRoot && (st.uid !== 0 || (st.mode & 0o022) !== 0)) throw new Error(`release floor ${file} is not root-owned and go-w`)
  const f = JSON.parse(fs.readFileSync(file, 'utf8'))
  if (f?.kind !== FLOOR_KIND || !/^[0-9a-f]{40}$/.test(String(f.release)) || !/^release-[0-9a-f]{7}$/.test(String(f.release_dir))
    || !Array.isArray(f.history) || !f.history.every(r => /^[0-9a-f]{40}$/.test(String(r)))) throw new Error(`release floor ${file} is malformed`)
  ms(f.applied_at)
  return f
}

/** Refuse when an installed approval predates the floor. `verified` is verifyGateSetApproval's result. */
export function checkFloor(floor, verified) {
  if (floor === null) throw new Error('no release floor is installed (run plugin-set-approval.mjs install for the live release); refusing to start')
  if (ms(verified.appliedAt) < ms(floor.applied_at)) {
    throw new Error(`release-below-floor: ${verified.release_dir} was owner-approved at ${verified.appliedAt}, before the floor `
      + `(${floor.release_dir}, approved ${floor.applied_at}). A rollback needs a fresh owner approval card for ${verified.release_dir}.`)
  }
  return { ok: true, floor: floor.release_dir, release: verified.release_dir }
}

/** The floor after installing `verified`; unchanged (same object) when it is not newer. Never moves back. */
export function advanceFloor(floor, verified) {
  if (floor !== null && ms(verified.appliedAt) <= ms(floor.applied_at)) return floor
  const history = floor === null ? [] : [...floor.history.filter(r => r !== floor.release && r !== verified.release), floor.release].slice(-HISTORY_MAX)
  return { kind: FLOOR_KIND, release: verified.release, release_dir: verified.release_dir, applied_at: verified.appliedAt, record: verified.record, history }
}

export function writeFloor(file, floor) {
  const tmp = path.join(path.dirname(file), `.release-floor.tmp-${process.pid}`)
  fs.writeFileSync(tmp, JSON.stringify(floor, null, 2) + '\n', { mode: 0o644, flag: 'wx' })
  fs.renameSync(tmp, file)
}

/** For the owner card: is this release one the floor has already moved past? (gate fact, read-only) */
export function isRollback(floor, release) {
  return floor !== null && floor.release !== release && floor.history.includes(release)
}
