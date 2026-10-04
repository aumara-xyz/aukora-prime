// SPDX-License-Identifier: AGPL-3.0-or-later
// Order comes only from verified signed ledger sequence and protected signer epoch.
// A rollback needs fresh owner proof with a greater (epoch, seq). Timestamps never
// order the floor. Boot requires the exact committed floor approval; newer proof
// cannot boot while its floor installation is incomplete.
import fs from 'node:fs'
import path from 'node:path'
import { randomBytes } from 'node:crypto'

export const FLOOR_FILE = '/etc/aukora-approvals/release-floor.json'
export const FLOOR_KIND = 'aukora-release-floor/v2'
const CLOCK_FLOOR_KIND = 'aukora-release-floor/v1'
const HISTORY_MAX = 64
const FLOOR_MAX_BYTES = 16 * 1024
const SHA40 = /^[0-9a-f]{40}$/u
const SHA64 = /^[0-9a-f]{64}$/u
const RELEASE_DIR = /^release-[0-9a-f]{7}$/u
const FLOOR_KEYS = 'history,kind,ledger_hash,ledger_seq,record,release,release_dir,signer_epoch,signer_key_sha256'
const refuse = (code, detail) => Object.assign(new Error(`${code}: ${detail}`), { code })
const hex = (value, pattern) => typeof value === 'string' && pattern.test(value)
const positiveInteger = value => Number.isSafeInteger(value) && value > 0

function releaseIdentity(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    && hex(value.release, SHA40) && hex(value.release_dir, RELEASE_DIR) && hex(value.record, SHA64)
}
function validHistory(value) {
  return Array.isArray(value.history) && value.history.length <= HISTORY_MAX
    && value.history.every(release => hex(release, SHA40) && release !== value.release)
    && new Set(value.history).size === value.history.length
}
function validClockTimestamp(value) {
  if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u.test(value)) return false
  const [year, month, day, hour, minute, second] = value.match(/\d+/gu).slice(0, 6).map(Number)
  const leap = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0)
  const days = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
  return month >= 1 && month <= 12 && day >= 1 && day <= days[month - 1] && hour < 24 && minute < 60 && second < 60
}
function clockFloor(value) {
  if (!releaseIdentity(value) || value.kind !== CLOCK_FLOOR_KIND || !validHistory(value)
    || !validClockTimestamp(value.applied_at)) {
    throw refuse('release-floor-malformed', 'legacy clock floor needs exact release, record, timestamp and history')
  }
  return value
}
function checkedFloor(value) {
  if (value?.kind === CLOCK_FLOOR_KIND) throw refuse('release-floor-migration-required', 'v1 needs explicit migrate-clock-floor with the exact current signed approval')
  if (!releaseIdentity(value) || value.kind !== FLOOR_KIND || Object.keys(value).sort().join(',') !== FLOOR_KEYS
    || !validHistory(value) || !positiveInteger(value.signer_epoch) || !positiveInteger(value.ledger_seq)
    || !hex(value.signer_key_sha256, SHA64) || !hex(value.ledger_hash, SHA64)) {
    throw refuse('release-floor-malformed', 'expected a v2 signed-sequence floor')
  }
  return value
}
function checkedApproval(value) {
  // Only verifyOrderedGateApproval supplies these after signature/map checks.
  if (!releaseIdentity(value) || !positiveInteger(value.signerEpoch) || !positiveInteger(value.ledgerSeq)
    || !hex(value.signerKeySha256, SHA64) || !hex(value.ledgerHash, SHA64)) {
    throw refuse('release-floor-ordering-evidence', 'approval needs verified epoch, sequence, exact key and ledger hash')
  }
  return value
}
function compare(floor, verified) {
  if (verified.signerEpoch !== floor.signer_epoch) return verified.signerEpoch > floor.signer_epoch ? 1 : -1
  if (verified.signerKeySha256 !== floor.signer_key_sha256) throw refuse('release-floor-signer-epoch-mismatch', 'one signer epoch cannot name another exact signer key')
  return verified.ledgerSeq === floor.ledger_seq ? 0 : verified.ledgerSeq > floor.ledger_seq ? 1 : -1
}
function sameApproval(floor, verified) {
  return verified.release === floor.release && verified.release_dir === floor.release_dir && verified.record === floor.record
    && verified.signerKeySha256 === floor.signer_key_sha256 && verified.ledgerHash === floor.ledger_hash
}
function fromApproval(verified, history) {
  return { kind: FLOOR_KIND, release: verified.release, release_dir: verified.release_dir, record: verified.record,
    signer_epoch: verified.signerEpoch, ledger_seq: verified.ledgerSeq,
    signer_key_sha256: verified.signerKeySha256, ledger_hash: verified.ledgerHash, history }
}
const floorApproval = floor => ({ release: floor.release, release_dir: floor.release_dir, record: floor.record,
  signerEpoch: floor.signer_epoch, ledgerSeq: floor.ledger_seq, signerKeySha256: floor.signer_key_sha256, ledgerHash: floor.ledger_hash })
const nextHistory = (floor, release) => floor === null ? []
  : [...floor.history.filter(previous => previous !== floor.release && previous !== release),
    ...(floor.release === release ? [] : [floor.release])].slice(-HISTORY_MAX)
function protectedNode(file, directory, metadata = fs.lstatSync(file)) {
  if (metadata.isSymbolicLink?.()) throw refuse('release-floor-symlink', 'protected floor paths cannot contain symlinks')
  if (metadata.uid !== 0 || (metadata.mode & 0o022) !== 0) throw refuse('release-floor-protection', 'floor and ancestors must be root-owned and go-w')
  if (directory ? !metadata.isDirectory() : !metadata.isFile()) throw refuse('release-floor-type', 'protected path has the wrong type')
  if (!directory && metadata.nlink !== 1) throw refuse('release-floor-hardlink', 'floor must have exactly one link')
  return metadata
}
function protectedPath(file) {
  if (typeof file !== 'string' || !path.isAbsolute(file) || path.resolve(file) !== file) throw refuse('release-floor-path', 'protected floor path must be absolute and canonical')
  const ancestors = []; let directory = path.dirname(file)
  while (true) { ancestors.push(directory); if (directory === '/') break; directory = path.dirname(directory) }
  for (const ancestor of ancestors.reverse()) protectedNode(ancestor, true)
}
function leaf(file, requireRoot) {
  let metadata
  try { metadata = fs.lstatSync(file) } catch (error) { if (error.code === 'ENOENT') return null; throw error }
  if (metadata.isSymbolicLink() || !metadata.isFile()) throw refuse('release-floor-type', 'floor must be a regular file without a symlink')
  if (metadata.nlink !== 1) throw refuse('release-floor-hardlink', 'floor must have exactly one link')
  return requireRoot ? protectedNode(file, false, metadata) : metadata
}

/** Absent leaf is null; malformed/unprotected data is always an error. */
export function readFloor(file = FLOOR_FILE, { requireRoot = false, allowClockMigration = false } = {}) {
  if (requireRoot) protectedPath(file)
  const before = leaf(file, requireRoot)
  if (before === null) return null
  if (before.size > FLOOR_MAX_BYTES) throw refuse('release-floor-size', 'floor is too large')
  const fd = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW)
  let bytes
  try {
    const opened = fs.fstatSync(fd)
    if (!opened.isFile() || opened.nlink !== 1 || opened.dev !== before.dev || opened.ino !== before.ino
      || opened.size > FLOOR_MAX_BYTES || (requireRoot && (opened.uid !== 0 || (opened.mode & 0o022) !== 0))) {
      throw refuse('release-floor-open-identity', 'opened floor identity or protection changed')
    }
    bytes = fs.readFileSync(fd)
    if (bytes.length > FLOOR_MAX_BYTES || bytes.length !== opened.size) throw refuse('release-floor-size', 'floor read changed size or exceeded its limit')
  } finally { fs.closeSync(fd) }
  let value
  try { value = JSON.parse(bytes.toString('utf8')) } catch { throw refuse('release-floor-malformed', 'floor is not JSON') }
  return allowClockMigration && value?.kind === CLOCK_FLOOR_KIND ? clockFloor(value) : checkedFloor(value)
}

/** Boot requires the exact committed approval. Newer uncommitted proof also refuses. */
export function checkFloor(floor, verified) {
  if (floor === null) throw refuse('release-floor-absent', 'no release floor is installed; refusing to start')
  checkedFloor(floor); checkedApproval(verified)
  const order = compare(floor, verified)
  if (order < 0) throw refuse('release-below-floor', `${verified.release_dir} precedes epoch ${floor.signer_epoch}, sequence ${floor.ledger_seq}; rollback needs fresh owner approval`)
  if (order > 0) throw refuse('release-floor-install-incomplete', 'approval is newer than the committed floor; complete its guarded floor installation before boot')
  if (order === 0 && !sameApproval(floor, verified)) throw refuse('release-floor-equal-conflict', 'equal epoch and sequence name another approval')
  return { ok: true, floor: floor.release_dir, release: verified.release_dir, signerEpoch: verified.signerEpoch, ledgerSeq: verified.ledgerSeq }
}

/** Installation requires strictly greater authenticated order, including rollback. */
export function advanceFloor(floor, verified) {
  checkedApproval(verified)
  if (floor !== null) {
    checkedFloor(floor)
    if (compare(floor, verified) <= 0) throw refuse('release-floor-not-newer', 'equal, replayed or older ordering cannot replace the floor')
  }
  return fromApproval(verified, nextHistory(floor, verified.release))
}

/** Explicit operator migration, bound to v1's exact current signed approval. */
export function migrateClockFloor(old, verified) {
  clockFloor(old); checkedApproval(verified)
  if (verified.release !== old.release || verified.release_dir !== old.release_dir || verified.record !== old.record
    || typeof verified.appliedAt !== 'string' || verified.appliedAt !== old.applied_at) {
    throw refuse('release-floor-migration-proof', 'migration needs exact legacy release, record and signed receipt timestamp')
  }
  return fromApproval(verified, [...old.history])
}

function releaseLock(file, identity, token) {
  const current = protectedNode(file, false)
  if (current.dev !== identity.dev || current.ino !== identity.ino) throw refuse('release-floor-lock-identity', 'live lock identity changed; operator reconciliation required')
  const fd = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW)
  try {
    const opened = protectedNode(file, false, fs.fstatSync(fd))
    if (opened.dev !== identity.dev || opened.ino !== identity.ino || opened.size !== Buffer.byteLength(token)
      || fs.readFileSync(fd).toString('utf8') !== token) throw refuse('release-floor-lock-identity', 'live lock token changed; operator reconciliation required')
  } finally { fs.closeSync(fd) }
  fs.unlinkSync(file)
}

/** Exclusive lock, reread under lock, fsync bytes, atomic rename, fsync directory.
 * A crashed/unknown lock is a fail-closed fence; there is no timeout or stealing.
 * Only explicit migration supplies clockMigrationProof, never ordinary install.
 */
export function writeFloor(file, floor, { clockMigrationProof } = {}) {
  checkedFloor(floor); protectedPath(file)
  const lock = `${file}.lock`, token = `${process.pid}:${randomBytes(16).toString('hex')}\n`
  let lockFd
  try { lockFd = fs.openSync(lock, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, 0o600) }
  catch (error) { if (error.code === 'EEXIST') throw refuse('release-floor-locked', 'existing lock requires operator reconciliation; no stale lock is stolen'); throw error }
  let identity, initialized = false
  try {
    identity = protectedNode(lock, false, fs.fstatSync(lockFd))
    fs.writeFileSync(lockFd, token); fs.fsyncSync(lockFd); initialized = true
    const current = readFloor(file, { requireRoot: true, allowClockMigration: clockMigrationProof !== undefined })
    if (clockMigrationProof !== undefined) {
      if (current === null || current.kind !== CLOCK_FLOOR_KIND) throw refuse('release-floor-migration-proof', 'migration requires an existing legacy clock floor')
      const old = clockMigrationProof?.old, verified = clockMigrationProof?.verified
      clockFloor(old)
      if (JSON.stringify(current) !== JSON.stringify(old) || JSON.stringify(migrateClockFloor(current, verified)) !== JSON.stringify(floor)) {
        throw refuse('release-floor-migration-proof', 'legacy floor or intended signed migration changed under lock')
      }
    } else if (current !== null && compare(current, floorApproval(floor)) <= 0) {
      throw refuse('release-floor-not-newer', 'current floor under lock is equal or newer than the intended replacement')
    }
    const replacement = clockMigrationProof === undefined ? fromApproval(floorApproval(floor), nextHistory(current, floor.release)) : floor
    const temporary = path.join(path.dirname(file), `.release-floor.tmp-${process.pid}-${randomBytes(16).toString('hex')}`)
    const fd = fs.openSync(temporary, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, 0o644)
    try {
      protectedNode(temporary, false, fs.fstatSync(fd))
      fs.writeFileSync(fd, JSON.stringify(replacement, null, 2) + '\n'); fs.fsyncSync(fd)
    } finally { fs.closeSync(fd) }
    fs.renameSync(temporary, file)
    const directory = path.dirname(file), directoryFd = fs.openSync(directory, fs.constants.O_RDONLY | fs.constants.O_DIRECTORY | fs.constants.O_NOFOLLOW)
    try { protectedNode(directory, true, fs.fstatSync(directoryFd)); fs.fsyncSync(directoryFd) } finally { fs.closeSync(directoryFd) }
  } finally {
    fs.closeSync(lockFd)
    if (initialized) releaseLock(lock, identity, token)
  }
}

/** Read-only gate fact for the owner card. */
export function isRollback(floor, release) {
  if (floor === null) return false
  checkedFloor(floor)
  return floor.release !== release && floor.history.includes(release)
}
