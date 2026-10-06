// SPDX-License-Identifier: AGPL-3.0-or-later
// This import and its deployed source must be pinned before the host starts Node.
// releaseRoot selects a diagnostic destination; it never selects executable code.
import fs from 'node:fs'
import path from 'node:path'
import { randomBytes } from 'node:crypto'
import { readGateSnapshot } from '../../../scripts/aura/gate-snapshot.mjs'
import { canonicalAbsolutePath, checkProtectedPublicAncestors, sameFileIdentity, sameDirectoryIdentity } from './protected-public-data.mjs'

const EVENTS = new Set(['apply', 'apply-failed', 'apply-incomplete', 'decide', 'decide-refused', 'expire',
  'gate-start', 'genesis-target', 'genesis-target-invalid', 'harness-start', 'owner-authorization-consumed',
  'owner-authorization-required', 'owner-bearer-rotated', 'propose', 'reconcile', 'reject', 'relay-intent',
  'relay-posted', 'review-issued', 'revert-applied', 'selfcheck'])
const unavailable = () => { throw new Error('redacted-gate-summary:unavailable') }
const diagnostic = () => ({ kind: 'aukora-host-ledger-summary/v1', classification: 'diagnostic',
  release_digest_coverage: 'excluded', grants_authority: false, freshness: 'selected-snapshot-only' })

/** Host-only source read. Any bad/gapped/oversized signature chain produces no head or counts. */
export function readRedactedGateSummary(snapshotOptions) {
  try {
    const snapshot = readGateSnapshot(snapshotOptions)
    if (snapshot.ok !== true || snapshot.status !== 'complete') unavailable()
    const counts = Object.create(null)
    for (const record of snapshot.records) {
      const event = record.entry.event
      // A signed free-form event is not permitted to smuggle private text into a count key.
      if (!EVENTS.has(event)) unavailable()
      counts[event] = (counts[event] ?? 0) + 1
    }
    return Object.freeze({ ...diagnostic(), selected_head: Object.freeze({ ...snapshot.selected_head }),
      counts_by_event_type: Object.freeze(Object.fromEntries(Object.entries(counts).sort(([a], [b]) => a.localeCompare(b)))) })
  } catch { unavailable() }
}

function safeExistingOutput(file, readerGid) {
  let info
  try { info = fs.lstatSync(file) } catch (error) { if (error.code === 'ENOENT') return; unavailable() }
  if (!info.isFile() || info.uid !== 0 || info.gid !== readerGid || info.nlink !== 1
    || (info.mode & 0o777) !== 0o440) unavailable()
}

/** The operator supplies an already provisioned diagnostic directory and reader group.
 * Atomic 0600 staging -> 0440 publication, never a target, receipt or authority file.
 * Failed verification preserves the last verified snapshot, whose freshness remains explicitly bounded.
 */
export function writeRedactedGateSummary({ releaseRoot, snapshotOptions, readerGid } = {}) {
  let fd, directoryFd
  try {
    if (!canonicalAbsolutePath(releaseRoot) || !Number.isSafeInteger(readerGid) || readerGid < 0
      || readerGid > 0xffffffff || typeof process.getuid !== 'function' || process.getuid() !== 0
      || typeof fs.constants.O_NOFOLLOW !== 'number' || typeof fs.constants.O_DIRECTORY !== 'number') unavailable()
    const outputPath = path.join(releaseRoot, '.dsh-build', 'host-ledger-summary.json')
    const directory = path.dirname(outputPath)
    checkProtectedPublicAncestors(outputPath, { readerGid })
    const namedDirectory = fs.lstatSync(directory)
    if (namedDirectory.gid !== readerGid || (namedDirectory.mode & 0o050) !== 0o050) unavailable()
    directoryFd = fs.openSync(directory, fs.constants.O_RDONLY | fs.constants.O_DIRECTORY | fs.constants.O_NOFOLLOW)
    if (!sameDirectoryIdentity(namedDirectory, fs.fstatSync(directoryFd))) unavailable()
    safeExistingOutput(outputPath, readerGid)
    // Signature/chain verification is the sole source of counts; callers cannot supply them.
    const summary = readRedactedGateSummary(snapshotOptions)
    const bytes = Buffer.from(JSON.stringify(summary) + '\n')
    const temporary = path.join(directory, `.host-ledger-summary.${process.pid}.${randomBytes(12).toString('hex')}.pending`)
    fd = fs.openSync(temporary, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, 0o600)
    let offset = 0
    while (offset < bytes.length) {
      const count = fs.writeSync(fd, bytes, offset, bytes.length - offset)
      if (count < 1) unavailable()
      offset += count
    }
    fs.fchownSync(fd, 0, readerGid)
    fs.fchmodSync(fd, 0o440)
    fs.fsyncSync(fd)
    // Protected ancestors exclude untrusted directory swaps; the root updater must stay quiescent.
    checkProtectedPublicAncestors(outputPath, { readerGid })
    if (!sameDirectoryIdentity(namedDirectory, fs.fstatSync(directoryFd))
      || !sameDirectoryIdentity(namedDirectory, fs.lstatSync(directory))) unavailable()
    safeExistingOutput(outputPath, readerGid)
    fs.renameSync(temporary, outputPath)
    const published = fs.lstatSync(outputPath), staged = fs.fstatSync(fd)
    if (!sameFileIdentity(published, staged) || published.uid !== 0 || published.gid !== readerGid
      || published.nlink !== 1 || (published.mode & 0o777) !== 0o440) unavailable()
    fs.fsyncSync(directoryFd)
    return summary
  } catch { unavailable() }
  finally {
    if (fd !== undefined) fs.closeSync(fd)
    if (directoryFd !== undefined) fs.closeSync(directoryFd)
  }
}
