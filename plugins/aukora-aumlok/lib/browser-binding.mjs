// SPDX-License-Identifier: AGPL-3.0-or-later
// First binding recovers incomplete custody and derives memory identity from the record.
import { createHash, randomBytes } from 'node:crypto'
import { chmodSync, closeSync, constants as FS, fstatSync, fsyncSync, lstatSync, mkdirSync, openSync, unlinkSync } from 'node:fs'
import { isAbsolute, join, resolve } from 'node:path'
import { performance } from 'node:perf_hooks'
import { bindV3, BIND_REFUSE } from './bind-v3.mjs'
import { requireHandle, DERIVE_REFUSE } from './derive-v3.mjs'
import { generatePhrase, validatePhrase, PHRASE_REFUSE } from './ceremony-phrase.mjs'
import { openAttemptLimiter, ATTEMPT_REFUSE } from './attempt-limit.mjs'
import { loadLocalAumlokPublicControl, LOCAL_AUMLOK_CONTROL_FILENAME } from './store.mjs'
import { MACHINE_SEED_FILE, readKeptMachineSeed, recordProjection } from './record-v3.mjs'
import { ed25519FromSeed } from './derive-v3.mjs'
import { durableWrite, readJsonStrictBytes, readTextStrict, syncDirectory } from './strict-read.mjs'
import { MEMORY_OVERLAY_NAME, readKiraDeploymentOverlay, UNLINKED_MEMORY_SUBJECT } from '../../aukora-kira/lib/memory-identity.mjs'

export const BROWSER_BIND_REFUSE = Object.freeze({
  CONFIG: 'aumlok:browser-binding-config',
  STORAGE: 'aumlok:browser-binding-storage',
  BOUND: 'aumlok:bind-already-bound',
  BUSY: 'aumlok:browser-binding-busy',
  NO_DRAW: 'aumlok:no-pending-draw',
  EXPIRED: 'aumlok:browser-draw-expired',
  ACK: 'aumlok:browser-acknowledgement-required',
  SHAPE: 'aumlok:phrase-shape',
  MISMATCH: 'aumlok:phrase-mismatch',
  RECORD: 'aumlok:bind-record-unreadable',
  OVERLAY: 'aumlok:browser-memory-overlay-refused',
  WRITE: 'aumlok:bind-write-failed',
})
export const BROWSER_DRAW_LIFETIME_MS = 10 * 60_000
export const BROWSER_ATTEMPT_FILE = 'browser-binding-attempts.sqlite'
export const BROWSER_BIND_LOCK = 'browser-first-bind.lock'
const refused = (reason, extra = {}) => ({ ok: false, reason, ...extra })
const fail = code => { throw Object.assign(new Error(code), { code }) }
const knownCodes = new Set([BROWSER_BIND_REFUSE, BIND_REFUSE, DERIVE_REFUSE, PHRASE_REFUSE, ATTEMPT_REFUSE]
  .flatMap(codes => Object.values(codes)))
const codeOf = (cause, fallback) => typeof cause?.code === 'string'
  && (knownCodes.has(cause.code) || /^aumlok:bind-write-failed:[A-Z][A-Z0-9]{1,15}$/u.test(cause.code))
  ? cause.code : fallback
const hash = text => createHash('sha256').update(text).digest('hex')
const heldLocks = new Map()

function pathOf(value) {
  if (typeof value !== 'string' || !isAbsolute(value) || resolve(value) !== value
    || /[\u0000-\u001f\u007f-\u009f\u2028\u2029]/u.test(value)) fail(BROWSER_BIND_REFUSE.CONFIG)
  return value
}

function directory(path, create = false) {
  let fresh = false
  if (create) {
    try { mkdirSync(path, { mode: 0o700 }); fresh = true }
    catch (cause) { if (cause?.code !== 'EEXIST') fail(BROWSER_BIND_REFUSE.STORAGE) }
  }
  let info
  try { info = lstatSync(path) } catch { fail(BROWSER_BIND_REFUSE.STORAGE) }
  if (!info.isDirectory() || info.isSymbolicLink() || (info.mode & 0o022) !== 0
    || (process.getuid && info.uid !== process.getuid())) fail(BROWSER_BIND_REFUSE.STORAGE)
  return fresh
}

function occupied(dir) {
  try { lstatSync(join(dir, LOCAL_AUMLOK_CONTROL_FILENAME)); return true }
  catch (cause) { if (cause?.code === 'ENOENT') return false; fail(BROWSER_BIND_REFUSE.STORAGE) }
}

function releaseLock(dir, inode) {
  const path = join(dir, BROWSER_BIND_LOCK)
  const seen = lstatSync(path)
  if (seen.ino !== inode.ino || seen.dev !== inode.dev) return false
  unlinkSync(path); syncDirectory(dir)
  return true
}

function overlayBeforeBind(supportRoot, stateRoot) {
  const path = join(supportRoot, MEMORY_OVERLAY_NAME)
  let text
  try { text = readTextStrict(path, { maxBytes: 64 * 1024 }) }
  catch (cause) { if (cause?.code === 'ENOENT') return undefined; fail(BROWSER_BIND_REFUSE.OVERLAY) }
  let owner
  try { owner = readKiraDeploymentOverlay(text) } catch { fail(BROWSER_BIND_REFUSE.OVERLAY) }
  if (owner.subject !== UNLINKED_MEMORY_SUBJECT
    || (owner.stateDir !== undefined && owner.stateDir !== join(stateRoot, 'kira-memory'))) fail(BROWSER_BIND_REFUSE.OVERLAY)
  return text
}

function overlayForSubject(previous, subject, stateRoot) {
  if (!/^aukora:1:[0-9a-f]{64}$/u.test(subject)) fail(BROWSER_BIND_REFUSE.RECORD)
  const stateDir = join(stateRoot, 'kira-memory')
  if (previous === undefined) {
    return `- id: aukora-kira\n  config:\n    retrieval: lexical\n    memoryOwner:\n      stateDir: ${JSON.stringify(stateDir)}\n      subject: ${JSON.stringify(subject)}\n      permittedPrivacy: [local]\n`
  }
  const lines = previous.split(/\r?\n/u)
  let row = false, memory = false, memoryIndent = 0, subjectLine = -1, stateLine = -1
  for (let at = 0; at < lines.length; at++) {
    const line = lines[at]
    if (/^\s*-\s+id:/u.test(line)) { row = /^\s*-\s+id:\s*aukora-kira\s*(?:#.*)?$/u.test(line); memory = false }
    if (!row || line.trim() === '' || line.trimStart().startsWith('#')) continue
    const indentation = line.length - line.trimStart().length
    if (memory && indentation <= memoryIndent) memory = false
    if (/^\s*memoryOwner:\s*(?:#.*)?$/u.test(line)) { memory = true; memoryIndent = indentation; continue }
    if (memory && /^\s*subject:/u.test(line)) subjectLine = at
    if (memory && /^\s*stateDir:/u.test(line)) stateLine = at
  }
  if (subjectLine < 0) fail(BROWSER_BIND_REFUSE.OVERLAY)
  const indent = lines[subjectLine].match(/^\s*/u)[0]
  lines[subjectLine] = `${indent}subject: ${JSON.stringify(subject)}`
  if (stateLine < 0) lines.splice(subjectLine, 0, `${indent}stateDir: ${JSON.stringify(stateDir)}`)
  else lines[stateLine] = `${lines[stateLine].match(/^\s*/u)[0]}stateDir: ${JSON.stringify(stateDir)}`
  const text = lines.join('\n')
  const owner = readKiraDeploymentOverlay(text)
  if (owner.subject !== subject || owner.stateDir !== stateDir) fail(BROWSER_BIND_REFUSE.OVERLAY)
  return text
}

export function createBrowserBinding({ dir, supportRoot, stateRoot, now = Date.now, monotonicNow = () => performance.now() } = {}) {
  dir = pathOf(dir); supportRoot = pathOf(supportRoot); stateRoot = pathOf(stateRoot)
  if (typeof now !== 'function' || typeof monotonicNow !== 'function') fail(BROWSER_BIND_REFUSE.CONFIG)
  directory(supportRoot, true); directory(stateRoot, true)
  const fresh = directory(dir, true)
  const attemptSubject = `aukora:1:${hash(`aumlok-browser-first-bind:${dir}`)}`
  const permit = hash(`aumlok-browser-type-back:${dir}`)
  let limiter, pending = null, closed = false
  function initializeLimiter() {
    if (!limiter) {
      const file = join(dir, BROWSER_ATTEMPT_FILE)
      if (!fresh) {
        let info
        try { info = lstatSync(file) }
        catch (cause) { if (cause?.code !== 'ENOENT') fail('aumlok:attempt-store-unavailable') }
        if (info && (!info.isFile() || info.isSymbolicLink() || info.nlink !== 1 || (info.mode & 0o077) !== 0
          || (process.getuid && info.uid !== process.getuid()))) fail('aumlok:attempt-store-unavailable')
      }
      limiter = openAttemptLimiter({ file, initialize: fresh, now,
        rootForSubject: subject => subject === attemptSubject ? permit : undefined })
      if (fresh) chmodSync(file, 0o600)
    }
  }
  if (fresh) initializeLimiter()
  function remove(path, parent) {
    try { unlinkSync(path); syncDirectory(parent) }
    catch (cause) { if (cause?.code !== 'ENOENT') fail(BROWSER_BIND_REFUSE.STORAGE) }
  }
  function recover() {
    directory(dir); directory(supportRoot); directory(stateRoot)
    if (heldLocks.has(dir)) return undefined
    const lockPath = join(dir, BROWSER_BIND_LOCK)
    let interrupted = false
    try { lstatSync(lockPath); interrupted = true }
    catch (cause) { if (cause?.code !== 'ENOENT') fail(BROWSER_BIND_REFUSE.STORAGE) }
    let projection
    if (occupied(dir)) {
      let machine, incomplete = false
      try {
        const saved = readJsonStrictBytes(join(dir, LOCAL_AUMLOK_CONTROL_FILENAME))
        machine = readJsonStrictBytes(join(dir, MACHINE_SEED_FILE)).value
        incomplete = !saved.text.endsWith('\n')
      } catch (cause) {
        if (cause?.code !== 'ENOENT' && cause?.code !== 'json:malformed') fail(BROWSER_BIND_REFUSE.RECORD)
        incomplete = true
      }
      if (incomplete) {
        if (!interrupted) fail(BROWSER_BIND_REFUSE.RECORD)
        remove(join(dir, LOCAL_AUMLOK_CONTROL_FILENAME), dir)
      } else try {
        const key = ed25519FromSeed(Buffer.from(machine.ed25519SeedHex, 'hex'))
        if (machine.ed25519PublicKeyHex !== key.publicKeyHex) fail(BROWSER_BIND_REFUSE.RECORD)
        projection = loadLocalAumlokPublicControl(dir, undefined, machine.ed25519PublicKeyHex).projection
      } catch { fail(BROWSER_BIND_REFUSE.RECORD) }
    }
    if (projection === undefined) {
      remove(join(dir, MACHINE_SEED_FILE), dir)
      let unlinked = false
      try { unlinked = overlayBeforeBind(supportRoot, stateRoot) !== undefined } catch { /* Orphan overlays are removed. */ }
      if (!unlinked) remove(join(supportRoot, MEMORY_OVERLAY_NAME), supportRoot)
    } else {
      const path = join(supportRoot, MEMORY_OVERLAY_NAME)
      let previous, owner
      try { previous = readTextStrict(path, { maxBytes: 64 * 1024 }); owner = readKiraDeploymentOverlay(previous) }
      catch (cause) { if (cause?.code !== 'ENOENT') fail(BROWSER_BIND_REFUSE.OVERLAY) }
      if (owner?.subject !== projection.subject || owner?.stateDir !== join(stateRoot, 'kira-memory')) {
        durableWrite(path, overlayForSubject(previous, projection.subject, stateRoot))
      }
      const stored = readKiraDeploymentOverlay(readTextStrict(path, { maxBytes: 64 * 1024 }))
      if (projection.subject !== stored.subject || join(stateRoot, 'kira-memory') !== stored.stateDir) fail(BROWSER_BIND_REFUSE.OVERLAY)
    }
    remove(lockPath, dir)
    return projection
  }
  // Keep an interrupted marker until its custody and overlay have been reconciled.
  try { recover() } catch { /* Status retries recovery and returns a named refusal. */ }
  function attempts(correct) {
    initializeLimiter()
    return limiter.present({ subject: attemptSubject, rootId: correct ? permit : '0'.repeat(64) })
  }
  function available() {
    if (closed) fail(BROWSER_BIND_REFUSE.STORAGE)
    directory(dir); directory(supportRoot); directory(stateRoot)
    if (occupied(dir)) fail(BROWSER_BIND_REFUSE.BOUND)
  }
  function status() {
    try {
      if (closed) fail(BROWSER_BIND_REFUSE.STORAGE)
      const projection = recover()
      if (heldLocks.has(dir)) return { ok: true, bound: false, state: 'binding-in-progress' }
      if (projection === undefined) return { ok: true, bound: false, state: 'unbound' }
      return { ok: true, bound: true, state: 'bound', subject: projection.subject, handle: projection.handle,
        boundAt: projection.boundAt, rootId: projection.activeControlDigest }
    } catch (cause) { return refused(codeOf(cause, BROWSER_BIND_REFUSE.RECORD)) }
  }
  function prepare({ handle, language = 'en' } = {}) {
    try {
      available()
      const normalizedHandle = requireHandle(handle)
      const at = monotonicNow()
      if (!Number.isFinite(at) || at < 0 || at > Number.MAX_SAFE_INTEGER - BROWSER_DRAW_LIFETIME_MS) fail(BROWSER_BIND_REFUSE.CONFIG)
      if (pending !== null && at < pending.expiresAt) fail(BROWSER_BIND_REFUSE.BUSY)
      pending = null
      const previous = overlayBeforeBind(supportRoot, stateRoot)
      overlayForSubject(previous, `aukora:1:${'0'.repeat(64)}`, stateRoot)
      try { lstatSync(join(dir, BROWSER_BIND_LOCK)); fail(BROWSER_BIND_REFUSE.BUSY) }
      catch (cause) { if (cause?.code !== 'ENOENT') throw cause }
      if (!attempts(true).ok) fail('aumlok:enrollment-refused')
      const drawn = generatePhrase({ language })
      const ceremonyId = randomBytes(32).toString('hex')
      pending = { ceremonyId, words: drawn.words, handle: normalizedHandle,
        language: drawn.language, expiresAt: at + BROWSER_DRAW_LIFETIME_MS }
      return { ok: true, draw: { ceremonyId, words: [...drawn.words], language: drawn.language,
        entropyBits: drawn.entropyBits } }
    } catch (cause) { return refused(codeOf(cause, BROWSER_BIND_REFUSE.STORAGE)) }
  }
  async function bind({ ceremonyId, typedPhrase, acknowledged } = {}) {
    let lock, inode
    const expected = pending
    if (expected === null || ceremonyId !== expected.ceremonyId) return refused(BROWSER_BIND_REFUSE.NO_DRAW, { drawSpent: expected === null })
    pending = null
    try {
      available()
      const at = monotonicNow()
      if (!Number.isFinite(at) || at < 0) fail(BROWSER_BIND_REFUSE.CONFIG)
      if (at >= expected.expiresAt) fail(BROWSER_BIND_REFUSE.EXPIRED)
      if (acknowledged !== true) { attempts(false); fail(BROWSER_BIND_REFUSE.ACK) }
      if (typeof typedPhrase !== 'string' || typedPhrase.length < 1 || typedPhrase.length > 512) {
        attempts(false); fail(BROWSER_BIND_REFUSE.SHAPE)
      }
      let offered
      try { offered = validatePhrase(typedPhrase, { language: expected.language }).words }
      catch { attempts(false); fail(BROWSER_BIND_REFUSE.SHAPE) }
      if (offered.some((word, at) => word !== expected.words[at])) { attempts(false); fail(BROWSER_BIND_REFUSE.MISMATCH) }
      if (!attempts(true).ok) fail('aumlok:enrollment-refused')
      const previousOverlay = overlayBeforeBind(supportRoot, stateRoot)
      try { lock = openSync(join(dir, BROWSER_BIND_LOCK), FS.O_WRONLY | FS.O_CREAT | FS.O_EXCL | FS.O_NOFOLLOW, 0o600) }
      catch (cause) { fail(cause?.code === 'EEXIST' ? BROWSER_BIND_REFUSE.BUSY : BROWSER_BIND_REFUSE.STORAGE) }
      inode = fstatSync(lock)
      heldLocks.set(dir, inode)
      fsyncSync(lock)
      syncDirectory(dir)
      available()
      const bound = await bindV3({ handle: expected.handle, words: offered, phraseLanguage: expected.language,
        directory: dir, boundAt: new Date(now()).toISOString(), custodian: 'file' })
      let projection
      try {
        const machine = readKeptMachineSeed({ directory: dir })
        const key = ed25519FromSeed(Buffer.from(machine.ed25519SeedHex, 'hex'))
        if (key.publicKeyHex !== machine.ed25519PublicKeyHex) fail(BROWSER_BIND_REFUSE.RECORD)
        const control = loadLocalAumlokPublicControl(dir, undefined, machine.ed25519PublicKeyHex).projection
        const saved = readJsonStrictBytes(join(dir, LOCAL_AUMLOK_CONTROL_FILENAME)).value
        projection = recordProjection(saved)
        if (saved.version !== 3 || projection.subject !== bound.projection.subject
          || projection.rootId !== bound.projection.rootId || projection.subject !== control.subject
          || projection.rootId !== control.activeControlDigest) fail(BROWSER_BIND_REFUSE.RECORD)
      } catch { fail(BROWSER_BIND_REFUSE.RECORD) }
      const currentOverlay = overlayBeforeBind(supportRoot, stateRoot)
      if (currentOverlay !== previousOverlay) fail(BROWSER_BIND_REFUSE.OVERLAY)
      const overlay = overlayForSubject(currentOverlay, projection.subject, stateRoot)
      durableWrite(join(supportRoot, MEMORY_OVERLAY_NAME), overlay)
      const stored = readKiraDeploymentOverlay(readTextStrict(join(supportRoot, MEMORY_OVERLAY_NAME), { maxBytes: 64 * 1024 }))
      if (stored.subject !== projection.subject || stored.stateDir !== join(stateRoot, 'kira-memory')) fail(BROWSER_BIND_REFUSE.OVERLAY)
      if (!releaseLock(dir, inode)) fail(BROWSER_BIND_REFUSE.STORAGE)
      return { ok: true, reason: 'aumlok:ceremony-verified', binding: { subject: projection.subject,
        handle: projection.handle, boundAt: projection.boundAt, rootId: projection.rootId }, drawSpent: true }
    } catch (cause) { return refused(codeOf(cause, BROWSER_BIND_REFUSE.WRITE), { drawSpent: true }) }
    finally {
      if (lock !== undefined) {
        try {
          closeSync(lock)
          if (!occupied(dir)) releaseLock(dir, inode)
        } catch { /* Startup reclaims a marker left by an interrupted write. */ }
        finally { heldLocks.delete(dir) }
      }
    }
  }
  function cancel({ ceremonyId } = {}) {
    if (pending === null || ceremonyId !== pending.ceremonyId) return refused(BROWSER_BIND_REFUSE.NO_DRAW)
    pending = null
    return { ok: true, drawSpent: true }
  }
  return Object.freeze({ prepare, bind, cancel, status, close() {
    pending = null
    if (closed) return
    closed = true
    limiter?.close()
  } })
}
