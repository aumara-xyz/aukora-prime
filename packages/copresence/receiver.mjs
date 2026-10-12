// Verifies fresh receipts and consumes their core once; returned evidence grants nothing.
import { spawnSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { closeSync, fsyncSync, mkdtempSync, openSync, realpathSync, rmSync, statSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { verifyEvent } from '../../plugins/aukora-nostr/lib/event.mjs'
import { gateCall } from '../../plugins/aukora-buzz-door/lib/index.mjs'

export const RECEIVER_REFUSE = Object.freeze({
  MALFORMED: 'copresence:malformed',
  VERIFIER: 'copresence:verifier-refused',
  STALE: 'copresence:stale',
  FUTURE: 'copresence:future',
  WRONG_ASKER: 'copresence:wrong-asker',
  WRONG_APPROVER: 'copresence:wrong-approver',
  ROLES_REQUIRE_TEXT: 'copresence:roles-require-text',
  STORE: 'copresence:store',
  REPLAY: 'copresence:replay',
  BINDING: 'copresence:binding',
  AURA: 'copresence:aura-unrecorded',
})

const here = path.dirname(fileURLToPath(import.meta.url))
const refuse = code => Object.assign(new Error(code), { code })
const hex = (value, length) => typeof value === 'string' && value.length === length && /^[0-9a-f]+$/i.test(value)
const p256 = value => hex(value, 130) && value.startsWith('04')
const object = value => value !== null && typeof value === 'object' && !Array.isArray(value)
const hash = (...parts) => createHash('sha256').update(Buffer.concat(parts)).digest('hex')

function digestInput(core) {
  if (typeof core !== 'string' || !/^[0-9a-f]{64}$/.test(core)) throw refuse(RECEIVER_REFUSE.STORE)
}

// Atomic within one process only; callers needing restart protection must use durable storage.
export function createMemoryStore() {
  const spent = new Set()
  return Object.freeze({ consume(core) {
    digestInput(core)
    if (spent.has(core)) return false
    spent.add(core)
    return true
  } })
}

// The caller owns an existing durable directory; exclusive markers are never removed on failure.
export function createFileStore(directory) {
  let root
  try {
    root = realpathSync(directory)
    if (!statSync(root).isDirectory()) throw new Error()
  } catch { throw refuse(RECEIVER_REFUSE.STORE) }
  return Object.freeze({ consume(core) {
    digestInput(core)
    let marker, dir
    try {
      try { marker = openSync(path.join(root, core), 'wx', 0o600) }
      catch (error) {
        if (error.code === 'EEXIST') return false
        throw error
      }
      fsyncSync(marker)
      dir = openSync(root, 'r')
      fsyncSync(dir)
      return true
    } catch { throw refuse(RECEIVER_REFUSE.STORE) }
    finally {
      if (marker !== undefined) closeSync(marker)
      if (dir !== undefined) closeSync(dir)
    }
  } })
}

// Only verifier inputs cross into scratch; location and arbitrary serialization hooks are ignored.
function verificationFields(receipt, withText) {
  if (!object(receipt)) throw refuse(RECEIVER_REFUSE.MALFORMED)
  const r = {}
  for (const name of ['v', 'pk_A', 'pk_B', 'nonce_A', 'nonce_B', 't_A', 't_B', 'sig_A', 'sig_B']) r[name] = receipt[name]
  if (r.v !== 0 || !p256(r.pk_A) || !p256(r.pk_B)
    || !hex(r.nonce_A, 16) || !hex(r.nonce_B, 16) || !hex(r.sig_A, 128) || !hex(r.sig_B, 128)
    || !Number.isSafeInteger(r.t_A) || r.t_A < 0 || !Number.isSafeInteger(r.t_B) || r.t_B < 0) {
    throw refuse(RECEIVER_REFUSE.MALFORMED)
  }
  if (receipt.audio !== undefined) {
    if (!object(receipt.audio)) throw refuse(RECEIVER_REFUSE.MALFORMED)
    r.audio = {}
    for (const name of ['nonce', 'delay_ms', 'matched']) {
      const value = receipt.audio[name]
      if (value !== undefined) {
        if (!['string', 'number', 'boolean'].includes(typeof value)) throw refuse(RECEIVER_REFUSE.MALFORMED)
        r.audio[name] = value
      }
    }
  }
  if (withText && receipt.intent !== undefined) {
    const it = receipt.intent
    if (!object(it)) throw refuse(RECEIVER_REFUSE.MALFORMED)
    r.intent = {}
    for (const name of ['text', 'digest', 'salt', 'side']) {
      if (it[name] !== undefined && typeof it[name] !== 'string') throw refuse(RECEIVER_REFUSE.MALFORMED)
      r.intent[name] = it[name]
    }
    if (it.ack !== undefined) {
      if (!object(it.ack) || (it.ack.sig !== undefined && typeof it.ack.sig !== 'string')) throw refuse(RECEIVER_REFUSE.MALFORMED)
      r.intent.ack = { sig: it.ack.sig }
    }
  }
  return r
}

function coreOf(r) {
  const time = Buffer.alloc(8)
  time.writeBigUInt64BE(BigInt(r.t_B))
  return hash(Buffer.from('copresence.v0\0'), ...['pk_A', 'pk_B', 'nonce_A', 'nonce_B'].map(k => Buffer.from(r[k], 'hex')), time)
}

function runVerifier(script, file, ...args) {
  const p = spawnSync(process.execPath, [path.join(here, script), file, ...args], {
    encoding: 'utf8', timeout: 10_000, maxBuffer: 64 * 1024,
  })
  if (p.error || p.signal || p.status !== 0) throw refuse(RECEIVER_REFUSE.VERIFIER)
  return (p.stdout ?? '').trim()
}

function verifiedEvidence(receipt, options) {
  if (options.gateSocket !== undefined && (typeof options.gateSocket !== 'string'
    || !path.isAbsolute(options.gateSocket) || options.gateSocket.includes('\0'))) throw refuse(RECEIVER_REFUSE.AURA)
  const { now, maxAge = 300, expectedText, expectedAsker, expectedApprover, scratchDir = tmpdir(), store } = options
  if (!Number.isFinite(now) || now < 0 || !Number.isFinite(maxAge) || maxAge < 0
    || (expectedText !== undefined && typeof expectedText !== 'string')
    || (expectedAsker !== undefined && !p256(expectedAsker))
    || (expectedApprover !== undefined && !p256(expectedApprover))) throw refuse(RECEIVER_REFUSE.MALFORMED)
  if (!store || typeof store.consume !== 'function') throw refuse(RECEIVER_REFUSE.STORE)
  if (expectedText === undefined && (expectedAsker !== undefined || expectedApprover !== undefined)) {
    throw refuse(RECEIVER_REFUSE.ROLES_REQUIRE_TEXT)
  }
  const r = verificationFields(receipt, expectedText !== undefined)
  let scratch, intent
  try {
    scratch = mkdtempSync(path.join(scratchDir, 'copresence-'))
    const file = path.join(scratch, 'receipt.json')
    writeFileSync(file, JSON.stringify(r), { mode: 0o600, flag: 'wx' })
    if (runVerifier('verify.mjs', file) !== 'valid') throw refuse(RECEIVER_REFUSE.VERIFIER)
    if (expectedText !== undefined) intent = JSON.parse(runVerifier('verify-intent.mjs', file, '--text', expectedText))
  } catch { throw refuse(RECEIVER_REFUSE.VERIFIER) }
  finally { if (scratch !== undefined) rmSync(scratch, { recursive: true, force: true }) }
  if (now - r.t_B > maxAge) throw refuse(RECEIVER_REFUSE.STALE)
  if (r.t_B - now > 5) throw refuse(RECEIVER_REFUSE.FUTURE)
  const core = coreOf(r)
  const keys = { A: r.pk_A.toLowerCase(), B: r.pk_B.toLowerCase() }
  const evidence = { core, keys, t_B: r.t_B }
  if (expectedText !== undefined) {
    const side = r.intent?.side
    keys.asker = keys[side]
    keys.approver = keys[side === 'A' ? 'B' : 'A']
    const digest = hash(Buffer.from('copresence.intent.v1\0'), Buffer.from(expectedText))
    if (intent?.valid !== true || intent.core !== core || intent.t_B !== r.t_B
      || intent.asker_key !== keys.asker || intent.approver_key !== keys.approver || intent.text_digest !== digest) {
      throw refuse(RECEIVER_REFUSE.VERIFIER)
    }
    if (expectedAsker !== undefined && expectedAsker.toLowerCase() !== keys.asker) throw refuse(RECEIVER_REFUSE.WRONG_ASKER)
    if (expectedApprover !== undefined && expectedApprover.toLowerCase() !== keys.approver) throw refuse(RECEIVER_REFUSE.WRONG_APPROVER)
    evidence.textDigest = digest
  }
  Object.freeze(keys)
  return Object.freeze(evidence)
}

async function consume(evidence, { store, gateSocket, gate = gateCall }) {
  let result
  try { result = await store.consume(evidence.core) }
  catch { throw refuse(RECEIVER_REFUSE.STORE) }
  if (result === false) throw refuse(RECEIVER_REFUSE.REPLAY)
  if (result !== true) throw refuse(RECEIVER_REFUSE.STORE)
  // Only the verified signed core reaches Aura; a failed acknowledgement leaves that core spent.
  if (gateSocket !== undefined) {
    try {
      const ack = await gate(gateSocket, 'aura_note', { kind: 'copresence-accepted', digest_sha256: evidence.core })
      if (ack?.ok !== true || !Number.isSafeInteger(ack.seq) || ack.seq < 1
        || typeof ack.hash !== 'string' || !/^[0-9a-f]{64}$/.test(ack.hash)) throw refuse(RECEIVER_REFUSE.AURA)
    } catch { throw refuse(RECEIVER_REFUSE.AURA) }
  }
  return evidence
}

export async function receiveReceipt(receipt, options = {}) {
  if (!object(options)) throw refuse(RECEIVER_REFUSE.MALFORMED)
  const evidence = verifiedEvidence(receipt, options)
  return consume(evidence, options)
}

// Both the device's exact intent and the member's signed core statement must verify before consumption.
export async function verifyDeviceBinding(receipt, options = {}) {
  if (!object(options)) throw refuse(RECEIVER_REFUSE.MALFORMED)
  const { memberPubkey, deviceKey, event } = options
  if (!hex(memberPubkey, 64) || !p256(deviceKey)) throw refuse(RECEIVER_REFUSE.BINDING)
  const member = memberPubkey.toLowerCase()
  const text = `aukora-device:v1:${member}`
  if ((options.expectedText !== undefined && options.expectedText !== text)
    || (options.expectedApprover !== undefined && (!p256(options.expectedApprover)
      || options.expectedApprover.toLowerCase() !== deviceKey.toLowerCase()))) {
    throw refuse(RECEIVER_REFUSE.BINDING)
  }
  const evidence = verifiedEvidence(receipt, { ...options, expectedText: text, expectedApprover: deviceKey })
  try {
    if (verifyEvent(event) !== true || event.pubkey.toLowerCase() !== member || event.kind !== 1
      || event.tags.length !== 0 || event.content !== `${text}:${evidence.core}`) throw new Error()
  } catch { throw refuse(RECEIVER_REFUSE.BINDING) }
  return consume(evidence, options)
}
