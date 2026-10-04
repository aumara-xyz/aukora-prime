// SPDX-License-Identifier: AGPL-3.0-or-later
// H must pin this fixed entry, its full source-relative import closure and the
// protected JSON before Node starts. Parsing configuration is not authentication.
// Existing scoped material is read only; no enrollment, key discovery or fallback.
import { constants, openSync, closeSync, fstatSync, lstatSync, readSync } from 'node:fs'
import { dirname, isAbsolute } from 'node:path'
import { canonicalJson, parseStrictJson } from '../../../../packages/contracts/src/json.mjs'
import * as records from '../../../../plugins/aukora-nostr/lib/records.mjs'
import { publicKeyOf } from '../../../../plugins/aukora-nostr/lib/event.mjs'
import { verifyBindingWithKey } from '../../../../plugins/aukora-nostr/lib/identity.mjs'
import { createNostrCollectorCodec, createCollectorCitationReader } from '../../../../scripts/aura/collect-gate.mjs'
import { gatePublicKeySha256, readGateSnapshot } from '../../../../scripts/aura/gate-snapshot.mjs'
import { createAuraRecordsProvider } from './records-provider.mjs'

export const AURA_CONTEXT_PATH = '/etc/aukora-boundary-gate/aura-context.json'
const MAX_CONFIG_BYTES = 1024 * 1024
const HEX64 = /^[0-9a-f]{64}$/u
const SUBJECT = /^aukora:1:[0-9a-f]{64}$/u
const SOURCE_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u
const CONFIGURATIONS = new WeakSet()
const LOADED = new WeakSet()
const refuse = reason => Object.assign(new Error(`aura-context:${reason}`), { code: `aura-context:${reason}` })
const closed = (value, keys) => value !== null && typeof value === 'object' && !Array.isArray(value)
  && Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key))
const path = value => typeof value === 'string' && isAbsolute(value) && value.length <= 4096
  && value.isWellFormed() && !/[\u0000-\u001f\u007f]/u.test(value)
  && value.split('/').every(part => part !== '.' && part !== '..')
const hex = value => typeof value === 'string' && HEX64.test(value)
const bound = (value, maximum) => Number.isSafeInteger(value) && value > 0 && value <= maximum
const freeze = value => {
  if (value !== null && typeof value === 'object') {
    for (const child of Object.values(value)) freeze(child)
    Object.freeze(value)
  }
  return value
}

/** Closed data only. Independent owner/source pins are supplied by H's protected configuration. */
export function parseAuraConfiguration(text) {
  try {
    if (typeof text !== 'string' || Buffer.byteLength(text) > MAX_CONFIG_BYTES) throw refuse('configuration-invalid')
    const value = parseStrictJson(text)
    if (!closed(value, ['version', 'kind', 'owner_subject', 'store_dir', 'source', 'nostr', 'anchors', 'python_executable'])
      || value.version !== 1 || value.kind !== 'aukora-aura-context/v1'
      || typeof value.owner_subject !== 'string' || !SUBJECT.test(value.owner_subject)
      || !path(value.store_dir) || value.python_executable !== '/usr/bin/python3') throw refuse('configuration-invalid')
    const source = value.source, nostr = value.nostr
    if (!closed(source, ['db_path', 'source_id', 'public_key_pem', 'key_sha256', 'max_rows', 'max_bytes', 'max_record_bytes'])
      || !path(source.db_path) || typeof source.source_id !== 'string' || !SOURCE_ID.test(source.source_id)
      || typeof source.public_key_pem !== 'string' || !hex(source.key_sha256)
      || gatePublicKeySha256(source.public_key_pem) !== source.key_sha256
      || !bound(source.max_rows, 50000) || !bound(source.max_bytes, 16 * 1024 * 1024)
      || !bound(source.max_record_bytes, 48 * 1024)) throw refuse('source-invalid')
    if (!closed(nostr, ['binding', 'controller_key_hex', 'author_pubkey_hex', 'owner_pubkey_hex', 'author_secret_path'])
      || !hex(nostr.controller_key_hex) || !hex(nostr.author_pubkey_hex) || !hex(nostr.owner_pubkey_hex)
      || !path(nostr.author_secret_path)) throw refuse('record-pins-invalid')
    const binding = verifyBindingWithKey(nostr.binding, {
      controllerKeyHex: nostr.controller_key_hex, expectSubject: value.owner_subject })
    if (binding.verdict !== 'verified' || binding.nostrPubkeyHex !== nostr.author_pubkey_hex)
      throw refuse('binding-invalid')
    if (!Array.isArray(value.anchors) || value.anchors.length > 4096) throw refuse('anchors-invalid')
    let previous = 0
    for (const anchor of value.anchors) {
      if (!closed(anchor, ['seq', 'head', 'gate_fp', 'entry_at', 'anchored_at'])
        || !Number.isSafeInteger(anchor.seq) || anchor.seq <= previous || !hex(anchor.head)
        || anchor.gate_fp !== source.key_sha256.slice(0, 16)
        || typeof anchor.entry_at !== 'string' || !anchor.entry_at || anchor.entry_at.length > 128
        || typeof anchor.anchored_at !== 'string' || !anchor.anchored_at || anchor.anchored_at.length > 128)
        throw refuse('anchors-invalid')
      previous = anchor.seq
    }
    freeze(value); CONFIGURATIONS.add(value)
    return value
  } catch (error) {
    throw refuse(typeof error?.code === 'string' && /^aura-context:[a-z-]+$/u.test(error.code)
      ? error.code.slice('aura-context:'.length) : 'configuration-invalid')
  }
}

/** Root-owned data; no-follow, bounded bytes, identity checked after reading. */
export function readProtectedAuraData(file, { secret = false, maximum = MAX_CONFIG_BYTES } = {}) {
  let fd
  try {
    if (!path(file) || !bound(maximum, MAX_CONFIG_BYTES)
      || typeof constants.O_NOFOLLOW !== 'number' || typeof constants.O_NONBLOCK !== 'number')
      throw refuse('protected-data-unavailable')
    for (let ancestor = dirname(file); ; ancestor = dirname(ancestor)) {
      const info = lstatSync(ancestor)
      if (!info.isDirectory() || info.uid !== 0 || (info.mode & 0o022) !== 0) throw refuse('protected-data-unavailable')
      if (ancestor === '/') break
    }
    fd = openSync(file, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK)
    const before = fstatSync(fd)
    if (!before.isFile() || before.uid !== 0 || before.nlink !== 1 || (before.mode & (secret ? 0o077 : 0o022)) !== 0
      || before.size < 1 || before.size > maximum) throw refuse('protected-data-unavailable')
    const bytes = Buffer.alloc(maximum + 1)
    let used = 0, count
    while ((count = readSync(fd, bytes, used, bytes.length - used, null)) > 0) {
      used += count
      if (used > maximum) throw refuse('protected-data-unavailable')
    }
    const after = fstatSync(fd)
    if (used !== before.size || ['dev', 'ino', 'uid', 'mode', 'nlink', 'size', 'mtimeMs', 'ctimeMs']
      .some(field => before[field] !== after[field])) throw refuse('protected-data-unavailable')
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes.subarray(0, used))
  } catch { throw refuse('protected-data-unavailable') }
  finally { if (fd !== undefined) closeSync(fd) }
}

/** Trusted-host construction seam; material is existing scoped data, never guest input. */
export async function createAuraCollectorContext(configuration, { authorSecretKeyHex } = {}) {
  try {
    if (!CONFIGURATIONS.has(configuration)) throw refuse('configuration-unrecognized')
    if (!hex(authorSecretKeyHex) || publicKeyOf(authorSecretKeyHex) !== configuration.nostr.author_pubkey_hex)
      throw refuse('scoped-material-unavailable')
    const { source, nostr } = configuration
    const codec = await createNostrCollectorCodec({ records, authorSecretKeyHex,
      binding: nostr.binding, controllerKeyHex: nostr.controller_key_hex, ownerSubject: configuration.owner_subject,
      authorPubkeyHex: nostr.author_pubkey_hex, ownerPubkeyHex: nostr.owner_pubkey_hex })
    const loaded = Object.freeze({ ownerSubject: configuration.owner_subject,
      collectorContext: Object.freeze({ storeDir: configuration.store_dir, codec,
        snapshotOptions: Object.freeze({ dbPath: source.db_path, sourceId: source.source_id,
          publicKeyPem: source.public_key_pem, expectedKeySha256: source.key_sha256,
          maxRows: source.max_rows, maxBytes: source.max_bytes, maxRecordBytes: source.max_record_bytes }),
        anchors: configuration.anchors, pythonExecutable: configuration.python_executable }) })
    LOADED.add(loaded)
    return loaded
  } catch (error) {
    throw refuse(typeof error?.code === 'string' && /^aura-context:[a-z-]+$/u.test(error.code)
      ? error.code.slice('aura-context:'.length) : 'scoped-material-unavailable')
  }
}

/** Fixed path only; H's pre-Node manifest also binds this JSON and import closure. */
export async function loadAuraContext() {
  const configuration = parseAuraConfiguration(readProtectedAuraData(AURA_CONTEXT_PATH))
  const secret = readProtectedAuraData(configuration.nostr.author_secret_path, { secret: true, maximum: 65 })
  if (!/^[0-9a-f]{64}\n?$/u.test(secret)) throw refuse('scoped-material-unavailable')
  return createAuraCollectorContext(configuration, { authorSecretKeyHex: secret.replace(/\n$/u, '') })
}

/** Register only provider.service; disposal and actual association lookup stay with the host. */
export function createConfiguredAuraRecords(loaded, { isLive, hasReadGrant, referenceForRecord = null } = {}) {
  if (!LOADED.has(loaded)) throw refuse('configuration-unrecognized')
  const reader = createCollectorCitationReader(loaded.collectorContext, { isLive, hasReadGrant })
  return createAuraRecordsProvider({ ownerSubject: loaded.ownerSubject, reader, isLive, hasReadGrant, referenceForRecord })
}

/**
 * Host-only capture seam for H's ACTUAL successful action result. The caller must
 * retain that result from the same authenticated capture, never model parameters.
 * Match its exact receipt/signature to the specific signed row, never journal tip.
 * This returns an observation coordinate; it does not validate owner authorization.
 */
export function createGateCaptureReferenceResolver(loaded, { isLive, hasReadGrant } = {}) {
  if (!LOADED.has(loaded) || typeof isLive !== 'function' || typeof hasReadGrant !== 'function')
    throw refuse('capture-resolver-unconfigured')
  let disposed = false
  const trueSync = (callback, ...args) => {
    const result = callback(...args)
    if (result !== true && result !== false) {
      try { Promise.prototype.then.call(result, undefined, () => {}) } catch {}
    }
    return result === true
  }
  const check = () => {
    try {
      if (disposed || !trueSync(isLive) || !trueSync(hasReadGrant, loaded.ownerSubject)
        || disposed || !trueSync(isLive) || disposed) throw refuse('capture-read-unavailable')
    } catch { throw refuse('capture-read-unavailable') }
  }
  return Object.freeze({
    referenceForAppliedAction(trustedActionResult) {
      check()
      try {
        if (!trustedActionResult || typeof trustedActionResult !== 'object' || Array.isArray(trustedActionResult))
          throw refuse('capture-result-invalid')
        const descriptors = Object.getOwnPropertyDescriptors(trustedActionResult)
        const selected = {}
        for (const field of ['applied', 'state', 'ledger_seq', 'ledger_hash', 'receipt', 'receipt_sig']) {
          const descriptor = descriptors[field]
          if (!descriptor || !Object.hasOwn(descriptor, 'value') || !descriptor.enumerable)
            throw refuse('capture-result-invalid')
          selected[field] = descriptor.value
        }
        if (selected.applied !== true || selected.state !== 'applied' || !Number.isSafeInteger(selected.ledger_seq)
          || selected.ledger_seq < 1 || !hex(selected.ledger_hash) || typeof selected.receipt_sig !== 'string'
          || !selected.receipt || typeof selected.receipt !== 'object' || Array.isArray(selected.receipt))
          throw refuse('capture-result-invalid')
        const receiptBytes = canonicalJson(selected.receipt)
        if (Buffer.byteLength(receiptBytes) > 48 * 1024) throw refuse('capture-result-invalid')
        check()
        const snapshot = readGateSnapshot(loaded.collectorContext.snapshotOptions)
        if (snapshot.ok !== true) throw refuse('capture-source-unavailable')
        const row = snapshot.records.find(record => record.position === selected.ledger_seq)
        if (!row || row.hash !== selected.ledger_hash || !['apply', 'revert-applied'].includes(row.entry.event))
          throw refuse('capture-source-mismatch')
        const detail = parseStrictJson(row.entry.detail)
        if (!detail || canonicalJson(detail.receipt) !== receiptBytes || detail.receipt_sig !== selected.receipt_sig)
          throw refuse('capture-receipt-mismatch')
        check()
        return Object.freeze({ source: Object.freeze({ journal_id: snapshot.source.journal_id,
          position: row.position, hash: row.hash }) })
      } catch (error) {
        check()
        throw refuse(typeof error?.code === 'string' && /^aura-context:[a-z-]+$/u.test(error.code)
          ? error.code.slice('aura-context:'.length) : 'capture-result-invalid')
      }
    },
    dispose() { disposed = true },
  })
}
