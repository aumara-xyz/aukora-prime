// SPDX-License-Identifier: AGPL-3.0-or-later
// H must pin this fixed entry, its full source-relative import closure and the
// protected JSON before Node starts. Parsing configuration is not authentication.
// Existing scoped material is read only; no enrollment, key discovery or fallback.
import { constants, openSync, closeSync, fstatSync, lstatSync, readSync } from 'node:fs'
import { dirname, isAbsolute } from 'node:path'
import { createHash } from 'node:crypto'
import { canonicalJson, parseStrictJson } from '../../../../packages/contracts/src/json.mjs'
import * as records from '../../../../plugins/aukora-nostr/lib/records.mjs'
import { publicKeyOf } from '../../../../plugins/aukora-nostr/lib/event.mjs'
import { verifyBindingWithKey } from '../../../../plugins/aukora-nostr/lib/identity.mjs'
import { createNostrCollectorCodec, createCollectorCitationReader } from '../../../../scripts/aura/collect-gate.mjs'
import { gatePublicKeySha256, readGateSnapshot } from '../../../../scripts/aura/gate-snapshot.mjs'
import { createRetainedProposalReadScope, isRetainedProposalReadScope,
  createProposalScopedAuraRecordsProvider } from './records-provider.mjs'

export const AURA_CONTEXT_PATH = '/etc/aukora-boundary-gate/aura-context.json'
const MAX_CONFIG_BYTES = 1024 * 1024
const HEX64 = /^[0-9a-f]{64}$/u
const SUBJECT = /^aukora:1:[0-9a-f]{64}$/u
const SOURCE_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u
const CONFIGURATIONS = new WeakSet()
const LOADED = new WeakSet()
const CONFIGURATION_DIGESTS = new WeakMap()
const LOADED_DIGESTS = new WeakMap()
export const AURA_READ_LIFECYCLE_PATH = '/etc/aukora-boundary-gate/aura-read-lifecycle.json'
export const AURA_READ_GRANTS_DIRECTORY = '/etc/aukora-boundary-gate/aura-read-grants'
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u
const sha256 = text => createHash('sha256').update(text, 'utf8').digest('hex')
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
    if (typeof text !== 'string' || text.charCodeAt(0) === 0xfeff || Buffer.byteLength(text) > MAX_CONFIG_BYTES)
      throw refuse('configuration-invalid')
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
    freeze(value); CONFIGURATIONS.add(value); CONFIGURATION_DIGESTS.set(value, sha256(text))
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
    // Preserve a leading BOM for the strict consumer to refuse; never silently
    // change the original protected bytes before its retained digest is taken.
    return new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes.subarray(0, used))
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
    LOADED_DIGESTS.set(loaded, CONFIGURATION_DIGESTS.get(configuration))
    return loaded
  } catch (error) {
    throw refuse(typeof error?.code === 'string' && /^aura-context:[a-z-]+$/u.test(error.code)
      ? error.code.slice('aura-context:'.length) : 'scoped-material-unavailable')
  }
}

/** Public configuration only. This does not read or load author material. */
export function loadAuraPublicConfiguration() {
  return parseAuraConfiguration(readProtectedAuraData(AURA_CONTEXT_PATH))
}

/** Digest of the original protected UTF8 JSON, never reserialized configuration. */
export function auraConfigurationSha256(configuration) {
  if (!CONFIGURATIONS.has(configuration)) throw refuse('configuration-unrecognized')
  return CONFIGURATION_DIGESTS.get(configuration)
}

/** Fixed path only; H's pre-Node manifest also binds this JSON and import closure. */
export async function loadAuraContext() {
  const configuration = loadAuraPublicConfiguration()
  const secret = readProtectedAuraData(configuration.nostr.author_secret_path, { secret: true, maximum: 65 })
  if (!/^[0-9a-f]{64}\n?$/u.test(secret)) throw refuse('scoped-material-unavailable')
  return createAuraCollectorContext(configuration, { authorSecretKeyHex: secret.replace(/\n$/u, '') })
}

/** Root-issued data is read, never issued here. H supplies the actual verified
 * completed-proposal binding and live owner callback, not model metadata.
 * Restart/release hooks must replace the root lifecycle identity before reads.
 * Missing custody, files or identity refuse; there is no owner-wide fallback. */
export function createRetainedAuraReadScope(loaded, proposalBinding, { isLive, now = Date.now } = {}) {
  if (!LOADED.has(loaded)) throw refuse('configuration-unrecognized')
  const scope = readProtectedProposalScope(proposalBinding, { isLive, now })
  try { verifyProposalScopeBinding(loaded, scope); return scope }
  catch (error) { scope.dispose(); throw error }
}

/** H's public completed-proposal validator. It reads the public signed journal
 * and protected grant/epoch only; no author key, archive codec or decryption. */
export function createProtectedAuraProposalReadScope(configuration, proposalBinding, { isLive, now = Date.now } = {}) {
  if (!CONFIGURATIONS.has(configuration)) throw refuse('configuration-unrecognized')
  const scope = readProtectedProposalScope(proposalBinding, { isLive, now })
  try { validateAuraPublicProposalReadScope(configuration, scope); return scope }
  catch (error) { scope.dispose(); throw error }
}

/** Recheck a retained public scope against the actual signed source. */
export function validateAuraPublicProposalReadScope(configuration, scope) {
  if (!CONFIGURATIONS.has(configuration)) throw refuse('configuration-unrecognized')
  const source = configuration.source
  verifySignedProposalScope({ ownerSubject: configuration.owner_subject,
      contextSha256: CONFIGURATION_DIGESTS.get(configuration),
      options: { dbPath: source.db_path, sourceId: source.source_id,
        publicKeyPem: source.public_key_pem, expectedKeySha256: source.key_sha256,
        maxRows: source.max_rows, maxBytes: source.max_bytes, maxRecordBytes: source.max_record_bytes } }, scope)
  return true
}

function readProtectedProposalScope(proposalBinding, { isLive, now }) {
  let proposalId, contextSha256
  try {
    const descriptor = Object.getOwnPropertyDescriptor(proposalBinding, 'proposal_id')
    if (!descriptor || !Object.hasOwn(descriptor, 'value') || !descriptor.enumerable
      || typeof descriptor.value !== 'string' || !UUID.test(descriptor.value)) throw refuse('proposal-grant-unconfigured')
    proposalId = descriptor.value
    const contextDescriptor = Object.getOwnPropertyDescriptor(proposalBinding, 'context_sha256')
    if (!contextDescriptor || !Object.hasOwn(contextDescriptor, 'value') || !contextDescriptor.enumerable
      || !hex(contextDescriptor.value)) throw refuse('proposal-grant-unconfigured')
    contextSha256 = contextDescriptor.value
  } catch { throw refuse('proposal-grant-unconfigured') }
  return createRetainedProposalReadScope(proposalBinding, { isLive, now,
    readGrant: () => parseStrictJson(readProtectedAuraData(`${AURA_READ_GRANTS_DIRECTORY}/${proposalId}.json`, { maximum: 16384 })),
    readLifecycle: () => {
      if (sha256(readProtectedAuraData(AURA_CONTEXT_PATH)) !== contextSha256) throw refuse('proposal-binding-mismatch')
      return parseStrictJson(readProtectedAuraData(AURA_READ_LIFECYCLE_PATH, { maximum: 4096 }))
    } })
}

function verifyProposalScopeBinding(loaded, scope) {
  if (!LOADED.has(loaded) || !isRetainedProposalReadScope(scope)) throw refuse('proposal-grant-unconfigured')
  verifySignedProposalScope({ ownerSubject: loaded.ownerSubject, contextSha256: LOADED_DIGESTS.get(loaded),
    options: loaded.collectorContext.snapshotOptions }, scope)
}

function verifySignedProposalScope({ ownerSubject, contextSha256, options }, scope) {
  if (!isRetainedProposalReadScope(scope)) throw refuse('proposal-grant-unconfigured')
  const binding = scope.bound
  if (binding.owner_subject !== ownerSubject || binding.context_sha256 !== contextSha256
    || binding.source.journal_id !== options.sourceId || binding.source.key_sha256 !== options.expectedKeySha256)
    throw refuse('proposal-binding-mismatch')
  scope.checkOwner(ownerSubject)
  const snapshot = readGateSnapshot(options)
  if (!snapshot.ok) throw refuse('capture-source-unavailable')
  const row = snapshot.records.find(record => record.position === binding.source.position)
  if (!row || row.hash !== binding.source.hash || row.entry.proposal !== binding.proposal_id
    || !['apply', 'revert-applied'].includes(row.entry.event)) throw refuse('proposal-binding-mismatch')
  const detail = parseStrictJson(row.entry.detail)
  if (!detail || !detail.receipt || detail.receipt.proposal !== binding.proposal_id
    || sha256(canonicalJson(detail.receipt)) !== binding.receipt_sha256) throw refuse('proposal-binding-mismatch')
  scope.checkOwner(ownerSubject)
}

/** Publish only this scoped service; raw reader/context and root grant remain private.
 * The cold verifier reads the owner prefix internally. This bounds citation
 * output to one proposal, not internal decryption to one row. */
export function createConfiguredAuraRecords(loaded, { proposalScope, referenceForRecord = null } = {}) {
  verifyProposalScopeBinding(loaded, proposalScope)
  const guards = { isLive: () => { proposalScope.checkOwner(loaded.ownerSubject); return true },
    hasReadGrant: owner => { proposalScope.checkOwner(owner); return true } }
  const reader = createCollectorCitationReader(loaded.collectorContext, guards)
  return createProposalScopedAuraRecordsProvider({ ownerSubject: loaded.ownerSubject,
    reader, scope: proposalScope, referenceForRecord })
}

/**
 * Host-only capture seam for H's ACTUAL successful action result. The caller must
 * retain that result from the same authenticated capture, never model parameters.
 * Match its exact receipt/signature to the specific signed row, never journal tip.
 * This returns an observation coordinate; it does not validate owner authorization.
 */
export function createGateCaptureReferenceResolver(loaded, { proposalScope } = {}) {
  verifyProposalScopeBinding(loaded, proposalScope)
  let disposed = false
  const check = () => {
    try {
      if (disposed) throw refuse('capture-read-unavailable')
      proposalScope.checkOwner(loaded.ownerSubject)
      if (disposed) throw refuse('capture-read-unavailable')
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
        const receiptProposal = Object.getOwnPropertyDescriptor(selected.receipt, 'proposal')
        if (!receiptProposal || !Object.hasOwn(receiptProposal, 'value') || !receiptProposal.enumerable)
          throw refuse('capture-result-invalid')
        if (selected.ledger_seq !== proposalScope.bound.source.position || selected.ledger_hash !== proposalScope.bound.source.hash
          || receiptProposal.value !== proposalScope.bound.proposal_id) throw refuse('capture-source-mismatch')
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
        if (sha256(receiptBytes) !== proposalScope.bound.receipt_sha256) throw refuse('capture-receipt-mismatch')
        check()
        return Object.freeze({ source: Object.freeze({ journal_id: snapshot.source.journal_id,
          position: row.position, hash: row.hash }) })
      } catch (error) {
        check()
        throw refuse(typeof error?.code === 'string' && /^aura-context:[a-z-]+$/u.test(error.code)
          ? error.code.slice('aura-context:'.length) : 'capture-result-invalid')
      }
    },
    dispose() { disposed = true; proposalScope.dispose() },
  })
}
