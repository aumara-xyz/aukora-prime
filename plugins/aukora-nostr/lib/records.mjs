// SPDX-License-Identifier: AGPL-3.0-or-later
// Local record format only: no key generation/storage, network, authorization or journal writes.
import { eventId, publicKeyOf, signEvent, verifyEvent } from './event.mjs'
import { calcPaddedLen, conversationKey, encrypt, decrypt, NIP44_VERSION } from './nip44.mjs'
import { signerKeyOf, verifyBindingWithKey } from './identity.mjs'
import { canonicalJson, parseStrictJson } from './canonical-json.mjs'

export const RECORD_VERSION = 1
export const ZERO_ID = '0'.repeat(64)
// Experimental application kinds in NIP-01's ordinary-event range, not registered standards.
export const RECORD_KINDS = Object.freeze({ aura: 8930, memory: 8931, decision: 8932, receipt: 8933, anchor: 8934 })
export const RECORD_LIMITS = Object.freeze({ privateBytes: 65535, references: 32, chainRecords: 4096, jsonBytes: 262144 })
const PAYLOAD_BYTES = 65 + 2 + calcPaddedLen(RECORD_LIMITS.privateBytes)
const PAYLOAD_CHARS = 4 * Math.ceil(PAYLOAD_BYTES / 3)
const HEX = /^[0-9a-f]{64}$/u
const SIG = /^[0-9a-f]{128}$/u
const TOKEN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u
const SUBJECT = /^aukora:1:[0-9a-f]{64}$/u
const EVENT_KEYS = ['id', 'pubkey', 'created_at', 'kind', 'tags', 'content']
const TAG_NAMES = ['prev', 'seq', 'src', 'act', 'v', 'enc', 'p']
const PIN_KEYS = ['binding', 'controllerKeyHex', 'ownerSubject', 'authorPubkeyHex', 'ownerPubkeyHex']

export class RecordValidationError extends TypeError {
  constructor(reason) { super(reason); this.name = 'RecordValidationError'; this.code = reason; this.reason = reason }
}
const fail = reason => { throw new RecordValidationError('nostr-record:' + reason) }
const plain = value => value !== null && typeof value === 'object' && !Array.isArray(value)
const exact = (value, required, optional = []) => plain(value)
  && required.every(key => Object.hasOwn(value, key))
  && Object.keys(value).every(key => required.includes(key) || optional.includes(key))
const integer = (value, minimum = 0) => Number.isSafeInteger(value) && !Object.is(value, -0) && value >= minimum
const hex = value => typeof value === 'string' && HEX.test(value)
function scalar(value, maxBytes, minimum = 0) {
  return typeof value === 'string' && value.length <= maxBytes && value.isWellFormed()
    && Buffer.byteLength(value, 'utf8') >= minimum && Buffer.byteLength(value, 'utf8') <= maxBytes
}
function freeze(value) {
  if (value && typeof value === 'object') { for (const child of Object.values(value)) freeze(child); Object.freeze(value) }
  return value
}
function snapshot(value) {
  let nodes = 0
  function visit(one, depth) {
    if (++nodes > 10000 || depth > 16) fail('json-bounds')
    if (typeof one === 'string') { if (!scalar(one, RECORD_LIMITS.jsonBytes)) fail('unicode-or-size'); return }
    if (one === null || typeof one === 'boolean' || (typeof one === 'number' && integer(Math.abs(one)))) return
    if (!one || typeof one !== 'object') fail('json-value')
    const array = Array.isArray(one), prototype = Object.getPrototypeOf(one)
    if (array ? prototype !== Array.prototype : prototype !== Object.prototype && prototype !== null) fail('json-object')
    const descriptors = Object.getOwnPropertyDescriptors(one)
    for (const key of Reflect.ownKeys(one)) {
      if (array && key === 'length') continue
      const descriptor = descriptors[key]
      if (typeof key !== 'string' || !scalar(key, 128) || !descriptor?.enumerable || !Object.hasOwn(descriptor, 'value')) fail('json-property')
      visit(descriptor.value, depth + 1)
    }
    if (array && Object.keys(one).length !== one.length) fail('json-array')
  }
  try {
    visit(value, 0)
    const text = canonicalJson(value)
    if (Buffer.byteLength(text) > RECORD_LIMITS.jsonBytes) fail('json-bounds')
    return JSON.parse(text)
  } catch (error) { if (error instanceof RecordValidationError) throw error; fail('json-value') }
}
function secret(value) {
  if (!hex(value)) fail('secret-syntax')
  try { return publicKeyOf(value) } catch { fail('secret-invalid') }
}
function decimal(value) {
  if (typeof value !== 'string' || !/^[1-9][0-9]{0,15}$/u.test(value)) fail('decimal')
  const number = Number(value)
  if (!integer(number, 1) || String(number) !== value) fail('decimal')
  return number
}
function sourceShape(value) {
  if (!exact(value, ['journal_id', 'position', 'hash']) || typeof value.journal_id !== 'string'
    || !TOKEN.test(value.journal_id) || !integer(value.position, 1) || !hex(value.hash)) fail('source')
}
function headShape(value) {
  if (!exact(value, ['sequence', 'id']) || !integer(value.sequence) || !hex(value.id)
    || (value.sequence === 0) !== (value.id === ZERO_ID)) fail('head')
}
function payloadShape(value) {
  // Bound BEFORE allocating and require a unique standard-base64 wire encoding.
  if (typeof value !== 'string' || value.length < 132 || value.length > PAYLOAD_CHARS
    || value.length % 4 !== 0 || !/^[A-Za-z0-9+/]*={0,2}$/u.test(value)) fail('ciphertext-shape')
  const bytes = Buffer.from(value, 'base64')
  if (bytes.length < 99 || bytes.length > PAYLOAD_BYTES || bytes[0] !== NIP44_VERSION
    || bytes.toString('base64') !== value) fail('ciphertext-shape')
}
function anchorShape(content) {
  let value
  try { value = parseStrictJson(content, { maxBytes: 2048, maxDepth: 2 }) } catch { fail('anchor-content') }
  if (!exact(value, ['head_id', 'head_sequence', 'count']) || !hex(value.head_id)
    || !integer(value.head_sequence) || !integer(value.count)
    || (value.head_sequence === 0) !== (value.head_id === ZERO_ID)
    || canonicalJson(value) !== content) fail('anchor-content')
}
function referencesShape(references) {
  if (!Array.isArray(references) || references.length > RECORD_LIMITS.references) fail('references')
  const seen = new Set()
  for (const tag of references) {
    if (!Array.isArray(tag) || tag.length !== 2) fail('reference')
    if (tag[0] === 'e') { if (!hex(tag[1])) fail('reference') }
    else if (tag[0] === 'a') {
      if (!scalar(tag[1], 256)) fail('reference')
      const match = /^([1-9][0-9]{4}):([0-9a-f]{64}):([A-Za-z0-9][A-Za-z0-9._:-]{0,127})$/u.exec(tag[1])
      if (!match || Number(match[1]) < 30000 || Number(match[1]) >= 40000) fail('reference')
    } else fail('reference')
    const key = canonicalJson(tag)
    if (seen.has(key)) fail('reference-duplicate')
    seen.add(key)
  }
  const sorted = [...references].sort((a, b) => a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : a[1] < b[1] ? -1 : a[1] > b[1] ? 1 : 0)
  if (canonicalJson(sorted) !== canonicalJson(references)) fail('reference-order')
}
function profile(event, signed) {
  if (!exact(event, signed ? [...EVENT_KEYS, 'sig'] : EVENT_KEYS) || !hex(event.id) || !hex(event.pubkey)
    || !integer(event.created_at) || !integer(event.kind) || event.kind > 65535
    || !scalar(event.content, PAYLOAD_CHARS) || (signed && (typeof event.sig !== 'string' || !SIG.test(event.sig)))) fail('event-shape')
  const type = Object.keys(RECORD_KINDS).find(key => RECORD_KINDS[key] === event.kind)
  if (!type || !Array.isArray(event.tags) || event.tags.length < 7 || event.tags.length > 7 + RECORD_LIMITS.references) fail('profile')
  for (let i = 0; i < TAG_NAMES.length; i++) {
    const tag = event.tags[i]
    if (!Array.isArray(tag) || tag.length !== (i === 2 ? 4 : 2) || tag[0] !== TAG_NAMES[i]
      || tag.some(value => typeof value !== 'string')) fail('reserved-tags')
  }
  const [prev, seq, src, act, version, enc, owner] = event.tags
  const sequence = decimal(seq[1])
  if (!hex(prev[1]) || (sequence === 1) !== (prev[1] === ZERO_ID)) fail('previous-id')
  const source = { journal_id: src[1], position: decimal(src[2]), hash: src[3] }
  sourceShape(source)
  if (act[1] !== '' && !TOKEN.test(act[1])) fail('action-id')
  if (version[1] !== String(RECORD_VERSION)) fail('version')
  if (!hex(owner[1])) fail('owner-recipient')
  if (enc[1] !== (type === 'anchor' ? 'none' : 'nip44-v2')) fail('encryption-profile')
  if (type === 'anchor') anchorShape(event.content); else payloadShape(event.content)
  const references = event.tags.slice(7)
  referencesShape(references)
  if (event.id !== eventId(event)) fail('event-id')
  return { version: RECORD_VERSION, type, id: event.id, pubkey: event.pubkey, created_at: event.created_at,
    sequence, previous_id: prev[1], source, action_id: act[1] || null, owner_pubkey_hex: owner[1],
    encryption: enc[1], references }
}
function expectations(value, optional = []) {
  const pins = snapshot(value)
  if (!exact(pins, PIN_KEYS, optional) || !hex(pins.controllerKeyHex) || !hex(pins.authorPubkeyHex)
    || !hex(pins.ownerPubkeyHex) || typeof pins.ownerSubject !== 'string' || !SUBJECT.test(pins.ownerSubject)) fail('expectations')
  return pins
}
function bindingCheck(event, pins) {
  const binding = pins.binding
  if (!exact(binding, ['domain', 'statement', 'signature', 'approvalKeyDid'], ['label', 'ceilings'])
    || signerKeyOf(binding) !== pins.controllerKeyHex || binding.statement?.nostrPubkeyHex !== event.pubkey) fail('binding-pin')
  const verdict = verifyBindingWithKey(binding, { controllerKeyHex: pins.controllerKeyHex, expectSubject: pins.ownerSubject })
  if (verdict.verdict !== 'verified') fail('binding-signature')
  return verdict.bindingDigest
}

/** Pure unsigned construction. Private content must already be NIP-44 v2 ciphertext. */
export function buildRecord(supplied) {
  const input = snapshot(supplied)
  if (!exact(input, ['type', 'pubkey', 'created_at', 'sequence', 'previous_id', 'source', 'action_id', 'owner_pubkey_hex', 'content'], ['references'])
    || typeof input.type !== 'string' || !Object.hasOwn(RECORD_KINDS, input.type) || !hex(input.pubkey) || !integer(input.created_at)
    || !integer(input.sequence, 1) || !hex(input.previous_id) || !hex(input.owner_pubkey_hex)
    || (input.action_id !== null && (typeof input.action_id !== 'string' || !TOKEN.test(input.action_id)))) fail('record-input')
  sourceShape(input.source)
  const references = Object.hasOwn(input, 'references') ? input.references : []
  referencesShape(references)
  const event = { pubkey: input.pubkey, created_at: input.created_at, kind: RECORD_KINDS[input.type],
    tags: [['prev', input.previous_id], ['seq', String(input.sequence)],
      ['src', input.source.journal_id, String(input.source.position), input.source.hash],
      ['act', input.action_id ?? ''], ['v', String(RECORD_VERSION)],
      ['enc', input.type === 'anchor' ? 'none' : 'nip44-v2'], ['p', input.owner_pubkey_hex], ...references], content: input.content }
  // Check profile before hashing unbounded or malformed caller-supplied content.
  if (input.type === 'anchor') anchorShape(event.content); else payloadShape(event.content)
  event.id = eventId(event)
  profile(event, false)
  return freeze(event)
}

/** Supplied existing key only. This is cryptographic authorship, never owner authorization. */
export function signRecord(supplied, secretKeyHex) {
  const event = snapshot(supplied)
  profile(event, false)
  if (secret(secretKeyHex) !== event.pubkey) fail('author-key')
  try { signEvent(event, secretKeyHex); verifyEvent(event) } catch { fail('event-signature') }
  profile(event, true)
  return freeze(event)
}

/** Signed-byte authenticity and key-to-subject binding; no journal/authority/custody claim. */
export function verifyRecord(supplied, suppliedExpectations) {
  const event = snapshot(supplied), pins = expectations(suppliedExpectations)
  const metadata = profile(event, true)
  if (event.pubkey !== pins.authorPubkeyHex) fail('author-pin')
  if (metadata.owner_pubkey_hex !== pins.ownerPubkeyHex) fail('recipient-pin')
  try { verifyEvent(event) } catch { fail('event-signature') }
  const binding_digest = bindingCheck(event, pins)
  return freeze({ ...metadata, binding_digest, grants_authority: false })
}

/** Encrypt literal bytes to the separately pinned owner Nostr key, using an existing service key. */
export function encryptPrivateContent(plaintext, suppliedOptions) {
  const options = snapshot(suppliedOptions)
  if (!exact(options, ['authorSecretKeyHex', 'ownerPubkeyHex']) || !hex(options.ownerPubkeyHex)) fail('encryption-options')
  secret(options.authorSecretKeyHex)
  if (!scalar(plaintext, RECORD_LIMITS.privateBytes, 1)) fail('plaintext')
  let shared
  try {
    shared = conversationKey(options.authorSecretKeyHex, Buffer.from(options.ownerPubkeyHex, 'hex'))
    const ciphertext = encrypt(plaintext, shared)
    payloadShape(ciphertext)
    return ciphertext
  } catch (error) { if (error instanceof RecordValidationError) throw error; fail('encryption') }
  finally { shared?.fill(0) }
}

/** Owner or service recovery, exactly one existing secret. Verify event/binding before decrypting. */
export function decryptRecord(supplied, suppliedOptions) {
  const event = snapshot(supplied), options = expectations(suppliedOptions, ['ownerSecretKeyHex', 'authorSecretKeyHex'])
  const owner = Object.hasOwn(options, 'ownerSecretKeyHex'), author = Object.hasOwn(options, 'authorSecretKeyHex')
  if (owner === author) fail('decryption-key-role')
  const pins = Object.fromEntries(PIN_KEYS.map(key => [key, options[key]]))
  const metadata = verifyRecord(event, pins)
  if (metadata.encryption !== 'nip44-v2') fail('not-private')
  const secretKeyHex = owner ? options.ownerSecretKeyHex : options.authorSecretKeyHex
  if (secret(secretKeyHex) !== (owner ? pins.ownerPubkeyHex : pins.authorPubkeyHex)) fail('decryption-key-pin')
  let shared
  try {
    shared = conversationKey(secretKeyHex, Buffer.from(owner ? event.pubkey : pins.ownerPubkeyHex, 'hex'))
    const plaintext = decrypt(event.content, shared)
    if (!scalar(plaintext, RECORD_LIMITS.privateBytes, 1)) fail('plaintext')
    return plaintext
  } catch (error) { if (error instanceof RecordValidationError) throw error; fail('ciphertext-authentication') }
  finally { shared?.fill(0) }
}

/** Strict SAME-text ingress followed by actual verification; duplicate JSON keys never disappear. */
export function parseRecord(text, suppliedExpectations) {
  let event
  try { event = parseStrictJson(text, { maxBytes: RECORD_LIMITS.jsonBytes, maxDepth: 16 }) } catch { fail('json-ingress') }
  const metadata = verifyRecord(event, suppliedExpectations)
  return freeze({ event: snapshot(event), metadata })
}

/** Bounded batch, one pinned author. Continuation heads must come from a trusted verified prefix. */
export function verifyChain(events, suppliedOptions) {
  const options = expectations(suppliedOptions, ['initialHead', 'expectedHead'])
  const pins = Object.fromEntries(PIN_KEYS.map(key => [key, options[key]]))
  if (!Array.isArray(events) || Object.getPrototypeOf(events) !== Array.prototype || events.length > RECORD_LIMITS.chainRecords) fail('chain-bounds')
  if (Reflect.ownKeys(events).length !== events.length + 1) fail('chain-array')
  const initialHead = Object.hasOwn(options, 'initialHead') ? options.initialHead : { sequence: 0, id: ZERO_ID }
  headShape(initialHead)
  if (Object.hasOwn(options, 'expectedHead')) headShape(options.expectedHead)
  let head = initialHead
  for (let i = 0; i < events.length; i++) {
    const descriptor = Object.getOwnPropertyDescriptor(events, String(i))
    if (!descriptor?.enumerable || !Object.hasOwn(descriptor, 'value')) fail('chain-array')
    const record = verifyRecord(descriptor.value, pins)
    if (head.sequence >= Number.MAX_SAFE_INTEGER || record.sequence !== head.sequence + 1) fail('chain-sequence')
    if (record.previous_id !== head.id) fail('chain-previous')
    head = { sequence: record.sequence, id: record.id }
  }
  if (options.expectedHead && (head.sequence !== options.expectedHead.sequence || head.id !== options.expectedHead.id)) fail('chain-head')
  return freeze({ count: events.length, initialHead, head,
    coverage: options.expectedHead ? 'THROUGH_EXPECTED_HEAD' : 'PREFIX_ONLY', grants_authority: false })
}
