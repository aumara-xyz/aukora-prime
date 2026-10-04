// SPDX-License-Identifier: AGPL-3.0-or-later
// SOURCE-ONLY: published test keys, in-memory records, no files with key material,
// no key generation, credential reads, sockets, relay traffic, or installed claims.
import assert from 'node:assert/strict'
import { createHash, createPrivateKey, sign as edSign } from 'node:crypto'
import { readFile } from 'node:fs/promises'
import { publicKeyOf, eventId, serializeForId, signEvent, verifyEvent } from '../lib/event.mjs'
import { conversationKey, encrypt, decrypt } from '../lib/nip44.mjs'
import { bindingPreimage, npubEncode, NOSTR_BINDING_DOMAIN } from '../lib/identity.mjs'

// Fixed public BIP-340 test scalars. These are never live identities.
const AUTHOR_SECRET = '0'.repeat(63) + '3'
const OWNER_SECRET = '0'.repeat(63) + '5'
const AUTHOR_PUBLIC = publicKeyOf(AUTHOR_SECRET)
const OWNER_PUBLIC = publicKeyOf(OWNER_SECRET)
// RFC 8032 section 7.1, TEST 1 (published Ed25519 seed/public key).
const RFC_SEED = '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60'
const ED_PUBLIC = 'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a'
const fixtureSigner = createPrivateKey({
  key: Buffer.from('302e020100300506032b657004220420' + RFC_SEED, 'hex'),
  format: 'der', type: 'pkcs8',
})
const SUBJECT = 'aukora:1:' + '1'.repeat(64)
const ZERO = '0'.repeat(64)
const clone = value => JSON.parse(JSON.stringify(value))

function fixtureBinding(author = AUTHOR_PUBLIC, overrides = {}) {
  const statement = {
    subject: SUBJECT, npub: npubEncode(author), nostrPubkeyHex: author,
    handle: 'published-fixture', createdAt: '2026-01-01T00:00:00Z', safetyVersion: 2,
    ...overrides,
  }
  return {
    domain: NOSTR_BINDING_DOMAIN, statement,
    signature: edSign(null, bindingPreimage(statement), fixtureSigner).toString('hex'),
    approvalKeyDid: 'did:key:' + ED_PUBLIC, label: 'TEST',
  }
}

const recordsUrl = new URL('../lib/records.mjs', import.meta.url)
async function mutatedModule(source, original, replacement) {
  assert.equal(source.split(original).length, 2, 'mutation must match exactly one actual guard')
  const changed = source.replace(original, replacement).replace(/from\s+(['"])(\.[^'"]+)\1/g,
    (_, quote, specifier) => `from ${quote}${new URL(specifier, recordsUrl).href}${quote}`)
  return import('data:text/javascript;base64,' + Buffer.from(changed).toString('base64'))
}

const BINDING = fixtureBinding()
const EXPECT = Object.freeze({
  binding: BINDING, controllerKeyHex: ED_PUBLIC, ownerSubject: SUBJECT,
  authorPubkeyHex: AUTHOR_PUBLIC, ownerPubkeyHex: OWNER_PUBLIC,
})
const TEXT = '  Published fixture: café 🌱\n<TEXT>\tkept exactly  '
const FIXED_NONCE = Buffer.alloc(32, 7)
const sharedKey = (secret, publicHex) => conversationKey(secret, Buffer.from(publicHex, 'hex'))
const CIPHERTEXT = encrypt(TEXT, sharedKey(AUTHOR_SECRET, OWNER_PUBLIC), FIXED_NONCE)
const baseInput = overrides => ({
  type: 'aura', pubkey: AUTHOR_PUBLIC, created_at: 1767225600,
  sequence: 1, previous_id: ZERO,
  source: { journal_id: 'published-fixture', position: 1, hash: '2'.repeat(64) },
  action_id: null, owner_pubkey_hex: OWNER_PUBLIC, content: CIPHERTEXT,
  ...overrides,
})
const signDraft = (module, overrides) => module.signRecord(module.buildRecord(baseInput(overrides)), AUTHOR_SECRET)
const changedSigned = (record, change) => {
  const value = clone(record)
  delete value.id; delete value.sig
  change(value)
  return signEvent(value, AUTHOR_SECRET)
}

async function runFocused(module) {
  let groups = 0
  function group(body) { body(); groups++ }
  const record = signDraft(module)

  group(() => {
    assert.equal(module.RECORD_VERSION, 1)
    assert.equal(module.ZERO_ID, ZERO)
    assert.deepEqual(module.RECORD_KINDS, { aura: 8930, memory: 8931, decision: 8932, receipt: 8933, anchor: 8934 })
    const draft = module.buildRecord(baseInput())
    assert.equal(Object.hasOwn(draft, 'sig'), false, 'build returns an unsigned draft')
    assert.deepEqual(draft.tags, [
      ['prev', ZERO], ['seq', '1'], ['src', 'published-fixture', '1', '2'.repeat(64)],
      ['act', ''], ['v', '1'], ['enc', 'nip44-v2'], ['p', OWNER_PUBLIC],
    ])
    assert.equal(draft.id, eventId(draft))
    assert.equal(draft.id, createHash('sha256').update(JSON.stringify([0, draft.pubkey, draft.created_at, draft.kind, draft.tags, draft.content])).digest('hex'))
    assert.equal(serializeForId(draft), JSON.stringify([0, draft.pubkey, draft.created_at, draft.kind, draft.tags, draft.content]))
    assert.equal(verifyEvent(record), true)
    assert.throws(() => module.signRecord(draft, OWNER_SECRET), 'different scoped signer must refuse')
    const metadata = module.verifyRecord(record, EXPECT)
    assert.deepEqual(Object.keys(metadata).sort(), [
      'version', 'type', 'id', 'pubkey', 'created_at', 'sequence', 'previous_id', 'source',
      'action_id', 'owner_pubkey_hex', 'encryption', 'references', 'binding_digest', 'grants_authority',
    ].sort())
    assert.deepEqual({ ...metadata, binding_digest: undefined }, {
      version: 1, type: 'aura', id: record.id, pubkey: AUTHOR_PUBLIC, created_at: 1767225600,
      sequence: 1, previous_id: ZERO, source: baseInput().source, action_id: null,
      owner_pubkey_hex: OWNER_PUBLIC, encryption: 'nip44-v2', references: [],
      binding_digest: undefined, grants_authority: false,
    })
    assert.equal(metadata.binding_digest, createHash('sha256').update(bindingPreimage(BINDING.statement)).digest('hex'))
    assert.deepEqual(module.parseRecord(JSON.stringify(record), EXPECT), { event: record, metadata })
  })

  group(() => {
    for (const field of ['id', 'sig']) {
      const changed = clone(record)
      changed[field] = (changed[field][0] === '0' ? '1' : '0') + changed[field].slice(1)
      assert.throws(() => module.verifyRecord(changed, EXPECT), `${field} mutation must refuse`)
    }
    const body = clone(record); body.content = body.content.slice(0, -4) + 'AAAA'
    assert.throws(() => module.verifyRecord(body, EXPECT), 'unsigned body change must refuse')
    for (const field of ['binding', 'controllerKeyHex', 'ownerSubject', 'authorPubkeyHex', 'ownerPubkeyHex']) {
      const absent = { ...EXPECT }; delete absent[field]
      assert.throws(() => module.verifyRecord(record, absent), `missing ${field} pin must refuse`)
    }
    assert.throws(() => module.verifyRecord(record, { ...EXPECT, extra: true }))
    assert.throws(() => module.verifyRecord(record, { ...EXPECT, controllerKeyHex: '4'.repeat(64) }))
    assert.throws(() => module.verifyRecord(record, { ...EXPECT, ownerSubject: 'aukora:1:' + '8'.repeat(64) }))
    assert.throws(() => module.verifyRecord(record, { ...EXPECT, authorPubkeyHex: OWNER_PUBLIC }))
    assert.throws(() => module.verifyRecord(record, { ...EXPECT, ownerPubkeyHex: AUTHOR_PUBLIC }))
    const alteredBinding = clone(BINDING); alteredBinding.signature = '0'.repeat(128)
    assert.throws(() => module.verifyRecord(record, { ...EXPECT, binding: alteredBinding }))
    assert.throws(() => module.verifyRecord(record, { ...EXPECT, binding: fixtureBinding(OWNER_PUBLIC) }))
    assert.throws(() => module.verifyRecord(module.buildRecord(baseInput()), EXPECT), 'unsigned draft is not a verified event')
  })

  group(() => {
    const payload = module.encryptPrivateContent(TEXT, { authorSecretKeyHex: AUTHOR_SECRET, ownerPubkeyHex: OWNER_PUBLIC })
    assert.equal(decrypt(payload, sharedKey(OWNER_SECRET, AUTHOR_PUBLIC)), TEXT)
    const raw = Buffer.from(payload, 'base64')
    assert.equal(payload, encrypt(TEXT, sharedKey(AUTHOR_SECRET, OWNER_PUBLIC), raw.subarray(1, 33)), 'wrapper uses exact existing NIP44 primitive')
    const signed = signDraft(module, { content: payload })
    assert.equal(module.decryptRecord(signed, { ...EXPECT, authorSecretKeyHex: AUTHOR_SECRET }), TEXT)
    assert.equal(module.decryptRecord(signed, { ...EXPECT, ownerSecretKeyHex: OWNER_SECRET }), TEXT)
    assert.throws(() => module.decryptRecord(signed, EXPECT), 'no private role must refuse')
    assert.throws(() => module.decryptRecord(signed, { ...EXPECT, authorSecretKeyHex: AUTHOR_SECRET, ownerSecretKeyHex: OWNER_SECRET }), 'both private roles must refuse')
    assert.throws(() => module.decryptRecord(signed, { ...EXPECT, authorSecretKeyHex: OWNER_SECRET }))
    assert.throws(() => module.decryptRecord(signed, { ...EXPECT, ownerSecretKeyHex: AUTHOR_SECRET }))
    const forgedSignature = clone(signed); forgedSignature.sig = '0'.repeat(128)
    assert.throws(() => module.decryptRecord(forgedSignature, { ...EXPECT, ownerSecretKeyHex: OWNER_SECRET }), { code: 'nostr-record:event-signature' }, 'authenticate event before exposing valid plaintext')
    const forgedBinding = clone(BINDING); forgedBinding.signature = '0'.repeat(128)
    assert.throws(() => module.decryptRecord(signed, { ...EXPECT, binding: forgedBinding, ownerSecretKeyHex: OWNER_SECRET }), { code: 'nostr-record:binding-signature' }, 'authenticate binding before exposing valid plaintext')
    raw[raw.length - 1] ^= 1
    const badMac = signDraft(module, { content: raw.toString('base64') })
    assert.equal(module.verifyRecord(badMac, EXPECT).grants_authority, false, 'event verification alone does not claim MAC success')
    assert.throws(() => module.decryptRecord(badMac, { ...EXPECT, ownerSecretKeyHex: OWNER_SECRET }), { code: 'nostr-record:ciphertext-authentication' })
    assert.throws(() => module.encryptPrivateContent('\uD800', { authorSecretKeyHex: AUTHOR_SECRET, ownerPubkeyHex: OWNER_PUBLIC }))
    assert.throws(() => module.encryptPrivateContent('', { authorSecretKeyHex: AUTHOR_SECRET, ownerPubkeyHex: OWNER_PUBLIC }))
  })

  group(() => {
    const refs = [['a', '30023:' + AUTHOR_PUBLIC + ':published-fixture'], ['e', '3'.repeat(64)]]
    const draft = module.buildRecord(baseInput({ references: refs }))
    assert.deepEqual(draft.tags.slice(7), refs)
    assert.throws(() => module.buildRecord(baseInput({ references: [...refs].reverse() })), 'noncanonical reference order must refuse')
    for (const name of ['prev', 'seq', 'src', 'act', 'v', 'enc', 'p']) {
      assert.throws(() => module.buildRecord(baseInput({ references: [[name, 'fixture']] })), `reserved ${name} reference must refuse`)
    }
    assert.throws(() => module.buildRecord(baseInput({ references: [refs[0], refs[0]] })), 'duplicate reference must refuse')
    assert.throws(() => module.buildRecord(baseInput({ references: null })), { code: 'nostr-record:references' }, 'explicit null references must not become omitted references')
    assert.throws(() => module.buildRecord(baseInput({ type: ['aura'] })), { code: 'nostr-record:record-input' }, 'array type must not coerce to the aura key')
    assert.throws(() => module.buildRecord(baseInput({ extra: true })))
    assert.throws(() => module.buildRecord(baseInput({ source: { ...baseInput().source, extra: true } })))
    for (const number of [0, -1, 1.1, Number.MAX_SAFE_INTEGER + 1, -0]) {
      assert.throws(() => module.buildRecord(baseInput({ sequence: number })))
      assert.throws(() => module.buildRecord(baseInput({ source: { ...baseInput().source, position: number } })))
    }
    for (const seq of ['01', '1e0', '+1', '9007199254740992']) {
      const changed = changedSigned(record, value => { value.tags[1][1] = seq })
      assert.throws(() => module.verifyRecord(changed, EXPECT), `noncanonical seq ${seq} must refuse`)
    }
    const duplicated = changedSigned(record, value => { value.tags.push(['enc', 'nip44-v2']) })
    assert.throws(() => module.verifyRecord(duplicated, EXPECT))
    const reordered = changedSigned(record, value => { [value.tags[0], value.tags[1]] = [value.tags[1], value.tags[0]] })
    assert.throws(() => module.verifyRecord(reordered, EXPECT))
    assert.throws(() => module.buildRecord(baseInput({ action_id: '\uD800' })))
    assert.throws(() => module.buildRecord(baseInput({ action_id: '' })))
    assert.throws(() => module.buildRecord(baseInput({ content: 'public private text' })))
    assert.throws(() => module.buildRecord(baseInput({ content: CIPHERTEXT + '\n' })))
    assert.throws(() => module.buildRecord(baseInput({ content: 'A'.repeat(132) })))
    assert.throws(() => module.buildRecord(baseInput({ content: 'A'.repeat(2 * 1024 * 1024) })), 'oversized payload must refuse')
  })

  group(() => {
    const commitment = { count: 2, head_id: record.id, head_sequence: 2 }
    const anchor = signDraft(module, { type: 'anchor', content: JSON.stringify(commitment) })
    const metadata = module.verifyRecord(anchor, EXPECT)
    assert.equal(metadata.type, 'anchor'); assert.equal(metadata.encryption, 'none')
    for (const content of [
      'plaintext', JSON.stringify({ ...commitment, private: TEXT }),
      JSON.stringify({ head_sequence: 2, head_id: record.id, count: 2 }),
      JSON.stringify({ ...commitment, head_id: 'bad' }),
      JSON.stringify({ ...commitment, head_sequence: Number.MAX_SAFE_INTEGER + 1 }),
      '{"count":2,"count":2,"head_id":"' + record.id + '","head_sequence":2}',
    ]) assert.throws(() => module.buildRecord(baseInput({ type: 'anchor', content })), 'public anchor is only a canonical closed commitment')
    assert.throws(() => module.decryptRecord(anchor, { ...EXPECT, authorSecretKeyHex: AUTHOR_SECRET }), 'public anchor must not become an arbitrary decrypt route')
    for (const type of ['memory', 'decision', 'receipt']) {
      assert.equal(module.verifyRecord(signDraft(module, { type }), EXPECT).type, type)
    }
    assert.throws(() => module.parseRecord('{"id":"' + record.id + '",' + JSON.stringify(record).slice(1), EXPECT), 'same-text duplicate id must refuse')
    assert.throws(() => module.parseRecord(JSON.stringify(record).replace('"created_at":1767225600', '"created_at":1767225600.00000000001'), EXPECT), 'rounded numeric ingress must refuse')
    assert.throws(() => module.parseRecord(JSON.stringify(record).replace('"content":', '"invalid":"\\ud800","content":'), EXPECT), 'decoded lone surrogate ingress must refuse')
  })

  group(() => {
    const second = signDraft(module, { sequence: 2, previous_id: record.id, source: { ...baseInput().source, position: 2 } })
    const third = signDraft(module, { sequence: 3, previous_id: second.id, source: { ...baseInput().source, position: 3 } })
    const expectedHead = { sequence: 3, id: third.id }
    assert.deepEqual(module.verifyChain([record, second, third], { ...EXPECT, expectedHead }), {
      count: 3, initialHead: { sequence: 0, id: ZERO }, head: expectedHead,
      coverage: 'THROUGH_EXPECTED_HEAD', grants_authority: false,
    })
    assert.equal(module.verifyChain([record, second], EXPECT).coverage, 'PREFIX_ONLY')
    assert.throws(() => module.verifyChain([record], { ...EXPECT, initialHead: null }), { code: 'nostr-record:head' }, 'explicit null head must not become an omitted genesis checkpoint')
    const hiddenExtra = [record]
    Object.defineProperty(hiddenExtra, 'extra', { value: 'published-fixture', enumerable: false })
    assert.throws(() => module.verifyChain(hiddenExtra, EXPECT), { code: 'nostr-record:chain-array' }, 'hidden chain properties must refuse')
    const symbolExtra = [record]
    Object.defineProperty(symbolExtra, Symbol('published-fixture'), { value: 'published-fixture' })
    assert.throws(() => module.verifyChain(symbolExtra, EXPECT), { code: 'nostr-record:chain-array' }, 'symbol chain properties must refuse')
    assert.throws(() => module.verifyChain([record, second], { ...EXPECT, expectedHead }), 'truncated prefix must refuse expected-head completeness')
    assert.throws(() => module.verifyChain([second, third], { ...EXPECT, expectedHead }), 'suffix without a trusted checkpoint must refuse')
    assert.deepEqual(module.verifyChain([second, third], { ...EXPECT, initialHead: { sequence: 1, id: record.id }, expectedHead }), {
      count: 2, initialHead: { sequence: 1, id: record.id }, head: expectedHead,
      coverage: 'THROUGH_EXPECTED_HEAD', grants_authority: false,
    })
    const wrongPrev = signDraft(module, { sequence: 2, previous_id: '7'.repeat(64) })
    assert.throws(() => module.verifyChain([record, wrongPrev], { ...EXPECT, expectedHead: { sequence: 2, id: wrongPrev.id } }))
    const gap = signDraft(module, { sequence: 3, previous_id: record.id })
    assert.throws(() => module.verifyChain([record, gap], { ...EXPECT, expectedHead: { sequence: 3, id: gap.id } }))
    assert.throws(() => module.verifyChain([record], { ...EXPECT, initialHead: { sequence: 0, id: '7'.repeat(64) } }))
    assert.throws(() => module.verifyChain([record], { ...EXPECT, expectedHead: { sequence: 1, id: '7'.repeat(64) } }))
  })

  return { groups, record }
}

const module = await import(recordsUrl.href)
const { groups, record } = await runFocused(module)
const source = await readFile(recordsUrl, 'utf8')
const second = signDraft(module, { sequence: 2, previous_id: record.id })
const badSignature = clone(record); badSignature.sig = '0'.repeat(128)
const badBinding = clone(BINDING); badBinding.signature = '0'.repeat(128)
const wrongPrev = signDraft(module, { sequence: 2, previous_id: '7'.repeat(64) })
const gap = signDraft(module, { sequence: 3, previous_id: record.id })
const protectedCases = [
  {
    guard: "  try { verifyEvent(event) } catch { fail('event-signature') }",
    replacement: '  // signature guard removed only in memory by source check',
    name: 'event signature',
    check: candidate => assert.throws(() => candidate.verifyRecord(badSignature, EXPECT)),
  },
  {
    guard: "  if (verdict.verdict !== 'verified') fail('binding-signature')",
    replacement: '  // binding signature guard removed only in memory by source check',
    name: 'Ed25519 binding signature',
    check: candidate => assert.throws(() => candidate.verifyRecord(record, { ...EXPECT, binding: badBinding })),
  },
  {
    guard: "  if (metadata.owner_pubkey_hex !== pins.ownerPubkeyHex) fail('recipient-pin')",
    replacement: '  // recipient pin removed only in memory by source check',
    name: 'owner recipient pin',
    check: candidate => assert.throws(() => candidate.verifyRecord(record, { ...EXPECT, ownerPubkeyHex: AUTHOR_PUBLIC })),
  },
  {
    guard: "    if (record.previous_id !== head.id) fail('chain-previous')",
    replacement: '    // predecessor guard removed only in memory by source check',
    name: 'chain predecessor',
    check: candidate => assert.throws(() => candidate.verifyChain([record, wrongPrev], { ...EXPECT, expectedHead: { sequence: 2, id: wrongPrev.id } })),
  },
  {
    guard: "    if (head.sequence >= Number.MAX_SAFE_INTEGER || record.sequence !== head.sequence + 1) fail('chain-sequence')",
    replacement: '    // chain sequence guard removed only in memory by source check',
    name: 'chain sequence',
    check: candidate => assert.throws(() => candidate.verifyChain([record, gap], { ...EXPECT, expectedHead: { sequence: 3, id: gap.id } })),
  },
  {
    guard: "  if (options.expectedHead && (head.sequence !== options.expectedHead.sequence || head.id !== options.expectedHead.id)) fail('chain-head')",
    replacement: '  // expected-head guard removed only in memory by source check',
    name: 'expected head completeness',
    check: candidate => assert.throws(() => candidate.verifyChain([record], { ...EXPECT, expectedHead: { sequence: 2, id: second.id } })),
  },
  {
    guard: "    if (seen.has(key)) fail('reference-duplicate')",
    replacement: '    // duplicate reference guard removed only in memory by source check',
    name: 'duplicate references',
    check: candidate => assert.throws(() => candidate.buildRecord(baseInput({ references: [['e', '3'.repeat(64)], ['e', '3'.repeat(64)]] }))),
  },
  {
    guard: '  const metadata = verifyRecord(event, pins)',
    replacement: '  const metadata = profile(event, true) // verification removed only in memory by source check',
    name: 'event authenticity before decryption',
    check: candidate => assert.throws(() => candidate.decryptRecord(badSignature, { ...EXPECT, ownerSecretKeyHex: OWNER_SECRET })),
  },
  {
    guard: "  if (owner === author) fail('decryption-key-role')",
    replacement: '  // exact private key-role guard removed only in memory by source check',
    name: 'exactly one private key role',
    check: candidate => assert.throws(() => candidate.decryptRecord(record, { ...EXPECT, authorSecretKeyHex: AUTHOR_SECRET, ownerSecretKeyHex: OWNER_SECRET })),
  },
  {
    guard: "typeof input.type !== 'string' || ",
    replacement: '',
    name: 'record type string guard',
    check: candidate => assert.throws(() => candidate.buildRecord(baseInput({ type: ['aura'] }))),
  },
]
// The plugin-local canonical JSON is a byte copy of packages/contracts/src/json.mjs, so the plugin closes
// inside a release (where it lives at <release>/aukora-nostr/) without forking the encoding.
assert.deepEqual(await readFile(new URL('../lib/canonical-json.mjs', import.meta.url)),
  await readFile(new URL('../../../packages/contracts/src/json.mjs', import.meta.url)),
  'plugins/aukora-nostr/lib/canonical-json.mjs must stay byte-identical to packages/contracts/src/json.mjs')
for (const { guard, replacement, name, check } of protectedCases) {
  check(module)
  const mutant = await mutatedModule(source, guard, replacement)
  assert.throws(() => check(mutant), { code: 'ERR_ASSERTION' }, `${name} negative must fail when the actual guard is removed`)
}
console.log(`PASS records: ${groups} focused groups; ${protectedCases.length} actual guard-removal mutants detected. SOURCE-ONLY published fixtures; no live keys, credentials, network, relay traffic, or installed qualification.`)
