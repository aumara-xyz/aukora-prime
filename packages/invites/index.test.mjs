// SPDX-License-Identifier: AGPL-3.0-or-later
// Tests signed invitation ancestry and atomic admission accounting.
import test from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync, readFileSync, writeFileSync, statSync, chmodSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { spawn, spawnSync } from 'node:child_process'
import { publicKeyOf, signEvent, isValidEvent } from '../../plugins/aukora-nostr/lib/event.mjs'
import {
  INVITE_KIND, REDEMPTION_KIND, GRANT_KIND, TTL_SECONDS, MAX_CLOCK_SKEW_SECONDS, REFUSE,
  createInvite, redeemInvite, createGrant, verifyAdmission, verifyRecord,
  createMemoryStore, createFileStore,
} from './index.mjs'

const NOW = 1_800_000_000
const keys = Array.from({ length: 12 }, (_, n) => (n + 1).toString(16).padStart(64, '0'))
const pubs = keys.map(publicKeyOf)
const root = pubs[0]
const directory = dirname(fileURLToPath(import.meta.url))
const moduleUrl = new URL('./index.mjs', import.meta.url).href
const refusal = (fn, code) => assert.throws(fn, error => error?.code === code)
const signed = (event, changes = {}, key = keys[0]) => signEvent({ ...event, ...changes }, key)
const content = (event, changes, key = keys[0]) => signed(event, {
  content: JSON.stringify({ ...JSON.parse(event.content), ...changes }),
}, key)
const binding = (invite, redemption) => signed(redemption, { tags: [['d', invite.id]],
  content: JSON.stringify({ inviteId: invite.id }) }, keys[1])
function memory(t) {
  const state = createMemoryStore()
  t.after(() => state.close())
  return state
}
function disk(t) {
  const dir = mkdtempSync(join(directory, '.test-'))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  return join(dir, 'admissions.sqlite')
}
function pair(inviter = 0, member = 1, now = NOW) {
  const invite = createInvite({ root, secretKey: keys[inviter], now })
  const redemption = redeemInvite({ invite, secretKey: keys[member], now })
  return { invite, redemption }
}
function admit(state, inviter = 0, member = 1, chain = [], now = NOW, grant) {
  return verifyAdmission({ root, ...pair(inviter, member, now), chain, state, now, grant })
}
function grant(allotment, sequence = 1, member = root) {
  return createGrant({ root, secretKey: keys[0], member, allotment, sequence, now: NOW })
}
function row(invite, redemption) {
  return { root, inviteId: invite.id, redemptionId: redemption.id,
    inviter: invite.pubkey, member: redemption.pubkey }
}

test('events use dedicated kinds, random 128-bit bearer codes, and only protocol fields', () => {
  assert.deepEqual([INVITE_KIND, REDEMPTION_KIND, GRANT_KIND], [39701, 39702, 39703])
  assert.equal(TTL_SECONDS, 48 * 60 * 60)
  assert.equal(MAX_CLOCK_SKEW_SECONDS, 300)
  const a = pair(), b = pair(), body = JSON.parse(a.invite.content)
  assert.deepEqual(Object.keys(body), ['network', 'codeId', 'issuedAt', 'expiresAt'])
  assert.equal(body.network, root)
  assert.match(body.codeId, /^[0-9a-f]{32}$/u)
  assert.notEqual(body.codeId, JSON.parse(b.invite.content).codeId)
  assert.deepEqual(a.invite.tags, [['d', body.codeId]])
  assert.equal(body.issuedAt, NOW)
  assert.equal(body.expiresAt, NOW + TTL_SECONDS)
  assert.equal(a.invite.pubkey, root)
  assert.deepEqual(a.redemption.tags, [['d', a.invite.id]])
  assert.deepEqual(JSON.parse(a.redemption.content), { inviteId: a.invite.id })
  assert.equal(a.redemption.pubkey, pubs[1])
  assert.ok(isValidEvent(a.invite) && isValidEvent(a.redemption))
})

test('happy path admits three levels and returns an offline-verifiable root chain', t => {
  const state = memory(t)
  const first = admit(state)
  const second = admit(state, 1, 2, first.record.chain)
  const third = admit(state, 2, 3, second.record.chain)
  assert.equal(third.member, pubs[3])
  assert.equal(third.record.chain.length, 3)
  assert.deepEqual(verifyRecord({ root, record: third.record }), { member: pubs[3] })
  assert.equal(state.transaction(tx => tx.count(root, root)), 1)
  assert.equal(state.transaction(tx => tx.count(root, pubs[1])), 1)
  assert.equal(state.transaction(tx => tx.count(root, pubs[2])), 1)
})

test('previously admitted ancestors remain usable after their invite expires', t => {
  const state = memory(t), first = admit(state)
  const second = admit(state, 1, 2, first.record.chain, NOW + TTL_SECONDS + 1)
  assert.equal(second.member, pubs[2])
  assert.equal(verifyRecord({ root, record: second.record }).member, pubs[2])
})

test('expiry uses the verifier clock and refuses exactly at 48 hours', t => {
  const state = memory(t), events = pair()
  refusal(() => verifyAdmission({ root, ...events, state, now: NOW + TTL_SECONDS }), REFUSE.EXPIRED)
  assert.equal(verifyAdmission({ root, ...events, state, now: NOW + TTL_SECONDS - 1 }).member, pubs[1])
})

test('future clock skew is bounded for both signer timestamps', t => {
  const state = memory(t)
  const boundary = pair(0, 1, NOW + MAX_CLOCK_SKEW_SECONDS)
  assert.equal(verifyAdmission({ root, ...boundary, state, now: NOW }).member, pubs[1])
  const future = pair(0, 2, NOW + MAX_CLOCK_SKEW_SECONDS + 1)
  refusal(() => verifyAdmission({ root, ...future, state, now: NOW }), REFUSE.TIME)
  const invite = createInvite({ root, secretKey: keys[0], now: NOW })
  const redemption = redeemInvite({ invite, secretKey: keys[3], now: NOW + MAX_CLOCK_SKEW_SECONDS + 1 })
  refusal(() => verifyAdmission({ root, invite, redemption, state, now: NOW }), REFUSE.TIME)
})

test('invalid verifier clocks and signed lifetime changes are refused', t => {
  const state = memory(t), events = pair()
  for (const now of [undefined, NaN, Infinity, -1, NOW + 0.5, Number.MAX_SAFE_INTEGER + 1]) {
    refusal(() => verifyAdmission({ root, ...events, state, now }), REFUSE.TIME)
  }
  const invite = content(events.invite, { expiresAt: NOW + TTL_SECONDS + 1 })
  const redemption = binding(invite, events.redemption)
  refusal(() => verifyAdmission({ root, invite, redemption, state, now: NOW }), REFUSE.TIME)
})

test('redemption must name the invite and fall within its signed lifetime', t => {
  const state = memory(t), { invite, redemption } = pair()
  const other = pair(0, 2)
  refusal(() => verifyAdmission({ root, invite, redemption: other.redemption, state, now: NOW }), REFUSE.SHAPE)
  for (const timestamp of [NOW - 1, NOW + TTL_SECONDS]) {
    const changed = signed(redemption, { created_at: timestamp }, keys[1])
    refusal(() => verifyAdmission({ root, invite, redemption: changed, state, now: NOW }), REFUSE.TIME)
    refusal(() => verifyRecord({ root, record: { chain: [{ invite, redemption: changed }] } }), REFUSE.TIME)
  }
})

test('replay and a second redemption by another valid key are refused', t => {
  const state = memory(t), events = pair()
  verifyAdmission({ root, ...events, state, now: NOW })
  refusal(() => verifyAdmission({ root, ...events, state, now: NOW }), REFUSE.REPLAY)
  const redemption = redeemInvite({ invite: events.invite, secretKey: keys[2], now: NOW })
  refusal(() => verifyAdmission({ root, invite: events.invite, redemption, state, now: NOW }), REFUSE.REPLAY)
})

test('a bearer invite permits a different valid new key to redeem first', t => {
  const state = memory(t), { invite } = pair()
  const redemption = redeemInvite({ invite, secretKey: keys[5], now: NOW })
  assert.equal(verifyAdmission({ root, invite, redemption, state, now: NOW }).member, pubs[5])
})

test('fourth distinct redemption is refused while unredeemed issuance costs nothing', t => {
  const state = memory(t)
  for (let i = 0; i < 5; i++) pair(0, 8)
  for (let member = 1; member <= 3; member++) assert.equal(admit(state, 0, member).member, pubs[member])
  refusal(() => admit(state, 0, 4), REFUSE.ALLOTMENT)
  assert.equal(state.transaction(tx => tx.count(root, root)), 3)
})

test('a missing chain does not admit even a known member as inviter', t => {
  const state = memory(t)
  admit(state)
  refusal(() => admit(state, 1, 2), REFUSE.CHAIN)
})

test('signed ancestry without an actual prior admission is refused', t => {
  const state = memory(t), first = pair()
  assert.equal(verifyRecord({ root, record: { chain: [first] } }).member, pubs[1])
  refusal(() => admit(state, 1, 2, [first]), REFUSE.UNADMITTED)
  refusal(() => admit(state, 1, 2, [first], NOW + TTL_SECONDS + 1), REFUSE.UNADMITTED)
})

test('ancestry must be contiguous, root-first, and match recorded admission bytes', t => {
  const state = memory(t), first = admit(state)
  const second = admit(state, 1, 2, first.record.chain)
  const chain = second.record.chain
  refusal(() => admit(state, 2, 3, [...chain].reverse()), REFUSE.CHAIN)
  refusal(() => admit(state, 2, 3, chain.slice(1)), REFUSE.CHAIN)
  refusal(() => admit(state, 2, 3, [...chain, chain[0]]), REFUSE.CHAIN)
  const altered = { ...chain[0], redemption: signed(chain[0].redemption, { created_at: NOW + 1 }, keys[1]) }
  refusal(() => admit(state, 1, 3, [altered]), REFUSE.UNADMITTED)
})

test('forged invite, redemption, and ancestor signatures are refused', t => {
  const state = memory(t), events = pair()
  for (const name of ['invite', 'redemption']) {
    const forged = { ...events, [name]: { ...events[name], sig: '00'.repeat(64) } }
    refusal(() => verifyAdmission({ root, ...forged, state, now: NOW }), REFUSE.SIGNATURE)
  }
  const first = admit(state)
  const ancestor = { ...first.record.chain[0], invite: { ...first.record.chain[0].invite, sig: '00'.repeat(64) } }
  refusal(() => admit(state, 1, 2, [ancestor]), REFUSE.SIGNATURE)
})

test('changing the redemption public key does not transfer its signature', t => {
  const state = memory(t), events = pair()
  const redemption = { ...events.redemption, pubkey: pubs[2] }
  refusal(() => verifyAdmission({ root, invite: events.invite, redemption, state, now: NOW }), REFUSE.SIGNATURE)
})

test('snapshot prevents a signer accessor from impersonating root', t => {
  const state = memory(t), { invite, redemption } = pair(9, 10)
  const signer = invite.pubkey
  Object.defineProperty(invite, 'pubkey', { enumerable: true, get() {
    return new Error().stack.includes('isValidEvent') ? signer : root
  } })
  refusal(() => verifyAdmission({ root, invite, redemption, state, now: NOW }), REFUSE.SIGNATURE)
  refusal(() => verifyRecord({ root, record: { chain: [{ invite, redemption }] } }), REFUSE.SIGNATURE)
})

test('signed code shape, issue time, and redemption reference cannot be substituted', t => {
  const state = memory(t), events = pair()
  const malformed = content(events.invite, { codeId: 'not-a-code' })
  const invite = signed(malformed, { tags: [['d', 'not-a-code']] })
  refusal(() => verifyAdmission({ root, invite, redemption: binding(invite, events.redemption), state, now: NOW }), REFUSE.SHAPE)
  const shifted = content(events.invite, { issuedAt: NOW + 1, expiresAt: NOW + TTL_SECONDS + 1 })
  refusal(() => verifyAdmission({ root, invite: shifted, redemption: events.redemption, state, now: NOW }), REFUSE.TIME)
  const redemption = content(events.redemption, { inviteId: 'ab'.repeat(32) }, keys[1])
  refusal(() => verifyAdmission({ root, invite: events.invite, redemption, state, now: NOW }), REFUSE.CHAIN)
})

test('network mismatch and signed free text or ambiguous protocol fields are refused', t => {
  const state = memory(t), events = pair()
  const foreign = content(events.invite, { network: pubs[9] })
  const redemption = redeemInvite({ invite: foreign, secretKey: keys[1], now: NOW })
  refusal(() => verifyAdmission({ root, invite: foreign, redemption, state, now: NOW }), REFUSE.NETWORK)
  const malformed = [
    { ...events.invite, note: 'operator must not retain this' },
    { ...events.invite, id: events.invite.id.toUpperCase() },
    content(events.invite, { invitee: pubs[1] }),
    signed(events.invite, { tags: [...events.invite.tags, ['note', 'free text']] }),
    signed(events.invite, { tags: [...events.invite.tags, events.invite.tags[0]] }),
    signed(events.invite, { kind: REDEMPTION_KIND }),
    signed(events.invite, { content: ` ${events.invite.content}` }),
  ]
  for (const invite of malformed) {
    refusal(() => verifyAdmission({ root, invite, redemption: binding(invite, events.redemption), state, now: NOW }), REFUSE.SHAPE)
  }
})

test('already admitted keys, inviter self-admission, and root admission are refused', t => {
  const state = memory(t), first = admit(state)
  refusal(() => admit(state, 0, 1), REFUSE.MEMBER)
  refusal(() => admit(state, 0, 0), REFUSE.MEMBER)
  refusal(() => admit(state, 1, 1, first.record.chain), REFUSE.MEMBER)
  refusal(() => admit(state, 1, 0, first.record.chain), REFUSE.MEMBER)
})

test('a root-signed absolute grant increases the allotment without additive replay', t => {
  const state = memory(t), allowance = grant(4)
  assert.equal(allowance.kind, GRANT_KIND)
  assert.deepEqual(allowance.tags, [['d', root]])
  assert.deepEqual(JSON.parse(allowance.content), { network: root, member: root, allotment: 4, sequence: 1 })
  for (let member = 1; member <= 4; member++) admit(state, 0, member, [], NOW, allowance)
  refusal(() => admit(state, 0, 5, [], NOW, allowance), REFUSE.ALLOTMENT)
  refusal(() => admit(state, 0, 5), REFUSE.ALLOTMENT)
})

test('latest known grant persists and stale or omitted grants do not restore old credit', t => {
  const state = memory(t), older = grant(5), newer = grant(2, 2)
  admit(state, 0, 1, [], NOW, older)
  admit(state, 0, 2, [], NOW, newer)
  refusal(() => admit(state, 0, 3, [], NOW, older), REFUSE.ALLOTMENT)
  refusal(() => admit(state, 0, 3), REFUSE.ALLOTMENT)
  refusal(() => admit(state, 0, 3, [], NOW, grant(8, 2)), REFUSE.GRANT)
})

test('a zero grant remains cached even though the admission is refused', t => {
  const state = memory(t), allowance = grant(0)
  refusal(() => admit(state, 0, 1, [], NOW, allowance), REFUSE.ALLOTMENT)
  assert.equal(state.transaction(tx => tx.grant(root, root)).allotment, 0)
  refusal(() => admit(state), REFUSE.ALLOTMENT)
  assert.equal(admit(state, 0, 1, [], NOW, grant(1, 2)).member, pubs[1])
})

test('grant timestamps and signatures are checked before policy changes', t => {
  const state = memory(t), allowance = grant(4)
  refusal(() => admit(state, 0, 1, [], NOW, { ...allowance, sig: '00'.repeat(64) }), REFUSE.SIGNATURE)
  const future = signed(allowance, { created_at: NOW + MAX_CLOCK_SKEW_SECONDS + 1 })
  refusal(() => admit(state, 0, 1, [], NOW, future), REFUSE.TIME)
  assert.equal(state.transaction(tx => tx.grant(root, root)), undefined)
})

test('wrong grant signer, network, member, or numeric policy is refused', t => {
  const state = memory(t), allowance = grant(4)
  const bad = [
    signed(allowance, { pubkey: pubs[9] }, keys[9]),
    content(allowance, { network: pubs[9] }),
    grant(4, 1, pubs[9]),
    content(allowance, { allotment: -1 }),
    content(allowance, { allotment: 1.5 }),
    content(allowance, { sequence: 0 }),
  ]
  for (const invalid of bad) refusal(() => admit(state, 0, 1, [], NOW, invalid), REFUSE.GRANT)
  refusal(() => admit(state, 0, 1, [], NOW, grant(0)), REFUSE.ALLOTMENT)
})

test('offline verification refuses forged, foreign, discontinuous, and future-parent chains', t => {
  const state = memory(t), first = admit(state)
  const second = admit(state, 1, 2, first.record.chain)
  refusal(() => verifyRecord({ root: pubs[9], record: second.record }), REFUSE.NETWORK)
  refusal(() => verifyRecord({ root, record: { chain: second.record.chain.slice(1) } }), REFUSE.CHAIN)
  const forged = structuredClone(second.record)
  forged.chain[0].redemption.sig = '00'.repeat(64)
  refusal(() => verifyRecord({ root, record: forged }), REFUSE.SIGNATURE)
  const later = pair(0, 1, NOW + MAX_CLOCK_SKEW_SECONDS + 1)
  const child = pair(1, 2)
  refusal(() => verifyRecord({ root, record: { chain: [later, child] } }), REFUSE.TIME)
  for (const chain of [[], Array(129).fill(forged.chain[0])]) {
    refusal(() => verifyRecord({ root, record: { chain } }), REFUSE.CHAIN)
  }
})

test('store transaction rolls back consumption and record on any thrown error', t => {
  const state = memory(t), events = pair()
  refusal(() => state.transaction(tx => {
    assert.equal(tx.consume(events.invite.id), true)
    tx.record(row(events.invite, events.redemption))
    throw new Error('interrupted admission')
  }), REFUSE.STATE)
  assert.equal(state.transaction(tx => tx.count(root, root)), 0)
  assert.equal(verifyAdmission({ root, ...events, state, now: NOW }).member, pubs[1])
})

test('unpaired consumption and asynchronous transaction callbacks cannot commit', t => {
  const state = memory(t), events = pair()
  refusal(() => state.transaction(tx => tx.consume(events.invite.id)), REFUSE.STATE)
  refusal(() => state.transaction(async tx => tx.consume(events.invite.id)), REFUSE.STATE)
  refusal(() => state.transaction(async () => {}), REFUSE.STATE)
  assert.equal(verifyAdmission({ root, ...events, state, now: NOW }).member, pubs[1])
})

test('store rejects free text, malformed ids, and transaction handles used after commit', t => {
  const state = memory(t), events = pair()
  let escaped
  state.transaction(tx => { escaped = tx })
  refusal(() => escaped.consume(events.invite.id), REFUSE.STATE)
  state.transaction(tx => refusal(() => tx.consume('free text'), REFUSE.STATE))
  refusal(() => state.transaction(tx => {
    tx.consume(events.invite.id)
    tx.record({ ...row(events.invite, events.redemption), note: 'ab'.repeat(32) })
  }), REFUSE.STATE)
  refusal(() => state.transaction(tx => tx.setGrant({ root, member: root,
    id: 'ab'.repeat(32), allotment: 2, sequence: 1, note: 'free text' })), REFUSE.STATE)
  assert.equal(verifyAdmission({ root, ...events, state, now: NOW }).member, pubs[1])
})

test('file state preserves consumed ids, quota, ancestry, and grants after reopening', t => {
  const path = disk(t), events = pair()
  writeFileSync(path, '')
  chmodSync(path, 0o644)
  const state = createFileStore(path)
  let first
  try {
    first = verifyAdmission({ root, ...events, state, now: NOW, grant: grant(1) })
  } finally { state.close() }
  assert.equal(statSync(path).mode & 0o777, 0o600)
  const reopened = createFileStore(path)
  try {
    refusal(() => verifyAdmission({ root, ...events, state: reopened, now: NOW }), REFUSE.REPLAY)
    refusal(() => admit(reopened, 0, 3), REFUSE.ALLOTMENT)
    assert.equal(admit(reopened, 1, 2, first.record.chain).member, pubs[2])
    assert.equal(reopened.transaction(tx => tx.count(root, root)), 1)
    assert.equal(reopened.transaction(tx => tx.grant(root, root)).allotment, 1)
  } finally { reopened.close() }
})

if (process.argv.includes('--mutations')) test('guard-removal mutations are detected', () => {
  const path = fileURLToPath(moduleUrl), original = readFileSync(path, 'utf8')
  const mutations = [
    ['snapshot', 'return structuredClone(value)', 'return value'],
    ['random-code', 'randomBytes(16)', 'Buffer.alloc(16)'],
    ['signature', 'if (!isValidEvent(event))', 'if (false)'],
    ['event-shape', "!fields(event, ['kind', 'pubkey', 'created_at', 'tags', 'content', 'id', 'sig'])", 'false'],
    ['event-kind', 'event.kind !== kind', 'false'],
    ['canonical-hex', '/^[0-9a-f]+$/.test(value)', '/^[0-9a-f]+$/i.test(value)'],
    ['content-schema', '!fields(value, names)', 'false'],
    ['content-canonical', 'JSON.stringify(value) !== event.content', 'false'],
    ['tag-schema', 'JSON.stringify(event.tags) !== JSON.stringify([[\'d\', identifier]])', 'false'],
    ['network', 'value.network !== root', 'false'],
    ['code-width', '!hex(value.codeId, 32)', 'false'],
    ['issue-binding', 'value.issuedAt !== invite.created_at', 'false'],
    ['lifetime', 'value.expiresAt !== value.issuedAt + TTL_SECONDS', 'false'],
    ['clock-shape', '!integer(now) || !Number.isSafeInteger(now + TTL_SECONDS)', 'false'],
    ['redemption-reference', 'claim.inviteId !== invite.id', 'false'],
    ['redemption-early', 'redemption.created_at < value.issuedAt', 'false'],
    ['redemption-late', 'redemption.created_at >= value.expiresAt', 'false'],
    ['chain-bound', 'record.chain.length > 128', 'false'],
    ['chain-empty', 'record.chain.length < 1', 'false'],
    ['chain-contiguity', 'entry.invite.pubkey !== inviter', 'false'],
    ['chain-chronology', 'entry.invite.created_at + MAX_CLOCK_SKEW_SECONDS < previousTime', 'false'],
    ['chain-cycle', 'members.has(member)', 'false'],
    ['verifier-expiry', 'now >= value.expiresAt', 'false'],
    ['redemption-future', 'redemption.created_at > now + MAX_CLOCK_SKEW_SECONDS', 'false'],
    ['ancestor-state', '!admitted || admitted.inviteId !== prior.invite.id\n        || admitted.redemptionId !== prior.redemption.id || admitted.inviter !== prior.invite.pubkey', 'false'],
    ['ancestor-bytes', 'admitted.redemptionId !== prior.redemption.id', 'false'],
    ['member-reuse', 'if (existing) return { refusal: REFUSE.MEMBER }', ''],
    ['replay', 'if (!tx.consume(invite.id)) return { refusal: REFUSE.REPLAY }', 'tx.consume(invite.id)'],
    ['allotment', 'tx.count(root, invite.pubkey) >= (knownGrant?.allotment ?? 3)', 'false'],
    ['grant-signer', 'grant.pubkey !== root', 'false'],
    ['grant-network', 'value.network !== root || value.member !== member', 'false || value.member !== member'],
    ['grant-member', 'value.member !== member', 'false'],
    ['grant-total', '!integer(value.allotment)', 'false'],
    ['grant-sequence', '!integer(value.sequence) || value.sequence < 1', 'false'],
    ['grant-future', 'grant.created_at > now + MAX_CLOCK_SKEW_SECONDS', 'false'],
    ['grant-conflict', 'knownGrant?.sequence === nextGrant.sequence && knownGrant.id !== nextGrant.id', 'false'],
    ['grant-rollback', '!knownGrant || nextGrant.sequence > knownGrant.sequence', 'true'],
    ['grant-cache', 'tx.setGrant(nextGrant)', ''],
    ['grant-refusal-commit', 'return { refusal: REFUSE.ALLOTMENT }', 'refuse(REFUSE.ALLOTMENT)'],
    ['store-paired', "if (get('SELECT 1 FROM consumed LEFT JOIN admissions USING (inviteId) WHERE admissions.inviteId IS NULL LIMIT 1'))", 'if (false)'],
    ['store-sync', "result && typeof result.then === 'function'", 'false'],
    ['store-handle', 'if (!active) refuse(REFUSE.STATE)', ''],
    ['store-id', 'if (!hex(inviteId)) refuse(REFUSE.STATE)', ''],
    ['store-record-schema', "!fields(entry, ['root', 'inviteId', 'redemptionId', 'inviter', 'member'])", 'false'],
    ['store-grant-schema', "!fields(entry, ['root', 'member', 'id', 'allotment', 'sequence'])", 'false'],
    ['store-rollback', "if (active) database.exec('ROLLBACK')", "if (active) database.exec('COMMIT')"],
    ['store-durable', 'store(new DatabaseSync(path))', "store(new DatabaseSync(':memory:'))"],
    ['store-atomic', /database\.exec\('(BEGIN IMMEDIATE|COMMIT|ROLLBACK)'\)/gu, 'undefined'],
    ['store-private', 'chmodSync(path, 0o600)', ''],
  ]
  try {
    for (const [name, before, after] of mutations) {
      assert.ok(typeof before === 'string' ? original.includes(before) : original.match(before), `mutation target missing: ${name}`)
      writeFileSync(path, original.replace(before, after))
      const result = spawnSync(process.execPath, ['--test', '--test-reporter=tap', fileURLToPath(import.meta.url)],
        { encoding: 'utf8', timeout: 15000 })
      assert.equal(result.status, 1, `mutation survived or crashed: ${name}\n${result.stdout}\n${result.stderr}`)
      assert.match(result.stdout, /not ok \d+ - /u, `no failing test: ${name}`)
      assert.doesNotMatch(result.stdout + result.stderr, /SyntaxError/u, `invalid mutation: ${name}`)
      console.log(`MUTATION ${name}: KILLED`)
    }
  } finally { writeFileSync(path, original) }
  console.log(`MUTATIONS ${mutations.length}/${mutations.length} KILLED`)
})

test('process crash between consume and record leaves no spent id or quota hole', t => {
  const path = disk(t), events = pair()
  createFileStore(path).close()
  const script = `import { createFileStore } from ${JSON.stringify(moduleUrl)};
    const state = createFileStore(process.argv[1]);
    state.transaction(tx => { if (!tx.consume(process.argv[2])) process.exit(74); process.exit(73) });`
  const crashed = spawnSync(process.execPath, ['--input-type=module', '--eval', script, path, events.invite.id], { encoding: 'utf8' })
  assert.equal(crashed.status, 73, crashed.stderr)
  const reopened = createFileStore(path)
  try {
    assert.equal(reopened.transaction(tx => tx.count(root, root)), 0)
    assert.equal(verifyAdmission({ root, ...events, state: reopened, now: NOW }).member, pubs[1])
    assert.equal(reopened.transaction(tx => tx.count(root, root)), 1)
    refusal(() => verifyAdmission({ root, ...events, state: reopened, now: NOW }), REFUSE.REPLAY)
  } finally { reopened.close() }
})

test('independent file-store writers cannot race past the last allotment slot', async t => {
  const path = disk(t), state = createFileStore(path)
  try { admit(state, 0, 1); admit(state, 0, 2) } finally { state.close() }
  const script = `import { createFileStore, verifyAdmission } from ${JSON.stringify(moduleUrl)};
    const state = createFileStore(process.argv[1]);
    try { verifyAdmission({ ...JSON.parse(process.argv[2]), state }); process.stdout.write('admitted'); }
    catch (error) { process.stdout.write(error.code || 'unexpected-error'); }
    finally { state.close(); }`
  const run = member => new Promise((resolve, reject) => {
    const args = { root, ...pair(0, member), now: NOW }
    const child = spawn(process.execPath, ['--input-type=module', '--eval', script, path, JSON.stringify(args)])
    let stdout = '', stderr = ''
    child.stdout.on('data', chunk => { stdout += chunk })
    child.stderr.on('data', chunk => { stderr += chunk })
    child.on('error', reject)
    child.on('close', status => status === 0 ? resolve(stdout) : reject(new Error(stderr)))
  })
  const outcomes = await Promise.all([run(3), run(4)])
  assert.deepEqual(outcomes.sort(), ['admitted', REFUSE.ALLOTMENT].sort())
  const reopened = createFileStore(path)
  try { assert.equal(reopened.transaction(tx => tx.count(root, root)), 3) } finally { reopened.close() }
})
