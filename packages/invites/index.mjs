// SPDX-License-Identifier: AGPL-3.0-or-later
// Signed invitation chains require atomic consumption, quota accounting and membership records.
import { randomBytes, createHash } from 'node:crypto'
import { closeSync, openSync, chmodSync } from 'node:fs'
import { DatabaseSync } from 'node:sqlite'
import { signEvent, isValidEvent, publicKeyOf } from '../../plugins/aukora-nostr/lib/event.mjs'
import { canonicalJson } from '../contracts/src/json.mjs'

export const INVITE_KIND = 39701
export const REDEMPTION_KIND = 39702
export const GRANT_KIND = 39703
export const ADMISSION_KIND = 39704
export const TTL_SECONDS = 48 * 60 * 60
export const MAX_CLOCK_SKEW_SECONDS = 300
export const REFUSE = Object.freeze(Object.fromEntries([
  'SIGNATURE', 'SHAPE', 'NETWORK', 'TIME', 'EXPIRED', 'CHAIN', 'UNADMITTED',
  'REPLAY', 'ALLOTMENT', 'MEMBER', 'GRANT', 'STATE',
].map(name => [name, `invites:${name.toLowerCase()}`])))

function refuse(code) { throw Object.assign(new Error(code), { code }) }
function snapshot(value) {
  try { return structuredClone(value) } catch { refuse(REFUSE.SHAPE) }
}
function hex(value, length = 64) {
  return typeof value === 'string' && value.length === length && /^[0-9a-f]+$/.test(value)
}
function integer(value) { return Number.isSafeInteger(value) && value >= 0 }
function fields(value, names) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    && Object.keys(value).sort().join(',') === [...names].sort().join(',')
}
function clock(now) {
  if (!integer(now) || !Number.isSafeInteger(now + TTL_SECONDS)) refuse(REFUSE.TIME)
}
function signed(kind, secretKey, now, identifier, body) {
  clock(now)
  return signEvent({ kind, pubkey: publicKeyOf(secretKey), created_at: now,
    tags: [['d', identifier]], content: JSON.stringify(body) }, secretKey)
}
function body(event, kind, names) {
  if (!fields(event, ['kind', 'pubkey', 'created_at', 'tags', 'content', 'id', 'sig'])
    || event.kind !== kind || !hex(event.pubkey) || !hex(event.id) || !hex(event.sig, 128)
    || typeof event.content !== 'string' || event.content.length > 512) refuse(REFUSE.SHAPE)
  if (!isValidEvent(event)) refuse(REFUSE.SIGNATURE)
  clock(event.created_at)
  let value
  try { value = JSON.parse(event.content) } catch { refuse(REFUSE.SHAPE) }
  if (!fields(value, names) || JSON.stringify(value) !== event.content) refuse(REFUSE.SHAPE)
  return value
}
function tag(event, identifier) {
  if (JSON.stringify(event.tags) !== JSON.stringify([['d', identifier]])) refuse(REFUSE.SHAPE)
}
function invitation(invite, root) {
  const value = body(invite, INVITE_KIND, ['network', 'codeId', 'issuedAt', 'expiresAt'])
  if (!hex(root) || value.network !== root) refuse(REFUSE.NETWORK)
  if (!hex(value.codeId, 32)) refuse(REFUSE.SHAPE)
  tag(invite, value.codeId)
  if (value.issuedAt !== invite.created_at || value.expiresAt !== value.issuedAt + TTL_SECONDS) refuse(REFUSE.TIME)
  return value
}
function pair(root, entry) {
  if (!fields(entry, ['invite', 'redemption'])) refuse(REFUSE.CHAIN)
  const { invite, redemption } = entry
  const value = invitation(invite, root)
  const claim = body(redemption, REDEMPTION_KIND, ['inviteId'])
  tag(redemption, invite.id)
  if (claim.inviteId !== invite.id) refuse(REFUSE.CHAIN)
  if (redemption.created_at < value.issuedAt || redemption.created_at >= value.expiresAt) refuse(REFUSE.TIME)
  return value
}

export function createInvite({ root, secretKey, now }) {
  if (!hex(root)) refuse(REFUSE.NETWORK)
  clock(now)
  const codeId = randomBytes(16).toString('hex')
  return signed(INVITE_KIND, secretKey, now, codeId,
    { network: root, codeId, issuedAt: now, expiresAt: now + TTL_SECONDS })
}

export function redeemInvite({ invite, secretKey, now }) {
  invite = snapshot(invite)
  const value = body(invite, INVITE_KIND, ['network', 'codeId', 'issuedAt', 'expiresAt'])
  invitation(invite, value.network)
  const redemption = signed(REDEMPTION_KIND, secretKey, now, invite.id, { inviteId: invite.id })
  pair(value.network, { invite, redemption })
  return redemption
}

export function createGrant({ root, secretKey, member, allotment, sequence, now }) {
  if (!hex(root) || publicKeyOf(secretKey) !== root || !hex(member)
    || !integer(allotment) || !integer(sequence) || sequence < 1) refuse(REFUSE.GRANT)
  return signed(GRANT_KIND, secretKey, now, member, { network: root, member, allotment, sequence })
}

function verifyChain(root, record) {
  if (!hex(root) || !fields(record, ['chain']) || !Array.isArray(record.chain)
    || record.chain.length < 1 || record.chain.length > 128) refuse(REFUSE.CHAIN)
  let inviter = root
  let previousTime = 0
  const members = new Set([root])
  for (const entry of record.chain) {
    pair(root, entry)
    if (entry.invite.pubkey !== inviter) refuse(REFUSE.CHAIN)
    if (entry.invite.created_at + MAX_CLOCK_SKEW_SECONDS < previousTime) refuse(REFUSE.TIME)
    const member = entry.redemption.pubkey
    if (members.has(member)) refuse(REFUSE.MEMBER)
    members.add(member)
    inviter = member
    previousTime = entry.redemption.created_at
  }
  return { member: inviter }
}

const recordDigest = chain => createHash('sha256').update(canonicalJson({ chain })).digest('hex')

// The root's signed confirmation binds the exact chain and last redemption.
export function createAdmissionRecord({ root, secretKey, record, now }) {
  record = snapshot(record)
  verifyChain(root, record)
  if (publicKeyOf(secretKey) !== root) refuse(REFUSE.SIGNATURE)
  const redemptionId = record.chain.at(-1).redemption.id
  return { chain: record.chain, confirmation: signed(ADMISSION_KIND, secretKey, now, redemptionId,
    { network: root, redemptionId, recordSha256: recordDigest(record.chain) }) }
}

export function verifyAdmissionRecord({ root, record }) {
  record = snapshot(record)
  if (!fields(record, ['chain', 'confirmation'])) refuse(REFUSE.CHAIN)
  const result = verifyChain(root, { chain: record.chain })
  const value = body(record.confirmation, ADMISSION_KIND, ['network', 'redemptionId', 'recordSha256'])
  if (record.confirmation.pubkey !== root) refuse(REFUSE.SIGNATURE)
  if (value.network !== root) refuse(REFUSE.NETWORK)
  const redemptionId = record.chain.at(-1).redemption.id
  if (value.redemptionId !== redemptionId || value.recordSha256 !== recordDigest(record.chain)) refuse(REFUSE.CHAIN)
  tag(record.confirmation, redemptionId)
  return result
}

// Bare offline records prove ancestry; confirmed records also require the root's signature.
export function verifyRecord({ root, record }) {
  record = snapshot(record)
  return Object.hasOwn(record ?? {}, 'confirmation') ? verifyAdmissionRecord({ root, record }) : verifyChain(root, record)
}

function grantFor(root, member, grant, now) {
  if (!grant) return undefined
  const value = body(grant, GRANT_KIND, ['network', 'member', 'allotment', 'sequence'])
  if (grant.pubkey !== root || value.network !== root || value.member !== member
    || !integer(value.allotment) || !integer(value.sequence) || value.sequence < 1) refuse(REFUSE.GRANT)
  tag(grant, member)
  if (grant.created_at > now + MAX_CLOCK_SKEW_SECONDS) refuse(REFUSE.TIME)
  return { root, member, id: grant.id, allotment: value.allotment, sequence: value.sequence }
}

// Availability verifies signed ancestry and current accounting without consuming an invite.
export function verifyAvailable({ root, invite, chain = [], state, now }) {
  ;({ root, invite, chain, now } = snapshot({ root, invite, chain, now }))
  clock(now)
  if (!Array.isArray(chain) || chain.length > 127) refuse(REFUSE.CHAIN)
  const value = invitation(invite, root)
  const inviter = chain.length ? verifyRecord({ root, record: { chain } }).member : root
  if (invite.pubkey !== inviter) refuse(REFUSE.CHAIN)
  if (chain.length && invite.created_at + MAX_CLOCK_SKEW_SECONDS < chain.at(-1).redemption.created_at) refuse(REFUSE.TIME)
  if (now < value.issuedAt) refuse(REFUSE.TIME)
  if (now >= value.expiresAt) refuse(REFUSE.EXPIRED)
  if (typeof state?.transaction !== 'function') refuse(REFUSE.STATE)
  return state.transaction(tx => {
    for (const prior of chain) {
      const admitted = tx.admission(root, prior.redemption.pubkey)
      if (!admitted || admitted.inviteId !== prior.invite.id
        || admitted.redemptionId !== prior.redemption.id || admitted.inviter !== prior.invite.pubkey) refuse(REFUSE.UNADMITTED)
    }
    if (tx.consumed(invite.id)) refuse(REFUSE.REPLAY)
    if (tx.count(root, inviter) >= (tx.grant(root, inviter)?.allotment ?? 3)) refuse(REFUSE.ALLOTMENT)
    return { available: true, invite_id: invite.id }
  })
}

export function verifyAdmission({ root, invite, redemption, chain = [], state, now, grant }) {
  ;({ root, invite, redemption, chain, now, grant } = snapshot({ root, invite, redemption, chain, now, grant }))
  clock(now)
  if (!Array.isArray(chain)) refuse(REFUSE.CHAIN)
  const record = { chain: [...chain, { invite, redemption }] }
  const { member } = verifyRecord({ root, record })
  const value = invitation(invite, root)
  if (now >= value.expiresAt) refuse(REFUSE.EXPIRED)
  if (redemption.created_at > now + MAX_CLOCK_SKEW_SECONDS) refuse(REFUSE.TIME)
  const nextGrant = grantFor(root, invite.pubkey, grant, now)
  if (typeof state?.transaction !== 'function') refuse(REFUSE.STATE)
  const result = state.transaction(tx => {
    for (const prior of chain) {
      const admitted = tx.admission(root, prior.redemption.pubkey)
      if (!admitted || admitted.inviteId !== prior.invite.id
        || admitted.redemptionId !== prior.redemption.id || admitted.inviter !== prior.invite.pubkey) refuse(REFUSE.UNADMITTED)
    }
    let knownGrant = tx.grant(root, invite.pubkey)
    if (nextGrant) {
      if (knownGrant?.sequence === nextGrant.sequence && knownGrant.id !== nextGrant.id) refuse(REFUSE.GRANT)
      if (!knownGrant || nextGrant.sequence > knownGrant.sequence) {
        tx.setGrant(nextGrant)
        knownGrant = nextGrant
      }
    }
    const existing = tx.admission(root, member)
    if (existing?.inviteId === invite.id) return { refusal: REFUSE.REPLAY }
    if (existing) return { refusal: REFUSE.MEMBER }
    if (tx.count(root, invite.pubkey) >= (knownGrant?.allotment ?? 3)) return { refusal: REFUSE.ALLOTMENT }
    if (!tx.consume(invite.id)) return { refusal: REFUSE.REPLAY }
    tx.record({ root, inviteId: invite.id, redemptionId: redemption.id, inviter: invite.pubkey, member })
    return { member, record }
  })
  if (result.refusal) refuse(result.refusal)
  return result
}

// A transaction never commits consumption without its membership and quota record.
function store(database) {
  database.exec(`
    PRAGMA busy_timeout = 5000;
    PRAGMA journal_mode = DELETE;
    PRAGMA synchronous = FULL;
    PRAGMA foreign_keys = ON;
    CREATE TABLE IF NOT EXISTS consumed (inviteId TEXT PRIMARY KEY) STRICT;
    CREATE TABLE IF NOT EXISTS admissions (
      root TEXT NOT NULL, inviteId TEXT NOT NULL UNIQUE REFERENCES consumed(inviteId),
      redemptionId TEXT NOT NULL UNIQUE, inviter TEXT NOT NULL, member TEXT NOT NULL,
      PRIMARY KEY (root, member)
    ) STRICT;
    CREATE INDEX IF NOT EXISTS inviter_count ON admissions(root, inviter);
    CREATE TABLE IF NOT EXISTS grants (
      root TEXT NOT NULL, member TEXT NOT NULL, id TEXT NOT NULL,
      allotment INTEGER NOT NULL, sequence INTEGER NOT NULL, PRIMARY KEY (root, member)
    ) STRICT;
  `)
  const run = (sql, ...args) => database.prepare(sql).run(...args)
  const get = (sql, ...args) => database.prepare(sql).get(...args)
  return {
    close() { database.close() },
    transaction(callback) {
      let active = false
      try {
        database.exec('BEGIN IMMEDIATE')
        active = true
        const check = () => { if (!active) refuse(REFUSE.STATE) }
        const tx = {
          consume(inviteId) {
            check()
            if (!hex(inviteId)) refuse(REFUSE.STATE)
            return run('INSERT OR IGNORE INTO consumed VALUES (?)', inviteId).changes === 1
          },
          consumed(inviteId) { check(); if (!hex(inviteId)) refuse(REFUSE.STATE); return Boolean(get('SELECT 1 FROM consumed WHERE inviteId = ?', inviteId)) },
          record(entry) {
            check()
            if (!fields(entry, ['root', 'inviteId', 'redemptionId', 'inviter', 'member'])
              || !Object.values(entry).every(value => hex(value))) refuse(REFUSE.STATE)
            run('INSERT INTO admissions VALUES (?, ?, ?, ?, ?)',
              entry.root, entry.inviteId, entry.redemptionId, entry.inviter, entry.member)
          },
          admission(root, member) { check(); return get('SELECT * FROM admissions WHERE root = ? AND member = ?', root, member) },
          count(root, inviter) { check(); return get('SELECT count(*) AS n FROM admissions WHERE root = ? AND inviter = ?', root, inviter).n },
          grant(root, member) { check(); return get('SELECT * FROM grants WHERE root = ? AND member = ?', root, member) },
          setGrant(entry) {
            check()
            if (!fields(entry, ['root', 'member', 'id', 'allotment', 'sequence'])
              || ![entry.root, entry.member, entry.id].every(value => hex(value))
              || !integer(entry.allotment) || !integer(entry.sequence) || entry.sequence < 1) refuse(REFUSE.STATE)
            run('INSERT OR REPLACE INTO grants VALUES (?, ?, ?, ?, ?)',
              entry.root, entry.member, entry.id, entry.allotment, entry.sequence)
          },
        }
        const result = callback(tx)
        if (result && typeof result.then === 'function') refuse(REFUSE.STATE)
        if (get('SELECT 1 FROM consumed LEFT JOIN admissions USING (inviteId) WHERE admissions.inviteId IS NULL LIMIT 1')) refuse(REFUSE.STATE)
        database.exec('COMMIT')
        active = false
        return result
      } catch (error) {
        if (active) database.exec('ROLLBACK')
        active = false
        if (Object.values(REFUSE).includes(error.code)) throw error
        refuse(REFUSE.STATE)
      }
    },
  }
}

export function createMemoryStore() { return store(new DatabaseSync(':memory:')) }

export { store as createDatabaseStore }

export function createFileStore(path) {
  if (typeof path !== 'string' || path.length === 0 || path === ':memory:') refuse(REFUSE.STATE)
  try {
    closeSync(openSync(path, 'a', 0o600))
    chmodSync(path, 0o600)
    return store(new DatabaseSync(path))
  } catch { refuse(REFUSE.STATE) }
}
