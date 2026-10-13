// SPDX-License-Identifier: AGPL-3.0-or-later
// Commits invite spending with bounded delivery states; appends intent before adding relay members.
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { DatabaseSync } from 'node:sqlite'
import { createHash } from 'node:crypto'
import { createInvite, redeemInvite, verifyAvailable, verifyAdmission, verifyRecord, createDatabaseStore, REFUSE as INVITE_REFUSE } from '../../packages/invites/index.mjs'
import { canonicalJson } from '../../packages/contracts/src/json.mjs'
import { gateCall, loadKey, RELAY_HTTP } from '../../plugins/aukora-buzz-door/lib/index.mjs'
import { publicKeyOf, isHex32 } from '../../plugins/aukora-nostr/lib/event.mjs'
import { createMemberClient, REFUSE as MEMBER_REFUSE } from './member.mjs'

export const REFUSE = Object.freeze({
  INPUT: 'buzz-admit:invalid-input', KEY: 'buzz-admit:isolated-key-required',
  STORE: 'buzz-admit:store-invalid', BUSY: 'buzz-admit:store-busy',
  UNKNOWN: 'buzz-admit:acceptance-unconfirmed', PENDING: 'buzz-admit:pending-admissions',
  RETRY: 'buzz-admit:retry-later', UNDELIVERABLE: 'buzz-admit:undeliverable',
  AURA: 'buzz-admit:aura-unrecorded',
})
const fail = code => Object.assign(new Error(code), { code })
const HERE = path.dirname(fileURLToPath(import.meta.url))
const defaultKeyOptions = () => ({ extraDenied: [path.resolve(HERE, '../..'), process.cwd()] })
const seconds = () => Math.floor(Date.now() / 1000)
const compact = (root, invite, redemption) => ({ root, inviteId: invite.id, redemptionId: redemption.id,
  inviter: invite.pubkey, member: redemption.pubkey })
const json = value => JSON.stringify(value)
const recordIds = record => record.chain.map(({ invite, redemption }) => [invite.id, redemption.id])
const MAX_DELIVERY_ATTEMPTS = 3
const RETRY_BASE_MS = 25
const RETRY_MAX_MS = 30_000
const LEGACY_DELIVERY_ERRORS = [...Object.values(MEMBER_REFUSE), REFUSE.AURA, REFUSE.UNKNOWN].filter(code => code !== MEMBER_REFUSE.INPUT)
const DELIVERY_STATES = new Set(['pending', 'admitted', 'undeliverable'])
const wait = milliseconds => new Promise(resolve => setTimeout(resolve, milliseconds))

function syncDirectory(directory) {
  const fd = fs.openSync(directory, 'r')
  try { fs.fsyncSync(fd) } finally { fs.closeSync(fd) }
}

function privateFile(file) {
  const fd = fs.openSync(file, fs.constants.O_CREAT | fs.constants.O_RDWR | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK, 0o600)
  try {
    const st = fs.fstatSync(fd)
    if (!st.isFile() || st.nlink !== 1 || (st.mode & 0o077) || st.uid !== process.getuid()) throw fail(REFUSE.STORE)
  } finally { fs.closeSync(fd) }
}

function openStore(directory, root, baseUrl) {
  let lock, db, state
  try {
    if (typeof directory !== 'string' || !path.isAbsolute(directory) || path.resolve(directory) !== directory) throw fail(REFUSE.STORE)
    if (!fs.existsSync(directory)) fs.mkdirSync(directory, { mode: 0o700 })
    const st = fs.lstatSync(directory)
    if (!st.isDirectory() || (st.mode & 0o077) || st.uid !== process.getuid()
      || fs.realpathSync(directory) !== directory) throw fail(REFUSE.STORE)
    for (const name of ['lock.sqlite', 'admissions.sqlite', 'admissions.jsonl']) {
      privateFile(path.join(directory, name))
      for (const suffix of ['-journal', '-wal', '-shm']) {
        const file = path.join(directory, name + suffix)
        if (fs.lstatSync(file, { throwIfNoEntry: false })) privateFile(file)
      }
    }
    lock = new DatabaseSync(path.join(directory, 'lock.sqlite'))
    try { lock.exec('PRAGMA busy_timeout = 0; BEGIN IMMEDIATE') } catch { throw fail(REFUSE.BUSY) }
    db = new DatabaseSync(path.join(directory, 'admissions.sqlite'))
    state = createDatabaseStore(db)
    db.exec(`CREATE TABLE IF NOT EXISTS delivery (
      sequence INTEGER PRIMARY KEY, inviteId TEXT NOT NULL UNIQUE REFERENCES consumed(inviteId),
      entry TEXT NOT NULL, record TEXT NOT NULL, done INTEGER NOT NULL DEFAULT 0 CHECK(done IN (0,1)),
      state TEXT NOT NULL DEFAULT 'pending' CHECK(state IN ('pending','admitted','undeliverable')),
      attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts >= 0), lastError TEXT, retryAt INTEGER NOT NULL DEFAULT 0
    ) STRICT;
    CREATE TABLE IF NOT EXISTS network (singleton INTEGER PRIMARY KEY CHECK(singleton = 1), root TEXT NOT NULL, relay TEXT NOT NULL) STRICT;`)
    const columns = new Set(db.prepare('PRAGMA table_info(delivery)').all().map(column => column.name))
    if (!columns.has('state')) {
      db.exec("BEGIN IMMEDIATE; ALTER TABLE delivery ADD COLUMN state TEXT NOT NULL DEFAULT 'pending' CHECK(state IN ('pending','admitted','undeliverable')); UPDATE delivery SET state = CASE done WHEN 1 THEN 'admitted' ELSE 'pending' END; COMMIT")
    }
    if (!columns.has('attempts')) db.exec('ALTER TABLE delivery ADD COLUMN attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts >= 0)')
    if (!columns.has('lastError')) db.exec('ALTER TABLE delivery ADD COLUMN lastError TEXT')
    if (!columns.has('retryAt')) db.exec('ALTER TABLE delivery ADD COLUMN retryAt INTEGER NOT NULL DEFAULT 0')
    // Older broad refusals retain the exact reserved redemption while delivery reopens.
    db.prepare(`UPDATE delivery SET state = 'pending', retryAt = 0 WHERE state = 'undeliverable'
      AND attempts = 3 AND done = 0 AND lastError IN (${LEGACY_DELIVERY_ERRORS.map(() => '?').join(',')})`).run(...LEGACY_DELIVERY_ERRORS)
    db.prepare('INSERT OR IGNORE INTO network VALUES (1, ?, ?)').run(root, baseUrl)
    const network = db.prepare('SELECT root, relay FROM network').get()
    if (network.root !== root || network.relay !== baseUrl) throw fail(REFUSE.STORE)
    if (db.prepare('SELECT 1 FROM admissions LEFT JOIN delivery USING (inviteId) WHERE delivery.inviteId IS NULL LIMIT 1').get()) throw fail(REFUSE.STORE)
    for (const row of db.prepare('SELECT * FROM delivery ORDER BY sequence').all()) checkedRecord({ state }, root, row)
    syncDirectory(path.dirname(directory))
    syncDirectory(directory)
    return { db, state, directory, close() { state.close(); lock.close() } }
  } catch (error) {
    if (db) db.close()
    if (lock) lock.close()
    throw Object.values(REFUSE).includes(error?.code) ? error : fail(REFUSE.STORE)
  }
}

// Only a prefix of committed records is repairable; recovery appends missing bytes without rewriting history.
function appendAdmissions(store) {
  const rows = store.db.prepare('SELECT entry FROM delivery ORDER BY sequence').all()
  const expected = Buffer.from(rows.map(row => row.entry + '\n').join(''))
  const file = path.join(store.directory, 'admissions.jsonl')
  const fd = fs.openSync(file, fs.constants.O_RDWR | fs.constants.O_APPEND | fs.constants.O_NOFOLLOW)
  try {
    const actual = fs.readFileSync(fd)
    if (actual.length > expected.length || !actual.equals(expected.subarray(0, actual.length))) throw fail(REFUSE.STORE)
    let offset = actual.length
    while (offset < expected.length) {
      const written = fs.writeSync(fd, expected, offset, expected.length - offset)
      if (!written) throw fail(REFUSE.STORE)
      offset += written
    }
    fs.fsyncSync(fd)
  } finally { fs.closeSync(fd) }
}

function context(options, deps) {
  if (options.gateSocket !== undefined && (typeof options.gateSocket !== 'string'
    || !path.isAbsolute(options.gateSocket) || options.gateSocket.includes('\0'))) throw fail(REFUSE.AURA)
  const baseUrl = options.baseUrl ?? RELAY_HTTP
  const client = createMemberClient({ keyFile: options.keyFile, baseUrl }, {
    keyOptions: deps.keyOptions ?? defaultKeyOptions(), fetchImpl: deps.fetchImpl,
  })
  const store = openStore(options.storeDir, client.pubkey, baseUrl)
  return { store, root: client.pubkey, sender: deps.sender ?? (command => client.send(command)),
    onStage: deps.onStage ?? (() => {}), gateSocket: options.gateSocket, gate: deps.gate ?? gateCall,
    nowMs: deps.nowMs ?? Date.now, sleep: deps.sleep ?? wait }
}

function checkedRecord(store, root, row) {
  const entry = JSON.parse(row.entry), record = JSON.parse(row.record)
  if (!DELIVERY_STATES.has(row.state) || !Number.isSafeInteger(row.attempts) || row.attempts < 0
    || !Number.isSafeInteger(row.retryAt) || row.retryAt < 0
    || (row.state === 'admitted') !== Boolean(row.done)
    || (row.state === 'undeliverable' && (row.attempts < 1 || row.lastError !== MEMBER_REFUSE.INPUT))) throw fail(REFUSE.STORE)
  if (verifyRecord({ root, record }).member !== entry.member) throw fail(REFUSE.STORE)
  const last = record.chain.at(-1)
  const stored = store.state.transaction(tx => tx.admission(root, entry.member))
  if (row.entry !== json(compact(root, last.invite, last.redemption)) || json(stored) !== row.entry) throw fail(REFUSE.STORE)
  return { entry, record }
}

function admittedState(store) {
  return { transaction(callback) {
    return store.state.transaction(tx => callback({ ...tx, admission(root, member) {
      const delivery = store.db.prepare('SELECT state FROM delivery JOIN admissions USING (inviteId) WHERE root = ? AND member = ?').get(root, member)
      return delivery?.state === 'admitted' ? tx.admission(root, member) : undefined
    } }))
  } }
}

const deliveryCode = error => [...Object.values(MEMBER_REFUSE), REFUSE.AURA, REFUSE.UNKNOWN].includes(error?.code)
  ? error.code : REFUSE.UNKNOWN

function deliveryResult(row, entry, record) {
  if (row.state === 'admitted') return { state: 'admitted', member: entry.member, record, attempts: row.attempts }
  return { state: row.state, member: entry.member, invite_id: entry.inviteId,
    attempts: row.attempts, code: row.lastError }
}

async function deliver(ctx, row) {
  const { store, sender, onStage } = ctx
  const { entry, record } = checkedRecord(store, ctx.root, row)
  if (row.state !== 'pending') return deliveryResult(row, entry, record)
  if (row.retryAt > ctx.nowMs()) throw fail(REFUSE.RETRY)
  appendAdmissions(store)
  onStage('append')
  let code
  // Retries may duplicate this digest; a configured gate must acknowledge before the relay is changed.
  if (ctx.gateSocket !== undefined) {
    try {
      const ack = await ctx.gate(ctx.gateSocket, 'aura_note', { kind: 'admission',
        digest_sha256: createHash('sha256').update(json(record)).digest('hex') })
      if (ack?.ok !== true || !Number.isSafeInteger(ack.seq) || ack.seq < 1
        || typeof ack.hash !== 'string' || !/^[0-9a-f]{64}$/.test(ack.hash)) throw fail(REFUSE.AURA)
    } catch { code = REFUSE.AURA }
  }
  if (!code) try {
    const ack = await sender({ command: 'add', pubkey: entry.member, role: 'member' })
    if (ack?.accepted !== true || ack.kind !== 9030 || !isHex32(ack.event_id)) throw fail(REFUSE.UNKNOWN)
  } catch (error) { code = deliveryCode(error) }
  if (code) {
    const attempts = row.attempts + 1, terminal = code === MEMBER_REFUSE.INPUT
    const retryAt = terminal ? 0 : ctx.nowMs() + Math.min(RETRY_MAX_MS, RETRY_BASE_MS * (2 ** Math.min(attempts - 1, 16)))
    store.db.prepare('UPDATE delivery SET state = ?, attempts = ?, lastError = ?, retryAt = ? WHERE inviteId = ?')
      .run(terminal ? 'undeliverable' : 'pending', attempts, code, retryAt, entry.inviteId)
    onStage('attempt')
    throw fail(terminal ? REFUSE.UNDELIVERABLE : code)
  }
  onStage('sent')
  store.db.prepare("UPDATE delivery SET done = 1, state = 'admitted', attempts = attempts + 1, lastError = NULL, retryAt = 0 WHERE inviteId = ?").run(entry.inviteId)
  onStage('done')
  return deliveryResult(store.db.prepare('SELECT * FROM delivery WHERE inviteId = ?').get(entry.inviteId), entry, record)
}

export function preflight(options, deps = {}) {
  let request
  try { request = structuredClone(options) } catch { throw fail(REFUSE.INPUT) }
  const { invite, chain = [] } = request ?? {}
  if (!invite || !Array.isArray(chain)) throw fail(REFUSE.INPUT)
  const ctx = context(request, deps), { store, root } = ctx
  try {
    if (request.root !== root) throw fail(INVITE_REFUSE.NETWORK)
    return verifyAvailable({ root, invite, chain, state: admittedState(store), now: (deps.now ?? seconds)() })
  } finally { store.close() }
}

async function admitRequest(options, deps, idempotent) {
  let request
  try { request = structuredClone(options) } catch { throw fail(REFUSE.INPUT) }
  const { invite, redemption, chain = [] } = request ?? {}
  if (!invite || !redemption || !Array.isArray(chain)) throw fail(REFUSE.INPUT)
  const ctx = context(request, deps), { store, root, onStage } = ctx
  try {
    if (idempotent && request.root !== root) throw fail(INVITE_REFUSE.NETWORK)
    const record = { chain: [...chain, { invite, redemption }] }
    verifyRecord({ root, record })
    const existing = store.db.prepare('SELECT * FROM delivery WHERE inviteId = ?').get(invite.id)
    if (idempotent && existing) {
      if (existing.entry !== json(compact(root, invite, redemption))) throw fail(INVITE_REFUSE.REPLAY)
      if (canonicalJson(recordIds(JSON.parse(existing.record))) !== canonicalJson(recordIds(record))) throw fail(INVITE_REFUSE.CHAIN)
      if (existing.state === 'admitted') {
        const stored = checkedRecord(store, root, existing)
        appendAdmissions(store)
        return deliveryResult(existing, stored.entry, stored.record)
      }
      if (existing.state === 'undeliverable') throw fail(REFUSE.UNDELIVERABLE)
      return await deliver(ctx, existing)
    }
    if (existing) {
      if (existing.entry !== json(compact(root, invite, redemption))) throw fail(INVITE_REFUSE.REPLAY)
      if (existing.record !== json(record)) throw fail(INVITE_REFUSE.CHAIN)
      if (existing.state !== 'pending') throw fail(existing.state === 'undeliverable' ? REFUSE.UNDELIVERABLE : INVITE_REFUSE.REPLAY)
      return await deliver(ctx, existing)
    }
    // Outbox insertion shares the verifier transaction; rollback cannot leave an unresumable spend.
    const state = { transaction(callback) {
      return admittedState(store).transaction(tx => callback({ ...tx, record(entry) {
        tx.record(entry)
        store.db.prepare('INSERT INTO delivery (inviteId, entry, record) VALUES (?, ?, ?)')
          .run(invite.id, json(entry), json(record))
        onStage('record')
      } }))
    } }
    verifyAdmission({ root, invite, redemption, chain, state, now: (deps.now ?? seconds)() })
    onStage('spent')
    return await deliver(ctx, store.db.prepare('SELECT * FROM delivery WHERE inviteId = ?').get(invite.id))
  } finally { store.close() }
}

// Exact incomplete CLI requests resume; completed CLI requests refuse replay.
export function admit(options, deps = {}) { return admitRequest(options, deps, false) }

// HTTP retries return the same completed signed record without another relay command.
export function admitIdempotent(options, deps = {}) { return admitRequest(options, deps, true) }

export async function resume(options, deps = {}) {
  const ctx = context(options, deps)
  try {
    appendAdmissions(ctx.store)
    const results = []
    for (const initial of ctx.store.db.prepare("SELECT * FROM delivery WHERE state = 'pending' ORDER BY sequence").all()) {
      let row = initial
      for (let attempt = 0; attempt < MAX_DELIVERY_ATTEMPTS; attempt++) {
        const delay = row.retryAt - ctx.nowMs()
        if (delay > 0) await ctx.sleep(delay)
        try {
          results.push(await deliver(ctx, row))
          break
        } catch (error) {
          row = ctx.store.db.prepare('SELECT * FROM delivery WHERE inviteId = ?').get(row.inviteId)
          if (row.state === 'undeliverable') {
            const stored = checkedRecord(ctx.store, ctx.root, row)
            results.push(deliveryResult(row, stored.entry, stored.record))
            break
          }
          if (![REFUSE.RETRY, REFUSE.AURA, REFUSE.UNKNOWN, ...Object.values(MEMBER_REFUSE)].includes(error?.code)) throw error
          if (attempt === MAX_DELIVERY_ATTEMPTS - 1) {
            const stored = checkedRecord(ctx.store, ctx.root, row)
            results.push(deliveryResult(row, stored.entry, stored.record))
          }
        }
      }
    }
    return results
  } finally { ctx.store.close() }
}

const HELP = `Usage: node ops/buzz-relay/admit.mjs <command> [options]
  issue  --key-file PATH --root OWNER_PUBKEY > invite.json
  redeem --key-file PATH --invite invite.json > redemption.json
  admit  --key-file OWNER_PATH --store ABSOLUTE_DIRECTORY --invite invite.json --redemption redemption.json [--chain chain.json] [--relay http://localhost:3000] [--gate-socket PATH]
  resume --key-file OWNER_PATH --store ABSOLUTE_DIRECTORY [--relay http://localhost:3000] [--gate-socket PATH]
Key files use member.mjs isolated-file rules; no inline secret keys. Output contains signed events, never secret keys.
The root is the relay owner's public key. --chain is the inviter's root-first array of signed pairs;
use the previous admit output's record.chain. Supply [] for the root. Transfer bearer invites privately.
The admissions store holds, unencrypted, every member's public key and who invited whom (the whole invite graph).
Resume: repeat an incomplete admit, or run resume with the same owner, relay and store. A spend committed before
expiry is still delivered after expiry; uncommitted requests must still be valid. Never reset or restore the store.
Delivery states are pending, admitted and undeliverable. Resume makes at most three attempts per entry per run;
backoff persists across runs and is capped at 30 seconds. Transport, Aura, unknown acknowledgements and unclassified
refusals stay pending for the same redemption. Only local invalid-command refusals terminalize delivery;
no remote refusal code is qualified as permanent.
Older broad terminal refusals reopen as pending. Terminal invites stay spent and cannot vouch for another member.
The append-only admissions.jsonl precedes each send. Recovery completes a torn matching prefix; other damage refuses.
With --gate-socket, the gate must record the signed admission record's SHA-256 before each send. Reuse that option
on resume. Gate failure leaves delivery pending; an uncertain send or gate reply may produce duplicate digest notes.
An uncertain send is retried as an idempotent member add; this is not exactly-once HTTP delivery. A completed invite
is refused as a replay. The store must have one trusted operator; permissions do not prevent owner tampering.
Requires a CLOSED relay owned by this key. Relay idempotence and closure require live qualification.
LIVE test: AUKORA_BUZZ_LIVE=1 AUKORA_BUZZ_OWNER_KEY_FILE=PATH node --test ops/buzz-relay/admit.test.mjs`

export async function runCli(args, deps = {}) {
  const { out = line => console.log(line), err = line => console.error(line) } = deps
  try {
    if (args.length === 1 && args[0] === '--help') { out(HELP); return 0 }
    const [command, ...rest] = args
    const allowed = {
      issue: ['--key-file', '--root'], redeem: ['--key-file', '--invite'],
      admit: ['--key-file', '--store', '--invite', '--redemption', '--chain', '--relay', '--gate-socket'],
      resume: ['--key-file', '--store', '--relay', '--gate-socket'],
    }
    if (!Object.hasOwn(allowed, command)) throw fail(REFUSE.INPUT)
    const opts = {}
    for (let i = 0; i < rest.length; i += 2) {
      const flag = rest[i], value = rest[i + 1]
      if (!allowed[command].includes(flag) || Object.hasOwn(opts, flag)
        || typeof value !== 'string' || value.startsWith('--')) throw fail(REFUSE.INPUT)
      opts[flag] = value
    }
    const read = flag => JSON.parse(fs.readFileSync(opts[flag], 'utf8'))
    let result
    if (command === 'issue' || command === 'redeem') {
      let key
      try { key = loadKey(opts['--key-file'], deps.keyOptions ?? defaultKeyOptions()); publicKeyOf(key) } catch { throw fail(REFUSE.KEY) }
      const now = (deps.now ?? seconds)()
      result = command === 'issue' ? createInvite({ root: opts['--root'], secretKey: key, now })
        : redeemInvite({ invite: read('--invite'), secretKey: key, now })
    } else {
      const options = { keyFile: opts['--key-file'], storeDir: opts['--store'], baseUrl: opts['--relay'], gateSocket: opts['--gate-socket'] }
      result = command === 'resume' ? await resume(options, deps)
        : await admit({ ...options, invite: read('--invite'), redemption: read('--redemption'),
          chain: opts['--chain'] ? read('--chain') : [] }, deps)
    }
    out(json(result))
    return 0
  } catch (error) {
    const codes = [...Object.values(REFUSE), ...Object.values(INVITE_REFUSE), ...Object.values(MEMBER_REFUSE)]
    err(codes.includes(error?.code) ? error.code : REFUSE.INPUT)
    return 1
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.exitCode = await runCli(process.argv.slice(2))
}
