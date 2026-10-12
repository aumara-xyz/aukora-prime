// SPDX-License-Identifier: AGPL-3.0-or-later
// Commits invite spending with pending delivery; appends admissions before adding relay members.
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { DatabaseSync } from 'node:sqlite'
import { createInvite, redeemInvite, verifyAdmission, verifyRecord, createDatabaseStore, REFUSE as INVITE_REFUSE } from '../../packages/invites/index.mjs'
import { loadKey, RELAY_HTTP } from '../../plugins/aukora-buzz-door/lib/index.mjs'
import { publicKeyOf, isHex32 } from '../../plugins/aukora-nostr/lib/event.mjs'
import { createMemberClient, REFUSE as MEMBER_REFUSE } from './member.mjs'

export const REFUSE = Object.freeze({
  INPUT: 'buzz-admit:invalid-input', KEY: 'buzz-admit:isolated-key-required',
  STORE: 'buzz-admit:store-invalid', BUSY: 'buzz-admit:store-busy',
  UNKNOWN: 'buzz-admit:acceptance-unconfirmed', PENDING: 'buzz-admit:pending-admissions',
})
const fail = code => Object.assign(new Error(code), { code })
const HERE = path.dirname(fileURLToPath(import.meta.url))
const defaultKeyOptions = () => ({ extraDenied: [path.resolve(HERE, '../..'), process.cwd()] })
const seconds = () => Math.floor(Date.now() / 1000)
const compact = (root, invite, redemption) => ({ root, inviteId: invite.id, redemptionId: redemption.id,
  inviter: invite.pubkey, member: redemption.pubkey })
const json = value => JSON.stringify(value)

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
      entry TEXT NOT NULL, record TEXT NOT NULL, done INTEGER NOT NULL DEFAULT 0 CHECK(done IN (0,1))
    ) STRICT;
    CREATE TABLE IF NOT EXISTS network (singleton INTEGER PRIMARY KEY CHECK(singleton = 1), root TEXT NOT NULL, relay TEXT NOT NULL) STRICT;`)
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
  const baseUrl = options.baseUrl ?? RELAY_HTTP
  const client = createMemberClient({ keyFile: options.keyFile, baseUrl }, {
    keyOptions: deps.keyOptions ?? defaultKeyOptions(), fetchImpl: deps.fetchImpl,
  })
  const store = openStore(options.storeDir, client.pubkey, baseUrl)
  return { store, root: client.pubkey, sender: deps.sender ?? (command => client.send(command)),
    onStage: deps.onStage ?? (() => {}) }
}

function checkedRecord(store, root, row) {
  const entry = JSON.parse(row.entry), record = JSON.parse(row.record)
  if (verifyRecord({ root, record }).member !== entry.member) throw fail(REFUSE.STORE)
  const last = record.chain.at(-1)
  const stored = store.state.transaction(tx => tx.admission(root, entry.member))
  if (row.entry !== json(compact(root, last.invite, last.redemption)) || json(stored) !== row.entry) throw fail(REFUSE.STORE)
  return { entry, record }
}

async function deliver(ctx, row) {
  const { store, sender, onStage } = ctx
  const { entry, record } = checkedRecord(store, ctx.root, row)
  appendAdmissions(store)
  onStage('append')
  const ack = await sender({ command: 'add', pubkey: entry.member, role: 'member' })
  if (ack?.accepted !== true || ack.kind !== 9030 || !isHex32(ack.event_id)) throw fail(REFUSE.UNKNOWN)
  onStage('sent')
  store.db.prepare('UPDATE delivery SET done = 1 WHERE inviteId = ?').run(entry.inviteId)
  onStage('done')
  return { member: entry.member, record }
}

// Exact incomplete requests resume at their committed decision, even after expiry; completed requests are replays.
export async function admit(options, deps = {}) {
  let request
  try { request = structuredClone(options) } catch { throw fail(REFUSE.INPUT) }
  const { invite, redemption, chain = [] } = request ?? {}
  if (!invite || !redemption || !Array.isArray(chain)) throw fail(REFUSE.INPUT)
  const ctx = context(request, deps), { store, root, onStage } = ctx
  try {
    const record = { chain: [...chain, { invite, redemption }] }
    verifyRecord({ root, record })
    const existing = store.db.prepare('SELECT * FROM delivery WHERE inviteId = ?').get(invite.id)
    if (existing) {
      if (existing.done || existing.entry !== json(compact(root, invite, redemption))) throw fail(INVITE_REFUSE.REPLAY)
      if (existing.record !== json(record)) throw fail(INVITE_REFUSE.CHAIN)
      return await deliver(ctx, existing)
    }
    if (store.db.prepare('SELECT 1 FROM delivery WHERE done = 0').get()) throw fail(REFUSE.PENDING)
    // Outbox insertion shares the verifier transaction; rollback cannot leave an unresumable spend.
    const state = { transaction(callback) {
      return store.state.transaction(tx => callback({ ...tx, record(entry) {
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

export async function resume(options, deps = {}) {
  const ctx = context(options, deps)
  try {
    appendAdmissions(ctx.store)
    const results = []
    for (const row of ctx.store.db.prepare('SELECT * FROM delivery WHERE done = 0 ORDER BY sequence').all()) {
      results.push(await deliver(ctx, row))
    }
    return results
  } finally { ctx.store.close() }
}

const HELP = `Usage: node ops/buzz-relay/admit.mjs <command> [options]
  issue  --key-file PATH --root OWNER_PUBKEY > invite.json
  redeem --key-file PATH --invite invite.json > redemption.json
  admit  --key-file OWNER_PATH --store ABSOLUTE_DIRECTORY --invite invite.json --redemption redemption.json [--chain chain.json] [--relay http://localhost:3000]
  resume --key-file OWNER_PATH --store ABSOLUTE_DIRECTORY [--relay http://localhost:3000]
Key files use member.mjs isolated-file rules; no inline secret keys. Output contains signed events, never secret keys.
The root is the relay owner's public key. --chain is the inviter's root-first array of signed pairs;
use the previous admit output's record.chain. Supply [] for the root. Transfer bearer invites privately.
Resume: repeat an incomplete admit, or run resume with the same owner, relay and store. A committed spend
retains its delivery across expiry; uncommitted requests must still be valid. Never reset or restore the store.
The append-only admissions.jsonl precedes each send. Recovery completes a torn matching prefix; other damage refuses.
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
      admit: ['--key-file', '--store', '--invite', '--redemption', '--chain', '--relay'],
      resume: ['--key-file', '--store', '--relay'],
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
      const options = { keyFile: opts['--key-file'], storeDir: opts['--store'], baseUrl: opts['--relay'] }
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
