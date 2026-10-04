// SPDX-License-Identifier: AGPL-3.0-or-later
// Source acceptance only. In-memory ordering and filesystem metadata fixtures.
// No filesystem writes/deletes, root action, signer enrollment or installed boot.
import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
const source = fs.readFileSync(new URL('../release-floor.mjs', import.meta.url), 'utf8')
const cli = fs.readFileSync(new URL('../../bin/release-floor.mjs', import.meta.url), 'utf8')
const load = text => import(`data:text/javascript;base64,${Buffer.from(text).toString('base64')}`)
const floor = await load(source)
const FILE = '/etc/aukora-approvals/release-floor.json'
const release = n => n.toString(16).padStart(40, '0')
const sha = n => n.toString(16).padStart(64, '0')
const proof = (changes = {}) => ({ release: release(1), release_dir: 'release-0000001', record: sha(1),
  signerEpoch: 1, ledgerSeq: 10, signerKeySha256: sha(2), ledgerHash: sha(3), appliedAt: '2026-10-04T00:00:00.000Z', ...changes })
const clock = (verified = proof()) => ({ kind: 'aukora-release-floor/v1', release: verified.release,
  release_dir: verified.release_dir, record: verified.record, applied_at: verified.appliedAt, history: [release(9)] })
const errorCode = code => error => error?.code === code

// All mutable filesystem state below is synthetic, including unlink and rename.
function memory(initial, options = {}) {
  const nodes = new Map(), opened = new Map(), events = []; let inode = 1, fd = 1000
  const node = (bytes, directory = false) => ({ bytes: Buffer.from(bytes ?? ''), directory, ino: inode++, dev: 1,
    uid: 0, mode: directory ? 0o40755 : 0o100644, nlink: 1, symlink: false })
  for (const directory of ['/', '/etc', '/etc/aukora-approvals']) nodes.set(directory, node('', true))
  const set = (file, value) => nodes.set(file, node(typeof value === 'string' ? value : JSON.stringify(value)))
  if (initial !== null) set(FILE, initial)
  if (options.existingLock) set(FILE + '.lock', options.existingLock)
  const get = file => { const n = nodes.get(file); if (!n) throw Object.assign(new Error('synthetic absent'), { code: 'ENOENT' }); return n }
  const metadata = n => ({ ...n, size: n.bytes.length, isDirectory: () => n.directory,
    isFile: () => !n.directory, isSymbolicLink: () => n.symlink })
  const handle = number => { const h = opened.get(number); assert.ok(h, 'synthetic descriptor must be live'); return h }
  const fixture = {
    lstatSync(file) { events.push(['lstat', file]); return metadata(get(file)) },
    openSync(file, flags, mode) {
      events.push(['open', file, flags])
      if ((flags & fs.constants.O_EXCL) && nodes.has(file)) throw Object.assign(new Error('synthetic exists'), { code: 'EEXIST' })
      if ((flags & fs.constants.O_CREAT) && !nodes.has(file)) { const n = node(''); n.mode = 0o100000 | mode; nodes.set(file, n) }
      const n = get(file)
      if (options.linkAtOpen && file === FILE) {
        if (flags & fs.constants.O_NOFOLLOW) throw Object.assign(new Error('synthetic symlink race'), { code: 'ELOOP' })
        // A symlink pointing to the original inode defeats identity-only checks.
      } else if (n.symlink && (flags & fs.constants.O_NOFOLLOW)) throw Object.assign(new Error('synthetic symlink'), { code: 'ELOOP' })
      if (file === FILE + '.lock' && (flags & fs.constants.O_CREAT) && options.afterLock) options.afterLock({ nodes, set })
      opened.set(++fd, { file, node: n }); return fd
    },
    fstatSync(number) {
      const h = handle(number), st = metadata(h.node)
      if (h.file === FILE && options.changedIdentity) st.ino++
      if (h.file === FILE && options.openOwner) st.uid = 501
      if (h.file === FILE && options.openMode) st.mode |= 0o022
      if (h.file === FILE && options.openLinks) st.nlink = 2
      return st
    },
    readFileSync(number) {
      const h = handle(number); events.push(['read', h.file])
      return options.extraBytes && h.file === FILE ? Buffer.concat([h.node.bytes, Buffer.from(' ')]) : Buffer.from(h.node.bytes)
    },
    writeFileSync(number, bytes) { const h = handle(number); events.push(['write', h.file]); h.node.bytes = Buffer.from(bytes) },
    fsyncSync(number) {
      const h = handle(number); events.push(['sync', h.file])
      if (options.failTemporarySync && h.file.includes('.release-floor.tmp-')) throw new Error('synthetic sync failure')
    },
    closeSync(number) { const h = handle(number); events.push(['close', h.file]); opened.delete(number) },
    renameSync(from, to) {
      events.push(['rename', from, to]); nodes.set(to, get(from)); nodes.delete(from)
      if (options.tamperLock) get(FILE + '.lock').bytes = Buffer.alloc(get(FILE + '.lock').bytes.length, 0x78)
    },
    unlinkSync(file) { events.push(['unlink', file]); assert.equal(file, FILE + '.lock', 'only own synthetic lock may be removed'); nodes.delete(file) },
  }
  const run = callback => {
    const saved = Object.fromEntries(Object.keys(fixture).map(key => [key, fs[key]]))
    Object.assign(fs, fixture)
    try { return callback() } finally { Object.assign(fs, saved) }
  }
  return { nodes, events, run, set, value: () => JSON.parse(get(FILE).bytes.toString('utf8')) }
}

test('sequence order survives clock rollback/forward; timestamps are not persisted', () => {
  const v = proof(), current = floor.advanceFloor(null, v)
  const newer = proof({ ledgerSeq: 11, ledgerHash: sha(4), appliedAt: '1990-01-01T00:00:00.000Z' })
  assert.throws(() => floor.checkFloor(current, newer), errorCode('release-floor-install-incomplete'))
  const advanced = floor.advanceFloor(current, newer)
  assert.equal(advanced.ledger_seq, 11); assert.deepEqual(advanced.history, [])
  assert.equal(floor.checkFloor(advanced, newer).ok, true)
  assert.throws(() => floor.advanceFloor(current, proof({ ledgerSeq: 9, appliedAt: '2099-01-01T00:00:00.000Z' })), errorCode('release-floor-not-newer'))
  assert.throws(() => floor.checkFloor(current, proof({ ledgerSeq: 9, appliedAt: '2099-01-01T00:00:00.000Z' })), errorCode('release-below-floor'))
  assert.equal(Object.hasOwn(current, 'applied_at'), false)
})
test('exact current boot works; every equal tuple install and distinct boot refuses', () => {
  const v = proof(), current = floor.advanceFloor(null, v)
  assert.equal(floor.checkFloor(current, v).ok, true)
  assert.throws(() => floor.advanceFloor(current, v), errorCode('release-floor-not-newer'))
  for (const changes of [{ release: release(2) }, { release_dir: 'release-0000002' }, { record: sha(9) }, { ledgerHash: sha(9) }]) {
    assert.throws(() => floor.checkFloor(current, proof(changes)), errorCode('release-floor-equal-conflict'))
    assert.throws(() => floor.advanceFloor(current, proof(changes)), errorCode('release-floor-not-newer'))
  }
  for (const ledgerSeq of [10, 11]) assert.throws(() => floor.checkFloor(current, proof({ ledgerSeq, signerKeySha256: sha(9) })), errorCode('release-floor-signer-epoch-mismatch'))
})
test('epoch precedes sequence; old signer replay refuses, fresh owner proof permits rollback', () => {
  const old = floor.advanceFloor(null, proof({ ledgerSeq: Number.MAX_SAFE_INTEGER }))
  const rotated = proof({ release: release(2), release_dir: 'release-0000002', signerEpoch: 2, ledgerSeq: 1, signerKeySha256: sha(8) })
  const current = floor.advanceFloor(old, rotated)
  assert.equal(current.signer_epoch, 2); assert.equal(current.ledger_seq, 1)
  assert.equal(floor.isRollback(current, release(1)), true)
  assert.throws(() => floor.checkFloor(current, proof({ ledgerSeq: Number.MAX_SAFE_INTEGER })), errorCode('release-below-floor'))
  const rollback = proof({ signerEpoch: 2, ledgerSeq: 2, signerKeySha256: sha(8), ledgerHash: sha(10) })
  const rolled = floor.advanceFloor(current, rollback)
  assert.deepEqual(rolled.history, [release(2)]); assert.equal(floor.checkFloor(rolled, rollback).ok, true)
})
test('missing, coerced, unsafe and malformed ordering evidence refuses', () => {
  for (const name of ['signerEpoch', 'ledgerSeq']) for (const value of [undefined, null, '10', 0, -1, 0.5, Number.MAX_SAFE_INTEGER + 1, NaN, Infinity]) {
    assert.throws(() => floor.advanceFloor(null, proof({ [name]: value })), errorCode('release-floor-ordering-evidence'))
  }
  for (const name of ['signerKeySha256', 'ledgerHash', 'record']) for (const value of [undefined, null, 'A'.repeat(64), '0'.repeat(63), 10]) {
    assert.throws(() => floor.advanceFloor(null, proof({ [name]: value })), errorCode('release-floor-ordering-evidence'))
  }
  const current = floor.advanceFloor(null, proof())
  for (const changes of [{ ledger_seq: '10' }, { signer_epoch: 0 }, { ledger_hash: 'A'.repeat(64) }, { extra: true },
    { history: [current.release] }, { history: [release(9), release(9)] }, { history: Array.from({ length: 65 }, (_, n) => release(n + 10)) }]) {
    assert.throws(() => floor.checkFloor({ ...current, ...changes }, proof()), errorCode('release-floor-malformed'))
  }
  assert.throws(() => floor.checkFloor(null, proof()), errorCode('release-floor-absent'))
})
test('legacy floor requires explicit exact-proof migration; no empty rebaseline', () => {
  const v = proof(), old = clock(v)
  assert.throws(() => floor.checkFloor(old, v), errorCode('release-floor-migration-required'))
  assert.throws(() => floor.advanceFloor(old, v), errorCode('release-floor-migration-required'))
  const migrated = floor.migrateClockFloor(old, v)
  assert.deepEqual(migrated.history, old.history); assert.notEqual(migrated.history, old.history)
  assert.equal(floor.checkFloor(migrated, v).ok, true)
  for (const changes of [{ release: release(2) }, { release_dir: 'release-0000002' }, { record: sha(4) },
    { appliedAt: undefined }, { appliedAt: '2026-10-04T00:00:00.001Z' }]) {
    assert.throws(() => floor.migrateClockFloor(old, proof(changes)), errorCode('release-floor-migration-proof'))
  }
  for (const oldFloor of [null, migrated]) assert.throws(() => floor.migrateClockFloor(oldFloor, v), errorCode('release-floor-malformed'))
  for (const applied_at of ['2026-99-99T99:99:99.999Z', '2026-02-29T00:00:00.000Z']) {
    assert.throws(() => floor.migrateClockFloor({ ...old, applied_at }, proof({ appliedAt: applied_at })), errorCode('release-floor-malformed'))
  }
  const m = memory(old)
  m.run(() => {
    assert.throws(() => floor.readFloor(FILE, { requireRoot: true }), errorCode('release-floor-migration-required'))
    assert.deepEqual(floor.readFloor(FILE, { requireRoot: true, allowClockMigration: true }), old)
    assert.throws(() => floor.writeFloor(FILE, migrated), errorCode('release-floor-migration-required'))
    floor.writeFloor(FILE, migrated, { clockMigrationProof: { old, verified: v } })
  })
  assert.deepEqual(m.value(), migrated)
})
test('protected reads check all ancestors, no-follow descriptor identity, links and bounds', () => {
  const current = floor.advanceFloor(null, proof())
  const valid = memory(current); valid.run(() => assert.deepEqual(floor.readFloor(FILE, { requireRoot: true }), current))
  assert.deepEqual(valid.events.filter(([event]) => event === 'lstat').map(([, file]) => file), ['/', '/etc', '/etc/aukora-approvals', FILE])
  const absent = memory(null); absent.run(() => assert.equal(floor.readFloor(FILE, { requireRoot: true }), null))
  for (const file of ['/', '/etc', '/etc/aukora-approvals', FILE]) for (const change of [{ uid: 501 }, { mode: 0o100666 }, { symlink: true }]) {
    const m = memory(current); Object.assign(m.nodes.get(file), change)
    m.run(() => assert.throws(() => floor.readFloor(FILE, { requireRoot: true })))
  }
  const badParent = memory(null); badParent.nodes.get('/etc').mode |= 0o022
  badParent.run(() => assert.throws(() => floor.readFloor(FILE, { requireRoot: true }), errorCode('release-floor-protection')))
  for (const options of [{ changedIdentity: true }, { openOwner: true }, { openMode: true }, { openLinks: true }, { extraBytes: true }, { linkAtOpen: true }]) {
    const m = memory(current, options); m.run(() => assert.throws(() => floor.readFloor(FILE, { requireRoot: true })))
    assert.equal(m.events.filter(([event]) => event === 'close').length, options.linkAtOpen ? 0 : 1)
  }
  for (const mutate of [n => { n.nlink = 2 }, n => { n.bytes = Buffer.alloc(16 * 1024 + 1) }, n => { n.bytes = Buffer.from('{') }]) {
    const m = memory(current); mutate(m.nodes.get(FILE)); m.run(() => assert.throws(() => floor.readFloor(FILE, { requireRoot: true })))
  }
})
test('atomic writes sync before rename and after it; only own live lock is removed', () => {
  const current = floor.advanceFloor(null, proof()), next = floor.advanceFloor(current, proof({ ledgerSeq: 11 }))
  const m = memory(current); m.run(() => floor.writeFloor(FILE, next)); assert.deepEqual(m.value(), next)
  const rename = m.events.findIndex(([event]) => event === 'rename')
  assert.ok(m.events.slice(0, rename).some(([event, file]) => event === 'sync' && file.includes('.release-floor.tmp-')))
  assert.ok(m.events.slice(rename + 1).some(([event, file]) => event === 'sync' && file === '/etc/aukora-approvals'))
  assert.equal(m.nodes.has(FILE + '.lock'), false)
  for (const [, file, flags] of m.events.filter(([event]) => event === 'open')) {
    assert.ok(flags & fs.constants.O_NOFOLLOW, 'all floor/lock/directory opens must be no-follow')
    if (file === FILE + '.lock' && flags & fs.constants.O_CREAT) assert.ok(flags & fs.constants.O_EXCL)
  }
  const locked = memory(current, { existingLock: 'unknown-or-crashed-token' })
  locked.run(() => assert.throws(() => floor.writeFloor(FILE, next), errorCode('release-floor-locked')))
  assert.deepEqual(locked.value(), current); assert.equal(locked.nodes.has(FILE + '.lock'), true)
  const broken = memory(current, { failTemporarySync: true })
  broken.run(() => assert.throws(() => floor.writeFloor(FILE, next), /synthetic sync failure/))
  assert.deepEqual(broken.value(), current); assert.equal(broken.events.some(([event]) => event === 'rename'), false)
  const tampered = memory(current, { tamperLock: true })
  tampered.run(() => assert.throws(() => floor.writeFloor(FILE, next), errorCode('release-floor-lock-identity')))
  assert.equal(tampered.nodes.has(FILE + '.lock'), true)
})
test('locked reread defeats stale competing writer and retains actual intervening history', () => {
  const initial = floor.advanceFloor(null, proof()), stale = floor.advanceFloor(initial, proof({ ledgerSeq: 12 }))
  const winner = floor.advanceFloor(initial, proof({ release: release(2), release_dir: 'release-0000002', ledgerSeq: 13 }))
  const m = memory(initial, { afterLock: ({ set }) => set(FILE, winner) })
  m.run(() => assert.throws(() => floor.writeFloor(FILE, stale), errorCode('release-floor-not-newer')))
  assert.deepEqual(m.value(), winner); assert.equal(m.events.some(([event]) => event === 'rename'), false)
  const latest = floor.advanceFloor(initial, proof({ release: release(3), release_dir: 'release-0000003', ledgerSeq: 14 }))
  const fresh = memory(initial, { afterLock: ({ set }) => set(FILE, winner) })
  fresh.run(() => floor.writeFloor(FILE, latest))
  assert.deepEqual(fresh.value().history, [release(1), release(2)])
  for (const current of [null, stale]) {
    const denied = memory(current), old = clock(), migrated = floor.migrateClockFloor(old, proof())
    denied.run(() => assert.throws(() => floor.writeFloor(FILE, migrated, { clockMigrationProof: { old, verified: proof() } }), errorCode('release-floor-migration-proof')))
  }
})
test('interrupted floor/cache publication refuses ahead or stale proof until exact commit', () => {
  const oldProof = proof(), current = floor.advanceFloor(null, oldProof)
  const candidates = [proof({ ledgerSeq: 11, ledgerHash: sha(4) }),
    proof({ release: release(2), release_dir: 'release-0000002', ledgerSeq: 11, ledgerHash: sha(5) }),
    proof({ signerEpoch: 2, ledgerSeq: 1, signerKeySha256: sha(6), ledgerHash: sha(7) })]
  for (const candidate of candidates) {
    const next = floor.advanceFloor(current, candidate), cacheAhead = memory(current)
    // A prior publisher's new cache is insufficient if the floor write never ran.
    cacheAhead.run(() => {
      const committed = floor.readFloor(FILE, { requireRoot: true })
      assert.throws(() => floor.checkFloor(committed, candidate), errorCode('release-floor-install-incomplete'))
      assert.equal(floor.checkFloor(committed, oldProof).ok, true)
    })
    // A failed durable write leaves the old floor; staged proof still cannot boot.
    const failed = memory(current, { failTemporarySync: true })
    failed.run(() => {
      assert.throws(() => floor.writeFloor(FILE, next), /synthetic sync failure/)
      assert.throws(() => floor.checkFloor(floor.readFloor(FILE, { requireRoot: true }), candidate), errorCode('release-floor-install-incomplete'))
    })
    // Floor-first publication interrupted before cache update stops stale boot.
    const floorAhead = memory(current)
    floorAhead.run(() => {
      floor.writeFloor(FILE, next)
      const committed = floor.readFloor(FILE, { requireRoot: true })
      assert.throws(() => floor.checkFloor(committed, oldProof), errorCode('release-below-floor'))
      assert.equal(floor.checkFloor(committed, candidate).ok, true)
      assert.throws(() => floor.advanceFloor(committed, candidate), errorCode('release-floor-not-newer'))
      // Recovery through installation needs another fresh owner proof.
      const recovery = { ...candidate, ledgerSeq: candidate.ledgerSeq + 1, ledgerHash: sha(8) }
      floor.writeFloor(FILE, floor.advanceFloor(committed, recovery))
      const recovered = floor.readFloor(FILE, { requireRoot: true })
      assert.throws(() => floor.checkFloor(recovered, candidate), errorCode('release-below-floor'))
      assert.equal(floor.checkFloor(recovered, recovery).ok, true)
    })
  }
  // A late stale cache publisher also causes refusal, even after a newer commit.
  const intermediate = candidates[0], winner = proof({ ledgerSeq: 12, ledgerHash: sha(9) }), raced = memory(current)
  raced.run(() => {
    floor.writeFloor(FILE, floor.advanceFloor(current, intermediate))
    floor.writeFloor(FILE, floor.advanceFloor(floor.readFloor(FILE, { requireRoot: true }), winner))
    const committed = floor.readFloor(FILE, { requireRoot: true })
    assert.throws(() => floor.checkFloor(committed, intermediate), errorCode('release-below-floor'))
    assert.equal(floor.checkFloor(committed, winner).ok, true)
  })
  assert.throws(() => floor.checkFloor(null, candidates[0]), errorCode('release-floor-absent'))
})
test('builtin-only closure and actual CLI use ordered proof and explicit migration', () => {
  for (const match of source.matchAll(/^import .* from '([^']+)'/gmu)) assert.ok(match[1].startsWith('node:'))
  assert.doesNotMatch(source, /Date\.|new Date|process\.env|child_process|createRequire/)
  const core = cli.split('// TRUSTED-BOOTSTRAP-END')[1]
  assert.match(core, /verifyOrderedGateApproval\(\{ record, approval, pin, epochs \}\)/u)
  assert.match(core, /readSignerEpochs\(\)/u)
  assert.match(core, /cmd === 'migrate-clock-floor' && process\.getuid\?\.\(\) !== 0/u)
  assert.match(core, /writeFloor\(o\.floor, migrated, \{ clockMigrationProof: \{ old: floor, verified: v \} \}\)/u)
  assert.doesNotMatch(core, /verifyGateSetApproval|Date\.parse/u)
})

if (process.argv.includes('--mutations')) test('named guard removals are killed by their focused behavior checks', async t => {
  const mutations = [
    ['clock-order', "return verified.ledgerSeq === floor.ledger_seq ? 0 : verified.ledgerSeq > floor.ledger_seq ? 1 : -1", "return verified.appliedAt > '2026-10-04T00:00:00.000Z' ? 1 : -1", m => assert.doesNotThrow(() => assert.equal(m.advanceFloor(m.advanceFloor(null, proof()), proof({ ledgerSeq: 11, appliedAt: '1990-01-01T00:00:00.000Z' })).ledger_seq, 11))],
    ['epoch-order', 'verified.signerEpoch > floor.signer_epoch ? 1 : -1', 'verified.ledgerSeq > floor.ledger_seq ? 1 : -1', m => assert.doesNotThrow(() => assert.equal(m.advanceFloor(m.advanceFloor(null, proof({ ledgerSeq: Number.MAX_SAFE_INTEGER })), proof({ signerEpoch: 2, ledgerSeq: 1, signerKeySha256: sha(9) })).signer_epoch, 2))],
    ['boot-uncommitted', 'if (order > 0)', 'if (false)', m => { const current = m.advanceFloor(null, proof()); for (const candidate of [proof({ ledgerSeq: 11, ledgerHash: sha(4) }), proof({ signerEpoch: 2, ledgerSeq: 1, signerKeySha256: sha(9) })]) assert.throws(() => m.checkFloor(current, candidate), errorCode('release-floor-install-incomplete')) }],
    ['install-equality', 'if (compare(floor, verified) <= 0)', 'if (compare(floor, verified) < 0)', m => assert.throws(() => m.advanceFloor(m.advanceFloor(null, proof()), proof()), errorCode('release-floor-not-newer'))],
    ...['release', 'release_dir', 'record', 'ledgerHash'].map(name => ['equal-' + name, `verified.${name} === floor.${name === 'ledgerHash' ? 'ledger_hash' : name}`, 'true', m => assert.throws(() => m.checkFloor(m.advanceFloor(null, proof()), proof({ [name]: name === 'release' ? release(2) : name === 'release_dir' ? 'release-0000002' : sha(9) })), errorCode('release-floor-equal-conflict'))]),
    ['same-epoch-key', "if (verified.signerKeySha256 !== floor.signer_key_sha256)", 'if (false)', m => assert.throws(() => m.advanceFloor(m.advanceFloor(null, proof()), proof({ ledgerSeq: 11, signerKeySha256: sha(9) })), errorCode('release-floor-signer-epoch-mismatch'))],
    ['safe-integer', 'Number.isSafeInteger(value) && value > 0', 'Number.isInteger(value) && value > 0', m => assert.throws(() => m.advanceFloor(null, proof({ ledgerSeq: Number.MAX_SAFE_INTEGER + 1 })), errorCode('release-floor-ordering-evidence'))],
    ['legacy-migration-binding', 'verified.appliedAt !== old.applied_at', 'false', m => assert.throws(() => m.migrateClockFloor(clock(), proof({ appliedAt: '2026-10-04T00:00:00.001Z' })), errorCode('release-floor-migration-proof'))],
    ['read-ancestor-protection', "metadata.uid !== 0 || (metadata.mode & 0o022) !== 0", 'false', m => { const w = memory(m.advanceFloor(null, proof())); w.nodes.get('/etc').uid = 501; w.run(() => assert.throws(() => m.readFloor(FILE, { requireRoot: true }), errorCode('release-floor-protection'))) }],
    ['read-no-follow', 'fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW', 'fs.constants.O_RDONLY', m => { const w = memory(m.advanceFloor(null, proof()), { linkAtOpen: true }); w.run(() => assert.throws(() => m.readFloor(FILE, { requireRoot: true }), { code: 'ELOOP' })) }],
    ['opened-identity', 'opened.ino !== before.ino', 'false', m => { const w = memory(m.advanceFloor(null, proof()), { changedIdentity: true }); w.run(() => assert.throws(() => m.readFloor(FILE, { requireRoot: true }), errorCode('release-floor-open-identity'))) }],
    ['locked-current-order', 'current !== null && compare(current, floorApproval(floor)) <= 0', 'false', m => { const initial = m.advanceFloor(null, proof()), stale = m.advanceFloor(initial, proof({ ledgerSeq: 12 })), winner = m.advanceFloor(initial, proof({ ledgerSeq: 13 })); const w = memory(initial, { afterLock: ({ set }) => set(FILE, winner) }); w.run(() => assert.throws(() => m.writeFloor(FILE, stale), errorCode('release-floor-not-newer'))) }],
    ['exclusive-lock', 'fs.openSync(lock, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW', 'fs.openSync(lock, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_NOFOLLOW', m => { const initial = m.advanceFloor(null, proof()), next = m.advanceFloor(initial, proof({ ledgerSeq: 11 })), w = memory(initial, { existingLock: 'unknown-token' }); w.run(() => assert.throws(() => m.writeFloor(FILE, next), errorCode('release-floor-locked'))) }],
    ['lock-token', "fs.readFileSync(fd).toString('utf8') !== token", 'false', m => { const initial = m.advanceFloor(null, proof()), next = m.advanceFloor(initial, proof({ ledgerSeq: 11 })), w = memory(initial, { tamperLock: true }); w.run(() => assert.throws(() => m.writeFloor(FILE, next), errorCode('release-floor-lock-identity'))) }],
    ['temporary-sync', 'fs.fsyncSync(fd)', 'void fd', m => { const initial = m.advanceFloor(null, proof()), w = memory(initial); w.run(() => m.writeFloor(FILE, m.advanceFloor(initial, proof({ ledgerSeq: 11 })))); const rename = w.events.findIndex(([event]) => event === 'rename'); assert.ok(w.events.slice(0, rename).some(([event, file]) => event === 'sync' && file.includes('.release-floor.tmp-'))) }],
    ['directory-sync', 'fs.fsyncSync(directoryFd)', 'void directoryFd', m => { const initial = m.advanceFloor(null, proof()), w = memory(initial); w.run(() => m.writeFloor(FILE, m.advanceFloor(initial, proof({ ledgerSeq: 11 })))); const rename = w.events.findIndex(([event]) => event === 'rename'); assert.ok(w.events.slice(rename + 1).some(([event, file]) => event === 'sync' && file === '/etc/aukora-approvals')) }],
  ]
  for (const [name, before, after, exercise] of mutations) await t.test(name, async () => {
    assert.equal(source.split(before).length - 1, name === 'read-no-follow' ? 2 : 1, 'exact named source guard removal')
    const mutant = await load(source.replaceAll(before, after) + '\n// guard mutant ' + name)
    assert.throws(() => exercise(mutant), assert.AssertionError, `guard mutant ${name} survived`)
  })
})
test.after(() => console.log('SOURCE_ONLY; SYNTHETIC_ORDERING_AND_ROOT_METADATA; NO_INSTALL_OR_RUNTIME_QUALIFICATION'))
