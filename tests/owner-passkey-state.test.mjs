// SPDX-License-Identifier: AGPL-3.0-or-later
// Synthetic protected setup and claim filesystem checks write no installed path.
import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'
import { createHash } from 'node:crypto'
import { createGate } from '../packages/boundary-gate/src/gate.mjs'
import { fixture } from './owner-passkey-gate.test.mjs'

const sourceUrl = new URL('../packages/boundary-gate/src/owner-state.mjs', import.meta.url)
const source = fs.readFileSync(sourceUrl, 'utf8')
const load = text => import('data:text/javascript;base64,' + Buffer.from(text.replace(/from '([^']+)'/gu,
  (statement, specifier) => specifier.startsWith('.') ? statement.replace(specifier, new URL(specifier, sourceUrl).href) : statement)).toString('base64'))
const module = await load(source), FILE = '/etc/aukora-boundary-gate/passkey-setup.json', CLAIM = '/root/claim.txt'
const hash = bytes => createHash('sha256').update(bytes).digest('hex')
const code = value => Object.assign(new Error(value), { code: value })
const setup = { version: 1, kind: 'aukora-gate-passkey-setup/v1', gate: hash('synthetic gate'), node: hash('synthetic C1'),
  rp_id: 'owner.example', origin: 'https://owner.example', claim_sha256: hash('synthetic one-use claim'), expires_at_ms: 1791072300000,
  binding: { identity: { owner_id: 'synthetic owner', subject: 'aukora:1:' + hash('synthetic final subject'),
    authorization_epoch: 1 }, passkey_profile: { profile: 'https', origin: 'https://owner.example', rp_id: 'owner.example' },
    existing_credential_ids: [] } }
const copy = value => JSON.parse(JSON.stringify(value))

function world({ present = true, uid = 0, statError, opened } = {}) {
  const nodes = new Map(), handles = new Map(), events = []; let inode = 0, fd = 100
  const node = (type, bytes = '') => ({ type, bytes: Buffer.from(bytes), uid: 0, mode: type === 'directory' ? 0o755 : 0o640,
    nlink: 1, ino: ++inode, dev: 1, symlink: false })
  for (const file of ['/', '/etc', '/etc/aukora-boundary-gate', '/root']) nodes.set(file, node('directory'))
  const put = (file, value) => nodes.set(file, node('file', typeof value === 'string' ? value : JSON.stringify(value)))
  if (present) put(FILE, setup)
  const get = file => { if (!nodes.has(file)) throw code('ENOENT'); return nodes.get(file) }
  const metadata = n => ({ ...n, size: n.bytes.length, isFile: () => n.type === 'file',
    isDirectory: () => n.type === 'directory', isSymbolicLink: () => n.symlink })
  const fixture = {
    lstatSync(file) { events.push(['stat', file]); if (statError) throw code(statError); return metadata(get(file)) },
    openSync(file, flags, mode) {
      events.push(['open', file, flags, mode])
      const writing = typeof flags === 'number' && (flags & fs.constants.O_CREAT)
      if (writing) {
        if ((flags & fs.constants.O_EXCL) && nodes.has(file)) throw code('EEXIST')
        if ((flags & fs.constants.O_NOFOLLOW) && nodes.get(file)?.symlink) throw code('ELOOP')
        nodes.set(file, { ...node('file'), mode }); events.push(['create', file])
      }
      const n = get(file), handle = ++fd; handles.set(handle, { n, file }); return handle
    },
    fstatSync(handle) { return { ...metadata(handles.get(handle).n), ...opened } },
    readSync(handle, buffer, offset, length, position) {
      assert.equal(position, 0); events.push(['read', handles.get(handle).file, length])
      return handles.get(handle).n.bytes.copy(buffer, offset, 0, length)
    },
    fchmodSync(handle, mode) { handles.get(handle).n.mode = mode; events.push(['mode', handles.get(handle).file, mode]) },
    writeFileSync(handle, bytes) { handles.get(handle).n.bytes = Buffer.from(bytes); events.push(['write', handles.get(handle).file]) },
    fsyncSync(handle) { events.push(['sync', handles.get(handle).file]) },
    closeSync(handle) { handles.delete(handle) },
  }
  function run(action) {
    const prior = Object.fromEntries(Object.keys(fixture).map(name => [name, fs[name]])), getuid = process.getuid
    Object.assign(fs, fixture); process.getuid = () => uid
    try { return action() }
    finally { Object.assign(fs, prior); process.getuid = getuid; assert.equal(handles.size, 0, 'all descriptors close') }
  }
  return { nodes, events, put, run }
}
function mint(m, w, options = {}) {
  return w.run(() => m.mintPasskeyClaim({ file: FILE, claimFile: CLAIM, gate: setup.gate, node: setup.node,
    origin: setup.origin, binding: setup.binding, nowMs: 1791072000000, ...options }))
}
function rejectsSetup(m, change) {
  const bad = copy(setup); change(bad)
  assert.throws(() => m.passkeySetup(bad))
}
function rejectsReader(m, options) {
  const w = world(options)
  w.run(() => assert.throws(() => m.passkeySetupReader(FILE)))
}
function rereads(m) {
  const w = world()
  w.run(() => {
    const reader = m.passkeySetupReader(FILE)
    assert.equal(reader().origin, 'https://owner.example')
    const changed = copy(setup); changed.origin = 'https://second.example'; changed.rp_id = 'second.example'
    changed.binding.passkey_profile = { profile: 'https', origin: changed.origin, rp_id: changed.rp_id }
    w.put(FILE, changed); assert.equal(reader().origin, changed.origin)
    w.nodes.delete(FILE); assert.throws(reader, { code: 'ENOENT' })
  })
}
function noWrites(w) { assert.equal(w.events.filter(([name]) => name === 'create' || name === 'write').length, 0) }

test('protected setup reader selects an absolute path, validates protection immediately and rereads current bytes', () => {
  assert.throws(() => module.passkeySetupReader('relative.json'), { code: 'passkey-setup-path' })
  rejectsReader(module, { statError: 'EACCES' })
  rejectsReader(module, { opened: { uid: 501 } })
  const w = world(); w.nodes.get('/etc').mode = 0o777
  w.run(() => assert.throws(() => module.passkeySetupReader(FILE), { code: 'owner-state-unprotected' }))
  rereads(module)
})
test('setup binds exact fields, HTTPS origin/RP, node, gate, claim, final subject and positive epoch', () => {
  assert.equal(module.passkeySetup(copy(setup)).binding.identity.subject, setup.binding.identity.subject)
  for (const change of [s => { s.extra = true }, s => { delete s.node }, s => { s.node = 'C1' }, s => { s.gate = 'short' },
    s => { s.claim_sha256 = 'short' }, s => { s.expires_at_ms = 1.5 }, s => { s.expires_at_ms = 0 },
    s => { s.origin = 'http://owner.example'; s.binding.passkey_profile.origin = s.origin },
    s => { s.origin += '/path'; s.binding.passkey_profile.origin = s.origin },
    s => { s.rp_id = 'example'; s.binding.passkey_profile.rp_id = s.rp_id },
    s => { s.binding.identity.subject = 'aukora:1:' + hash('owner') + 'extra' },
    s => { s.binding.identity.authorization_epoch = 0 }, s => { s.binding.identity.authorization_epoch = 1.5 },
    s => { s.binding.identity.authorization_epoch = '1' }, s => { s.binding.existing_credential_ids = { length: 0 } }, s => { s.binding.existing_credential_ids.push('known') },
    s => { s.binding.passkey_profile.origin = 'https://other.example' }, s => { s.binding.passkey_profile.rp_id = 'other.example' },
    s => { s.binding.passkey_profile.profile = 'localhost-pilot-v1' }]) rejectsSetup(module, change)
})
test('only root mints a claim; same path, unprotected parents and collisions create no setup', () => {
  const user = world({ present: false, uid: 501 })
  assert.throws(() => mint(module, user), { code: 'passkey-claim-root-required' }); noWrites(user)
  const same = world({ present: false })
  assert.throws(() => mint(module, same, { claimFile: FILE }), { code: 'passkey-setup-path' }); noWrites(same)
  const unsafe = world({ present: false }); unsafe.nodes.get('/root').mode = 0o777
  assert.throws(() => mint(module, unsafe), { code: 'owner-state-unprotected' }); noWrites(unsafe)
  const collision = world({ present: false }); collision.put(FILE, 'existing setup')
  assert.throws(() => mint(module, collision), { code: 'EEXIST' }); assert.equal(collision.nodes.has(CLAIM), false)
  assert.equal(collision.nodes.get(FILE).bytes.toString(), 'existing setup')
})
test('mint returns the secret once and persists only its digest in an exclusive synced setup', () => {
  const w = world({ present: false }), result = mint(module, w), claim = result.claim
  const selected = JSON.parse(w.nodes.get(FILE).bytes.toString())
  assert.match(claim, /^[A-Za-z0-9_-]{43}$/u)
  assert.deepEqual(result, { minted: true, expires_at_ms: 1791072300000, claim })
  assert.equal(selected.claim_sha256, hash(claim)); assert.equal(w.nodes.get(FILE).mode, 0o640)
  assert.equal(w.nodes.has(CLAIM), false)
  assert.ok([...w.nodes.values()].every(node => !node.bytes.toString().includes(claim)))
  assert.throws(() => mint(module, w), { code: 'EEXIST' })
  const entry = w.events.find(([event, target]) => event === 'open' && target === FILE)
  assert.ok((entry[2] & fs.constants.O_EXCL) && (entry[2] & fs.constants.O_NOFOLLOW))
  assert.deepEqual(w.events.filter(([event]) => event === 'sync'), [['sync', FILE], ['sync', '/etc/aukora-boundary-gate']])
})

test('the minted digest verifies through real enrollment; use, expiry and restart retain no raw code', t => {
  for (const finish of [true, false]) {
    let result, storage
    const f = fixture(t, options => {
      const selected = options.readPasskeySetup()
      if (!result) {
        storage = world({ present: false })
        result = mint(module, storage, { gate: selected.gate, node: selected.node, origin: selected.origin,
          binding: selected.binding, nowMs: selected.expires_at_ms - 300000 })
        selected.claim_sha256 = hash(result.claim)
      }
      return createGate(options)
    })
    f.claim = result.claim
    const noRaw = () => {
      assert.equal(storage.nodes.has(CLAIM), false)
      assert.ok([...storage.nodes.values()].every(node => !node.bytes.toString().includes(f.claim)))
      assert.ok(!fs.readFileSync(path.join(f.home, 'gate.db')).includes(Buffer.from(f.claim)))
    }
    noRaw()
    if (finish) assert.equal(f.enroll().enrolled, true)
    else { f.clock = f.setup.expires_at_ms; assert.throws(() => f.enroll(), /claim-expired/) }
    noRaw(); f.restart(); noRaw()
    assert.throws(() => f.enroll(), finish ? /enrollment-closed/ : /claim-expired/)
  }
})

test('new setup and mint guard mutations fail their focused checks', async t => {
  const mutations = [
    ['reader-path', "if (!path.isAbsolute(file)) throw refuse('passkey-setup-path')", '', m => {
      const w = world(), dirname = path.dirname
      path.dirname = file => file === 'relative.json' ? '/' : dirname(file)
      try { w.run(() => assert.throws(() => m.passkeySetupReader('relative.json'), { code: 'passkey-setup-path' })) }
      finally { path.dirname = dirname }
    }],
    ['initial-protected-read', '  read()\n  return read', '  return read', m => rejectsReader(m, { statError: 'EACCES' })],
    ['current-read', '  return read\n}', '  const saved = read(); return () => saved\n}', rereads],
    ['exact-setup-shape', 'Object.keys(supplied).length !== fields.length', 'false', m => rejectsSetup(m, s => { s.extra = true })],
    ['claim-digest-shape', "!['gate', 'node', 'claim_sha256'].every(k => typeof s[k] === 'string' && /^[0-9a-f]{64}$/u.test(s[k]))", 'false', m => rejectsSetup(m, s => { s.claim_sha256 = 'short' })],
    ['setup-expiry-integer', '!Number.isSafeInteger(s.expires_at_ms)', 'false', m => rejectsSetup(m, s => { s.expires_at_ms = 1.5 })],
    ['setup-https', "url.protocol !== 'https:'", 'false', m => rejectsSetup(m, s => { s.origin = 'http://owner.example'; s.binding.passkey_profile.origin = s.origin })],
    ['exact-origin', 'url.origin !== s.origin', 'false', m => rejectsSetup(m, s => { s.origin += '/path'; s.binding.passkey_profile.origin = s.origin })],
    ['exact-rp', 'url.hostname !== s.rp_id', 'false', m => rejectsSetup(m, s => { s.rp_id = 'example'; s.binding.passkey_profile.rp_id = s.rp_id })],
    ['credential-inventory-array', '!Array.isArray(s.binding.existing_credential_ids)', 'false', m => rejectsSetup(m, s => { s.binding.existing_credential_ids = { length: 0 } })],
    ['closed-enrollment', 's.binding.existing_credential_ids.length !== 0', 'false', m => rejectsSetup(m, s => { s.binding.existing_credential_ids.push('known') })],
    ['binding-profile', "s.binding?.passkey_profile?.profile !== 'https'", 'false', m => rejectsSetup(m, s => { s.binding.passkey_profile.profile = 'localhost-pilot-v1' })],
    ['binding-origin', 's.binding.passkey_profile.origin !== s.origin', 'false', m => rejectsSetup(m, s => { s.binding.passkey_profile.origin = 'https://other.example' })],
    ['binding-rp', 's.binding.passkey_profile.rp_id !== s.rp_id', 'false', m => rejectsSetup(m, s => { s.binding.passkey_profile.rp_id = 'other.example' })],
    ['safe-final-epoch', '!Number.isSafeInteger(s.binding?.identity?.authorization_epoch)', 'false', m => rejectsSetup(m, s => { s.binding.identity.authorization_epoch = 1.5 })],
    ['positive-final-epoch', 's.binding.identity.authorization_epoch < 1', 'false', m => rejectsSetup(m, s => { s.binding.identity.authorization_epoch = 0 })],
    ['final-subject', '!/^aukora:1:[0-9a-f]{64}$/u.test(s.binding.identity.subject)', 'false', m => rejectsSetup(m, s => { s.binding.identity.subject = 'wrong'.padEnd(73, 'x') })],
    ['root-mint', 'process.getuid?.() !== 0', 'false', m => {
      const w = world({ present: false, uid: 501 }); assert.throws(() => mint(m, w), { code: 'passkey-claim-root-required' })
    }],
    ['distinct-output-paths', 'file === claimFile', 'false', m => {
      const w = world({ present: false }); assert.throws(() => mint(m, w, { claimFile: FILE }), { code: 'passkey-setup-path' }); noWrites(w)
    }],
    ['exclusive-setup-file', ' | fs.constants.O_EXCL', '', m => {
      const w = world({ present: false }); w.put(FILE, 'existing setup'); assert.throws(() => mint(m, w), { code: 'EEXIST' })
    }],
    ['root-output-ancestors', "while (true) { protectedNode(fs.lstatSync(p), true); if (p === '/') break; p = path.dirname(p) }",
      "while (false) {}", m => {
        const w = world({ present: false }); w.nodes.get('/root').mode = 0o777
        assert.throws(() => mint(m, w), { code: 'owner-state-unprotected' })
      }],
    ['output-no-follow', 'fs.constants.O_NOFOLLOW | fs.constants.O_WRONLY', 'fs.constants.O_WRONLY', m => {
      const w = world({ present: false }); mint(m, w)
      assert.ok(w.events.filter(([event, file]) => event === 'open' && [FILE, CLAIM].includes(file))
        .every(entry => entry[2] & fs.constants.O_NOFOLLOW))
    }],
    ['file-and-parent-sync', 'fs.fsyncSync(fd)', 'void fd', m => {
      const w = world({ present: false }); mint(m, w); assert.equal(w.events.filter(([event]) => event === 'sync').length, 2)
    }],
    ['parent-directory-sync', 'fs.fsyncSync(d)', 'void d', m => {
      const w = world({ present: false }); mint(m, w); assert.equal(w.events.filter(([event]) => event === 'sync').length, 2)
    }],
    ['raw-claim-not-stored', "  write(file, JSON.stringify(setup) + '\\n', 0o640)",
      "  write(claimFile, claim + '\\n', 0o600)\n  write(file, JSON.stringify(setup) + '\\n', 0o640)", m => {
      const w = world({ present: false }); mint(m, w); assert.equal(w.nodes.has(CLAIM), false)
    }],
    ['claim-only-first-mint', ' | fs.constants.O_EXCL', '', m => {
      const w = world({ present: false }); mint(m, w); assert.throws(() => mint(m, w), { code: 'EEXIST' })
    }],
  ]
  for (const [label, before, after, exercise] of mutations) await t.test(label, async () => {
    assert.equal(source.split(before).length, 2, 'named guard preimage: ' + label)
    const mutant = await load(source.replace(before, after))
    assert.throws(() => exercise(mutant), assert.AssertionError, 'guard removal must fail: ' + label)
  })
  t.diagnostic(`SOURCE-ONLY passkey setup mutations: ${mutations.length}/${mutations.length} KILLED; 0 SURVIVED`)
})
