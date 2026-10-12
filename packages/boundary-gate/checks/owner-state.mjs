// SPDX-License-Identifier: AGPL-3.0-or-later
// Synthetic protected-file checks and guard removals; no installed paths are written.
import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import { createHash, generateKeyPairSync } from 'node:crypto'

const sourceUrl = new URL('../src/owner-state.mjs', import.meta.url)
const source = fs.readFileSync(sourceUrl, 'utf8')
const load = text => import('data:text/javascript;base64,' + Buffer.from(text.replace(
  "'../../owner-key/src/authorization.mjs'", JSON.stringify(new URL('../../owner-key/src/authorization.mjs', sourceUrl).href))).toString('base64'))
const reader = await load(source), FILE = '/etc/aukora-boundary-gate/owner-state.json'
const spki = generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).publicKey.export({ type: 'spki', format: 'der' })
const state = { version: 1, kind: 'aukora-owner-state/v1', owner_subject: 'aukora:1:' + '1'.repeat(64),
  owner_root_spki_base64: spki.toString('base64'), owner_root_id: createHash('sha256').update(spki).digest('hex'),
  owner_epoch: 1, registry_sha256: '2'.repeat(64), activation_sha256: '3'.repeat(64) }
const coded = code => Object.assign(new Error('synthetic filesystem refusal'), { code })

function memory(options = {}) {
  const nodes = new Map(), opened = new Map(), events = []; let inode = 0
  const node = (type, bytes = '') => ({ type, bytes: Buffer.from(bytes), uid: 0, mode: type === 'directory' ? 0o755 : 0o644,
    nlink: 1, ino: ++inode, dev: 1, symlink: false })
  for (const file of ['/', '/etc', '/etc/aukora-boundary-gate']) nodes.set(file, node('directory'))
  const set = value => nodes.set(FILE, node('file', Buffer.isBuffer(value) || typeof value === 'string' ? value : JSON.stringify(value)))
  set(state)
  const get = file => { if (!nodes.has(file)) throw coded('ENOENT'); return nodes.get(file) }
  const metadata = n => ({ ...n, size: n.size ?? n.bytes.length,
    isFile: () => n.type === 'file', isDirectory: () => n.type === 'directory', isSymbolicLink: () => n.symlink })
  const fixture = {
    lstatSync(file) { events.push(['stat', file]); if (options.statError) throw coded(options.statError); return metadata(get(file)) },
    openSync(file, flags) {
      events.push(['open', file, flags]); if (options.openError) throw coded(options.openError)
      if (options.linkAtOpen && (flags & fs.constants.O_NOFOLLOW)) throw coded('ELOOP')
      if (options.fifoAtOpen && !(flags & fs.constants.O_NONBLOCK)) throw coded('would-block')
      opened.set(1000, get(file)); return 1000
    },
    fstatSync(fd) {
      const result = metadata(opened.get(fd))
      if (options.fifoAtOpen) result.isFile = () => false
      return Object.assign(result, options.opened)
    },
    readSync(fd, buffer, offset, length, position) {
      assert.equal(position, 0); events.push(['read', length])
      const bytes = options.readBytes ?? opened.get(fd).bytes
      return bytes.copy(buffer, offset, 0, Math.min(bytes.length, length))
    },
    closeSync(fd) { events.push(['close']); opened.delete(fd) },
  }
  const run = callback => {
    const saved = Object.fromEntries(Object.keys(fixture).map(key => [key, fs[key]]))
    Object.assign(fs, fixture)
    try { return callback() } finally { Object.assign(fs, saved); assert.equal(opened.size, 0, 'descriptor is closed') }
  }
  return { nodes, events, run, set }
}
const read = module => module.ownerStateReader()()
function metadataRefusal(module, file, changes) {
  const w = memory(); Object.assign(w.nodes.get(file), changes)
  w.run(() => assert.throws(() => read(module), { code: 'owner-state-unprotected' }))
  assert.ok(!w.events.some(([event]) => event === 'read'), 'unprotected metadata refuses before bytes are read')
}
function readRefusal(module, options, code) {
  const w = memory(options)
  w.run(() => assert.throws(() => read(module), code ? { code } : undefined))
}
function lostState(module) {
  const w = memory()
  w.run(() => { const selected = module.ownerStateReader(); w.nodes.delete(FILE); assert.throws(selected, { code: 'ENOENT' }) })
}
function freshState(module) {
  const w = memory()
  w.run(() => {
    const selected = module.ownerStateReader(); assert.equal(selected().owner_epoch, 1)
    w.set({ ...state, owner_epoch: 2 }); assert.equal(selected().owner_epoch, 2)
  })
}

test('only an initially absent fixed state file selects legacy', () => {
  assert.equal(reader.OWNER_STATE_FILE, FILE)
  const w = memory(); w.nodes.delete(FILE)
  w.run(() => assert.equal(reader.ownerStateReader(), undefined))
  memory({ statError: 'EACCES' }).run(() => assert.throws(reader.ownerStateReader, { code: 'EACCES' }))
  const present = memory()
  present.run(() => assert.deepEqual({ ...read(reader) }, state))
})
test('root custody and non-writable ancestors prevent the gate user removing or replacing the state latch', () => {
  for (const file of ['/', '/etc', '/etc/aukora-boundary-gate', FILE]) {
    for (const changes of [{ uid: 501 }, { mode: 0o775 }, { mode: 0o757 }, { symlink: true }, { type: 'special' }])
      metadataRefusal(reader, file, changes)
  }
  metadataRefusal(reader, FILE, { nlink: 2 })
  metadataRefusal(reader, FILE, { type: 'directory' })
})
test('opened file retains protected metadata, identity, no-follow and nonblocking reads', () => {
  for (const opened of [{ uid: 501 }, { mode: 0o666 }, { nlink: 2 }, { isFile: () => false }])
    readRefusal(reader, { opened }, 'owner-state-unprotected')
  for (const opened of [{ ino: 999 }, { dev: 999 }]) readRefusal(reader, { opened }, 'owner-state-changed')
  readRefusal(reader, { linkAtOpen: true }, 'ELOOP')
  readRefusal(reader, { fifoAtOpen: true }, 'owner-state-unprotected')
})
test('reads are bounded and short or growing state bytes refuse', () => {
  metadataRefusal(reader, FILE, { size: 16385 })
  const oversized = memory(); oversized.set(JSON.stringify(state).padEnd(16385))
  oversized.run(() => assert.throws(() => read(reader), { code: 'owner-state-unprotected' }))
  readRefusal(reader, { readBytes: Buffer.from(JSON.stringify(state) + ' ') }, 'owner-state-changed')
  readRefusal(reader, { readBytes: Buffer.from('{}') }, 'owner-state-changed')
  readRefusal(reader, { opened: { size: 16384 }, readBytes: Buffer.alloc(16385, 32) }, 'owner-state-changed')
  const w = memory(); w.run(() => read(reader))
  assert.deepEqual(w.events.filter(([event]) => event === 'read'), [['read', 16385]])
})
test('malformed, unavailable and later missing state never downgrade to legacy', () => {
  for (const bad of ['{', '{}', JSON.stringify({ ...state, extra: true }), JSON.stringify({ ...state, owner_root_id: '0'.repeat(64) }), Buffer.from([0xff])]) {
    const w = memory(); w.set(bad)
    w.run(() => { const selected = reader.ownerStateReader(); assert.equal(typeof selected, 'function'); assert.throws(selected) })
  }
  readRefusal(reader, { openError: 'EACCES' }, 'EACCES')
  const utf8 = memory(); utf8.set(Buffer.from([0xff]))
  utf8.run(() => assert.throws(() => read(reader), { code: 'ERR_ENCODING_INVALID_ENCODED_DATA' }))
  lostState(reader)
})
test('each owner check rereads the protected current state', () => freshState(reader))

if (process.argv.includes('--mutations')) test('owner-state guard-removal mutants fail their focused checks', async t => {
  const mutations = [
    ['ancestor-checks', 'for (const p of parents.reverse())', 'for (const p of [])', m => metadataRefusal(m, '/etc', { uid: 501 })],
    ['root-owner', 'st.uid !== 0', 'false', m => metadataRefusal(m, FILE, { uid: 501 })],
    ['non-writable-mode', '(st.mode & 0o022)', 'false', m => metadataRefusal(m, FILE, { mode: 0o666 })],
    ['node-type', '(directory ? !st.isDirectory() : !st.isFile())', 'false', m => metadataRefusal(m, FILE, { type: 'directory' })],
    ['symlink', 'st.isSymbolicLink()', 'false', m => metadataRefusal(m, '/etc', { symlink: true })],
    ['single-link', 'st.nlink !== 1', 'false', m => metadataRefusal(m, FILE, { nlink: 2 })],
    ['initial-size', 'st.size > 16384', 'false', m => metadataRefusal(m, FILE, { size: 16385 })],
    ['size-ceiling', '16384', '16385', m => {
      const w = memory(); w.set(JSON.stringify(state).padEnd(16385))
      w.run(() => assert.throws(() => read(m), { code: 'owner-state-unprotected' }))
    }],
    ['opened-protection', 'protectedNode(opened, false)', 'void opened', m => readRefusal(m, { opened: { uid: 501 } }, 'owner-state-unprotected')],
    ['opened-inode', 'opened.ino !== before.ino', 'false', m => readRefusal(m, { opened: { ino: 999 } }, 'owner-state-changed')],
    ['opened-device', 'opened.dev !== before.dev', 'false', m => readRefusal(m, { opened: { dev: 999 } }, 'owner-state-changed')],
    ['no-follow', ' | fs.constants.O_NOFOLLOW', '', m => readRefusal(m, { linkAtOpen: true }, 'ELOOP')],
    ['nonblocking', ' | fs.constants.O_NONBLOCK', '', m => readRefusal(m, { fifoAtOpen: true }, 'owner-state-unprotected')],
    ['read-size-match', 'length !== opened.size', 'false', m => readRefusal(m, { readBytes: Buffer.from(JSON.stringify(state) + ' ') }, 'owner-state-changed')],
    ['bounded-read', 'Buffer.alloc(16385)', 'Buffer.alloc(32769)', m => {
      const w = memory(); w.run(() => read(m)); assert.deepEqual(w.events.filter(([event]) => event === 'read'), [['read', 16385]])
    }],
    ['owner-state-validation', 'return ownerAuthorizationOwnerState(', 'return (', m => {
      const w = memory(); w.set({ ...state, extra: true }); w.run(() => assert.throws(() => read(m)))
    }],
    ['utf8-decoder', '{ fatal: true }', '{ fatal: false }', m => {
      const w = memory(); w.set(Buffer.from([0xff]))
      w.run(() => assert.throws(() => read(m), { code: 'ERR_ENCODING_INVALID_ENCODED_DATA' }))
    }],
    ['only-absence-legacy', "error.code === 'ENOENT'", 'true', m => memory({ statError: 'EACCES' }).run(() => assert.throws(m.ownerStateReader, { code: 'EACCES' }))],
    ['no-loss-fallback', 'return readOwnerState', 'return () => { try { return readOwnerState() } catch { return undefined } }', lostState],
    ['reread-current-state', 'return readOwnerState', 'const retained = readOwnerState(); return () => retained', freshState],
  ]
  for (const [name, before, after, exercise] of mutations) await t.test(name, async () => {
    assert.equal(source.split(before).length - 1, name === 'size-ceiling' ? 2 : 1, 'exact named source guards')
    const mutant = await load(source.replaceAll(before, after) + '\n// mutant ' + name)
    assert.throws(() => exercise(mutant), assert.AssertionError, 'guard mutant survived: ' + name)
  })
})
