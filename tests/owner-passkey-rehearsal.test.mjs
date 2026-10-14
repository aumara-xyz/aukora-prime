// SPDX-License-Identifier: AGPL-3.0-or-later
// Synthetic protected-file reads exercise the gate marker; no installed node changes.
import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import { createPasskeyOwnerHandler, readRehearsalMarker } from '../packages/boundary-gate/src/owner-page.mjs'

const file = '/etc/aukora-boundary-gate/rehearsal.json'
const value = { version: 1, kind: 'aukora-passkey-rehearsal/v1' }
const sourceUrl = new URL('../packages/boundary-gate/src/owner-page.mjs', import.meta.url)
const meta = '<meta name="aukora-node-mode" content="rehearsal">'
const origin = 'https://owner.example.test', bearer = 'synthetic-rehearsal-bearer'
function info(directory, fields = {}) {
  return { uid: 0, mode: directory ? 0o755 : 0o644, nlink: 1, size: 0, ino: 1, dev: 1,
    isSymbolicLink: () => false, isDirectory: () => directory, isFile: () => !directory, ...fields }
}
async function custody(run, options = {}) {
  const bytes = Buffer.from(options.raw ?? JSON.stringify(options.value ?? value))
  const closed = [], methods = ['lstatSync', 'openSync', 'fstatSync', 'readSync', 'closeSync']
  const originals = Object.fromEntries(methods.map(name => [name, fs[name]]))
  Object.assign(fs, {
    lstatSync(path) {
      if (path !== file) return info(true, options.parent ?? {})
      if (options.absent) throw Object.assign(new Error('not present'), { code: 'ENOENT' })
      return info(false, { size: bytes.length, ...options.file })
    },
    openSync(path, flags) {
      assert.equal(path, file)
      assert.ok(flags & fs.constants.O_NOFOLLOW)
      return 99
    },
    fstatSync: () => info(false, { size: bytes.length, ...options.file, ...options.opened }),
    readSync(fd, buffer) { assert.equal(fd, 99); bytes.copy(buffer); return options.length ?? bytes.length },
    closeSync(fd) { closed.push(fd) },
  })
  try { return await run() } finally { Object.assign(fs, originals) }
}
async function page(factory, path = '/owner/enroll') {
  const gate = { owner: { bearer, bearer_expires: 2000 }, now: () => 1000, ownerOps: { pending: () => ({ pending: [] }) }, ownerBrowser: {} }
  const { handler } = factory(gate, { origin, rpId: new URL(origin).hostname,
    appOrigin: 'https://app.example.test', node: 'a'.repeat(64), gateId: 'b'.repeat(64) })
  const req = { method: 'GET', url: path, headers: { host: new URL(origin).host,
    'sec-fetch-site': 'none', 'sec-fetch-mode': 'navigate', 'sec-fetch-dest': 'document' } }
  const res = { writeHead(status) { this.status = status }, end(body) { this.body = body } }
  await handler(req, res)
  return res
}
const refusals = [
  ['foreign parent', { parent: { uid: 501 } }],
  ['writable parent', { parent: { mode: 0o777 } }],
  ['symlink parent', { parent: { isSymbolicLink: () => true } }],
  ['foreign marker', { file: { uid: 501 } }],
  ['writable marker', { file: { mode: 0o666 } }],
  ['symlink marker', { file: { isSymbolicLink: () => true } }],
  ['directory marker', { file: { isFile: () => false } }],
  ['hardlink marker', { file: { nlink: 2 } }],
  ['changed marker', { opened: { ino: 2 } }],
  ['partial read', { length: 0 }],
  ['invalid JSON', { raw: '{' }],
  ['wrong version', { value: { ...value, version: 2 } }],
  ['wrong kind', { value: { ...value, kind: 'ordinary-node' } }],
  ['extra field', { value: { ...value, approved: true } }],
]
test('only a protected root marker advertises rehearsal on the enrollment page', async () => {
  await custody(async () => {
    assert.equal(readRehearsalMarker(), true)
    const enrollment = await page(createPasskeyOwnerHandler)
    assert.equal(enrollment.status, 200); assert.ok(enrollment.body.includes(meta))
    for (const path of ['/owner/signin', '/owner/cards?bearer=' + bearer]) {
      const other = await page(createPasskeyOwnerHandler, path)
      assert.equal(other.status, 200); assert.ok(!other.body.includes(meta))
    }
  })
  await custody(async () => {
    assert.equal(readRehearsalMarker(), false)
    const result = await page(createPasskeyOwnerHandler)
    assert.equal(result.status, 200); assert.ok(!result.body.includes(meta))
  }, { absent: true })
  for (const [, options] of refusals) await custody(async () => {
    assert.throws(readRehearsalMarker, /OWNER_PASSKEY_REHEARSAL_MARKER_REFUSED/)
    const result = await page(createPasskeyOwnerHandler)
    assert.equal(result.status, 403); assert.ok(!result.body.includes(meta))
  }, options)
})
test('removing rehearsal checks fails the marker regressions', async () => {
  const source = fs.readFileSync(sourceUrl, 'utf8').replace(/from '(\.\/[^']+)'/g, (_, relative) => `from '${new URL(relative, sourceUrl).href}'`)
  const mutations = [
    ["value = readProtectedJson('/etc/aukora-boundary-gate/rehearsal.json')", 'value = ' + JSON.stringify(value), { parent: { uid: 501 } }, 'reader'],
    ["if (error.code === 'ENOENT') return false", "if (error.code === 'ENOENT') return true", { absent: true }, 'absent'],
    ['Object.keys(value).length !== 2', 'false', { value: { ...value, approved: true } }, 'shape'],
    ['value.version !== 1', 'false', { value: { ...value, version: 2 } }, 'version'],
    ["value.kind !== 'aukora-passkey-rehearsal/v1'", 'false', { value: { ...value, kind: 'ordinary-node' } }, 'kind'],
    ["mode === 'enroll' && readRehearsalMarker()", "mode === 'enroll'", { absent: true }, 'page'],
    ["mode === 'enroll' && readRehearsalMarker()", 'readRehearsalMarker()', {}, 'scope'],
  ]
  for (const [before, after, options, label] of mutations) {
    assert.equal(source.split(before).length, 2, label)
    const mutant = await import('data:text/javascript;base64,' + Buffer.from(source.replace(before, after)).toString('base64'))
    await custody(async () => {
      await assert.rejects(async () => {
        if (label === 'scope') assert.ok(!(await page(mutant.createPasskeyOwnerHandler, '/owner/signin')).body.includes(meta))
        else if (label === 'page') assert.ok(!(await page(mutant.createPasskeyOwnerHandler)).body.includes(meta))
        else if (label === 'absent') assert.equal(mutant.readRehearsalMarker(), false)
        else assert.throws(mutant.readRehearsalMarker, /OWNER_PASSKEY_REHEARSAL_MARKER_REFUSED/)
      }, assert.AssertionError, label)
    }, options)
  }
  console.log('SOURCE-ONLY rehearsal marker page mutations: 7/7 killed')
})
