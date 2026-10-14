// SPDX-License-Identifier: AGPL-3.0-or-later
// Requires exclusive record and machine-seed writes and their cleanup to reach directory fsync.
import assert from 'node:assert/strict'
import { existsSync, mkdtempSync, readFileSync, renameSync, rmSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'

const root = fileURLToPath(new URL('../', import.meta.url))
const sourcePath = join(root, 'plugins/aukora-aumlok/lib/record-v3.mjs')
const source = readFileSync(sourcePath, 'utf8')
const hookName = Symbol.for('aumlok.browser.record-durability')
const scratch = mkdtempSync(join(root, '.aumlok-browser-record-'))
const machine = { machineIndex: 0, ed25519SeedHex: '11'.repeat(32), ed25519PublicKeyHex: '22'.repeat(32) }
const writers = [
  { name: 'record', file: 'local-control.json', write: (module, directory) =>
    module.writeRecordV3({ record: { version: 3, publicRoot: {} }, directory, exclusive: true }) },
  { name: 'machine seed', file: 'machine-seed-v3.json', write: (module, directory) =>
    module.keepMachineSeed(machine, { directory, exclusive: true }) },
]

function moduleUrl(text) {
  const imports = text.replace(/from '([^']+)'/gu, (all, name) => name.startsWith('.')
    ? `from ${JSON.stringify(new URL(name, pathToFileURL(sourcePath)).href)}` : all)
    .replace(/import \{([^}]+)\} from 'node:fs'/u, (all, names) => `import {${names.replace(
      /\b(closeSync|fsyncSync|openSync|unlinkSync|writeSync)\b/gu, name => `${name} as actual_${name}`,
    )}} from 'node:fs'`)
  const wrappers = `
const openSync = (...args) => { const fd = actual_openSync(...args); globalThis[Symbol.for('aumlok.browser.record-durability')]?.open(fd, args[0]); return fd }
const closeSync = fd => { try { return actual_closeSync(fd) } finally { globalThis[Symbol.for('aumlok.browser.record-durability')]?.close(fd) } }
const fsyncSync = fd => globalThis[Symbol.for('aumlok.browser.record-durability')]?.sync(fd, () => actual_fsyncSync(fd)) ?? actual_fsyncSync(fd)
const writeSync = (...args) => globalThis[Symbol.for('aumlok.browser.record-durability')]?.write(args, () => actual_writeSync(...args)) ?? actual_writeSync(...args)
const unlinkSync = path => { actual_unlinkSync(path); globalThis[Symbol.for('aumlok.browser.record-durability')]?.unlink(path) }
`
  return `data:text/javascript;base64,${Buffer.from(`${imports}\n${wrappers}`).toString('base64')}`
}

async function verify(text) {
  const module = await import(moduleUrl(text))
  let passed = 0
  for (const writer of writers) {
    for (const failure of [null, 'write', 'file fsync', 'directory fsync', 'replacement']) {
      const directory = mkdtempSync(join(scratch, 'case-'))
      const path = join(directory, writer.file)
      const descriptors = new Map(), events = []
      let injected = false
      function inject() {
        injected = true
        if (failure === 'replacement') {
          renameSync(path, `${path}.owned`)
          writeFileSync(path, 'replacement', { mode: 0o600 })
        }
        const cause = new Error('injected custody I/O failure')
        cause.code = 'EIO'
        throw cause
      }
      globalThis[hookName] = {
        open(fd, opened) { descriptors.set(fd, opened) },
        close(fd) { descriptors.delete(fd) },
        sync(fd, actual) {
          const opened = descriptors.get(fd)
          events.push(opened === path ? 'file fsync' : 'directory fsync')
          if (!injected && ((failure === 'file fsync' || failure === 'replacement') && opened === path
            || failure === 'directory fsync' && opened === directory)) inject()
          actual()
          return true
        },
        write(args, actual) {
          if (failure === 'write' && !injected) {
            actual()
            inject()
          }
          return actual()
        },
        unlink(removed) { assert.equal(removed, path); events.push('unlink') },
      }
      try {
        if (failure === null) {
          writer.write(module, directory)
          assert.deepEqual(events, ['file fsync', 'directory fsync'], `${writer.name}: write durability order`)
          assert.equal(existsSync(path), true)
        } else {
          assert.throws(() => writer.write(module, directory), /injected custody I\/O failure/u,
            `${writer.name}: ${failure} must propagate`)
          if (failure === 'replacement') {
            assert.equal(existsSync(path), true, `${writer.name}: preserve another inode`)
            assert.equal(readFileSync(path, 'utf8'), 'replacement', `${writer.name}: preserve another inode`)
            assert.equal(events.includes('unlink'), false)
          } else {
            assert.equal(existsSync(path), false, `${writer.name}: remove an incomplete exclusive file`)
            assert.deepEqual(events.slice(-2), ['unlink', 'directory fsync'], `${writer.name}: durable cleanup`)
          }
        }
        assert.equal(descriptors.size, 0, `${writer.name}: descriptors close`)
        passed += 1
      } finally {
        delete globalThis[hookName]
        rmSync(directory, { recursive: true, force: true })
      }
    }
    const directory = mkdtempSync(join(scratch, 'rollback-'))
    try {
      const written = writer.write(module, directory)
      const path = join(directory, writer.file)
      assert.throws(() => writer.write(module, directory), { code: 'EEXIST' })
      assert.equal(existsSync(path), true, `${writer.name}: preserve the first exclusive file`)
      if (writer.name === 'record') assert.equal(module.removeIfCreated(path, written.created), true)
      passed += 1
    } finally { rmSync(directory, { recursive: true, force: true }) }
  }
  return passed
}

try {
  const passed = await verify(source)
  console.log(`aumlok browser record durability: ${passed} PASS, 0 FAIL`)
  const mutations = [
    ['file fsync removed', '    fsyncSync(descriptor)\n', ''],
    ['directory fsync removed', 'try { fsyncSync(directoryDescriptor) }', 'try { /* mutation */ }'],
    ['cleanup directory fsync removed', '    unlinkSync(path)\n    syncCustodyDirectory(path)\n', '    unlinkSync(path)\n'],
    ['failed exclusive file retained', '    if (created !== undefined) removeIfCreated(path, created)\n', ''],
    ['inode ownership check removed', '    if (!now.isFile() || now.dev !== created?.dev || now.ino !== created?.ino) return false\n', ''],
  ]
  for (const [name, before, after] of mutations) {
    assert.equal(source.split(before).length, 2, `${name}: mutation target must occur once`)
    await assert.rejects(() => verify(source.replace(before, after)), { name: 'AssertionError' }, `${name}: survived`)
    console.log(`aumlok browser record durability mutation: KILLED ${name}`)
  }
} finally {
  delete globalThis[hookName]
  rmSync(scratch, { recursive: true, force: true })
}
