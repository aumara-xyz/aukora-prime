// Refused scratch opens close descriptors before control returns.
import assert from 'node:assert/strict'
import { createRequire, syncBuiltinESMExports } from 'node:module'
import { join } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'

const fs = createRequire(import.meta.url)('node:fs')
const ROOT = fs.realpathSync(fileURLToPath(new URL('..', import.meta.url)))
const probeFile = join(ROOT, 'scripts/kira/release-recall-probe.mjs')
const source = fs.readFileSync(probeFile, 'utf8')
const previousMask = process.umask(0o002)
const work = fs.mkdtempSync(join(ROOT, 'tests/.recall-descriptors-'))
let sequence = 0, passed = 0, killed = 0

function refusedOpen(module, { descriptorPaths = false, during = 'final-check', acquire = false } = {}) {
  const original = { openSync: fs.openSync, closeSync: fs.closeSync, fstatSync: fs.fstatSync,
    ftruncateSync: fs.ftruncateSync, renameSync: fs.renameSync, mkdirSync: fs.mkdirSync, chdir: process.chdir }
  const scratch = join(work, `scratch-${sequence++}`), moved = `${scratch}-moved`, initialCwd = process.cwd()
  original.mkdirSync(scratch, { mode: 0o700 })
  original.mkdirSync(join(scratch, 'inner'), { mode: 0o700 })
  const descriptors = new Set()
  let held, restore, armed = false, swapped = false
  const swap = () => {
    assert.equal(swapped, false)
    swapped = true
    original.renameSync(scratch, moved)
    original.mkdirSync(scratch, { mode: 0o700 })
  }
  const openCount = () => [...descriptors].filter(fd => {
    try { original.fstatSync(fd); return true } catch (error) { if (error.code === 'EBADF') return false; throw error }
  }).length
  fs.openSync = (path, ...args) => {
    const fd = original.openSync(path, ...args)
    descriptors.add(fd)
    if (acquire && path === scratch || during === 'post-open' && String(path).endsWith('/candidate')) swap()
    return fd
  }
  fs.ftruncateSync = (fd, ...args) => {
    const result = original.ftruncateSync(fd, ...args)
    if (during === 'parent-close') armed = true
    else swap()
    return result
  }
  process.chdir = path => {
    if (armed && path === scratch) { armed = false; swap() }
    return original.chdir(path)
  }
  syncBuiltinESMExports()
  try {
    if (!acquire) {
      held = fs.openSync(scratch, fs.constants.O_RDONLY | fs.constants.O_DIRECTORY | fs.constants.O_NOFOLLOW)
      restore = module.bindScratchIO(scratch, held, { descriptorPaths })
    }
    const before = openCount()
    assert.throws(() => acquire ? module.acquireScratch(scratch, join(work, 'real-state'), { cleanup: true })
      : fs.openSync(join(scratch, 'inner/candidate'), 'w', 0o600), error => error.code === 'kira.release-probe:scratch-replaced')
    const after = openCount()
    assert.equal(swapped, true)
    assert.equal(after, before, `refused open descriptor count: before ${before}, after ${after}`)
  } finally {
    try { restore?.() } finally {
      process.chdir = original.chdir
      original.chdir(initialCwd)
      Object.assign(fs, { openSync: original.openSync, ftruncateSync: original.ftruncateSync })
      syncBuiltinESMExports()
      for (const fd of descriptors) { try { original.closeSync(fd) } catch (error) { if (error.code !== 'EBADF') throw error } }
    }
  }
}

try {
  const probe = await import(pathToFileURL(probeFile).href)
  const cases = [
    ['final scratch check', { descriptorPaths: false }],
    ['parent close refusal', { descriptorPaths: false, during: 'parent-close' }],
    ['post-open check', { descriptorPaths: false, during: 'post-open' }],
    ['scratch acquisition refusal', { acquire: true }],
    ...(process.platform === 'linux' ? [['descriptor-path final scratch check', { descriptorPaths: true }]] : []),
  ]
  for (const [name, options] of cases) { refusedOpen(probe, options); passed++; console.log(`PASS ${name}: descriptor count unchanged`) }
  const target = 'if (!accepted && opened !== undefined) fs.closeSync(opened)'
  assert.equal(source.split(target).length, 2, 'close-on-refusal mutation target missing or repeated')
  const mutantFile = join(work, 'close-refusal-mutant.mjs')
  fs.writeFileSync(mutantFile, source.replace(target, 'void 0')
    .replace("'../lib/is-main.mjs'", JSON.stringify(pathToFileURL(join(ROOT, 'scripts/lib/is-main.mjs')).href)), { mode: 0o600 })
  const mutant = await import(pathToFileURL(mutantFile).href)
  for (const options of [{ descriptorPaths: false }, { descriptorPaths: false, during: 'parent-close' }]) {
    assert.throws(() => refusedOpen(mutant, options), error => error.code === 'ERR_ASSERTION' && /refused open descriptor count/u.test(error.message))
    killed++
  }
  console.log(`kira-release-recall-descriptors-test: ${passed} passed, 0 failed; ${killed} close-on-refusal mutants killed`)
} finally {
  fs.rmSync(work, { recursive: true, force: true })
  process.umask(previousMask)
}
