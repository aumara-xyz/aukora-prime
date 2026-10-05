// SPDX-License-Identifier: AGPL-3.0-or-later
// Scoped source/unit evidence only: production policy, real disposable regular
// FDs, and mocked directory/proc metadata + SDK matcher protocol. This does not
// qualify Linux kernel custody, a live harness, or installed containment. No
// protected-content fixture, concurrent rename, provider, or regex-engine clone.
import assert from 'node:assert/strict'
import * as fs from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import * as source from '../lib/descriptor-search.mjs'
import { createPolicy } from '../lib/policy.mjs'

const { snapshotSearchTree, readAcceptedDescriptor, createDescriptorSearch,
  LINUX_DESCRIPTOR_IO, SEARCH_BOUNDS, DescriptorSearchError } = source
const searchURL = new URL('../lib/descriptor-search.mjs', import.meta.url)
const policyURL = new URL('../lib/policy.mjs', import.meta.url)
const indexURL = new URL('../lib/index.mjs', import.meta.url)
const receiptsURL = new URL('../lib/receipts.mjs', import.meta.url)
const searchText = fs.readFileSync(searchURL, 'utf8')
const policyText = fs.readFileSync(policyURL, 'utf8')
const tests = []
const check = (name, run) => tests.push({ name, run })
const cloneStat = (st, changes) => Object.assign(Object.create(Object.getPrototypeOf(st)), st, changes)

// Every fixture is immutable once created. Mock traversal returns already-held
// descriptors; content reads always use fs.readSync on the real harmless FD.
function fixture(items = [{ name: 'alpha.txt', text: 'alpha\nbeta\n' }]) {
  const root = fs.mkdtempSync(join(tmpdir(), 'descriptor-source-check-'))
  const nodes = new Map()
  const fds = []
  const trace = []
  function hold(path) {
    const fd = fs.openSync(path, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW)
    fds.push(fd)
    const node = { fd, path, children: new Map() }
    nodes.set(path, node)
    return node
  }
  const rootNode = hold(root)
  function add(parent, item) {
    const path = join(parent.path, item.name)
    if (item.children) fs.mkdirSync(path)
    else if (item.linkTo) fs.linkSync(join(root, item.linkTo), path)
    else fs.writeFileSync(path, item.text ?? '', { flag: 'wx' })
    const node = hold(path)
    parent.children.set(item.name, node)
    for (const child of item.children ?? []) add(node, child)
  }
  try { for (const item of items) add(rootNode, item) }
  catch (error) { for (const fd of fds) fs.closeSync(fd); fs.rmSync(root, { recursive: true }); throw error }
  const byFd = new Map([...nodes.values()].map(node => [node.fd, node]))
  const settings = { home: join(root, 'user'), supportRoot: join(root, 'support'),
    dshHome: join(root, 'support', 'state', 'home'), auraDir: join(root, 'receipts'),
    repoRoots: [], releaseRoots: [], extraWritableRoots: [], readRoots: [],
    confineReads: true, networkAllow: [], allowLoopback: false, mainBranch: 'main', defaultWorkspace: root }
  const productionPolicy = createPolicy(settings)
  const policy = { judgeReadDescriptor(proof, call) {
    trace.push({ op: 'judge', path: proof.logicalPath, proof })
    return productionPolicy.judgeReadDescriptor(proof, call)
  } }
  const io = {
    openRoot(path) { trace.push({ op: 'openRoot', path }); assert.equal(path, root); return rootNode.fd },
    openChild(fd, name) { trace.push({ op: 'openChild', fd, name }); return byFd.get(fd).children.get(name).fd },
    names(fd, budget, limit) {
      const names = [...byFd.get(fd).children.keys()].sort()
      for (let i = 0; i < names.length; i++) {
        budget()
        if (i >= limit) throw new DescriptorSearchError('search:unqualified', 'fixture entry budget exhausted')
      }
      return names
    },
    stat(fd) { trace.push({ op: 'stat', fd }); return fs.fstatSync(fd, { bigint: true }) },
    physical(fd) { trace.push({ op: 'physical', fd }); return byFd.get(fd).path },
    mountId(fd) { trace.push({ op: 'mountId', fd }); return 42n },
    read(fd, buffer, offset, length, position) {
      trace.push({ op: 'read', fd, position })
      return fs.readSync(fd, buffer, offset, length, position)
    },
    close(fd) { trace.push({ op: 'close', fd }) },
  }
  return { root, rootNode, nodes, trace, io, policy, settings, productionPolicy,
    node: name => nodes.get(join(root, name)),
    dispose() { for (const fd of fds) fs.closeSync(fd); fs.rmSync(root, { recursive: true }) } }
}
async function withFixture(items, run) {
  if (typeof items === 'function') { run = items; items = undefined }
  const f = fixture(items)
  try { return await run(f) } finally { f.dispose() }
}
function state(f, overrides = {}) {
  return { io: f.io, policy: f.policy, call: { workspace: f.root }, signal: new AbortController().signal,
    bounds: SEARCH_BOUNDS, now: () => 0, deadline: SEARCH_BOUNDS.metadataMs, bytes: 0, ...overrides }
}
function snapshot(f, overrides = {}, implementation = snapshotSearchTree) {
  return implementation(f.root, { io: f.io, policy: f.policy, call: { workspace: f.root }, now: () => 0,
    ...overrides })
}
const reads = f => f.trace.filter(event => event.op === 'read')
function refused(fn, rule) {
  assert.throws(fn, error => error instanceof DescriptorSearchError && (rule === undefined || error.rule === rule))
}

// The matcher stub returns typed protocol facts, never evaluates the pattern.
// Its completion and stream methods have the same owned-boundary shape as DSH.
function protocol(f, options = {}, implementation = createDescriptorSearch) {
  const events = []
  const spawns = []
  const denials = []
  const spawned = Promise.withResolvers()
  let nextCalls = 0
  const definition = Object.freeze({ timeoutMs: 1000,
    outputSchema: Object.freeze({ name: 'registered-grep-output' }), render: value => value.matches })
  const stdoutText = options.stdoutText ?? JSON.stringify(options.matches ?? [
    { path: '<stdin>', lineNumber: 1, line: 'alpha' },
  ])
  const handle = {
    done: options.done ?? Promise.resolve(options.outcome ?? { signal: null, exitCode: 0 }),
    terminate() { events.push('terminate') },
    async waitForExit() { events.push('waitForExit'); return options.exitConfirmed ?? true },
    collected: { stdout: { readFrom(offset) {
      events.push('stdout'); assert.equal(offset, 0)
      return options.missingStdout ? undefined : { text: stdoutText, lossy: options.lossy ?? false }
    } } },
  }
  Object.assign(handle, options.handle)
  const ctx = { tools: { get(name) { assert.equal(name, 'grep'); return definition } },
    subprocess: { spawn(spec) { events.push('spawn'); spawns.push(spec); spawned.resolve(); return handle } } }
  const module = { parseGrepArgs: () => ({ pattern: options.pattern ?? 'alpha', path: '.' }),
    resolveRgPath: async () => '/mock/rg', parseGrepMatches: text => JSON.parse(text) }
  const controller = new AbortController()
  const exec = { name: 'grep', arguments: { pattern: 'unused by protocol stub' }, signal: controller.signal,
    agent: { session: { header: { cwd: f.root } } } }
  const config = { ctx, settings: f.settings, policy: f.policy, io: f.io, now: () => 0,
    recordDenial: (actualExec, error) => denials.push({ exec: actualExec, error }), loadSearch: async () => module,
    ...options.config }
  const wrapper = implementation(config)
  return { ctx, definition, module, handle, events, spawns, denials, exec, controller, spawned: spawned.promise,
    get nextCalls() { return nextCalls },
    run: () => wrapper(exec, () => { nextCalls++; return { originalBody: true } }), wrapper }
}
function assertRefusal(result, p, rule) {
  assert.equal(result.isError, true)
  assert.equal(p.denials.length, 1)
  const expectedCode = { 'search:aborted': 'SEARCH_ABORTED', 'search:invalid-pattern': 'SEARCH_INVALID_PATTERN',
    'search:output-overflow': 'SEARCH_RAW_OUTPUT_OVERFLOW' }[p.denials[0].error.rule] ?? 'SEARCH_FAILED'
  assert.equal(result.error.info.code, expectedCode)
  assert.equal(p.denials[0].exec, p.exec)
  if (rule) assert.equal(p.denials[0].error.rule, rule)
  assert.equal(p.nextCalls, 0)
}

let indexModule
async function actualIndex() {
  if (indexModule) return indexModule
  // Import the actual tracked gate, kernel, receipt writer and chain helpers.
  // Only the tool registry and selected matcher provider are protocol stubs.
  const [module, receiptHelpers] = await Promise.all([import(indexURL), import(receiptsURL)])
  return indexModule = { ...module, argsDigest: receiptHelpers.argsDigest }
}

check('real regular FD is judged before content read and preserves bytes', () => withFixture(f => {
  const node = f.node('alpha.txt')
  const result = readAcceptedDescriptor(node.fd, node.path, state(f))
  assert.deepEqual(result, Buffer.from('alpha\nbeta\n'))
  assert.ok(reads(f).length >= 2)
  assert.ok(reads(f).every(event => event.fd === node.fd))
  assert.ok(f.trace.findIndex(event => event.op === 'judge') < f.trace.findIndex(event => event.op === 'read'))
  assert.equal(f.trace.find(event => event.op === 'judge').proof.nlink, fs.fstatSync(node.fd, { bigint: true }).nlink)
}))
check('real immutable hardlink metadata refuses before content read', () => withFixture([
  { name: 'alpha.txt', text: 'ordinary fixture\n' }, { name: 'copy.txt', linkTo: 'alpha.txt' },
], f => {
  const node = f.node('alpha.txt')
  assert.equal(fs.fstatSync(node.fd, { bigint: true }).nlink, 2n)
  refused(() => readAcceptedDescriptor(node.fd, node.path, state(f)), 'read:hardlink')
  assert.equal(reads(f).length, 0)
}))
check('descriptor policy validates types, normalized paths and bigint counts', () => withFixture(f => {
  const good = { logicalPath: f.node('alpha.txt').path, physicalPath: f.node('alpha.txt').path, kind: 'file', nlink: 1n }
  assert.equal(f.productionPolicy.judgeReadDescriptor(good).decision, 'allow')
  for (const bad of [null, [], { ...good, kind: 'device' }, { ...good, nlink: 1 }, { ...good, nlink: 0n },
    { ...good, logicalPath: 'relative.txt' }, { ...good, physicalPath: `${f.root}/../elsewhere.txt` },
    { ...good, physicalPath: `${good.physicalPath} (deleted)` }, { ...good, logicalPath: `${f.root}/bad\0name` }]) {
    assert.equal(f.productionPolicy.judgeReadDescriptor(bad).decision, 'deny')
  }
}))
check('both descriptor names must be inside approved roots', () => withFixture(f => {
  const good = f.node('alpha.txt').path
  const outside = join(dirname(f.root), 'ordinary-outside.txt')
  for (const [logicalPath, physicalPath] of [[good, outside], [outside, good]]) {
    assert.equal(f.productionPolicy.judgeReadDescriptor({ logicalPath, physicalPath, kind: 'file', nlink: 1n }).rule,
      'read:outside-workspace')
  }
}))
check('nonregular descriptor metadata refuses without content read', () => withFixture(f => {
  const io = { ...f.io, stat: fd => cloneStat(f.io.stat(fd), { isFile: () => false, isDirectory: () => false }) }
  const node = f.node('alpha.txt')
  refused(() => readAcceptedDescriptor(node.fd, node.path, state(f, { io })))
  assert.equal(reads(f).length, 0)
}))
check('file size bound refuses before content read', () => withFixture(f => {
  const node = f.node('alpha.txt')
  refused(() => readAcceptedDescriptor(node.fd, node.path, state(f, { bounds: { ...SEARCH_BOUNDS, bytes: 3 } })))
  assert.equal(reads(f).length, 0)
}))
check('invalid descriptor read counts refuse', () => withFixture(f => {
  const node = f.node('alpha.txt')
  for (const count of [-1, 0.5, Number.NaN, 70000]) {
    refused(() => readAcceptedDescriptor(node.fd, node.path, state(f, { io: { ...f.io, read: () => count } })))
  }
}))
check('stale fstat after a read refuses the snapshot', () => withFixture(f => {
  const node = f.node('alpha.txt')
  let observed = false
  const io = { ...f.io,
    read(...args) { observed = true; return f.io.read(...args) },
    stat(fd) { const st = f.io.stat(fd); return observed ? cloneStat(st, { ctimeNs: st.ctimeNs + 1n }) : st },
  }
  refused(() => readAcceptedDescriptor(node.fd, node.path, state(f, { io })))
  assert.ok(reads(f).length > 0)
}))
check('physical name drift after a read refuses the snapshot', () => withFixture(f => {
  const node = f.node('alpha.txt')
  let observed = false
  const io = { ...f.io, read(...args) { observed = true; return f.io.read(...args) },
    physical(fd) { return observed ? join(f.root, 'other-name.txt') : f.io.physical(fd) } }
  refused(() => readAcceptedDescriptor(node.fd, node.path, state(f, { io })))
}))
check('missing, non-bigint or nonpositive mount metadata refuses before bytes', () => withFixture(f => {
  const node = f.node('alpha.txt')
  for (const mountId of [undefined, 42, 0n, -1n]) {
    refused(() => readAcceptedDescriptor(node.fd, node.path, state(f, { io: { ...f.io, mountId: () => mountId } })))
  }
  assert.equal(reads(f).length, 0)
}))
check('descendant mount crossing refuses despite unchanged stat identities', () => withFixture(f => {
  const node = f.node('alpha.txt')
  const io = { ...f.io, mountId: fd => fd === node.fd ? 43n : 42n }
  refused(() => snapshot(f, { io }))
  assert.equal(reads(f).length, 0)
}))
check('mount identity drift after a read refuses the snapshot', () => withFixture(f => {
  const node = f.node('alpha.txt')
  let observed = false
  const io = { ...f.io, read(...args) { observed = true; return f.io.read(...args) },
    mountId: () => observed ? 43n : 42n }
  refused(() => readAcceptedDescriptor(node.fd, node.path, state(f, { io })))
}))
check('cancelled or expired observation refuses before metadata or bytes', () => withFixture(f => {
  const node = f.node('alpha.txt')
  const controller = new AbortController(); controller.abort()
  refused(() => readAcceptedDescriptor(node.fd, node.path, state(f, { signal: controller.signal })), 'search:aborted')
  refused(() => readAcceptedDescriptor(node.fd, node.path, state(f, { now: () => SEARCH_BOUNDS.metadataMs })))
  assert.equal(f.trace.length, 0)
}))
check('cancellation between read chunks refuses partial bytes', () => withFixture(f => {
  const node = f.node('alpha.txt')
  const controller = new AbortController()
  const io = { ...f.io, read(...args) { const count = f.io.read(...args); controller.abort(); return count } }
  refused(() => readAcceptedDescriptor(node.fd, node.path, state(f, { io, signal: controller.signal })), 'search:aborted')
  assert.equal(reads(f).length, 1)
}))
check('snapshot returns deterministic relative paths and FD-owned bytes', () => withFixture([
  { name: 'z.txt', text: 'zeta\n' }, { name: 'nested', children: [{ name: 'a.txt', text: 'alpha\n' }] },
], f => {
  const files = snapshot(f)
  assert.deepEqual(files.map(file => file.path), ['nested/a.txt', 'z.txt'])
  assert.deepEqual(files.map(file => file.bytes), [Buffer.from('alpha\n'), Buffer.from('zeta\n')])
  const opens = f.trace.filter(event => event.op === 'openChild').length + 1
  assert.equal(f.trace.filter(event => event.op === 'close').length, opens)
}))
check('hidden and ignored entries are judged without entering content result', () => withFixture([
  { name: '.gitignore', text: '*.tmp\n' }, { name: '.notes', text: 'ordinary hidden text\n' },
  { name: 'skip.tmp', text: 'ordinary ignored text\n' }, { name: 'alpha.txt', text: 'alpha\n' },
], f => {
  assert.deepEqual(snapshot(f).map(file => file.path), ['alpha.txt'])
  for (const name of ['.notes', 'skip.tmp']) {
    assert.ok(f.trace.some(event => event.op === 'judge' && event.path === f.node(name).path))
    assert.ok(!reads(f).some(event => event.fd === f.node(name).fd))
  }
  assert.ok(reads(f).some(event => event.fd === f.node('.gitignore').fd))
}))
check('positive include filtering is applied to captured files', () => withFixture([
  { name: 'alpha.txt', text: 'alpha\n' }, { name: 'beta.md', text: 'beta\n' },
], f => { assert.deepEqual(snapshot(f, { include: '*.txt' }).map(file => file.path), ['alpha.txt']) }))
check('unqualified include and ignore syntax refuses', () => withFixture([
  { name: '.ignore', text: '!alpha.txt\n' }, { name: 'alpha.txt', text: 'alpha\n' },
], f => {
  refused(() => snapshot(f, { include: '[a-z]*' }))
  assert.equal(f.trace.length, 0)
  refused(() => snapshot(f))
}))
check('depth, entry, file and aggregate input-byte budgets refuse', () => withFixture([
  { name: 'alpha.txt', text: 'alpha\n' }, { name: 'nested', children: [{ name: 'beta.txt', text: 'beta\n' }] },
], f => {
  for (const change of [{ depth: 0 }, { entries: 1 }, { files: 1 }, { bytes: 8 }]) {
    refused(() => snapshot(f, { bounds: { ...SEARCH_BOUNDS, ...change } }))
  }
}))
check('missing descriptor policy refuses before opening a tree', () => withFixture(f => {
  refused(() => snapshot(f, { policy: {} }))
  assert.equal(f.trace.length, 0)
}))
check('default child helper rejects non-component names before any open', () => {
  for (const name of ['', '.', '..', 'parent/child', 'bad\0name', null]) {
    refused(() => LINUX_DESCRIPTOR_IO.openChild(-1, name))
  }
})
check('default root helper rejects unqualified paths and fails closed off Linux', () => {
  for (const path of ['relative', '/tmp/../other', '/tmp/bad\0name']) refused(() => LINUX_DESCRIPTOR_IO.openRoot(path))
  if (process.platform !== 'linux') refused(() => LINUX_DESCRIPTOR_IO.openRoot('/'))
})

check('grep replacement sends copied Buffer only with fixed stdin argv', () => withFixture(async f => {
  const pattern = '--option-looking pattern'
  const p = protocol(f, { pattern })
  const result = await p.run()
  assert.equal(result.isError, false)
  assert.deepEqual(result.value, { matches: [{ path: 'alpha.txt', lineNumber: 1, line: 'alpha' }] })
  assert.deepEqual(result.content, [])
  assert.equal(p.nextCalls, 0)
  assert.equal(p.denials.length, 0)
  assert.equal(p.spawns.length, 1)
  const spec = p.spawns[0]
  assert.deepEqual(spec.argv, ['/mock/rg', '--no-config', '--json', `--regexp=${pattern}`, '--', '-'])
  assert.equal(spec.cwd, '/')
  assert.ok(Buffer.isBuffer(spec.stdio.stdin.data))
  assert.deepEqual(spec.stdio.stdin.data, Buffer.from('alpha\nbeta\n'))
  assert.equal(spec.stdio.stdout.maxBytes, SEARCH_BOUNDS.rawBytes)
  assert.ok(p.events.indexOf('waitForExit') < p.events.indexOf('stdout'))
  assert.equal(p.ctx.tools.get('grep'), p.definition)
  assert.deepEqual(p.definition.render(result.value), result.value.matches)
  assert.equal(p.definition.outputSchema.name, 'registered-grep-output')
}))
check('other tools retain their original next callback', () => withFixture(async f => {
  const p = protocol(f); p.exec.name = 'read'
  assert.deepEqual(await p.run(), { originalBody: true })
  assert.equal(p.nextCalls, 1)
  assert.equal(p.spawns.length, 0)
  assert.equal(f.trace.length, 0)
}))
check('empty qualified tree validates the pattern with owned empty stdin', () => withFixture([], async f => {
  const p = protocol(f, { outcome: { signal: null, exitCode: 1 }, matches: [] })
  const result = await p.run()
  assert.equal(result.isError, false)
  assert.deepEqual(result.value, { matches: [] })
  assert.equal(p.spawns.length, 1)
  assert.deepEqual(p.spawns[0].argv.slice(-2), ['--', '-'])
  assert.ok(Buffer.isBuffer(p.spawns[0].stdio.stdin.data))
  assert.equal(p.spawns[0].stdio.stdin.data.length, 0)
  assert.ok(p.events.indexOf('waitForExit') < p.events.indexOf('stdout'))
  assert.equal(p.nextCalls, 0)
}))
check('empty page preserves typed regex-invalid refusal', () => withFixture([], async f => {
  const p = protocol(f, { outcome: { signal: null, exitCode: 2 }, handle: { collected: {
    stderr: { readFrom: () => ({ text: 'regex parse error', lossy: false }) },
  } } })
  assertRefusal(await p.run(), p, 'search:invalid-pattern')
  assert.equal(p.spawns.length, 1)
  assert.equal(p.spawns[0].stdio.stdin.data.length, 0)
}))
check('empty page refuses unexpected matcher content results', () => withFixture([], async f => {
  const p = protocol(f)
  assertRefusal(await p.run(), p)
  assert.equal(p.spawns.length, 1)
  assert.equal(p.spawns[0].stdio.stdin.data.length, 0)
}))
check('typed matcher exit 1 with empty matches succeeds', () => withFixture(async f => {
  const p = protocol(f, { outcome: { signal: null, exitCode: 1 }, matches: [] })
  assert.deepEqual((await p.run()).value, { matches: [] })
  assert.equal(p.denials.length, 0)
}))
check('matcher output budget decreases across distinct accepted files', () => withFixture([
  { name: 'alpha.txt', text: 'alpha\n' }, { name: 'beta.txt', text: 'beta\n' },
], async f => {
  const stdoutText = JSON.stringify([{ path: '-', lineNumber: 1, line: 'ordinary match' }])
  const p = protocol(f, { stdoutText })
  const result = await p.run()
  assert.equal(result.isError, false)
  assert.deepEqual(result.value.matches.map(match => match.path), ['alpha.txt', 'beta.txt'])
  assert.equal(p.spawns[0].stdio.stdout.maxBytes, SEARCH_BOUNDS.rawBytes)
  assert.equal(p.spawns[1].stdio.stdout.maxBytes, SEARCH_BOUNDS.rawBytes - Buffer.byteLength(stdoutText))
  assert.deepEqual(p.spawns.map(spec => spec.stdio.stdin.data), [Buffer.from('alpha\n'), Buffer.from('beta\n')])
}))
check('invalid, signalled or contradictory matcher exits refuse', () => withFixture(async f => {
  for (const outcome of [{ signal: null, exitCode: 2 }, { signal: null }, { exitCode: 0 },
    { signal: 'SIGTERM', exitCode: 0 }, { signal: null, exitCode: 1 }]) {
    const p = protocol(f, { outcome })
    assertRefusal(await p.run(), p)
  }
}))
check('typed invalid-pattern failure preserves the registered search error code', () => withFixture(async f => {
  const p = protocol(f, { outcome: { signal: null, exitCode: 2 }, handle: { collected: {
    stderr: { readFrom: () => ({ text: 'regex parse error', lossy: false }) },
  } } })
  assertRefusal(await p.run(), p, 'search:invalid-pattern')
}))
check('lossy, untyped, missing or oversized matcher output refuses', () => withFixture(async f => {
  for (const options of [{ lossy: true }, { missingStdout: true },
    { stdoutText: ' '.repeat(SEARCH_BOUNDS.rawBytes + 1) },
    { handle: { collected: { stdout: { readFrom: () => ({ text: '[]' }) } } } }]) {
    const p = protocol(f, options)
    assertRefusal(await p.run(), p)
  }
}))
check('matcher output identity, line type and line number must be qualified', () => withFixture(async f => {
  for (const match of [{ path: 'alpha.txt', lineNumber: 1, line: 'alpha' },
    { path: '<stdin>', lineNumber: 0, line: 'alpha' }, { path: '-', lineNumber: 1.5, line: 'alpha' },
    { path: '-', lineNumber: 1, line: null }]) {
    const p = protocol(f, { matches: [match] })
    assertRefusal(await p.run(), p)
  }
}))
check('owned matcher waitForExit must confirm actual completion', () => withFixture(async f => {
  const p = protocol(f, { exitConfirmed: false })
  assertRefusal(await p.run(), p)
  assert.ok(p.events.includes('terminate'))
  assert.ok(!p.events.includes('stdout'))
  const missing = protocol(f, { handle: { waitForExit: undefined } })
  assertRefusal(await missing.run(), missing)
  assert.ok(missing.events.includes('terminate'))
}))
check('synchronous cleanup failures do not skip draining the owned handle', () => withFixture(async f => {
  let doneReads = 0
  let waitCalls = 0
  let terminateCalls = 0
  let failure
  const p = protocol(f, { handle: {
    terminate() { terminateCalls++; throw new Error('mock terminate failure') },
    waitForExit() { waitCalls++; throw new Error('mock wait failure') },
  } })
  Object.defineProperty(p.handle, 'done', { get() {
    doneReads++
    return failure ??= Promise.reject(new Error('mock owned process failure'))
  } })
  assertRefusal(await p.run(), p)
  assert.equal(terminateCalls, 1)
  assert.equal(waitCalls, 1)
  assert.ok(doneReads >= 2, 'the owned done promise must also participate in cleanup')
}))
check('result stays pending until the owned exit boundary completes', () => withFixture(async f => {
  const exit = Promise.withResolvers()
  const entered = Promise.withResolvers()
  const p = protocol(f, { handle: { waitForExit() { entered.resolve(); return exit.promise } } })
  let settled = false
  const pending = p.run().then(result => { settled = true; return result })
  await entered.promise
  await Promise.resolve()
  assert.equal(settled, false)
  assert.ok(!p.events.includes('stdout'))
  exit.resolve(true)
  assert.equal((await pending).isError, false)
}))
check('aborted grep never invokes matcher or original body', () => withFixture(async f => {
  const p = protocol(f); p.controller.abort()
  assertRefusal(await p.run(), p, 'search:aborted')
  assert.equal(p.spawns.length, 0)
}))
check('abort after matcher completion refuses before consuming output', () => withFixture(async f => {
  const done = Promise.withResolvers()
  const p = protocol(f, { done: done.promise })
  const pending = p.run()
  await p.spawned
  p.controller.abort(); done.resolve({ signal: null, exitCode: 0 })
  assertRefusal(await pending, p, 'search:aborted')
  assert.ok(!p.events.includes('stdout'))
}))
check('missing policy, source loader or SDK service records a refusal', () => withFixture(async f => {
  for (const config of [{ policy: undefined }, { loadSearch: undefined },
    { ctx: { tools: { get: () => ({}) } } }, { ctx: { subprocess: {} } }]) {
    const p = protocol(f, { config })
    assertRefusal(await p.run(), p)
  }
}))
check('descriptor denial reaches receipt callback before any matcher spawn', () => withFixture([
  { name: 'alpha.txt', text: 'ordinary fixture\n' }, { name: 'copy.txt', linkTo: 'alpha.txt' },
], async f => {
  const p = protocol(f)
  assertRefusal(await p.run(), p, 'read:hardlink')
  assert.equal(p.spawns.length, 0)
  assert.equal(reads(f).length, 0)
}))
check('failed refusal receipt remains an error with receipt-failed evidence', () => withFixture(async f => {
  const p = protocol(f, { config: { policy: undefined, recordDenial() { throw new Error('fixture recorder unavailable') } } })
  const result = await p.run()
  assert.equal(result.isError, true)
  assert.match(result.error.message, /\[receipt:failed\]/u)
  assert.equal(p.nextCalls, 0)
}))
check('ACTUAL SOURCE: guard and refusal share one synchronous receipt chain', () => withFixture(async f => {
  const { createGuard, readSettings, argsDigest } = await actualIndex()
  const definition = Object.freeze({ render: value => value, outputSchema: Object.freeze({ name: 'grep-schema' }) })
  const ctx = { tools: { get: () => definition } }
  const settings = readSettings(f.settings)
  const guard = createGuard({ settings, ctx, definitionOf: () => definition,
    loadSearch: async () => { throw new Error('disposable selected-loader refusal') } })
  const exec = { name: 'grep', arguments: { path: f.node('alpha.txt').path, pattern: 'alpha' },
    signal: new AbortController().signal, callId: 'ordinary-source-call',
    agent: { id: 'ordinary-source-agent', session: { header: { cwd: f.root } } } }
  assert.equal(guard(exec), undefined)
  const readReceipts = () => fs.readFileSync(join(settings.auraDir, 'aura.jsonl'), 'utf8').trim().split('\n').map(JSON.parse)
  assert.equal(readReceipts().length, 1)
  let nextCalls = 0
  const result = await guard.searchExecutor(exec, () => { nextCalls++; return 'original-body' })
  assert.equal(result.isError, true)
  assert.equal(nextCalls, 0)
  const entries = readReceipts()
  assert.equal(entries.length, 2)
  assert.deepEqual(entries.map(entry => entry.sequence), [1, 2])
  assert.deepEqual(entries.map(entry => entry.decision), ['allow', 'deny'])
  assert.equal(entries[1].phase, 'execution')
  assert.equal(entries[1].prev, entries[0].hash)
  assert.equal(entries[0].argsDigest, argsDigest(exec.arguments))
  assert.equal(entries[1].argsDigest, entries[0].argsDigest)
  assert.equal(entries[0].callId, entries[1].callId)
  assert.equal(ctx.tools.get('grep'), definition)
  assert.equal(definition.outputSchema.name, 'grep-schema')
  assert.equal(definition.render(result), result)
  const descriptor = Object.getOwnPropertyDescriptor(guard, 'searchExecutor')
  assert.equal(descriptor.writable, false)
  assert.equal(descriptor.configurable, false)
}))
check('ACTUAL SOURCE: apply mounts exactly the guard-owned search executor', () => withFixture(async f => {
  const { apply } = await actualIndex()
  let registeredGuard
  const listeners = []
  const definition = Object.freeze({ render: value => value, outputSchema: Object.freeze({ name: 'grep-schema' }) })
  const ctx = { tools: { get: () => definition, guard(value) { registeredGuard = value } },
    on(event, listener) { listeners.push({ event, listener }) } }
  apply(ctx, f.settings)
  assert.equal(typeof registeredGuard, 'function')
  assert.equal(listeners.length, 1)
  assert.equal(listeners[0].event, 'tools/execute')
  assert.equal(listeners[0].listener, registeredGuard.searchExecutor)
  assert.equal(ctx.tools.get('grep'), definition)
}))
check('ACTUAL SOURCE: gate and trusted factory explicitly require subprocess', async () => {
  const module = await actualIndex()
  assert.deepEqual(module.inject, ['tools', 'subprocess'])
  const plugin = module.createPlugin({ loadSearch: async () => ({}) })
  assert.equal(plugin.name, module.name)
  assert.deepEqual(plugin.inject, module.inject)
  assert.ok(Object.isFrozen(plugin))
  assert.ok(Object.isFrozen(plugin.inject))
  for (const options of [undefined, {}, { loadSearch: null }, { loadSearch: 'module path' }]) {
    assert.throws(() => module.createPlugin(options), TypeError)
  }
})
check('ACTUAL SOURCE: trusted factory mounts the shared path and uses its exact cached loader', () => withFixture(async f => {
  const { createPlugin } = await actualIndex()
  let registeredGuard
  let hook
  let loaderCalls = 0
  let parseCalls = 0
  let nextCalls = 0
  const definition = Object.freeze({ render: value => value, outputSchema: Object.freeze({ name: 'original-grep-schema' }) })
  const ownedSubprocess = Object.freeze({ spawn() { throw new Error('parser sentinel must precede any matcher') } })
  const selected = Object.freeze({ parseGrepArgs(args) {
    assert.equal(this, selected)
    assert.equal(args.pattern, 'ordinary pattern')
    parseCalls++
    throw new Error('selected-module parser sentinel')
  } })
  const plugin = createPlugin({ loadSearch: async () => { loaderCalls++; return selected } })
  const ctx = { subprocess: ownedSubprocess, tools: { get: () => definition, guard(value) { registeredGuard = value } },
    on(event, listener) { assert.equal(event, 'tools/execute'); assert.equal(hook, undefined); hook = listener } }
  plugin.apply(ctx, f.settings)
  assert.equal(hook, registeredGuard.searchExecutor)
  const exec = { name: 'grep', arguments: { path: f.node('alpha.txt').path, pattern: 'ordinary pattern' },
    signal: new AbortController().signal, agent: { session: { header: { cwd: f.root } } } }
  for (let i = 0; i < 2; i++) {
    assert.equal(registeredGuard(exec), undefined)
    const result = await hook(exec, () => { nextCalls++; return 'original-body' })
    assert.equal(result.isError, true)
    assert.equal(result.error.info.code, 'SEARCH_FAILED')
  }
  assert.equal(loaderCalls, 1)
  assert.equal(parseCalls, 2)
  assert.equal(nextCalls, 0)
  assert.equal(ctx.subprocess, ownedSubprocess)
  assert.equal(ctx.tools.get('grep'), definition)
  assert.equal(definition.outputSchema.name, 'original-grep-schema')
}))

function replaceOnce(text, before, after) {
  assert.equal(text.split(before).length - 1, 1, `removal control must find one actual-source target: ${before}`)
  return text.replace(before, after)
}
async function copyModule(text, baseURL) {
  // Rewrite imports to their same production dependencies, then import only
  // this in-memory source copy. No dependency tree or repository mutation.
  const imports = text.replace(/from\s+(['"])(\.{1,2}\/[^'"]+)\1/gu,
    (_, quote, path) => `from ${quote}${new URL(path, baseURL).href}${quote}`)
  return import(`data:text/javascript;base64,${Buffer.from(imports).toString('base64')}`)
}
async function removalWitness(witness, original, mutant) {
  await witness(original)
  let error
  try { await witness(mutant) } catch (caught) { error = caught }
  assert.ok(error instanceof assert.AssertionError, 'the actual-source mutant must violate the same invariant witness')
}
check('REMOVAL: descriptor proof kind validation is necessary', async () => {
  const mutant = await copyModule(replaceOnce(policyText, "!['file', 'directory'].includes(kind)", 'false'), policyURL)
  await removalWitness(implementation => withFixture(f => {
    const path = f.node('alpha.txt').path
    const verdict = implementation.createPolicy(f.settings).judgeReadDescriptor({
      logicalPath: path, physicalPath: path, kind: 'device', nlink: 1n,
    })
    assert.equal(verdict.decision, 'deny')
  }), { createPolicy }, mutant)
})
check('REMOVAL: file hardlink refusal is necessary', async () => {
  const mutant = await copyModule(replaceOnce(policyText, "if (kind === 'file' && nlink !== 1n)", 'if (false)'), policyURL)
  await removalWitness(implementation => withFixture(f => {
    const path = f.node('alpha.txt').path
    const verdict = implementation.createPolicy(f.settings).judgeReadDescriptor({
      logicalPath: path, physicalPath: path, kind: 'file', nlink: 2n,
    })
    assert.equal(verdict.rule, 'read:hardlink')
  }), { createPolicy }, mutant)
})
check('REMOVAL: physical-name policy classification is necessary', async () => {
  const mutant = await copyModule(replaceOnce(policyText,
    'const forms = [...new Set([logicalPath, physicalPath])]', 'const forms = [logicalPath]'), policyURL)
  await removalWitness(implementation => withFixture(f => {
    const verdict = implementation.createPolicy(f.settings).judgeReadDescriptor({
      logicalPath: f.node('alpha.txt').path, physicalPath: join(dirname(f.root), 'ordinary-outside.txt'),
      kind: 'file', nlink: 1n,
    })
    assert.equal(verdict.rule, 'read:outside-workspace')
  }), { createPolicy }, mutant)
})
check('REMOVAL: descriptor policy must judge before content read', async () => {
  const mutant = await copyModule(replaceOnce(searchText,
    'const verdict = state.policy.judgeReadDescriptor({ logicalPath, physicalPath, kind, nlink: st.nlink }, state.call)',
    "const verdict = { decision: 'allow' }"), searchURL)
  await removalWitness(implementation => withFixture([
    { name: 'alpha.txt', text: 'ordinary fixture\n' }, { name: 'copy.txt', linkTo: 'alpha.txt' },
  ], f => {
    const node = f.node('alpha.txt')
    assert.throws(() => implementation.readAcceptedDescriptor(node.fd, node.path, state(f)),
      error => error instanceof Error && error.rule === 'read:hardlink')
    assert.equal(reads(f).length, 0)
  }), source, mutant)
})
check('REMOVAL: content reads must use the judged FD, never its name', async () => {
  const mutant = await copyModule(replaceOnce(searchText,
    'state.io.read(fd, chunk, 0, chunk.length, position)', 'state.io.read(logicalPath, chunk, 0, chunk.length, position)'), searchURL)
  await removalWitness(implementation => withFixture(f => {
    const node = f.node('alpha.txt')
    const supplied = []
    const io = { ...f.io, read(fd, ...args) {
      supplied.push(fd)
      // This instrumentation never opens a supplied name, including for the mutant.
      return f.io.read(node.fd, ...args)
    } }
    assert.deepEqual(implementation.readAcceptedDescriptor(node.fd, node.path, state(f, { io })), Buffer.from('alpha\nbeta\n'))
    assert.ok(supplied.length > 0)
    assert.ok(supplied.every(fd => fd === node.fd))
  }), source, mutant)
})
check('REMOVAL: matcher receives stdin-only argv', async () => {
  const mutant = await copyModule(replaceOnce(searchText,
    "`--regexp=${pattern}`, '--', '-'", "`--regexp=${pattern}`, '--', file.path"), searchURL)
  await removalWitness(implementation => withFixture(async f => {
    const p = protocol(f, {}, implementation.createDescriptorSearch)
    assert.equal((await p.run()).isError, false)
    assert.deepEqual(p.spawns[0].argv.slice(-2), ['--', '-'])
    assert.ok(Buffer.isBuffer(p.spawns[0].stdio.stdin.data))
    assert.equal(p.nextCalls, 0)
  }), source, mutant)
})
check('REMOVAL: grep must not reach the original path-based body', async () => {
  const mutant = await copyModule(replaceOnce(searchText,
    "if (exec.name !== 'grep') return next()", 'if (true) return next()'), searchURL)
  await removalWitness(implementation => withFixture(async f => {
    const p = protocol(f, {}, implementation.createDescriptorSearch)
    const result = await p.run()
    assert.equal(p.nextCalls, 0)
    assert.equal(result.isError, false)
  }), source, mutant)
})
check('REMOVAL: output-loss refusal prevents false completeness', async () => {
  const mutant = await copyModule(replaceOnce(searchText, 'stdout === undefined || stdout.lossy !== false ||',
    'stdout === undefined ||'), searchURL)
  await removalWitness(implementation => withFixture(async f => {
    const p = protocol(f, { lossy: true }, implementation.createDescriptorSearch)
    assertRefusal(await p.run(), p)
  }), source, mutant)
})

let passed = 0
for (const { name, run } of tests) {
  try { await run(); passed++; process.stdout.write(`ok ${passed} - ${name}\n`) }
  catch (error) {
    process.stderr.write(`FAIL - ${name}\n${error.stack}\n`)
    process.exitCode = 1
    break
  }
}
process.stdout.write(`${passed}/${tests.length} descriptor source/unit checks passed; mocked protocol, not Linux authority\n`)
