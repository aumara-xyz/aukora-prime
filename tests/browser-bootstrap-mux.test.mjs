// Browser admission precedes Remote resolution, execution and mux event content.
import test from 'node:test'
import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { createHash, randomUUID } from 'node:crypto'
import { existsSync, readFileSync } from 'node:fs'
import { stripTypeScriptTypes } from 'node:module'
import { EventEmitter } from 'node:events'
import { createBrowserAccess } from '../plugins/aukora-action-gate/lib/browser-bootstrap.mjs'

const required = 'browser-node:binding-required', unavailable = 'browser-node:binding-guard-unavailable'
const archive = new URL('../vendor/dsh-source.tar.gz', import.meta.url)
if (!existsSync(archive)) { console.log('UNPERFORMED: vendor/dsh-source.tar.gz absent'); process.exit(2) }
const pin = JSON.parse(readFileSync(new URL('../upstream-dsh.json', import.meta.url)))
assert.equal(createHash('sha256').update(readFileSync(archive)).digest('hex'), pin.archiveSha256)
const archivePath = archive.pathname
const archiveRoot = execFileSync('/usr/bin/python3', ['-I', '-S', '-B', '-c',
  "import sys,tarfile\nwith tarfile.open(sys.argv[1], 'r:gz') as tar: print(tar.next().name.split('/')[0])", archivePath], { encoding: 'utf8' }).trim()
function pinned(path) {
  return execFileSync('tar', ['-xOzf', archivePath, `${archiveRoot}/${path}`], { encoding: 'utf8' })
}
const gatewayPath = 'packages/api/gateway/src/index.ts'
const upstream = pinned(gatewayPath)
const patch = JSON.parse(readFileSync(new URL('../patches/browser-bootstrap-guard.patch.json', import.meta.url)))
let patched = upstream
for (const edit of patch.edits.filter(edit => edit.path === gatewayPath)) {
  assert.equal(patched.split(edit.find).length - 1, edit.occurrences, 'gateway carrier matches pinned source')
  patched = patched.replaceAll(edit.find, edit.replace)
}
for (const expectation of patch.expectAfterApply.filter(row => row.path === gatewayPath)) {
  assert.ok(patched.includes(expectation.contains), expectation.contains)
}
function moduleSource(source, names, imports = {}) {
  const javascript = stripTypeScriptTypes(source, { mode: 'transform' })
    .replace(/^import .*;\n/gmu, '').replace(/^export default .*;\n/gmu, '').replace(/^export /gmu, '')
  return new Function(...Object.keys(imports), `${javascript}\nreturn { ${names} }`)(...Object.values(imports))
}
const protocol = moduleSource(pinned('packages/api/gateway/src/stream-protocol.ts'),
  'REMOTE_EVENT_STREAM_ENDPOINT, REMOTE_EVENT_RESULT_ENDPOINT, REMOTE_EVENT_STREAM_READY, REMOTE_STREAM_MUX_PATH, isRemoteEventAgentId, isRemoteJsonValue, parseRemoteEventResult, projectRemoteEventRequest, restoreRemoteEventRejection, parseRemoteStreamClientMessage')
const { RemoteError, remoteErrorOf } = moduleSource(pinned('packages/typert/protocol/src/remote-error.ts'), 'RemoteError, remoteErrorOf')
class Service { constructor(ctx) { this.ctx = ctx } }
class Deque { rows = []; get size() { return this.rows.length } pushBack(value) { this.rows.push(value) } popFront() { return this.rows.shift() } }
const schema = new Proxy(() => schema, { get: (_target, key) => key === 'default' ? value => value : schema })
const z = { object: value => value, boolean: () => schema, number: () => schema }
const { RemoteStreamMuxConnection } = moduleSource(pinned('packages/api/gateway/src/stream-server.ts'), 'RemoteStreamMuxConnection',
  { WebSocket: { OPEN: 1 }, WebSocketServer: class {}, ...protocol })
function fixture(source, { enabled = true, access, stream = false, prepare } = {}) {
  const { TypertGatewayService } = moduleSource(source, 'TypertGatewayService', {
    Service, symbols: { original: Symbol('original') }, Deque, z, MAX_TIMER_DELAY_MS: 2147483647,
    RemoteError, remoteErrorOf, remoteMethods() { return [] }, randomUUID, RemoteStreamMuxServer: class {}, ...protocol,
  })
  assert.equal(TypertGatewayService.Config.browserAccessGuard, false, 'ordinary profile default remains disabled')
  const ctx = { on() {}, inject() {}, get(name) { assert.equal(name, 'aukoraBrowserAccess'); return access } }
  const gateway = new TypertGatewayService(ctx, { browserAccessGuard: enabled })
  const calls = { prepare: 0, method: 0 }
  gateway.prepareInvocation = async request => {
    calls.prepare++; prepare?.()
    const method = () => { calls.method++; return stream ? ['fixture-read'] : 'fixture-result' }
    return { endpoint: `${request.namespace}/${request.method}`, descriptor: { mode: stream ? 'stream' : undefined }, receiver: {}, args: [], method }
  }
  return { gateway, calls }
}
const payload = { args: {} }, signal = new AbortController().signal
function refusal(error, reason = required) {
  assert.ok(error && typeof error === 'object', 'refusal must reach the caller')
  assert.equal(error.code, reason)
  assert.equal(error.message, reason)
  assert.deepEqual(error.details, { status: 403, reason })
}
async function muxOpen(gateway, endpoint) {
  const socket = new EventEmitter(), frames = []
  socket.readyState = 1
  socket.send = (text, done) => { frames.push(JSON.parse(text)); done() }
  socket.close = () => socket.emit('close')
  const mux = new RemoteStreamMuxConnection(socket, gateway.wireStream.open, gateway.wireStream.failure)
  const running = mux.run()
  socket.emit('message', Buffer.from(JSON.stringify({ type: 'open', streamId: 'fixture', endpoint, payload })), false)
  await new Promise(resolve => setImmediate(resolve))
  socket.emit('close')
  await running
  return frames
}
const effectful = ['session/create', 'session/prompt', 'session/page', 'session/follow', 'session/control', 'session/list',
  'workspace/follow', 'workspaceFiles/list', 'workspaceFiles/read', 'fileUploads/upload',
  'credentials/set', 'credentials/unset', 'commands/execute', '$events/result']
test('effect and content-read representatives name actual pinned Remote exports', () => {
  for (const [path, binding, exports] of [
    ['packages/api/session-controller/src/index.ts', "namespace: 'session'", [
      "@Remote('create')", "@Remote('prompt')", "@Remote('page')", "@Remote('list')",
      "@Remote({ mode: 'stream' })\n  follow(", "@Remote({ mode: 'stream' })\n  control("]],
    ['packages/api/workspace-controller/src/index.ts', "namespace: 'workspace'", ["@Remote({ mode: 'stream' })\n  follow("]],
    ['packages/api/workspace-files/src/index.ts', "super(ctx, 'workspaceFiles')", ['@Remote\n  async list(', '@Remote\n  async read(']],
    ['packages/client/file-upload/src/index.ts', "super(ctx, 'fileUploads')", ["@Remote('upload')"]],
    ['packages/api/settings-controller/src/credentials.ts', "namespace: 'credentials'", ['@Remote\n  async set(', '@Remote\n  async unset(']],
    ['packages/interaction/commands/src/index.ts', "super(ctx, 'commands')", ['@Remote\n  async execute(']],
  ]) {
    const source = pinned(path)
    assert.ok(source.includes(binding), `Remote namespace in ${path}`)
    for (const declaration of exports) assert.ok(source.includes(declaration), `Remote export ${declaration} in ${path}`)
  }
  assert.equal(protocol.REMOTE_EVENT_RESULT_ENDPOINT, '$events/result')
})
async function checkDispatch(source) {
  const access = { rpcRejection: () => required }
  for (const stream of [false, true]) {
    const row = fixture(source, { access, stream })
    const request = { namespace: 'session', method: 'create', args: {}, signal }
    await assert.rejects(stream ? row.gateway.stream(request) : row.gateway.invoke(request), error => { refusal(error); return true })
    assert.deepEqual(row.calls, { prepare: 0, method: 0 }, 'direct dispatch refuses before providers')
  }
  for (const endpoint of effectful) {
    const unary = fixture(source, { access })
    const result = await unary.gateway.dispatchRpc(endpoint, payload, signal)
    assert.equal(result.ok, false, `unbound unary ${endpoint}`); refusal(result.error)
    assert.deepEqual(unary.calls, { prepare: 0, method: 0 }, 'refuse before context and lookup providers')
    const stream = fixture(source, { access, stream: true })
    const frames = await muxOpen(stream.gateway, endpoint)
    assert.equal(frames.length, 1); assert.equal(frames[0].type, 'error'); refusal(frames[0].error)
    assert.deepEqual(stream.calls, { prepare: 0, method: 0 })
  }
  for (const access of [undefined, {}, { rpcRejection() { throw Error('fixture-private') } },
    ...[null, false, 0, '', {}].map(value => ({ rpcRejection() { return value } }))]) {
    const { gateway, calls } = fixture(source, { access })
    refusal((await gateway.dispatchRpc('session/create', payload, signal)).error, unavailable)
    const frames = await muxOpen(gateway, '$events')
    assert.equal(frames[0]?.type, 'error'); refusal(frames[0].error, unavailable)
    assert.deepEqual(calls, { prepare: 0, method: 0 })
  }
  for (const options of [{ access: { rpcRejection() {} } }, { enabled: false }]) {
    const unary = fixture(source, options)
    assert.deepEqual(await unary.gateway.dispatchRpc('session/create', payload, signal), { ok: true, value: 'fixture-result' })
    const stream = fixture(source, { ...options, stream: true })
    assert.deepEqual(await muxOpen(stream.gateway, 'session/control'), [
      { type: 'item', streamId: 'fixture', value: 'fixture-read' }, { type: 'end', streamId: 'fixture' }])
  }
  for (const stream of [false, true]) {
    let bound = true
    const access = { rpcRejection() { return bound ? undefined : required } }
    const row = fixture(source, { access, stream, prepare() { bound = false } })
    const request = { namespace: 'session', method: 'create', args: {}, signal }
    await assert.rejects(stream ? row.gateway.stream(request) : row.gateway.invoke(request), error => { refusal(error); return true })
    assert.deepEqual(row.calls, { prepare: 1, method: 0 }, 'recheck immediately before method execution')
  }
}
test('plain Remote and actual mux pump refuse effects before providers; bound and ordinary calls retain dispatch', async () => {
  await checkDispatch(patched)
})

async function checkEvents(source) {
  let bound = false
  const access = { rpcRejection(endpoint) { return bound || endpoint === '$events' ? undefined : required } }
  const { gateway } = fixture(source, { access })
  gateway.remoteEvents = { lifetime: new AbortController(), host: { home: '/fixture' } }
  const abort = new AbortController(), events = await gateway.wireStream.open('$events', payload, abort.signal)
  const iterator = events[Symbol.asyncIterator]()
  const ready = await iterator.next()
  assert.equal(ready.value.type, 'ready')
  const client = gateway.remoteEventClients.get(ready.value.clientId)
  const pending = { id: 'fixture-event', frame: { type: 'waterfall', request: { content: 'fixture-private' } }, deliveries: new Set() }
  gateway.deliverRemoteEvent(pending, client)
  gateway.broadcastRemoteEvent({ event: 'session/content', args: ['fixture-private'] })
  assert.equal(pending.deliveries.size, 0); assert.equal(client.deliveries.size, 0); assert.equal(client.queue.frames.size, 0)
  bound = true
  gateway.deliverRemoteEvent(pending, client)
  gateway.broadcastRemoteEvent({ event: 'fixture-event', args: [] })
  assert.equal(pending.deliveries.size, 1); assert.equal(client.queue.frames.size, 2)
  bound = false
  const next = iterator.next()
  await new Promise(resolve => setImmediate(resolve))
  abort.abort()
  assert.deepEqual(await next, { value: undefined, done: true }, 'queued bound data is withheld after binding disappears')
  for (const invalid of [undefined, {}, { rpcRejection() { throw Error('fixture-private') } }, { rpcRejection() { return null } }]) {
    const row = fixture(source, { access: invalid }).gateway
    const contents = [], recipient = { deliveries: new Map(), queue: { push(frame) { contents.push(frame) } } }
    row.remoteEventClients.set('fixture', recipient)
    row.deliverRemoteEvent({ ...pending, deliveries: new Set() }, recipient)
    row.broadcastRemoteEvent({ event: 'session/content', args: ['fixture-private'] })
    assert.deepEqual(contents, [], 'event content fails closed')
  }
}
test('unbound mux events provide ready only; content and waterfalls recheck binding at enqueue and yield', async () => {
  await checkEvents(patched)
})
test('the shared policy refuses session, files, upload, run and result endpoints inside the mux', async () => {
  const access = createBrowserAccess({ refresh() { throw Error('unbound') } })
  assert.equal(typeof access.rpcRejection, 'function')
  for (const endpoint of effectful) {
    const { gateway } = fixture(patched, { access, stream: true })
    const frames = await muxOpen(gateway, endpoint)
    refusal(frames[0].error)
  }
})
test('mutations expose every Remote and event-content admission branch', async t => {
  const mutations = [
    ['invoke before providers', '    this.assertBrowserRemoteAccess(endpointOf(request.namespace, request.method))\n    const prepared = await this.prepareInvocation(request)', '    const prepared = await this.prepareInvocation(request)', 0],
    ['stream before providers', '    this.assertBrowserRemoteAccess(endpointOf(request.namespace, request.method))\n    const prepared = await this.prepareInvocation(request)', '    const prepared = await this.prepareInvocation(request)', 1],
    ['invoke before execution', '      this.assertBrowserRemoteAccess(prepared.endpoint)\n      return await Reflect.apply', '      return await Reflect.apply'],
    ['stream before execution', '      this.assertBrowserRemoteAccess(prepared.endpoint)\n      source = Reflect.apply', '      source = Reflect.apply'],
    ['result endpoint', '    try { this.assertBrowserRemoteAccess(endpoint) } catch (error) { return rpcFailure(error) }\n', ''],
    ['mux special stream', '    this.assertBrowserRemoteAccess(endpoint)\n    if (endpoint === REMOTE_EVENT_STREAM_ENDPOINT)', '    if (endpoint === REMOTE_EVENT_STREAM_ENDPOINT)'],
    ['missing policy', "if (guard === undefined) return 'browser-node:binding-guard-unavailable'", 'if (guard === undefined) return undefined'],
    ['invalid policy', "        : 'browser-node:binding-guard-unavailable'", '        : undefined'],
    ['throwing policy', "    } catch {\n      return 'browser-node:binding-guard-unavailable'", '    } catch {\n      return undefined'],
    ['ordinary default', 'browserAccessGuard: z.boolean().default(false)', 'browserAccessGuard: z.boolean().default(true)'],
    ['named wire refusal', 'isDSHRemoteError: true, code: reason', 'isDSHRemoteError: false, code: reason'],
    ['forbidden status', 'details: { status: 403, reason }', 'details: { status: 200, reason }'],
    ['content at yield', "if (this.browserRemoteRejection('$events/content') === undefined) yield frame", 'yield frame'],
    ['content broadcast', "  private broadcastRemoteEvent(frame: TypertRemoteEventFrame): void {\n    if (this.browserRemoteRejection('$events/content') !== undefined) return", '  private broadcastRemoteEvent(frame: TypertRemoteEventFrame): void {'],
    ['waterfall delivery', "  private deliverRemoteEvent(pending: PendingRemoteEvent, client: RemoteEventClient): void {\n    if (this.browserRemoteRejection('$events/content') !== undefined) return", '  private deliverRemoteEvent(pending: PendingRemoteEvent, client: RemoteEventClient): void {'],
  ]
  for (const [label, before, after, occurrence = 0] of mutations) {
    const at = patched.indexOf(before, occurrence === 0 ? 0 : patched.indexOf(before) + before.length)
    assert.ok(at >= 0, `mutation anchor ${label}`)
    const mutant = patched.slice(0, at) + after + patched.slice(at + before.length)
    await assert.rejects(async () => { await checkDispatch(mutant); await checkEvents(mutant) }, assert.AssertionError, `survived ${label}`)
  }
  t.diagnostic(`MUTATION browser bootstrap Remote carrier: ${mutations.length}/${mutations.length} killed; pinned source in memory, no listener`)
})
