// SPDX-License-Identifier: AGPL-3.0-or-later
// The snapshot route survives absent Kira and drops readers with their injected scope.
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { stripTypeScriptTypes } from 'node:module'

const entryUrl = new URL('../plugins/aukora-face/settings/src/index.ts', import.meta.url)
const source = readFileSync(entryUrl, 'utf8')
const moduleUrl = text => `data:text/javascript;base64,${Buffer.from(text).toString('base64')}`
const projectionUrl = moduleUrl('export const auraCoherenceProjectionDefinition = {}')
const readerUrl = moduleUrl(`
  export const AURA_SNAPSHOT_ENDPOINT = '/api/aukora/aura-snapshot'
  export const snapshotGateSocket = () => null
  export const createAuraSnapshotReader = read => read
  export const auraSnapshotHandler = (_connection, read) => async (_req, res) => res.end(await read())
  export async function readAuraSnapshot(_root, _socket, readKira) {
    return { kira: await readKira?.() ?? null }
  }
`)

async function entry(text) {
  const executable = stripTypeScriptTypes(text)
    .replace("import z from '@deepseek-ai/schemastery'", 'const z = { object: value => value, string: () => ({}) }')
    .replace("'./aura/projection.ts'", JSON.stringify(projectionUrl))
    .replace("'./aura/snapshot-reader.ts'", JSON.stringify(readerUrl))
    .replaceAll('import.meta.url', JSON.stringify(entryUrl.href))
  return await import(moduleUrl(executable))
}

function scope(services, onInject) {
  const disposers = []
  const context = new Proxy({
    inject: onInject,
    effect(run) { const dispose = run(); if (typeof dispose === 'function') disposers.push(dispose) },
  }, {
    get(target, name) {
      if (Reflect.has(target, name)) return Reflect.get(target, name)
      assert.ok(Object.hasOwn(services, name), `service ${String(name)} must be injected`)
      return services[name]
    },
  })
  return { context, dispose: () => { for (const dispose of disposers.splice(0).reverse()) dispose() } }
}

async function check(apply) {
  const injections = [], routes = new Map()
  const root = scope({}, (names, callback) => injections.push({ names, callback }))
  apply(root.context)
  const kira = injections.find(injection => injection.names.includes('kira.head'))
  assert.ok(kira, 'Kira reads require named service injection')
  const web = injections.find(injection => injection.names.includes('webServer'))
  assert.ok(web)
  assert.deepEqual(web.names, ['webServer', 'connection'], 'absent Kira cannot withhold authenticated routes')
  const webScope = scope({
    connection: { requestRejection: () => undefined },
    webServer: { register(route) { routes.set(route.path, route.handler); return () => routes.delete(route.path) } },
  })
  web.callback(webScope.context)
  const handler = routes.get('/api/aukora/aura-snapshot')
  assert.equal(typeof handler, 'function', 'snapshot route mounts without Kira')
  const read = async () => {
    let answer
    await handler({ method: 'GET', headers: {} }, { end(value) { answer = value } })
    return answer
  }
  assert.deepEqual(await read(), { kira: null })
  let firstReads = 0, secondReads = 0
  const firstValue = { head: '11'.repeat(32), entries: 1 }
  const secondValue = { head: '22'.repeat(32), entries: 2 }
  const first = scope({ 'kira.head': { readHead() { firstReads += 1; return firstValue } } })
  kira.callback(first.context)
  assert.deepEqual(await read(), { kira: firstValue })
  assert.equal(firstReads, 1)
  const second = scope({ 'kira.head': { readHead() { secondReads += 1; return secondValue } } })
  kira.callback(second.context)
  assert.deepEqual(await read(), { kira: secondValue })
  first.dispose()
  assert.deepEqual(await read(), { kira: secondValue }, 'old scope cleanup cannot erase a replacement reader')
  assert.equal(firstReads, 1, 'disposed service is never read again')
  assert.equal(secondReads, 2)
  second.dispose()
  assert.deepEqual(await read(), { kira: null }, 'disposed Kira cannot leave a stale head reader')
  assert.equal(secondReads, 2)
  webScope.dispose()
  assert.equal(routes.has('/api/aukora/aura-snapshot'), false)
  root.dispose()
}

await check((await entry(source)).apply)
console.log('PASS Aura snapshot service lifecycle: named injection, absence, replacement and disposal')

const mutations = [
  ["ctx.inject(['kira.head']", "ctx.inject([]"],
  ["ctx.inject(['webServer', 'connection']", "ctx.inject(['webServer', 'connection', 'kira.head']"],
  ['readKira = read', 'readKira = undefined'],
  ['if (readKira === read) readKira = undefined', 'if (false) readKira = undefined'],
  ['if (readKira === read) readKira = undefined', 'readKira = undefined'],
  ['() => readKira?.()', '() => undefined'],
]
let killed = 0
for (let offset = 0; offset < mutations.length; offset += 3) {
  const batch = mutations.slice(offset, offset + 3)
  const outcomes = await Promise.all(batch.map(async ([before, after]) => {
    assert.ok(source.includes(before), `missing mutation seam: ${before}`)
    const changed = source.replaceAll(before, after)
    const candidate = await entry(changed)
    try { await check(candidate.apply) }
    catch (error) { if (error.code === 'ERR_ASSERTION') return true; throw error }
    return false
  }))
  killed += outcomes.filter(Boolean).length
}
assert.equal(killed, mutations.length, 'a removed service protection survived its regression')
console.log(`PASS Aura snapshot service mutation controls: ${killed}/${mutations.length} killed`)
