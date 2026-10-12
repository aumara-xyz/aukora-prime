// Optional board state lookup does not read an undeclared context property.
import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'

const entry = new URL('../plugins/aukora-board/lib/index.js', import.meta.url)
const source = readFileSync(entry, 'utf8')

async function load(input = source) {
  const code = input.replace(/(?<=from ['"])(\.{1,2}\/[^'"]+)(?=['"])/gu,
    specifier => new URL(specifier, entry).href)
  return import(`data:text/javascript;base64,${Buffer.from(code).toString('base64')}`)
}

async function check(input = source) {
  const plugin = await load(input)
  for (const baseDir of [undefined, '/synthetic/board-home']) {
    const logs = [], events = []
    const own = {
      get: name => name === 'baseDir' ? baseDir : undefined,
      reflect: { get: () => undefined },
      logger: { info: line => logs.push(line), warn: () => {} },
      provide: () => () => {},
      on: name => { events.push(name); return () => {} },
    }
    const ctx = new Proxy(own, {
      get(target, name) {
        if (typeof name === 'symbol' || Object.hasOwn(target, name)) return Reflect.get(target, name)
        throw new Error(`cannot get property "${name}" without inject`)
      },
    })
    plugin.apply(ctx)
    assert.deepEqual(events, ['agent/pre-step', 'agent/turn-stopping'])
    assert.equal(logs[0], `aukora-board: digests at ${join(baseDir ?? process.cwd(), 'board-state', 'turn-digests.jsonl')}`)
  }
}

test('board mounts with no stateDir when its optional baseDir service is absent or present', async () => {
  await check()
})

test('board context mutation fails when optional lookup becomes an undeclared property read', async () => {
  const target = "ctx.get('baseDir')"
  assert.equal(source.split(target).length - 1, 1, 'board context mutation target')
  await assert.rejects(check(source.replace(target, 'ctx.baseDir')),
    /cannot get property "baseDir" without inject/u)
})
