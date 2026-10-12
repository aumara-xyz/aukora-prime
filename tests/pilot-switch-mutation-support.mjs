// Executes parseable private script copies and requires the named assertion to reject each mutant.
import assert from 'node:assert/strict'
import { test } from 'node:test'
import { copyFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { spawnSync } from 'node:child_process'
import { join } from 'node:path'
import { fixture, script } from './pilot-switch-fixture.mjs'

const original = readFileSync(script, 'utf8')
const cases = []
export const output = result => `${result.stdout ?? ''}\n${result.stderr ?? ''}`
export const stops = f => f.events().filter(event => event.name === 'systemctl' && event.args[0] === 'stop')
export function restored(f, label) {
  for (const [path, body] of Object.entries(f.oldFiles)) {
    assert.ok(existsSync(f.at(path)), label)
    assert.equal(readFileSync(f.at(path), 'utf8'), body, label)
  }
}
export function replaceOnce(source, from, to) {
  const matches = typeof from === 'string' ? source.split(from).length - 1 : [...source.matchAll(new RegExp(from.source, from.flags.includes('g') ? from.flags : from.flags + 'g'))].length
  assert.equal(matches, 1, `mutation anchor must occur once: ${from}`)
  const changed = source.replace(from, to)
  assert.notEqual(changed, source, 'mutation must change bytes')
  return changed
}
function privateScript(f, source, probe = true) {
  const dir = f.at('/court')
  mkdirSync(dir)
  const path = join(dir, 'live-switch-main.sh')
  writeFileSync(path, source, { mode: 0o700 })
  if (probe) copyFileSync(join(script, '..', 'ui-probe.mjs'), join(dir, 'ui-probe.mjs'))
  const syntax = spawnSync('/bin/bash', ['-n', path], { encoding: 'utf8' })
  assert.equal(syntax.status, 0, `mutant must parse: ${syntax.stderr}`)
  return path
}
export function mutation(label, config, from, to, inspect, options = {}) {
  cases.push({ label, body: async () => {
    const changed = typeof from === 'function' ? from(original) : replaceOnce(original, from, to)
    const arms = [[original, false], [changed, true]].map(([source, mutant]) => {
      const f = fixture(config)
      const path = privateScript(f, source, options.probe !== false)
      options.prepare?.(f)
      return { f, path, source, mutant, initial: f.active() }
    })
    try {
      const settled = await Promise.allSettled(arms.map(({ f, path }) => options.execute ? options.execute(f, path) : f.runAsync(options.args, options.env, { script: path })))
      for (const result of settled) if (result.status === 'rejected') throw result.reason
      const results = settled.map(result => result.value)
      for (let index = 0; index < arms.length; index++) {
        const { f, initial, path, source, mutant } = arms[index]
        if (mutant) {
          assert.throws(() => inspect(f, results[index], initial, path, source), error => error.code === 'ERR_ASSERTION' && error.message.includes(label), `${label}: mutant must fail its own assertion`)
          console.log(`KILLED ${label}`)
        } else inspect(f, results[index], initial, path, source)
      }
    } finally { for (const { f } of arms) f.cleanup() }
  } })
}
export function staticMutation(label, from, to, inspect) {
  cases.push({ label, body: () => {
    inspect(original, label)
    const changed = replaceOnce(original, from, to)
    const syntax = spawnSync('/bin/bash', ['-n'], { input: changed, encoding: 'utf8' })
    assert.equal(syntax.status, 0, 'static mutant must parse')
    assert.throws(() => inspect(changed, label), error => error.code === 'ERR_ASSERTION' && error.message.includes(label))
    console.log(`KILLED ${label}`)
  } })
}

export function runMutationCourt(label) {
  test(label, { concurrency: 2 }, async t => { await Promise.all(cases.map(item => t.test(item.label, item.body))) })
}
