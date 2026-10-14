// Exercise installer checks and mutations without privileged host operations.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import './browser-node-aura-collector.test.mjs'
import './browser-aura-reader.test.mjs'
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const checks = ['browser-node-unit.py', 'browser-node-pipeline.py', 'browser-node-openviking.py'].map(name => path.join(root, 'tests', name))
checks.push(path.join(root, 'ops/node-spawn/browser/rehearse-bind.test.py'))

test('browser Aura independent head reader and mutations', () => {
  const result = spawnSync(process.execPath, ['tests/browser-node-aura-head.test.mjs', '--mutate'],
    { cwd: root, encoding: 'utf8' })
  assert.equal(result.status, 0, result.stdout + result.stderr)
  process.stdout.write(result.stdout)
})

const variants = unit => path.basename(unit) === 'browser-node-unit.py'
  ? [[], ['--mutations'], ...['1', '2', '3'].map(part => ['--refusal-mutations', part])] : [[], ['--mutations']]
for (const unit of checks) for (const args of variants(unit)) {
  const name = path.basename(unit) === 'rehearse-bind.test.py' ? 'browser-node-unit rehearsal driver'
    : path.basename(unit, '.py') === 'browser-node-openviking' ? 'browser-node-pipeline OpenViking' : path.basename(unit, '.py')
  const mode = args.length === 0 ? 'checks' : args[0] === '--refusal-mutations' ? `refusal mutations part ${args[1]}` : 'guard mutations'
  test(`browser installer ${name} ${mode}`, () => {
    const result = spawnSync('python3', ['-I', '-S', '-B', unit, ...args], { cwd: root, encoding: 'utf8' })
    assert.equal(result.status, 0, result.stdout + result.stderr)
    process.stdout.write(result.stdout)
    if (args.length === 0) process.stdout.write(result.stderr)
  })
}

test('browser installer browser-node-unit OpenViking bundle', () => {
  const env = { ...process.env }
  delete env.NODE_TEST_CONTEXT
  const result = spawnSync(process.execPath, ['--test', '--test-reporter=tap', path.join(root, 'tests/openviking-browser-bundle.test.mjs')],
    { cwd: root, env, encoding: 'utf8' })
  assert.equal(result.status, 0, result.stdout + result.stderr)
  assert.match(result.stdout, /^# tests [1-9][0-9]*$/m)
  process.stdout.write(result.stdout)
})

test('browser shell wrappers parse and reject unknown arguments and preloads', () => {
  for (const name of ['install', 'start', 'status', 'remove', 'acceptance', 'create']) {
    const file = path.join(root, `ops/node-spawn/browser/${name}.sh`)
    assert.equal(spawnSync('bash', ['-n', file]).status, 0, name)
    const bad = spawnSync('bash', [file, '--unknown'], { encoding: 'utf8' })
    assert.equal(bad.status, 1)
    assert.match(bad.stderr, /REFUSED BROWSER_.*USAGE/)
    if (['install', 'start', 'status', 'remove'].includes(name)) {
      const preload = spawnSync('bash', [file], { env: { ...process.env, NODE_OPTIONS: '' }, encoding: 'utf8' })
      assert.equal(preload.status, 1)
      assert.match(preload.stderr, /BROWSER_PRELOAD_FORBIDDEN/)
    }
  }
})
