// Exercise installer checks and mutations without privileged host operations.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const checks = ['browser-node-unit.py', 'browser-node-pipeline.py'].map(name => path.join(root, 'tests', name))

for (const unit of checks) for (const args of [[], ['--mutations']]) {
  const name = path.basename(unit, '.py'), mode = args.length === 0 ? 'checks' : 'guard mutations'
  test(`browser installer ${name} ${mode}`, () => {
    const result = spawnSync('python3', ['-I', '-S', '-B', unit, ...args], { cwd: root, encoding: 'utf8' })
    assert.equal(result.status, 0, result.stdout + result.stderr)
    process.stdout.write(result.stdout)
    if (args.length === 0) process.stdout.write(result.stderr)
  })
}

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
