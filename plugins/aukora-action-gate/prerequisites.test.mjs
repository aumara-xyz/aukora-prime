// Missing check prerequisites report one unperformed line before product work.
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import test from 'node:test'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '../..')
const mutant = process.env.PLUGIN_CHECK_MUTANT
function run(file, args = [], selector = '', vitestManifest = null) {
  const path = join(root, file)
  const env = { ...process.env, DSH_ROOT: join(root, '.absent-check-harness') }
  for (const name of ['NODE_OPTIONS', 'NODE_PATH']) delete env[name]
  let argv = [path, ...args]
  if ((selector && mutant === selector) || selector === 'vitest') {
    let source = readFileSync(path, 'utf8')
    if (selector === 'vitest') {
      const before = "const require = createRequire(join(root, 'package.json'))"
      assert.equal(source.split(before).length, 2)
      source = source.replace(before, vitestManifest
        ? `const require = { resolve: () => ${JSON.stringify(vitestManifest)} }`
        : "const require = { resolve: () => { throw Object.assign(Error('absent fixture tooling'), { code: 'MODULE_NOT_FOUND' }) } }")
    }
    if (mutant === selector) {
      assert.ok(source.includes('process.exit(2)'), 'prerequisite mutation must remove the incomplete exit')
      source = source.replaceAll('process.exit(2)', 'process.exit(0)')
    }
    source = source
      .replaceAll('import.meta.url', JSON.stringify(new URL(file, new URL('../../', import.meta.url)).href))
      .replace(/from (['"])(\.[^'"]+)\1/gu, (_match, _quote, relative) => `from ${JSON.stringify(new URL(relative, new URL(file, new URL('../../', import.meta.url))).href)}`)
    argv = ['--input-type=module', '-e', source]
  }
  return spawnSync(process.execPath, argv, { cwd: root, env, encoding: 'utf8', timeout: 5000 })
}
function unperformed(result, reason) {
  assert.equal(result.status, 2, result.stdout + result.stderr)
  assert.match(result.stdout, /^UNPERFORMED: [^\n]+\n$/u)
  assert.match(result.stdout, reason)
  assert.equal(result.stderr, '')
}

test('action gate names its absent built harness', () => {
  unperformed(run('plugins/aukora-action-gate/check.mjs', [], 'action-gate'), /built DeepSeek Harness absent/u)
})
test('seatbelt names absent macOS or built harness', () => {
  unperformed(run('plugins/aukora-seatbelt/check.mjs', [], 'seatbelt'), /Seatbelt requires macOS|built DeepSeek Harness absent/u)
})
test('carried TypeScript courts name absent Vitest', () => {
  unperformed(run('plugins/aukora-face/apps/scripts/check-vendor-tests.mjs', [], 'vitest'), /installed Vitest absent for 20 carried TypeScript tests/u)
})
test('installed Vitest CLI receives every carried TypeScript test', t => {
  const fixture = mkdtempSync(join(root, '.vendor-test-tool-'))
  t.after(() => rmSync(fixture, { recursive: true, force: true }))
  const manifest = join(fixture, 'package.json')
  writeFileSync(manifest, JSON.stringify({ bin: 'cli.mjs' }))
  writeFileSync(join(fixture, 'cli.mjs'), "import assert from 'node:assert/strict'; assert.equal(process.argv[2], 'run'); assert.equal(process.argv.slice(3).length, 20); console.log('PASS Vitest CLI received 20 carried tests')\n")
  const result = run('plugins/aukora-face/apps/scripts/check-vendor-tests.mjs', [], 'vitest', manifest)
  assert.equal(result.status, 0, result.stdout + result.stderr)
  assert.match(result.stdout, /PASS Vitest CLI received 20 carried tests/u)
})
