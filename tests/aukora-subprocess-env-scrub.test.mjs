// SPDX-License-Identifier: AGPL-3.0-or-later
// Check the pinned subprocess inheritance scrub and explicit environment overrides.
// Donor assertion: aukora-harness 9d11730438d7f15695a9caf6295ac0451dd8ee92,
// packages/subprocess/subprocess/tests/service.spec.ts; DeepSeek MIT (licenses/DSH-MIT-LICENSE).
import assert from 'node:assert/strict'
import { execFileSync, spawnSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { copyFileSync, cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { stripTypeScriptTypes } from 'node:module'
import { join } from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'
import vm from 'node:vm'

const root = fileURLToPath(new URL('../', import.meta.url))
const archive = join(root, 'vendor/dsh-source.tar.gz')
const patchFile = 'patches/subprocess-env-scrub.patch.json'
const pin = JSON.parse(readFileSync(join(root, 'upstream-dsh.json'), 'utf8'))
const patchBytes = readFileSync(join(root, patchFile))
const patch = JSON.parse(patchBytes)
const sourceFile = 'packages/subprocess/subprocess/src/index.ts'
const sha256 = bytes => createHash('sha256').update(bytes).digest('hex')

test('subprocess scrub patch is digest-bound with the donor MIT notice', () => {
  const entry = pin.localPatches.find(item => item.file === patchFile)
  assert.equal(entry?.sha256, sha256(patchBytes))
  assert.equal(entry.reason, patch.reason)
  assert.equal(patch.upstream.baseCommit, pin.commit)
  assert.equal(patch.upstream.license, 'MIT')
  assert.match(readFileSync(join(root, patch.upstream.licenseFiles[0]), 'utf8'), /Copyright \(c\) 2026 DeepSeek/u)
})

function declaration(source, pattern) {
  const match = source.match(pattern)
  assert.ok(match, 'pinned environment declaration must exist')
  return match[0]
}

function loadPolicy(source, spawn, types, parent, overlay = {}, platform = 'linux') {
  const code = [
    declaration(types, /^export const DSH_ENV_PREFIX[^\n]+/mu),
    declaration(source, /^export const SENSITIVE_ENV_PATTERN[^\n]+/mu),
    declaration(source, /^export function scrubbedParentEnv\([^]*?^\}/mu),
    declaration(spawn, /^export function childEnv\([^]*?^\}/mu),
  ].join('\n')
  const javascript = stripTypeScriptTypes(code).replace(/^export /gmu, '')
  return vm.runInNewContext(`${javascript}\n;({ scrubbedParentEnv, childEnv })`, {
    process: { env: parent, platform }, proxyEnvironmentForChild: () => overlay,
  })
}

const sensitive = [
  'DEEPSEEK_API_KEY', 'SCRUB_PROBE_PASSWORD', 'SCRUB_PROBE_SECRET', 'SCRUB_PROBE_TOKEN',
  'SERVICE_AUTH', 'CREDENTIAL_CACHE', 'PRIVATE_CONFIG', 'SSH_AUTH_SOCK', 'SSH_AGENT_PID', 'GPG_AGENT_INFO',
  'DSH_SCRUB_PROBE', 'AUKORA_ROOT_DIR',
].flatMap(name => [name, name.toLowerCase()])
const ordinary = { PATH: '/fixture/bin', HOME: '/fixture/home', LANG: 'C.UTF-8', SCRUB_PROBE_PLAIN: 'visible' }
const parentEnv = () => ({ ...ordinary, ...Object.fromEntries(sensitive.map(name => [name, 'synthetic'])), OMIT: undefined })

function assertScrub(load) {
  const parent = parentEnv()
  const original = { ...parent }
  const { scrubbedParentEnv } = load(parent)
  const env = scrubbedParentEnv()
  for (const name of sensitive) assert.equal(Object.hasOwn(env, name), false, `inherited ${name}`)
  assert.equal(Object.hasOwn(env, 'OMIT'), false)
  assert.deepEqual({ ...env }, ordinary)
  env.SCRUB_PROBE_PLAIN = 'changed'
  assert.deepEqual({ ...scrubbedParentEnv() }, ordinary, 'each call returns a fresh environment')
  assert.deepEqual(parent, original, 'the parent environment is unchanged')
}

test('pinned DSH subprocess inheritance policy', {
  skip: !existsSync(archive) && 'UNPERFORMED: place the pinned archive at vendor/dsh-source.tar.gz; no download attempted',
}, async t => {
  const scratch = mkdtempSync(join(root, '.prime-check-subprocess-env-'))
  try {
    assert.equal(sha256(readFileSync(archive)), pin.archiveSha256)
    const sourceRoot = join(scratch, 'vendor/dsh')
    mkdirSync(sourceRoot, { recursive: true })
    copyFileSync(archive, join(scratch, 'vendor/dsh-source.tar.gz'))
    copyFileSync(join(root, 'upstream-dsh.json'), join(scratch, 'upstream-dsh.json'))
    cpSync(join(root, 'patches'), join(scratch, 'patches'), { recursive: true })
    execFileSync('tar', ['-xzf', archive, '--strip-components=1', '-C', sourceRoot])
    const read = relative => readFileSync(join(sourceRoot, relative), 'utf8')
    const before = read(sourceFile)
    const build = () => spawnSync('python3', [join(root, 'scripts/build-dsh.py'), '--root', scratch, '--patches-only'], {
      cwd: root, encoding: 'utf8', timeout: 30_000,
    })
    const applied = build()
    assert.equal(applied.status, 0, applied.stderr)
    assert.match(applied.stdout, /patch: applied patches\/subprocess-env-scrub.patch.json/u)
    t.diagnostic(applied.stdout.trim().split('\n').at(-1))
    const source = read(sourceFile)
    const spawn = read('packages/subprocess/subprocess-local/src/spawn.ts')
    const types = read('packages/subprocess/subprocess/src/types.ts')
    const load = (parent, overlay, platform) => loadPolicy(source, spawn, types, parent, overlay, platform)

    await t.test('translated donor scrub assertion; all categories, case folding and fresh output', () => {
      assertScrub(load)
      assert.throws(() => assertScrub(parent => loadPolicy(before, spawn, types, parent)), { code: 'ERR_ASSERTION' },
        'the pristine upstream must fail the carried assertion')
    })

    await t.test('explicit host entries override scrubbed inheritance and keep tombstones', () => {
      for (const platform of ['linux', 'win32']) {
        const extra = { ...Object.fromEntries(sensitive.map(name => [name, 'explicit'])), SCRUB_PROBE_PLAIN: undefined }
        // Use one spelling per key on Windows, which folds environment names.
        if (platform === 'win32') for (const name of sensitive) if (name !== name.toUpperCase()) delete extra[name]
        const env = load(parentEnv(), {}, platform).childEnv(extra)
        for (const name of Object.keys(extra)) assert.equal(env[name], extra[name])
        assert.equal(env.PATH, ordinary.PATH)
        const override = load({ Path: 'old' }, {}, platform).childEnv({ PATH: 'new' })
        assert.equal(override.PATH, 'new')
        assert.equal(Object.hasOwn(override, 'Path'), platform !== 'win32')
      }
    })

    await t.test('pinned proxy overlay and its deletion semantics survive the port', () => {
      const env = load({ HTTPS_PROXY: 'old', HTTP_PROXY: 'remove' }, {
        HTTPS_PROXY: 'http://proxy.invalid:8080', HTTP_PROXY: undefined, NODE_USE_ENV_PROXY: '1',
      }).scrubbedParentEnv()
      assert.deepEqual({ ...env }, { HTTPS_PROXY: 'http://proxy.invalid:8080', NODE_USE_ENV_PROXY: '1' })
    })

    await t.test('guard removal mutations fail the same behavioral assertions', () => {
      const mutations = [
        ...['KEY', 'PASSWORD', 'SECRET', 'TOKEN', 'AUTH', 'CREDENTIAL', 'PRIVATE', 'SSH_AGENT_PID', 'GPG_AGENT_INFO']
          .map(term => [term, text => text.replace(`|${term}`, '').replace(`/${term}|`, '/')]),
        ['sensitive case folding', text => text.replace('GPG_AGENT_INFO/i', 'GPG_AGENT_INFO/')],
        ['namespace case folding', text => text.replace('key.toUpperCase()', 'key')],
        ['DSH namespace', text => text.replace('!upper.startsWith(DSH_ENV_PREFIX)', 'true')],
        ['AUKORA namespace', text => text.replace("!upper.startsWith('AUKORA_')", 'true')],
      ]
      for (const [name, mutate] of mutations) {
        const changed = mutate(source)
        assert.notEqual(changed, source, name)
        assert.throws(() => assertScrub(parent => loadPolicy(changed, spawn, types, parent)), { code: 'ERR_ASSERTION' }, name)
      }
      const changed = spawn.replace('const env = scrubbedParentEnv()', 'const env = { ...process.env }')
      assert.notEqual(changed, spawn)
      assert.throws(() => assert.equal(loadPolicy(source, changed, types, parentEnv()).childEnv().AUKORA_ROOT_DIR, undefined),
        { code: 'ERR_ASSERTION' }, 'local childEnv must call the scrub')
      t.diagnostic(`${mutations.length + 1} guard removal mutations detected; pristine upstream also rejected`)
    })

    await t.test('the build refuses patch bytes changed without updating their digest', () => {
      writeFileSync(join(scratch, patchFile), `${patchBytes}\n`)
      const result = build()
      assert.equal(result.status, 1)
      assert.match(result.stderr, /patch-file-drift:/u)
    })
  } finally {
    rmSync(scratch, { recursive: true, force: true })
  }
})
