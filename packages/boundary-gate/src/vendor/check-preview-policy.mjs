#!/usr/bin/env node
// Focused source-policy checks. Synthetic configuration only; no backend, key or real support root.
// The Python check executes only the launcher's AST-selected argument/profile prefix, never launch code.
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { lstat, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { assertDesktopLaunchConfig, CONFIG_TEMPLATE, loadConfig, resolveTarget } from '../../../../apps/aukora-desktop/resolve.mjs'
import { launcherProfileArguments, startHarness } from '../../../../apps/aukora-desktop/supervisor.mjs'
import { assertProductionCutoverConfig } from '../../../../scripts/aukora/desktop-cutover.mjs'

const scratch = await mkdtemp(join(tmpdir(), 'aukora-preview-policy-'))
const resolverPath = fileURLToPath(new URL('../../../../apps/aukora-desktop/resolve.mjs', import.meta.url))
const launcherPath = fileURLToPath(new URL('../../../../scripts/launch-dsh.py', import.meta.url))
const unsafeKey = 'unsafePreviewAllowUnapproved'
const legacyKey = 'allowUnapproved'
const productionRefusal = /unsafe-preview-configuration-refused/u
const legacyRefusal = /legacy-preview-setting-refused/u

function productionOracle(guard = assertDesktopLaunchConfig) {
  for (const value of [false, true, undefined, null, 'false', 0]) {
    assert.throws(() => guard({ [unsafeKey]: value }), productionRefusal)
  }
}

function legacyOracle(guard = assertDesktopLaunchConfig) {
  for (const profile of ['production', 'disposable-preview']) {
    for (const value of [false, true, undefined]) {
      assert.throws(() => guard({ [legacyKey]: value }, profile), legacyRefusal)
    }
  }
}

const pythonWorker = String.raw`
import ast, json, sys
payload = json.load(sys.stdin)
tree = ast.parse(payload['source'], filename='launch-dsh.py')
cut = next(i for i, node in enumerate(tree.body) if isinstance(node, ast.FunctionDef) and node.name == '_root_protected')
prefix = ast.Module(body=tree.body[:cut], type_ignores=[])
sys.argv = ['launch-dsh.py', '--release', '/fixture/release', '--state-root', '/fixture/state', *payload['argv']]
sys.platform = 'linux'
scope = {}
exec(compile(prefix, 'launch-dsh.py:argument-prefix', 'exec'), scope)
a = scope['a']
print(json.dumps({'profile': a.launch_profile, 'unsafe': a.unsafe_preview_allow_unapproved, 'ungated': a.unsafe_preview_allow_ungated}))
`

function cli(source, argv) {
  const result = spawnSync(process.env.PYTHON ?? '/usr/bin/python3', ['-c', pythonWorker], {
    input: JSON.stringify({ source, argv }), encoding: 'utf8', timeout: 10_000,
  })
  assert.equal(result.error, undefined, 'argument-prefix worker must be available')
  return result
}

function cliRefusalOracle(source) {
  for (const flag of ['--unsafe-preview-allow-unapproved', '--unsafe-preview-allow-ungated']) {
    const result = cli(source, [flag])
    assert.equal(result.status, 2, 'production must refuse ' + flag)
    assert.match(result.stderr, /unsafe-preview-options-refused/u)
  }
}

try {
  productionOracle()
  legacyOracle()
  for (const profile of [null, true, false, 1, {}, [], '', 'preview', 'PRODUCTION']) {
    assert.throws(() => assertDesktopLaunchConfig({}, profile), /launch-profile-refused/u)
    assert.throws(() => launcherProfileArguments({ launchProfile: profile }), /launch-profile-refused/u)
  }
  for (const file of [null, [], true, 1, 'config']) {
    assert.throws(() => assertDesktopLaunchConfig(file), /desktop-config-malformed/u)
  }
  for (const value of ['true', 'false', null, 1, undefined]) {
    assert.throws(() => assertDesktopLaunchConfig({ [unsafeKey]: value }, 'disposable-preview'), /unsafe-preview-setting-malformed/u)
  }
  assert.deepEqual(launcherProfileArguments({}), ['--launch-profile', 'production'])
  for (const value of [false, true]) {
    const options = { launchProfile: 'disposable-preview', [unsafeKey]: value }
    assertDesktopLaunchConfig(options, options.launchProfile)
    assert.deepEqual(launcherProfileArguments(options), ['--launch-profile', 'disposable-preview',
      ...(value ? ['--unsafe-preview-allow-unapproved'] : [])])
    assert.throws(() => launcherProfileArguments({ [unsafeKey]: value }), productionRefusal)
    assert.throws(() => assertProductionCutoverConfig({ [unsafeKey]: value }), productionRefusal)
  }
  assert.throws(() => assertProductionCutoverConfig({ [legacyKey]: false }), legacyRefusal)
  assertProductionCutoverConfig({ approvedRecordSha: [] })

  let unsafeValueRead = false
  const unparsed = { get unsafePreviewAllowUnapproved() { unsafeValueRead = true; return false } }
  assert.throws(() => assertDesktopLaunchConfig(unparsed), productionRefusal)
  assert.throws(() => launcherProfileArguments(unparsed), productionRefusal)
  assert.equal(unsafeValueRead, false, 'production must reject presence before reading the unsafe value')
  const noStateAccess = { [unsafeKey]: false, get stateRoot() { throw new Error('state accessed before refusal') } }
  await assert.rejects(startHarness(noStateAccess), productionRefusal)
  assert.deepEqual(launcherProfileArguments(Object.create({ launchProfile: 'disposable-preview', [unsafeKey]: true })),
    ['--launch-profile', 'production'], 'inherited settings are not an explicit preview selection')

  for (const [key, value] of [[unsafeKey, false], [unsafeKey, true], [legacyKey, false], [legacyKey, true]]) {
    const userData = join(scratch, key + '-' + value)
    await mkdir(userData)
    const configPath = join(userData, 'config.json')
    const bytes = JSON.stringify({ attachUrl: 'http://127.0.0.1:3187/?token=fixture', [key]: value }) + '\n'
    await writeFile(configPath, bytes)
    const refusal = key === unsafeKey ? productionRefusal : legacyRefusal
    await assert.rejects(loadConfig(userData), refusal)
    await assert.rejects(resolveTarget({ env: {}, userData, checkoutsDir: join(userData, 'checkouts') }), refusal)
    assert.equal(await readFile(configPath, 'utf8'), bytes)
    for (const path of ['checkouts', 'state', 'aumlok-directory.patch.yml']) {
      await assert.rejects(lstat(join(userData, path)), { code: 'ENOENT' })
    }
  }

  const missing = join(scratch, 'missing-config')
  await assert.rejects(loadConfig(missing, { launchProfile: null }), /launch-profile-refused/u)
  await assert.rejects(lstat(missing), { code: 'ENOENT' })
  const loaded = await loadConfig(missing)
  assert.equal(Object.hasOwn(loaded.file, unsafeKey), false)
  assert.equal(Object.hasOwn(loaded.file, legacyKey), false)
  const unapprovedRelease = join(scratch, 'unapproved-release')
  await mkdir(join(unapprovedRelease, '.dsh-build'), { recursive: true })
  await writeFile(join(unapprovedRelease, '.dsh-build/genesis-artifacts.json'),
    JSON.stringify({ producer: { genesisCommit: '1'.repeat(40) } }))
  await assert.rejects(resolveTarget({ env: { AUKORA_DESKTOP_RELEASE: unapprovedRelease },
    userData: missing, checkoutsDir: join(missing, 'checkouts') }), /unapproved-release/u)
  await assert.rejects(lstat(join(missing, 'checkouts')), { code: 'ENOENT' })
  CONFIG_TEMPLATE[unsafeKey] = true
  try {
    await assert.rejects(loadConfig(join(scratch, 'unsafe-template'), { launchProfile: 'disposable-preview' }), productionRefusal)
    await assert.rejects(lstat(join(scratch, 'unsafe-template')), { code: 'ENOENT' })
  } finally { delete CONFIG_TEMPLATE[unsafeKey] }
  console.log('PASS production config, attach, supervisor and cutover reject unsafe presence; no implicit first-run waiver')

  const source = await readFile(resolverPath, 'utf8')
  for (const [name, anchor, replacement, oracle] of [
    ['production-presence', "if (launchProfile !== 'disposable-preview') {", 'if (false) {', productionOracle],
    ['legacy-presence', "if (Object.hasOwn(file, 'allowUnapproved')) {", 'if (false) {', legacyOracle],
  ]) {
    assert.equal(source.split(anchor).length, 2, 'mutation must replace one policy guard')
    const mutantSource = source.replace(anchor, replacement).replace(/from (['"])(\.[^'"]+)\1/gu,
      (_match, _quote, specifier) => 'from ' + JSON.stringify(new URL(specifier, pathToFileURL(resolverPath)).href))
    const mutantPath = join(scratch, name + '.mjs')
    await writeFile(mutantPath, mutantSource)
    const mutant = await import(pathToFileURL(mutantPath).href)
    assert.throws(() => oracle(mutant.assertDesktopLaunchConfig), error => error.code === 'ERR_ASSERTION')
    console.log('RED caught: removing ' + name + ' guard violates its policy oracle')
  }

  const launcherSource = await readFile(launcherPath, 'utf8')
  cliRefusalOracle(launcherSource)
  const normal = cli(launcherSource, [])
  assert.equal(normal.status, 0)
  assert.deepEqual(JSON.parse(normal.stdout), { profile: 'production', unsafe: false, ungated: false })
  for (const [flag, field] of [['--unsafe-preview-allow-unapproved', 'unsafe'], ['--unsafe-preview-allow-ungated', 'ungated']]) {
    const preview = cli(launcherSource, ['--launch-profile', 'disposable-preview', flag])
    assert.equal(preview.status, 0)
    assert.equal(JSON.parse(preview.stdout)[field], true)
  }
  for (const flag of ['--allow-unapproved', '--allow-ungated']) {
    assert.equal(cli(launcherSource, ['--launch-profile', 'disposable-preview', flag]).status, 2)
  }
  assert.equal(cli(launcherSource, ['--launch-profile', 'preview']).status, 2)
  const service = cli(launcherSource, ['--foreground', '--launch-profile', 'disposable-preview'])
  assert.equal(service.status, 2)
  assert.match(service.stderr, /foreground-requires-approval/u)
  const cliAnchor = "if a.launch_profile != 'disposable-preview' and (a.unsafe_preview_allow_unapproved or a.unsafe_preview_allow_ungated):"
  assert.equal(launcherSource.split(cliAnchor).length, 2)
  assert.throws(() => cliRefusalOracle(launcherSource.replace(cliAnchor, 'if False:')), error => error.code === 'ERR_ASSERTION')
  console.log('RED caught: removing launcher profile guard admits unsafe production flags')
  console.log('PASS preview-policy: source argument/configuration checks only; launch and runtime qualification excluded')
} finally {
  await rm(scratch, { recursive: true, force: true })
}
