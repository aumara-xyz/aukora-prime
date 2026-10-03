// SPDX-License-Identifier: AGPL-3.0-or-later
// Compiler-hook regression only; no bundle, browser, host or runtime qualification.
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { readFile, mkdir, mkdtemp, realpath, rm, symlink, writeFile } from 'node:fs/promises'
import { createRequire } from 'node:module'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { OWNER_CONFIG, OWNER_ID } from '../../scripts/verify-owner-build.mjs'

const args = process.argv.slice(2)
const dshArgument = args.length === 1 ? args[0]
  : args.length === 2 && args[0] === '--dsh' ? args[1] : null
assert.ok(dshArgument, 'usage: node css-reproduction.mjs --dsh <pinned-dsh-root>')
const dshRoot = resolve(dshArgument)
const presetPath = join(dshRoot, 'packages/client/tsdown.client.ts')
const presetRequire = createRequire(pathToFileURL(presetPath))
const cssPackage = JSON.parse(await readFile(
  join(dirname(presetRequire.resolve('lightningcss')), '../package.json'), 'utf8'))
assert.equal(cssPackage.version, '1.32.0',
  'the check requires the frozen LightningCSS version')
const { transform } = presetRequire('lightningcss')
const { clientBundle } = await import(pathToFileURL(presetPath).href)
const sourceRoot = resolve(dirname(fileURLToPath(import.meta.url)), '../src/client')
const names = ['OwnerSurface.module.css', 'PrimeProviderEditor.module.css']
const cssSources = await Promise.all(names.map(name => readFile(join(sourceRoot, name))))
const sha256 = bytes => createHash('sha256').update(bytes).digest('hex')

// Compare hook/config source without exercising any bundler or module-table effect.
function comparable(value) {
  if (typeof value === 'function') return { function_source: value.toString() }
  if (value instanceof RegExp) return { regexp: value.toString() }
  if (Array.isArray(value)) return value.map(comparable)
  if (value && typeof value === 'object') return Object.fromEntries(
    Object.entries(value).map(([key, entry]) => [key, comparable(entry)]))
  return value
}
function cssPlugin(config) {
  const matches = config.plugins.filter(plugin => plugin?.name === 'dsh-css-modules-inline')
  assert.equal(matches.length, 1, 'expected one actual DSH CSS module hook')
  assert.equal(typeof matches[0].load, 'function')
  return matches[0]
}
function cssPayload(module) {
  const lines = module.split('\n')
  assert.ok(lines[0].startsWith('const css = ') && lines[0].endsWith(';'))
  assert.ok(lines.at(-1).startsWith('export default ') && lines.at(-1).endsWith(';'))
  return {
    css: JSON.parse(lines[0].slice('const css = '.length, -1)),
    classes: JSON.parse(lines.at(-1).slice('export default '.length, -1)),
  }
}
function classMap(exports) {
  return Object.fromEntries(Object.entries(exports ?? {})
    .sort(([left], [right]) => left < right ? -1 : left > right ? 1 : 0)
    .map(([local, entry]) => [local, entry.name]))
}
const root = await realpath(await mkdtemp(join(tmpdir(), 'prime-css-reproduction-')))
try {
  const upstreamFactory = clientBundle(OWNER_ID, [], { hostPhase: true })
  const options = { env: { DSH_BUILD_FACE: 'client' } }
  const [upstreamConfig] = upstreamFactory(options)
  const upstreamPlugin = cssPlugin(upstreamConfig)
  const seatResults = []
  for (const seatName of ['physical-seat-one', 'different-physical-seat-two']) {
    const seatRoot = join(root, seatName, 'dsh')
    const ownerRoot = join(seatRoot, 'packages/client/aukora-prime-authority')
    const cssRoot = join(ownerRoot, 'src/client')
    await mkdir(cssRoot, { recursive: true })
    await symlink(join(dshRoot, 'node_modules'), join(seatRoot, 'node_modules'), 'dir')
    await symlink(presetPath, join(seatRoot, 'packages/client/tsdown.client.ts'))
    await writeFile(join(ownerRoot, '.prime-client.config.ts'), OWNER_CONFIG)
    await Promise.all(names.map((name, index) => writeFile(join(cssRoot, name), cssSources[index])))
    const { default: factory } = await import(
      pathToFileURL(join(ownerRoot, '.prime-client.config.ts')).href)
    const [config] = factory(options)
    const plugin = cssPlugin(config)
    const { plugins: upstreamPlugins, ...upstreamRest } = upstreamConfig
    const { plugins, ...rest } = config
    assert.deepEqual(comparable(rest), comparable(upstreamRest),
      'the adapter changed non-plugin client configuration')
    assert.equal(plugins.length, upstreamPlugins.length)
    for (let index = 0; index < plugins.length; index++) {
      if (plugins[index] === plugin) {
        const { load: oldLoad, ...oldHooks } = upstreamPlugins[index]
        const { load, ...hooks } = plugin
        assert.notEqual(load.toString(), oldLoad.toString(), 'owned CSS hook was not adapted')
        assert.deepEqual(comparable(hooks), comparable(oldHooks),
          'the adapter changed the physical resolver or other CSS hook properties')
      } else {
        assert.deepEqual(comparable(plugins[index]), comparable(upstreamPlugins[index]),
          'the adapter changed another preset plugin')
      }
    }
    assert.deepEqual(comparable(factory({ env: { DSH_BUILD_FACE: 'host' } })),
      comparable(upstreamFactory({ env: { DSH_BUILD_FACE: 'host' } })),
      'the adapter changed the host configuration')
    const results = []
    for (let index = 0; index < names.length; index++) {
      const fileId = join(cssRoot, names[index])
      const virtualId = `\0dsh-css:${fileId}.mjs`
      assert.equal(plugin.resolveId(`./${names[index]}`, join(cssRoot, 'index.ts')), virtualId,
        'the resolver must retain the exact physical stylesheet ID')
      const watched = []
      const module = await plugin.load.call({ addWatchFile: path => watched.push(path) }, virtualId)
      assert.deepEqual(watched, [fileId], 'the watch input must remain the physical stylesheet')
      const actual = cssPayload(module)
      const expected = transform({ filename: fileId, projectRoot: seatRoot,
        code: cssSources[index], cssModules: { pattern: '[hash]_[local]' }, minify: true })
      assert.equal(actual.css, expected.code.toString(), 'CSS differs from the actual pinned compiler')
      assert.deepEqual(actual.classes, classMap(expected.exports),
        'class map differs from the actual pinned compiler')
      assert.deepEqual(Object.keys(actual.classes), Object.keys(actual.classes).sort(),
        'class-map order changed')
      const rawWatched = []
      const rawModule = await upstreamPlugin.load.call(
        { addWatchFile: path => rawWatched.push(path) }, virtualId)
      assert.deepEqual(rawWatched, [fileId])
      results.push({ module, actual, rawModule, raw: cssPayload(rawModule) })
    }
    // A third ordinary stylesheet delegates unchanged to the original hook.
    const otherFile = join(cssRoot, 'ordinary-check.module.css')
    await writeFile(otherFile, '.ordinary { color: red }')
    const otherId = `\0dsh-css:${otherFile}.mjs`
    const originalWatch = [], adaptedWatch = []
    assert.equal(await plugin.load.call({ addWatchFile: path => adaptedWatch.push(path) }, otherId),
      await upstreamPlugin.load.call({ addWatchFile: path => originalWatch.push(path) }, otherId),
      'the adapter changed an unselected stylesheet')
    assert.deepEqual(adaptedWatch, originalWatch)
    assert.deepEqual(adaptedWatch, [otherFile])
    assert.equal(await plugin.load.call({ addWatchFile() { assert.fail('non-CSS input watched') } },
      'ordinary-module.js'), null, 'the adapter changed non-CSS delegation')
    seatResults.push(results)
  }
  for (let index = 0; index < names.length; index++) {
    const [first, second] = seatResults.map(seat => seat[index])
    assert.equal(first.module, second.module,
      'generated hook bytes differ between physical seats')
    assert.deepEqual(first.actual, second.actual,
      'CSS payload or complete class map differs between physical seats')
    assert.notEqual(first.rawModule, second.rawModule,
      'the upstream compiler must reproduce the original physical-path variation')
    assert.notEqual(first.raw.css, second.raw.css)
    assert.notDeepEqual(first.raw.classes, second.raw.classes)
  }
  console.log(JSON.stringify({ result: 'PASS', check: 'actual-pinned-css-hook-reproduction',
    owner_config_sha256: sha256(Buffer.from(OWNER_CONFIG)),
    preset_sha256: sha256(await readFile(presetPath)), lightningcss_version: '1.32.0',
    physical_seats: 2, selected_stylesheets: names.map((name, index) => ({ name,
      source_sha256: sha256(cssSources[index]),
      generated_module_sha256: sha256(Buffer.from(seatResults[0][index].module)),
      classes: Object.keys(seatResults[0][index].actual.classes).length })),
    generated_hook_bytes: 'IDENTICAL', css_payload_and_complete_class_maps: 'IDENTICAL',
    unadapted_physical_path_variation: 'REPRODUCED', physical_resolution_and_watch: 'PRESERVED',
    other_preset_hooks_and_delegation: 'PRESERVED', full_bundle_reproduction: 'UNPERFORMED',
    runtime_acceptance: 'UNPERFORMED' }))
} finally {
  await rm(root, { recursive: true, force: true })
}
