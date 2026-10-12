// Check emitted mount exports with inert imports; this does not qualify activation or import closure.
import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync, readdirSync, existsSync } from 'node:fs'
import { stripTypeScriptTypes } from 'node:module'
import { dirname, join, relative, resolve } from 'node:path'
import vm from 'node:vm'
import { root, source, generated, rows, sourcePath } from './helpers/release-composition.mjs'
// Module evaluation in a vm context sits behind a Node flag. Run plainly (as CI runs every test file),
// this file starts itself again with the flag and reports that run's result.
if (vm.SourceTextModule === undefined) {
  const { spawnSync } = await import('node:child_process')
  const again = spawnSync(process.execPath, ['--experimental-vm-modules', ...process.execArgv, ...process.argv.slice(1)], { stdio: 'inherit' })
  process.exit(again.status ?? 1)
}
const { createContext, SourceTextModule, SyntheticModule } = vm

async function mountable(path, upstream, replacement) {
  const context = createContext({ process: { platform: process.platform, env: {} } })
  const modules = new Map()
  const dummy = () => undefined
  function load(file) {
    if (modules.has(file)) return modules.get(file)
    const upstreamPath = relative(root, file).replace('/lib/', '/src/').replace(/\.js$/u, '.ts')
    const code = replacement?.path === file ? replacement.code
      : existsSync(file) ? readFileSync(file, 'utf8')
        : upstream === null && file === path && upstreamPath.startsWith('packages/') ? undefined
          : upstream?.[upstreamPath] === undefined ? null : stripTypeScriptTypes(upstream[upstreamPath], { mode: 'transform' })
    if (code === undefined) return undefined
    assert.notEqual(code, null, `overlay-mount:entry-absent: ${relative(root, file)}`)
    const reexports = new Set([...code.matchAll(/\bexport\s+(?:\*|\{[^}]*\})\s+from\s+['"]([^'"]+)['"]/gu)].map(match => match[1]))
    const names = [...new Set(['default', ...code.matchAll(/\b[A-Za-z_$][\w$]*\b/gu)].map(value => typeof value === 'string' ? value : value[0]))]
    const module = new SourceTextModule(code, { context, identifier: file })
    modules.set(file, module)
    module.dependencies = specifier => reexports.has(specifier) && specifier.startsWith('.')
      ? load(resolve(dirname(file), specifier))
      : new SyntheticModule(names, function () { for (const name of names) this.setExport(name, dummy) }, { context })
    return module
  }
  const module = load(path)
  if (module === undefined) return 'harness-row-not-inspected'
  await module.link((specifier, parent) => parent.dependencies(specifier))
  const accepted = () => {
    let plugin = module.namespace.default ?? module.namespace
    if (plugin?.__esModule) plugin = plugin.default ?? plugin
    return typeof plugin === 'function' || typeof plugin?.apply === 'function'
  }
  try { if (accepted()) return true }
  catch (error) { if (!(error instanceof ReferenceError)) throw error }
  // Default object/class and const bindings need initialization; their dependencies remain inert.
  await module.evaluate()
  return accepted()
}

async function check(input = source, overlayChanges = {}, replacement) {
  const fixture = generated(input)
  const patches = { ...fixture.patches }
  for (const name of readdirSync(join(root, 'overlays')).filter(name => /\.patch\.ya?ml$/u.test(name))) {
    patches[`overlays/${name}`] = overlayChanges[name] ?? readFileSync(join(root, 'overlays', name), 'utf8')
  }
  const only = rows(patches['aukora-aumlok-only.patch.yml'], 'aukora-aumlok-only.patch.yml')
  assert.equal(only.length, 1)
  assert.equal(only[0].name, './plugins/aukora-aumlok/lib/service.mjs', 'overlay-mount:aumlok-service-entry')
  const mounts = Object.entries(patches).flatMap(([name, text]) => rows(text, name)).filter(row => row.name)
  assert.ok(mounts.some(row => row.label === 'aukora-composition.patch.yml' && row.id === 'aukora-goal-resume'))
  assert.ok(mounts.some(row => row.label === 'aukora-composition.patch.yml' && row.id === 'aukora-eye'))
  let uninspected = 0
  for (const row of mounts) {
    const result = await mountable(sourcePath(row.name), fixture.upstream, replacement)
    if (result === 'harness-row-not-inspected') { uninspected++; continue }
    assert.equal(result, true, `overlay-mount:entry-not-plugin: ${row.label}:${row.id}:${row.name}`)
  }
  assert.ok(uninspected < mounts.length / 2, 'overlay-mount:most-rows-uninspected')
  return { inspected: mounts.length - uninspected, uninspected }
}
const archivePresent = existsSync(join(root, 'vendor/dsh-source.tar.gz'))

test('every emitted overlay and default composition mount names a plugin; id-only patches remain overrides', async t => {
  const counted = await check()
  t.diagnostic(`${counted.inspected} mount rows inspected, ${counted.uninspected} harness package rows not inspected`)
  assert.equal(counted.uninspected === 0, archivePresent)
})
test('rows naming harness packages are inspected against the pinned harness archive',
  { skip: archivePresent ? false : 'UNPERFORMED: the pinned harness archive (vendor/dsh-source.tar.gz) is not in this checkout' },
  async () => assert.equal((await check()).uninspected, 0))

test('mount export inspection accepts namespace apply and loader default function/object/class forms', async () => {
  const path = join(root, 'synthetic.mjs')
  for (const code of ['export function apply() {}', 'export const apply = () => {}', 'export default function() {}', 'export default { apply() {} }', 'export default class {}',
    'export default { __esModule: true, default: { apply() {} } }']) {
    assert.equal(await mountable(path, {}, { path, code }), true)
  }
  for (const code of ['export const apply = 1', 'export function apply() {}; export default {}',
    'export default { __esModule: true, apply() {}, default: {} }']) {
    assert.equal(await mountable(path, {}, { path, code }), false)
  }
})

test('mount protection mutants fail for the optional target, composition, overlay and missing apply', async () => {
  const target = '      name: ./plugins/aukora-aumlok/lib/service.mjs\\n\')'
  assert.equal(source.split(target).length - 1, 1, 'aumlok-only mutation target')
  await assert.rejects(check(source.replace(target, '      name: ./plugins/aukora-aumlok/lib/index.mjs\\n\')')), /overlay-mount:aumlok-service-entry/u)
  const eye = './plugins/aukora-eye/lib/index.js'
  await assert.rejects(check(source.replace(eye, './plugins/aukora-aumlok/lib/canonical.mjs')), /overlay-mount:entry-not-plugin/u)
  const overlay = readFileSync(join(root, 'overlays/caged-worker.patch.yml'), 'utf8')
  await assert.rejects(check(source, { 'caged-worker.patch.yml': overlay.replace('./plugins/aukora-caged-worker/lib/index.mjs', './plugins/aukora-aumlok/lib/canonical.mjs') }), /overlay-mount:entry-not-plugin/u)
  await assert.rejects(check(source, { 'caged-worker.patch.yml': '- insert:\n    - name: ./plugins/aukora-aumlok/lib/canonical.mjs\n' }), /overlay-mount:entry-not-plugin/u)
  await assert.rejects(check(source, { 'caged-worker.patch.yml': overlay.replace('      name: ./plugins/aukora-caged-worker/lib/index.mjs\n', '') }), /overlay-mount:insert-without-name/u)
  const path = join(root, 'plugins/aukora-goal-resume/lib/index.mjs')
  const original = readFileSync(path, 'utf8')
  assert.equal(original.split('export function apply(').length - 1, 1, 'apply mutation target')
  await assert.rejects(check(source, {}, { path, code: original.replace('export function apply(', 'function apply(') }), /overlay-mount:entry-not-plugin/u)
})
