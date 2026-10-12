// Check emitted mount exports with inert imports; this does not qualify activation or import closure.
import test from 'node:test'
import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { readFileSync, readdirSync, existsSync } from 'node:fs'
import { stripTypeScriptTypes } from 'node:module'
import { dirname, join, relative, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import vm from 'node:vm'
// Module evaluation in a vm context sits behind a Node flag. Run plainly (as CI runs every test file),
// this file starts itself again with the flag and reports that run's result.
if (vm.SourceTextModule === undefined) {
  const { spawnSync } = await import('node:child_process')
  const again = spawnSync(process.execPath, ['--experimental-vm-modules', ...process.execArgv, ...process.argv.slice(1)], { stdio: 'inherit' })
  process.exit(again.status ?? 1)
}
const { createContext, SourceTextModule, SyntheticModule } = vm

const root = fileURLToPath(new URL('../', import.meta.url))
const builder = join(root, 'scripts/materialize-aukora-release.py')
const source = readFileSync(builder, 'utf8')
const release = '/synthetic/release'

function generated(input = source) {
  return JSON.parse(execFileSync('/usr/bin/python3', ['-I', '-S', '-B', '-c', `
import ast, hashlib, json, re, sys, tarfile
from pathlib import Path
from types import SimpleNamespace
source = sys.stdin.read()
path = sys.argv[1]
ns = dict(__file__=path, __name__='mount_fixture')
exec(compile(source, path, 'exec'), ns)
main = next(n for n in ast.parse(source).body if isinstance(n, ast.FunctionDef) and n.name == 'main')
patches = {}
class Patch:
    def __init__(self, name): self.name = name
    def read_text(self, **kwargs): return patches.get(self.name, '')
ns.update(target=Path('/synthetic/release'), args=SimpleNamespace(development=False, kira_openviking_home=None, kira_project_map=None),
          patch=Patch('aukora-composition.patch.yml'), default_patch=Patch('aukora-composition.patch.yml'),
          hmr_row=ns['hmr_disable_row'](False))
for node in main.body:
    if not isinstance(node, ast.Expr) or not isinstance(node.value, ast.Call): continue
    call = node.value
    if not isinstance(call.func, ast.Attribute) or call.func.attr != 'write_text': continue
    target = call.func.value
    name = 'aukora-composition.patch.yml' if isinstance(target, ast.Name) and target.id in ('patch', 'default_patch') else None
    if isinstance(target, ast.BinOp) and isinstance(target.left, ast.Name) and target.left.id == 'target' and isinstance(target.right, ast.Constant):
        name = target.right.value
    if name and name.endswith('.patch.yml'):
        patches[name] = eval(compile(ast.Expression(call.args[0]), path, 'eval'), ns)
archive = ns['ROOT'] / 'vendor/dsh-source.tar.gz'
if not archive.is_file(): raise SystemExit('overlay-mount:harness-archive-unavailable')
pin = json.loads((ns['ROOT'] / 'upstream-dsh.json').read_text())
if hashlib.sha256(archive.read_bytes()).hexdigest() != pin['archiveSha256']:
    raise SystemExit('overlay-mount:harness-archive-pin')
with tarfile.open(archive, 'r:gz') as tar:
    package_roots = set()
    for patch in patches.values():
        for match in re.finditer(r'^\\s*name: (?:\\./|/synthetic/release/)(packages/[^\\n]+?)/lib/index.js$', patch, re.M):
            package_roots.add(match.group(1) + '/src/')
    upstream = {}
    for entry in tar.getmembers():
        path = entry.name.partition('/')[2]
        if entry.isfile() and any(path.startswith(prefix) for prefix in package_roots) and path.endswith('.ts'):
            upstream[path] = tar.extractfile(entry).read().decode('utf-8')
print(json.dumps(dict(patches=patches, upstream=upstream)))
`, builder], { cwd: root, input, encoding: 'utf8', env: { PATH: process.env.PATH, HOME: '/synthetic/home' } }))
}

function rows(patch, label) {
  const result = []
  let row
  for (const line of patch.split('\n')) {
    const id = /^(\s*)- id: (\S+)\s*$/u.exec(line)
    if (id) { row = { id: id[2], indent: id[1].length, label }; result.push(row); continue }
    const anonymous = /^(\s*)- name: (.+?)\s*$/u.exec(line)
    if (anonymous) {
      row = { id: '<anonymous>', indent: anonymous[1].length, label, name: anonymous[2].replace(/^(['"])(.*)\1$/u, '$2') }
      result.push(row); continue
    }
    const name = /^(\s*)name: (.+?)\s*$/u.exec(line)
    if (name) {
      assert.ok(row && name[1].length === row.indent + 2, `overlay-mount:unmatched-name: ${label}`)
      row.name = name[2].replace(/^(['"])(.*)\1$/u, '$2')
    }
  }
  for (const row of result) assert.ok(row.name || row.indent === 0, `overlay-mount:insert-without-name: ${label}:${row.id}`)
  return result
}

function sourcePath(name) {
  let path = name.startsWith(`${release}/`) ? name.slice(release.length + 1) : name.replace(/^\.\//u, '')
  path = path.replace(/^plugins\/aukora-face-([^/]+)\//u, 'plugins/aukora-face/$1/')
  if (path === 'plugins/aukora-aura-association/lib/index.js') path = 'scripts/aura/composition/association-plugin.js'
  return resolve(root, path)
}

async function mountable(path, upstream, replacement) {
  const context = createContext({ process: { platform: process.platform, env: {} } })
  const modules = new Map()
  const dummy = () => undefined
  function load(file) {
    if (modules.has(file)) return modules.get(file)
    const upstreamPath = relative(root, file).replace('/lib/', '/src/').replace(/\.js$/u, '.ts')
    const code = replacement?.path === file ? replacement.code
      : existsSync(file) ? readFileSync(file, 'utf8')
        : upstream[upstreamPath] === undefined ? null : stripTypeScriptTypes(upstream[upstreamPath], { mode: 'transform' })
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
  for (const row of mounts) assert.equal(await mountable(sourcePath(row.name), fixture.upstream, replacement), true,
    `overlay-mount:entry-not-plugin: ${row.label}:${row.id}:${row.name}`)
}

test('every emitted overlay and default composition mount names a plugin; id-only patches remain overrides', () => check())

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
