// Materialization refuses face bundles whose recorded source or output bytes changed.
import test from 'node:test'
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { mkdirSync, mkdtempSync, rmSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { join } from 'node:path'

const root = fileURLToPath(new URL('../', import.meta.url))
const fixtureParent = join(root, '.runtime')
const faces = ['layout', 'sidebar', 'threads', 'apps', 'messages', 'documents', 'aumlok', 'settings', 'memory']
const python = String.raw`
import ast, importlib.machinery, importlib.util, json, shutil, sys, types
from pathlib import Path
root, fixture = map(Path, sys.argv[1:3])
change, mutant = sys.argv[3:5]
materializer = root / 'scripts/materialize-aukora-release.py'
tree = ast.parse(materializer.read_text())
if mutant in ('copy-output', 'copy-manifest'):
    main = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'main')
    loop = next(n for n in main.body if isinstance(n, ast.For) and isinstance(n.iter, ast.Name) and n.iter.id == 'FACE_PACKAGES')
    reason = 'face-bundle-output-mismatch' if mutant == 'copy-output' else 'face-build-manifest-changed'
    changed = [0]
    class CopyFailOpen(ast.NodeTransformer):
        def visit_Expr(self, node):
            call = node.value
            if isinstance(call, ast.Call) and isinstance(call.func, ast.Name) and call.func.id == 'fail' and reason in ast.unparse(call):
                changed[0] += 1
                return ast.copy_location(ast.Pass(), node)
            return self.generic_visit(node)
    CopyFailOpen().visit(loop)
    assert changed[0] == 1
elif mutant == 'face-preflight':
    main = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'main')
    calls = [n for n in ast.walk(main) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
             and n.func.id == 'assert_face_bundles_current']
    assert len(calls) == 1
    calls[0].func.id = 'dict'
elif mutant and not mutant.startswith('omit-'):
    guard = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'assert_face_bundles_current')
    changed = [0]
    class FailOpen(ast.NodeTransformer):
        def visit_Expr(self, node):
            call = node.value
            if isinstance(call, ast.Call) and isinstance(call.func, ast.Name) and call.func.id == 'fail':
                text = ast.unparse(call.args[0])
                if mutant in text:
                    changed[0] += 1
                    return ast.copy_location(ast.Return(value=ast.Constant(value=None)), node)
            return self.generic_visit(node)
    FailOpen().visit(guard)
    assert changed[0] == (2 if mutant == 'face-build-manifest-invalid' else 1), changed
m = types.ModuleType('materializer'); m.__file__ = str(materializer)
exec(compile(ast.fix_missing_locations(tree), str(materializer), 'exec'), vars(m))
face_root = fixture / 'plugins/aukora-face'
face_root.mkdir(parents=True)
for relative in ('scripts/build-face.py', 'scripts/build-face-bundles.sh', 'upstream-dsh.json', 'plugins/aukora-face/tsdown.client.ts'):
    target = fixture / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(root / relative, target)
if mutant.startswith('omit-'):
    builder_path = root / 'scripts/build-face.py'
    builder_tree = ast.parse(builder_path.read_text())
    digest = next(n for n in builder_tree.body if isinstance(n, ast.FunctionDef) and n.name == 'src_digest')
    changed = [0]
    class OmitInput(ast.NodeTransformer):
        def visit_Tuple(self, node):
            removed = {'omit-assets': {'assets'}, 'omit-vendor': {'vendor'},
                       'omit-tsconfig': {'tsconfig.json', 'tsconfig.client.json', 'tsconfig.host.json'}}.get(mutant, set())
            remaining = [n for n in node.elts if not (isinstance(n, ast.Constant) and n.value in removed)]
            changed[0] += len(node.elts) - len(remaining)
            node.elts = remaining
            return self.generic_visit(node)
        def visit_If(self, node):
            if mutant == 'omit-aumlok' and ast.unparse(node.test) == "name == 'aumlok'":
                changed[0] += 1
                return ast.copy_location(ast.Pass(), node)
            return self.generic_visit(node)
        def visit_Expr(self, node):
            if mutant == 'omit-shared' and "'../../../scripts/build-face.py'" in ast.unparse(node):
                changed[0] += 1
                return ast.copy_location(ast.Pass(), node)
            return self.generic_visit(node)
    OmitInput().visit(digest)
    assert changed[0] == (3 if mutant == 'omit-tsconfig' else 1), changed
    original_spec = importlib.util.spec_from_file_location
    class MutantBuilder(importlib.machinery.SourceFileLoader):
        def get_code(self, fullname):
            return compile(ast.fix_missing_locations(builder_tree), str(builder_path), 'exec')
    def builder_spec(name, location, *args, **kwargs):
        if Path(location) == builder_path:
            return importlib.util.spec_from_loader(name, MutantBuilder(name, str(location)))
        return original_spec(name, location, *args, **kwargs)
    importlib.util.spec_from_file_location = builder_spec
spec = importlib.util.spec_from_file_location('builder', root / 'scripts/build-face.py')
b = importlib.util.module_from_spec(spec); spec.loader.exec_module(b)
b.FACE = face_root
m.FACE = face_root
for face in m.FACE_PACKAGES:
    package = face_root / face
    for directory in ('src', 'lib', 'assets', 'vendor'):
        (package / directory).mkdir(parents=True)
    for relative, content in {
        'src/index.ts': 'export const value = 1;\n',
        'package.json': json.dumps({'name': '@aukora/face-' + face, 'type': 'module'}),
        'tsconfig.json': '{}\n', 'tsconfig.client.json': '{}\n', 'tsconfig.host.json': '{}\n',
        'assets/icon.svg': '<svg/>\n', 'vendor/helper.js': 'export const vendor = 1;\n',
    }.items():
        (package / relative).write_text(content)
    shutil.copy2(root / 'plugins/aukora-face' / face / 'tsdown.config.ts', package / 'tsdown.config.ts')
    for output in b.bundle_outputs(face):
        (package / 'lib' / output).write_text('export const value = 1;\n')
for name in ('qr-scanner.ts', 'add-contact.ts'):
    target = face_root / 'messages/src/client' / name
    target.parent.mkdir(exist_ok=True)
    target.write_text('export const helper = 1;\n')
for face in m.FACE_PACKAGES:
    package = face_root / face
    (package / 'lib/.build-inputs.json').write_text(json.dumps(b.build_record(face)))
manifest = face_root / 'apps/lib/.build-inputs.json'
if change == 'missing-manifest': manifest.unlink()
elif change == 'invalid-json': manifest.write_text('{')
elif change == 'old-manifest':
    record = json.loads(manifest.read_text()); record.pop('formatVersion'); manifest.write_text(json.dumps(record))
elif change == 'wrong-face':
    record = json.loads(manifest.read_text()); record['face'] = 'layout'; manifest.write_text(json.dumps(record))
elif change.startswith('source:'):
    path = face_root / change.split(':')[1] / 'src/index.ts'
    path.write_text(path.read_text().replace('1', '2', 1))
elif change.startswith('output:'):
    path = face_root / change.split(':')[1] / 'lib/index.js'
    path.write_text(path.read_text().replace('1', '2', 1))
elif change.startswith('input:'):
    path = fixture / change.split(':', 1)[1]
    path.write_text(path.read_text() + '\n')
    if change.endswith('messages/src/client/qr-scanner.ts'):
        m.FACE_PACKAGES = ('aumlok',)
elif change == 'added-source': (face_root / 'apps/src/extra.ts').write_text('export {}\n')
elif change == 'removed-source': (face_root / 'apps/src/index.ts').unlink()
elif change == 'missing-output': (face_root / 'apps/lib/auma-canvas-tool.js').unlink()
elif change == 'unrecorded-output':
    record = json.loads(manifest.read_text()); record['outputs']['unreviewed.js'] = '0' * 64
    manifest.write_text(json.dumps(record))
elif change.startswith('copy-'):
    records = m.assert_face_bundles_current()
    if change == 'copy-output':
        path = face_root / 'apps/lib/index.js'; path.write_text(path.read_text().replace('1', '2', 1))
    elif change == 'copy-manifest': manifest.write_text(json.dumps({'changed': True}))
    elif change == 'copy-invalid-manifest': manifest.write_text('{')
    main = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'main')
    loop = next(n for n in main.body if isinstance(n, ast.For) and isinstance(n.iter, ast.Name) and n.iter.id == 'FACE_PACKAGES')
    namespace = dict(vars(m), target=fixture / 'release', face_builds=records)
    exec(compile(ast.Module(body=[loop], type_ignores=[]), str(materializer), 'exec'), namespace)
    print('FACE COPY ACCEPTED')
    sys.exit(0)
elif change == 'main-source':
    path = face_root / 'apps/src/index.ts'; path.write_text(path.read_text() + '\n')
    target = fixture / 'existing-release'; target.mkdir(); (target / 'keep').write_text('unchanged')
    m.assert_harness_clean = lambda source: None
    sys.argv = [str(materializer), '--from', str(fixture / 'dsh'), '--to', str(target), '--force']
    try: m.main()
    finally: assert (target / 'keep').read_text() == 'unchanged'
    sys.exit(0)
records = m.assert_face_bundles_current()
if not mutant:
    assert set(records) == set(m.FACE_PACKAGES)
print('FACE BUNDLE FRESHNESS ACCEPTED')
`

function run(change = '', mutant = '') {
  mkdirSync(fixtureParent, { recursive: true })
  const fixture = mkdtempSync(join(fixtureParent, 'face-freshness-'))
  try {
    const result = spawnSync('python3', ['-B', '-c', python, root, fixture, change, mutant], {
      cwd: root, encoding: 'utf8', env: { ...process.env, PYTHONDONTWRITEBYTECODE: '1' }, timeout: 30_000,
    })
    assert.equal(result.error, undefined)
    return { status: result.status, output: `${result.stdout}${result.stderr}` }
  } finally {
    rmSync(fixture, { recursive: true, force: true })
  }
}

function refused(result, reason) {
  assert.notEqual(result.status, 0, `accepted ${reason}: ${result.output}`)
  assert.ok(result.output.includes(`${reason}:`), result.output)
}

test('fresh manifests bind all nine faces and every declared bundle', () => {
  const result = run()
  assert.equal(result.status, 0, result.output)
  assert.match(result.output, /FACE BUNDLE FRESHNESS ACCEPTED/u)
})

test('missing, malformed and historical manifests refuse materialization', () => {
  refused(run('missing-manifest'), 'face-build-manifest-missing')
  for (const change of ['invalid-json', 'old-manifest', 'wrong-face']) refused(run(change), 'face-build-manifest-invalid')
})

test('changing one source byte in any face refuses materialization', () => {
  for (const face of faces) refused(run(`source:${face}`), 'face-bundle-source-stale')
  for (const change of ['added-source', 'removed-source']) refused(run(change), 'face-bundle-source-stale')
})

test('configuration, assets, vendored, shared and cross-face inputs participate in freshness', () => {
  for (const input of [
    'plugins/aukora-face/apps/tsconfig.host.json', 'plugins/aukora-face/apps/tsdown.config.ts',
    'plugins/aukora-face/apps/assets/icon.svg', 'plugins/aukora-face/apps/vendor/helper.js',
    'plugins/aukora-face/tsdown.client.ts', 'plugins/aukora-face/messages/src/client/qr-scanner.ts',
    'scripts/build-face.py', 'scripts/build-face-bundles.sh', 'upstream-dsh.json',
  ]) refused(run(`input:${input}`), 'face-bundle-source-stale')
})

test('changed, missing and unrecorded bundle outputs refuse materialization', () => {
  for (const face of faces) refused(run(`output:${face}`), 'face-bundle-output-mismatch')
  refused(run('missing-output'), 'face-output-missing')
  refused(run('unrecorded-output'), 'face-bundle-output-mismatch')
})

test('the actual materializer checks freshness before replacing an existing target', () => {
  refused(run('main-source'), 'face-bundle-source-stale')
})

test('the actual face copy loop refuses output and manifest changes after preflight', t => {
  const fresh = run('copy-fresh')
  assert.equal(fresh.status, 0, fresh.output)
  refused(run('copy-output'), 'face-bundle-output-mismatch')
  for (const change of ['copy-manifest', 'copy-invalid-manifest']) refused(run(change), 'face-build-manifest-changed')
  for (const [mutant, reason] of [
    ['copy-output', 'face-bundle-output-mismatch'], ['copy-manifest', 'face-build-manifest-changed'],
  ]) {
    const result = run(mutant, mutant)
    assert.equal(result.status, 0, result.output)
    assert.throws(() => refused(result, reason), { code: 'ERR_ASSERTION' })
    t.diagnostic(`MUTATION CAUGHT ${mutant}`)
  }
})

test('fail-open mutations turn each freshness regression red', t => {
  for (const [change, reason] of [
    ['missing-manifest', 'face-build-manifest-missing'],
    ['invalid-json', 'face-build-manifest-invalid'],
    ['source:apps', 'face-bundle-source-stale'],
    ['output:apps', 'face-bundle-output-mismatch'],
  ]) {
    const result = run(change, reason)
    assert.equal(result.status, 0, result.output)
    assert.throws(() => refused(result, reason), { code: 'ERR_ASSERTION' })
    t.diagnostic(`MUTATION CAUGHT ${reason}`)
  }
  const bypassed = run('main-source', 'face-preflight')
  assert.equal(bypassed.output.includes('face-bundle-source-stale:'), false, bypassed.output)
  assert.throws(() => refused(bypassed, 'face-bundle-source-stale'), { code: 'ERR_ASSERTION' })
  t.diagnostic('MUTATION CAUGHT face-preflight invocation')
})

test('omitting a source input category turns its freshness regression red', t => {
  for (const [mutant, input] of [
    ['omit-assets', 'plugins/aukora-face/apps/assets/icon.svg'],
    ['omit-vendor', 'plugins/aukora-face/apps/vendor/helper.js'],
    ['omit-tsconfig', 'plugins/aukora-face/apps/tsconfig.host.json'],
    ['omit-aumlok', 'plugins/aukora-face/messages/src/client/qr-scanner.ts'],
    ['omit-shared', 'scripts/build-face-bundles.sh'],
  ]) {
    const baseline = run('', mutant)
    assert.equal(baseline.status, 0, baseline.output)
    const result = run(`input:${input}`, mutant)
    assert.equal(result.status, 0, result.output)
    assert.throws(() => refused(result, 'face-bundle-source-stale'), { code: 'ERR_ASSERTION' })
    t.diagnostic(`MUTATION CAUGHT ${mutant}`)
  }
})
