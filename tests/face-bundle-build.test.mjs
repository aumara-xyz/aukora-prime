// SPDX-License-Identifier: AGPL-3.0-or-later
// Exercise build refusals with disposable compiler and harness fixtures.
import test from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, readFileSync, writeFileSync, mkdirSync, rmSync, chmodSync } from 'node:fs'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { spawnSync } from 'node:child_process'

const root = fileURLToPath(new URL('..', import.meta.url))
const builderPath = join(root, 'scripts/build-face.py')
const builder = readFileSync(builderPath, 'utf8')
const wrapper = readFileSync(join(root, 'scripts/build-face-bundles.sh'), 'utf8')
const pnpm = JSON.parse(readFileSync(join(root, 'upstream-dsh.json'))).packageManager.slice(5)

function mutate(source, from, to) {
  assert.equal(source.split(from).length - 1, 1, `mutation anchor must match once: ${from}`)
  return source.replace(from, to)
}

function wrapperRun(source, env = {}) {
  const scratch = mkdtempSync(join(root, '.face-bundle-build-test-'))
  try {
    mkdirSync(join(scratch, 'scripts'))
    mkdirSync(join(scratch, 'bin'))
    writeFileSync(join(scratch, 'upstream-dsh.json'), JSON.stringify({ packageManager: `pnpm@${pnpm}` }))
    writeFileSync(join(scratch, 'scripts/build-face-bundles.sh'), source)
    writeFileSync(join(scratch, 'scripts/build-dsh.py'), 'import os, sys\nprint("harness fixture verified")\nsys.exit("harness-patch-set-mismatch: fixture") if os.environ.get("BAD_HARNESS") else None\n')
    writeFileSync(join(scratch, 'scripts/build-face.py'), 'print("FIXTURE BUILD REACHED")\n')
    for (const [name, body] of Object.entries({ node: 'echo "${TEST_NODE:-v24.11.1}"', pnpm: `echo "\${TEST_PNPM:-${pnpm}}"` })) {
      const target = join(scratch, 'bin', name)
      writeFileSync(target, `#!/bin/sh\n${body}\n`)
      chmodSync(target, 0o755)
    }
    return spawnSync('bash', [join(scratch, 'scripts/build-face-bundles.sh')], {
      cwd: scratch, encoding: 'utf8', env: { ...process.env, ...env, PATH: `${join(scratch, 'bin')}:${process.env.PATH}` },
    })
  } finally { rmSync(scratch, { recursive: true, force: true }) }
}

for (const [label, env, reason, anchor] of [
  ['Node version', { TEST_NODE: 'v24.0.0' }, 'face-build-node-version', '[[ "$actual_node" != v24.11.1 ]]'],
  ['pnpm version', { TEST_PNPM: '0.0.0' }, 'face-build-pnpm-version', '[[ "$actual_pnpm" != "$expected_pnpm" ]]'],
  ['pinned harness', { BAD_HARNESS: '1' }, 'harness-patch-set-mismatch', 'python3 scripts/build-dsh.py --root "$root" --verify-built --source "$dsh"'],
]) {
  test(`build-face-bundles.sh refuses wrong ${label} before build; removed guard is detected`, () => {
    const denied = wrapperRun(wrapper, env)
    assert.notEqual(denied.status, 0)
    assert.match(denied.stdout + denied.stderr, new RegExp(reason))
    assert.doesNotMatch(denied.stdout, /FIXTURE BUILD REACHED/)
    const mutant = mutate(wrapper, anchor, label === 'pinned harness' ? ':' : 'false')
    const bypass = wrapperRun(mutant, env)
    assert.equal(bypass.status, 0, bypass.stdout + bypass.stderr)
    assert.match(bypass.stdout, /FIXTURE BUILD REACHED/)
  })
}

test('build-face-bundles.sh admits matching fixture tools and harness', () => {
  const result = wrapperRun(wrapper)
  assert.equal(result.status, 0, result.stdout + result.stderr)
  assert.match(result.stdout, /FIXTURE BUILD REACHED/)
})

const python = String.raw`
import hashlib, io, json, os, pathlib, sys, tarfile, tempfile, types
request = json.load(sys.stdin)
namespace = {'__file__': sys.argv[1], '__name__': 'face_build_fixture'}
exec(compile(request['source'], sys.argv[1], 'exec'), namespace)
with tempfile.TemporaryDirectory(prefix='.face-bundle-build-test-', dir=pathlib.Path(sys.argv[1]).parents[1]) as temp:
    root = pathlib.Path(temp)
    face = root / 'plugins/aukora-face'
    pkg = face / 'apps'
    overlay = root / 'overlay'
    built = overlay / 'packages/client/aukora-face-apps'
    (pkg / 'src').mkdir(parents=True)
    (built / 'lib').mkdir(parents=True)
    (root / 'scripts').mkdir()
    (root / 'scripts/build-face.py').write_text('fixture builder')
    (root / 'scripts/build-face-bundles.sh').write_text('fixture wrapper')
    (root / 'upstream-dsh.json').write_text('{}')
    (face / 'tsdown.client.ts').write_text('fixture shared config')
    (pkg / 'package.json').write_text('{}')
    (pkg / 'src/index.ts').write_text('export const fixture = 1')
    (pkg / 'tsdown.config.ts').write_text("clientBundle('apps', ['lib/types/index.js', 'lib/types/invariant.js', 'lib/types/auma-canvas-tool.js'])")
    (overlay / '.dsh-build').mkdir()
    (overlay / '.dsh-build/client-build-environment.json').write_text('{"environment": {}}')
    namespace.update(ROOT=root, FACE=face, OVERLAY=overlay, PINNED=overlay)
    arm = request['arm']
    expected = ('auma-canvas-tool.js', 'client.js', 'index.js', 'invariant.js')
    for item in expected:
        (built / 'lib' / item).write_text('export const fixture = 1')
    if arm.startswith('harness '):
        pinned = root / 'pinned'
        pinned.mkdir()
        namespace['PINNED'] = pinned
        (root / 'vendor').mkdir()
        archive = root / 'vendor/dsh-source.tar.gz'
        original = b'before before' if arm == 'harness ambiguous patch' else b'before'
        with tarfile.open(archive, 'w:gz') as snapshot:
            member = tarfile.TarInfo('upstream/source.ts')
            member.size = len(original)
            snapshot.addfile(member, io.BytesIO(original))
        pin = {'archiveSha256': hashlib.sha256(archive.read_bytes()).hexdigest(), 'localPatches': []}
        actual = original
        if arm not in ('harness unchanged', 'harness wrong archive hash'):
            patch = root / 'fixture.patch.json'
            patch.write_text(json.dumps({'edits': [{'path': 'source.ts', 'find': 'before', 'replace': 'after'}]}))
            pin['localPatches'] = [{'file': patch.name, 'sha256': hashlib.sha256(patch.read_bytes()).hexdigest()}]
            actual = original.replace(b'before', b'after')
        if arm == 'harness source changed':
            actual = b'afteX'
        if arm == 'harness wrong archive hash':
            pin['archiveSha256'] = '0' * 64
        if arm == 'harness wrong patch hash':
            pin['localPatches'][0]['sha256'] = '0' * 64
        (pinned / 'source.ts').write_bytes(actual)
        (root / 'upstream-dsh.json').write_text(json.dumps(pin))
        refused = None
        try:
            namespace['verify_pinned_sources']()
        except SystemExit as error:
            refused = str(error)
        if arm in ('harness unchanged', 'harness patched'):
            assert refused is None, 'CHECK FAILED: ' + arm
        else:
            reason = 'source' if arm == 'harness source changed' else 'archive' if arm == 'harness wrong archive hash' else 'patch'
            assert refused and refused.startswith('face-harness-' + reason + '-mismatch:'), 'CHECK FAILED: ' + arm
    elif arm == 'declared outputs':
        assert namespace['bundle_outputs']('apps') == expected, 'CHECK FAILED: declared outputs'
    elif arm == 'missing tool output':
        (built / 'lib/auma-canvas-tool.js').unlink()
        namespace['run'] = lambda *a, **k: types.SimpleNamespace(returncode=0, stdout='')
        lib, why = namespace['bundle']('apps')
        assert lib is None and why == 'face-output-missing: apps/lib/auma-canvas-tool.js', 'CHECK FAILED: missing tool output'
    elif arm in ('client compiler failure', 'host compiler failure'):
        (built / 'tsconfig.host.json').write_text('{}')
        count = [0]
        def compiler(*a, **k):
            count[0] += 1
            failed = count[0] == (1 if arm.startswith('client') else 2)
            return types.SimpleNamespace(returncode=137 if failed else 0, stdout='compiler killed' if failed else '')
        namespace['run'] = compiler
        client, host = namespace['type_build']('apps')
        errors = client if arm.startswith('client') else host
        assert len(errors) == 1 and 'face-typecheck-failed:' in errors[0], 'CHECK FAILED: ' + arm
    elif arm in ('CSS filename normalization', 'unexpected CSS preset'):
        pinned = root / 'pinned'
        (pinned / 'packages/client').mkdir(parents=True)
        namespace['PINNED'] = pinned
        original = 'filename: fileId\n' * (2 if arm == 'unexpected CSS preset' else 3)
        original_path = pinned / 'packages/client/tsdown.client.ts'
        original_path.write_text(original)
        refused = None
        try:
            namespace['normalize_overlay_css']()
        except SystemExit as error:
            refused = str(error)
        if arm == 'unexpected CSS preset':
            assert refused and refused.startswith('face-css-preset-mismatch:'), 'CHECK FAILED: ' + arm
        else:
            expected_css = "filename: relative(REPOSITORY_ROOT, fileId).split(sep).join('/')\n" * 3
            assert (overlay / 'packages/client/tsdown.client.ts').read_text() == expected_css, 'CHECK FAILED: ' + arm
            assert original_path.read_text() == original, 'CHECK FAILED: ' + arm
    elif arm in ('dependency packages changed', 'dependency snapshots changed', 'matching dependency lock'):
        pinned = root / 'pinned'
        loader = pinned / 'node_modules/js-yaml'
        loader.mkdir(parents=True)
        (loader / 'index.js').write_text('exports.load = JSON.parse')
        (pinned / 'package.json').write_text('{}')
        namespace['PINNED'] = pinned
        lock = {'packages': {'dependency@1': {'resolution': {'integrity': 'fixture'}}}, 'snapshots': {'dependency@1': {}}}
        (pinned / 'pnpm-lock.yaml').write_text(json.dumps(lock))
        if arm != 'matching dependency lock':
            section = 'packages' if arm == 'dependency packages changed' else 'snapshots'
            lock[section]['dependency@1']['changed'] = True
        (overlay / 'pnpm-lock.yaml').write_text(json.dumps(lock))
        refused = None
        try:
            namespace['verify_dependency_lock']()
        except SystemExit as error:
            refused = str(error)
        if arm == 'matching dependency lock':
            assert refused is None, 'CHECK FAILED: ' + arm
        else:
            assert refused and refused.startswith('face-dependency-lock-mismatch:'), 'CHECK FAILED: ' + arm
    elif arm.startswith('install '):
        pinned = root / 'pinned'
        namespace.update(PINNED=pinned, FACES=('apps',), DEFERRED=())
        for home in (pinned, overlay):
            loader = home / 'node_modules/js-yaml'
            loader.mkdir(parents=True)
            (loader / 'index.js').write_text('exports.load = JSON.parse')
            (home / 'package.json').write_text('{"name":"fixture-root"}')
        semver = overlay / 'node_modules/.pnpm/node_modules/semver'
        semver.mkdir(parents=True)
        (semver / 'index.js').write_text("exports.valid = value => /^\\d+\\.\\d+\\.\\d+$/.test(value); exports.satisfies = (value, range) => range === '*' || value === range.replace(/^\\^/, '')")
        project = overlay / 'packages/core/fixture'
        project.mkdir(parents=True)
        (project / 'package.json').write_text('{"name":"@fixture/workspace","version":"1.0.0"}')
        dependencies = {'fixture-external': '^1.0.0', '@fixture/workspace': 'workspace:*'}
        manifest = {'name': '@fixture/face', 'dependencies': dependencies,
                    'devDependencies': {'fixture-dev': '1.0.0', 'fixture-external': '99.0.0'},
                    'optionalDependencies': {'fixture-optional': '1.0.0'}}
        importer = {'dependencies': {}}
        targets = {}
        for name in ('fixture-external', 'fixture-dev', 'fixture-optional'):
            target = overlay / 'node_modules/.pnpm' / name / 'node_modules' / name
            target.mkdir(parents=True)
            (target / 'package.json').write_text(json.dumps({'name': name, 'version': '1.0.0'}))
            link = project / 'node_modules' / name
            link.parent.mkdir(exist_ok=True)
            link.symlink_to(os.path.relpath(target, link.parent), target_is_directory=True)
            importer['dependencies'][name] = {'specifier': '1.0.0', 'version': '1.0.0(peer@1.0.0)'}
            targets[name] = target
        lock = {'importers': {'.': {}, 'packages/core/fixture': importer},
                'packages': {'fixture-external@1.0.0': {}}, 'snapshots': {'fixture-external@1.0.0(peer@1.0.0)': {}}}
        if arm == 'install range mismatch': dependencies['fixture-external'] = '^2.0.0'
        if arm == 'install invalid pinned version':
            dependencies['fixture-external'] = '*'
            importer['dependencies']['fixture-external']['version'] = 'invalid'
            (targets['fixture-external'] / 'package.json').write_text('{"name":"fixture-external","version":"invalid"}')
        if arm == 'install ambiguous peers':
            lock['importers']['.'] = {'dependencies': {'fixture-external': {'specifier': '1.0.0', 'version': '1.0.0(peer@2.0.0)'}}}
        if arm == 'install workspace missing': dependencies['@fixture/missing'] = 'workspace:*'
        if arm == 'install workspace range mismatch': dependencies['@fixture/workspace'] = 'workspace:^2.0.0'
        if arm in ('install workspace range', 'install workspace caret', 'install workspace tilde'):
            dependencies['@fixture/workspace'] = {'install workspace range': 'workspace:^1.0.0',
                'install workspace caret': 'workspace:^', 'install workspace tilde': 'workspace:~'}[arm]
        if arm == 'install optional precedence':
            dependencies['fixture-external'] = '98.0.0'
            manifest['optionalDependencies']['fixture-external'] = '1.0.0'
        if arm in ('install wrong package name', 'install wrong package version'):
            value = {'name': 'fixture-external', 'version': '1.0.0'}
            value['name' if arm.endswith('name') else 'version'] = 'wrong' if arm.endswith('name') else '2.0.0'
            (targets['fixture-external'] / 'package.json').write_text(json.dumps(value))
        if arm in ('install external escape', 'install workspace escape'):
            outside = root / 'outside'
            outside.mkdir()
            (outside / 'package.json').write_text('{"name":"fixture-external","version":"1.0.0"}' if arm == 'install external escape' else '{"name":"@fixture/escape","version":"1.0.0"}')
            if arm == 'install external escape':
                link = project / 'node_modules/fixture-external'
                link.unlink()
                link.symlink_to(outside, target_is_directory=True)
            else:
                (overlay / 'escape').symlink_to(outside, target_is_directory=True)
                lock['importers']['escape'] = {}
                dependencies['@fixture/escape'] = 'workspace:*'
        (built / 'package.json').write_text(json.dumps(manifest))
        lock_bytes = json.dumps(lock)
        for home in (pinned, overlay): (home / 'pnpm-lock.yaml').write_text(lock_bytes)
        calls, original_run = [], namespace['run']
        def installed(*args, **kwargs):
            calls.append(args[0])
            assert args[0][0] == 'node', 'CHECK FAILED: ' + arm
            return original_run(*args, **kwargs)
        namespace['run'] = installed
        refused = None
        try:
            namespace['install']()
        except SystemExit as error:
            refused = str(error)
        if arm in ('install matching links', 'install lock preflight', 'install lock final', 'install optional precedence',
                   'install workspace range', 'install workspace caret', 'install workspace tilde'):
            assert refused is None, 'CHECK FAILED: ' + arm + ': ' + str(refused)
            for name, target in dict(targets, **{'@fixture/workspace': project}).items():
                link = built / 'node_modules' / name
                assert link.is_symlink() and not os.path.isabs(os.readlink(link)) and link.resolve() == target, 'CHECK FAILED: ' + arm
            assert len(calls) == 3, 'CHECK FAILED: ' + arm
        else:
            reason = 'face-dependency-outside-overlay' if arm.endswith('escape') else 'face-dependency-install-mismatch' if arm.startswith('install wrong') else 'face-dependency-unpinned'
            assert refused and reason + ':' in refused, 'CHECK FAILED: ' + arm
            assert not (built / 'node_modules').exists(), 'CHECK FAILED: ' + arm
        assert all((home / 'pnpm-lock.yaml').read_text() == lock_bytes for home in (pinned, overlay)), 'CHECK FAILED: ' + arm
    elif arm == 'pinned bundle environment':
        os.environ['DSH_CLIENT_CALLER'] = 'unrecorded'
        os.environ['NODE_OPTIONS'] = '--conditions=unrecorded'
        os.environ['DSH_BUILD_FACE'] = 'unrecorded'
        os.environ['DSH_CLIENT_TITLE'] = 'wrong'
        (overlay / '.dsh-build/client-build-environment.json').write_text('{"environment": {"DSH_CLIENT_TITLE": "fixture"}}')
        captured = {}
        def bundler(*a, **k):
            captured.update(k['env'])
            return types.SimpleNamespace(returncode=0, stdout='')
        namespace['run'] = bundler
        namespace['bundle']('apps')
        assert captured.get('DSH_CLIENT_TITLE') == 'fixture' and not any(k in captured for k in ('DSH_CLIENT_CALLER', 'NODE_OPTIONS', 'DSH_BUILD_FACE')), 'CHECK FAILED: ' + arm
        assert all(captured.get(k) == v for k, v in {'NODE_ENV': 'production', 'TZ': 'UTC', 'LC_ALL': 'C', 'SOURCE_DATE_EPOCH': '0'}.items()), 'CHECK FAILED: ' + arm
    elif arm in ('source changed before copy', 'source changed during copy', 'fresh outputs stamped'):
        inputs = namespace['src_digest']('apps')
        (pkg / 'lib').mkdir()
        manifest = pkg / 'lib/.build-inputs.json'
        if arm == 'source changed before copy':
            (pkg / 'src/index.ts').write_text('export const fixture = 2')
        if arm == 'source changed during copy':
            def change_source(path):
                (pkg / 'src/index.ts').write_text('export const fixture = 2')
            namespace['strip_home_paths'] = change_source
        refused = None
        try:
            namespace['copy_back']('apps', built / 'lib', inputs)
        except SystemExit as error:
            refused = str(error)
        if arm == 'fresh outputs stamped':
            assert refused is None, 'CHECK FAILED: fresh outputs stamped'
            record = json.loads(manifest.read_text())
            assert record['formatVersion'] == 2 and tuple(sorted(record['outputs'])) == expected, 'CHECK FAILED: fresh outputs stamped'
            assert (record['srcDigest'], record['files']) == inputs, 'CHECK FAILED: fresh outputs stamped'
        else:
            assert refused == 'face-source-changed-during-build: apps' and not manifest.exists(), 'CHECK FAILED: ' + arm
            if arm == 'source changed before copy':
                assert not (pkg / 'lib/index.js').exists(), 'CHECK FAILED: ' + arm
    else:
        raise AssertionError('unknown test arm')
print('PASS build-face: ' + arm)
`

function builderRun(arm, source = builder) {
  return spawnSync('python3', ['-c', python, builderPath], {
    cwd: root, encoding: 'utf8', input: JSON.stringify({ arm, source }),
  })
}

for (const [arm, anchor, replacement] of [
  ['harness source changed', 'if not path.is_file() or path.read_bytes() != content:', 'if False:'],
  ['harness wrong archive hash', "if not archive.is_file() or hashlib.sha256(archive.read_bytes()).hexdigest() != pin['archiveSha256']:", 'if False:'],
  ['harness wrong patch hash', "if not patch.is_file() or hashlib.sha256(patch.read_bytes()).hexdigest() != declared['sha256']:", 'if False:'],
  ['harness ambiguous patch', "if original.count(edit['find']) != edit.get('occurrences', 1):", 'if False:'],
  ['declared outputs', "set(('index.js', 'client.js', *entries))", "set(('index.js', 'client.js'))"],
  ['missing tool output', "for item in bundle_outputs(name):\n        if not (pkg / 'lib' / item).is_file():", "for item in ():\n        if not (pkg / 'lib' / item).is_file():"],
  ['client compiler failure', 'if out.returncode and not errors:', 'if False:'],
  ['host compiler failure', 'if host.returncode and not host_errors:', 'if False:'],
  ['CSS filename normalization', 'original.replace(needle, "filename: relative(REPOSITORY_ROOT, fileId).split(sep).join(\'/\')")', 'original'],
  ['unexpected CSS preset', 'if original.count(needle) != 3:', 'if False:'],
  ['dependency packages changed', 'JSON.stringify(canonical(pinned[section])) !== JSON.stringify(canonical(built[section]))', 'false'],
  ['dependency snapshots changed', 'JSON.stringify(canonical(pinned[section])) !== JSON.stringify(canonical(built[section]))', 'false'],
  ['install range mismatch', "semver.satisfies(entry.version.split('(')[0], wanted)", 'true'],
  ['install invalid pinned version', "semver.valid(entry.version.split('(')[0])", 'true'],
  ['install ambiguous peers', 'new Set(candidates.map(entry => entry.version)).size !== 1', 'false'],
  ['install workspace missing', "if (!target) refuse('face-dependency-unpinned', `${face}: ${name} ${wanted}`);", ''],
  ['install workspace range mismatch', "!['*', '^', '~'].includes(range) && !semver.satisfies(read(path.join(inside(target), 'package.json')).version, range)", 'false'],
  ['install optional precedence', "const sections = ['devDependencies', 'dependencies', 'optionalDependencies'];", "const sections = ['devDependencies', 'optionalDependencies', 'dependencies'];"],
  ['install wrong package name', 'pkg.name === name && ', ''],
  ['install wrong package version', "pkg.version === entry.version.split('(')[0]", 'true'],
  ...['install external escape', 'install workspace escape'].map(arm =>
    [arm, "if (!real.startsWith(overlay + path.sep)) refuse('face-dependency-outside-overlay', target);", '']),
  ['install lock preflight', "    verify_dependency_lock()\n    link = r'''", "    link = r'''"],
  ['install lock final', '    print(out.stdout.strip(), flush=True)\n    verify_dependency_lock()', '    print(out.stdout.strip(), flush=True)'],
  ['pinned bundle environment', "env = {key: os.environ[key] for key in ('PATH', 'HOME') if key in os.environ}", 'env = dict(os.environ)'],
  ['source changed before copy', 'if src_digest(name) != inputs:', 'if False:'],
  ['source changed during copy', "if (record['srcDigest'], record['files']) != inputs:", 'if False:'],
]) {
  test(`build-face.py ${arm}; protection removal fails its assertion`, () => {
    const actual = builderRun(arm)
    assert.equal(actual.status, 0, actual.stdout + actual.stderr)
    const mutant = builderRun(arm, mutate(builder, anchor, replacement))
    assert.notEqual(mutant.status, 0, 'mutant survived')
    assert.ok(mutant.stderr.includes(`AssertionError: CHECK FAILED: ${arm}`), mutant.stdout + mutant.stderr)
  })
}

for (const arm of ['fresh outputs stamped', 'matching dependency lock', 'harness unchanged', 'harness patched', 'install matching links',
  'install workspace range', 'install workspace caret', 'install workspace tilde']) {
  test(`build-face.py ${arm}`, () => {
    const result = builderRun(arm)
    assert.equal(result.status, 0, result.stdout + result.stderr)
  })
}
