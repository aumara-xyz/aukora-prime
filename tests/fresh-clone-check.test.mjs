// Exercise clone isolation and refusal propagation with disposable offline repositories.
import test from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, symlinkSync, unlinkSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { spawnSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'

const root = fileURLToPath(new URL('../', import.meta.url))
const subject = readFileSync(join(root, 'scripts/fresh-clone-check.sh'), 'utf8')
const sha = value => createHash('sha256').update(value).digest('hex')
const quote = value => "'" + value.replaceAll("'", "'\\''") + "'"
const archiveBytes = Buffer.from('disposable pinned harness archive\n')
const privateNames = ['SYNTHETIC_PRIVATE_VALUE', 'OPENAI_API_KEY', 'DSH_HOME', 'AUKORA_SUPPORT_ROOT', 'NODE_OPTIONS', 'GIT_DIR', 'npm_config_userconfig']
const childOutput = 'SYNTHETIC CHILD OUTPUT MUST REMAIN PRIVATE'

function write(path, content, executable = false) {
  mkdirSync(dirname(path), { recursive: true })
  writeFileSync(path, content)
  if (executable) chmodSync(path, 0o755)
}

function command(name, args, cwd, env = process.env) {
  const result = spawnSync(name, args, { cwd, env, encoding: 'utf8' })
  assert.equal(result.status, 0, result.stderr)
  return result
}

function fixture(t, options = {}) {
  const base = join(root, '.runtime')
  mkdirSync(base, { recursive: true })
  const scratch = mkdtempSync(join(base, 'fresh-clone-test-'))
  t.after(() => rmSync(scratch, { recursive: true, force: true }))
  const source = join(scratch, 'source'), tools = join(scratch, 'tools')
  const report = join(scratch, 'observed.jsonl'), callerHome = join(scratch, 'caller-home')
  const temporary = join(scratch, 'shared-tmp'), archive = join(scratch, 'archive.tar.gz')
  for (const directory of [source, tools, callerHome, temporary]) mkdirSync(directory, { mode: 0o755 })
  const config = { report, callerHome, privateNames, buildStatus: 0, materializeStatus: 0, runtimeStatus: 0, ...options }
  write(join(source, 'fixture.json'), JSON.stringify(config))
  write(join(source, 'payload.txt'), 'committed fixture bytes\n')
  write(join(source, '.gitignore'), 'vendor/\n')
  write(join(source, 'upstream-dsh.json'), JSON.stringify({ archiveSha256: sha(archiveBytes), archiveUrl: 'file://' + archive,
    packageManager: 'pnpm@11.7.0' }))
  const common = String.raw`import json, os, sys
from pathlib import Path
root = Path(__file__).resolve().parents[1]
config = json.loads((root / 'fixture.json').read_text())
print('SYNTHETIC CHILD OUTPUT MUST REMAIN PRIVATE')
def event(kind):
    with open(config['report'], 'a') as output:
        output.write(json.dumps({'kind': kind}) + '\n')
`
  write(join(source, 'scripts/build-dsh.py'), common + String.raw`
if '--verify-built' in sys.argv:
    event('verify')
    source = Path(sys.argv[sys.argv.index('--source') + 1])
    if not (source / 'receipt.json').is_file() or json.loads((source / 'receipt.json').read_text()) != {'valid': True}:
        sys.exit('harness-build-record-mismatch: fixture')
else:
    event('build')
    source = root / 'vendor/dsh'
    source.mkdir(parents=True, exist_ok=True)
    (source / 'receipt.json').write_text('{"valid": true}')
    if config.get('buildDescendant'):
        import subprocess, time
        child_code = "import pathlib,time; time.sleep(0.9); pathlib.Path(" + repr(config['report']) + ").open('a').write('{\"kind\":\"descendant-escaped\"}\\n'); time.sleep(0.5)"
        child = subprocess.Popen([sys.executable, '-c', child_code])
        with open(config['report'], 'a') as output:
            output.write(json.dumps({'kind': 'descendant', 'pid': child.pid}) + '\n')
        time.sleep(1.5)
    if config.get('buildNetwork'):
        sys.exit('ENOTFOUND: fixture')
    sys.exit(config['buildStatus'])
`)
  write(join(source, 'scripts/materialize-aukora-release.py'), common + String.raw`
event('materialize')
target = Path(sys.argv[sys.argv.index('--to') + 1])
target.mkdir(parents=True)
(target / 'fixture.txt').write_text('release fixture')
sys.exit(config['materializeStatus'])
`)
  write(join(source, 'scripts/fresh-clone-runtime.mjs'), String.raw`
import { appendFileSync, existsSync, readFileSync, statSync } from 'node:fs'
import { execFileSync } from 'node:child_process'
import { basename, join } from 'node:path'
const value = name => process.argv[process.argv.indexOf(name) + 1]
const checkout = value('--checkout'), root = value('--root'), release = value('--release')
const config = JSON.parse(readFileSync(join(checkout, 'fixture.json')))
const tip = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: checkout, encoding: 'utf8' }).trim()
const modes = Object.fromEntries([root, checkout, release, process.env.HOME, process.env.TMPDIR]
  .map(path => [path, statSync(path).mode & 0o777]))
appendFileSync(config.report, JSON.stringify({ kind: 'runtime', root, modes,
  releaseBound: basename(release) === 'release-' + tip.slice(0, 7),
  privatePresent: config.privateNames.filter(name => Object.hasOwn(process.env, name)),
  privateHome: process.env.HOME !== config.callerHome && process.env.HOME.startsWith(root + '/'),
  privateTemporary: process.env.TMPDIR.startsWith(root + '/'),
  ignoredPresent: existsSync(join(checkout, 'vendor/dsh/ignored.txt')),
  payload: readFileSync(join(checkout, 'payload.txt'), 'utf8'),
  cleanGitConfig: process.env.GIT_CONFIG_NOSYSTEM === '1' && process.env.GIT_CONFIG_GLOBAL === '/dev/null',
}) + '\n')
console.log('PASS | disposable runtime fixture')
console.log('SYNTHETIC CHILD OUTPUT MUST REMAIN PRIVATE')
if (config.runtimeListenUnavailable) console.error('EPERM: fixture')
process.exit(config.runtimeStatus)
`)
  for (const path of ['scripts/artifact-record.mjs', 'scripts/artifacts-coverage.json', 'scripts/lib/artifact-integrity.mjs']) {
    write(join(source, path), 'fixture cache input\n')
  }
  write(join(tools, 'pnpm'), '#!/bin/sh\nprintf "' + (options.pnpmVersion ?? '11.7.0') + '\\n"\n', true)
  if (options.nodeVersion) write(join(tools, 'node'), '#!/bin/sh\nif [ "$1" = --version ]; then printf "' + options.nodeVersion + '\\n"; else exec ' + quote(process.execPath) + ' "$@"; fi\n', true)
  if (options.missingTool) {
    const actualPython = command('python3', ['-c', 'import sys; print(sys.executable)'], root).stdout.trim()
    const actualGit = command('sh', ['-c', 'command -v git'], root).stdout.trim()
    const actualCc = command('sh', ['-c', 'command -v cc'], root).stdout.trim()
    for (const [name, target] of [['sh', '/bin/sh'], ['node', process.execPath], ['python3', actualPython], ['git', actualGit], ['cc', actualCc]]) {
      symlinkSync(target, join(tools, name))
    }
    unlinkSync(join(tools, options.missingTool))
  }
  const gitEnv = { PATH: process.env.PATH, HOME: callerHome, GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null', LANG: 'C' }
  command('git', ['init', '--quiet', source], scratch, gitEnv)
  command('git', ['add', '-A'], source, gitEnv)
  command('git', ['-c', 'user.name=Fixture', '-c', 'user.email=fixture', 'commit', '--quiet', '-m', 'fixture: clean source'], source, gitEnv)
  write(join(source, 'vendor/dsh/ignored.txt'), 'ignored machine state\n')
  write(join(source, 'payload.txt'), 'dirty working-tree bytes\n')
  write(archive, options.badArchive ? 'wrong archive' : archiveBytes)
  const built = join(scratch, 'built')
  write(join(built, 'receipt.json'), JSON.stringify({ valid: !options.badBuilt }))
  const env = { PATH: options.missingTool ? tools : tools + ':' + process.env.PATH, HOME: callerHome, TMPDIR: temporary, LANG: 'C' }
  for (const name of privateNames) env[name] = 'disposable-fixture-value'
  // NODE_OPTIONS and GIT_DIR must be valid enough for the initial tool preflight.
  env.NODE_OPTIONS = '--no-warnings'
  env.GIT_DIR = join(source, '.git')
  const wrapper = join(scratch, 'launcher/scripts/fresh-clone-check.sh')
  function run(code = subject, args = ['--archive', archive, '--built', built]) {
    write(wrapper, code, true)
    const result = spawnSync('sh', ['-c', 'umask 002; exec "$@"', 'fixture', wrapper, source, ...args],
      { cwd: scratch, env, encoding: 'utf8', timeout: 20000 })
    assert.equal(result.error, undefined, result.error?.message)
    return result
  }
  function events() {
    return existsSync(report) ? readFileSync(report, 'utf8').trim().split('\n').filter(Boolean).map(line => JSON.parse(line)) : []
  }
  return { run, events, source, scratch, archive, built, temporary }
}

function mutation(before, after, code = subject) {
  assert.equal(code.split(before).length - 1, 1, 'mutation anchor must match once')
  return code.replace(before, after)
}

function denied(result, status, reason) {
  assert.equal(result.status, status, result.stdout + result.stderr)
  assert.match(result.stdout, new RegExp(reason))
  assert.doesNotMatch(result.stdout, /TOTAL [\d.]+s \| PASS/)
  assert.equal(result.stdout.includes(childOutput), false)
}

function isolated(f, code = subject) {
  const result = f.run(code)
  assert.equal(result.status, 0, result.stdout + result.stderr)
  assert.equal(result.stdout.includes(childOutput), false)
  const observed = f.events().findLast(event => event.kind === 'runtime')
  assert.ok(observed)
  assert.equal(observed.releaseBound, true)
  assert.deepEqual(observed.privatePresent, [])
  assert.equal(observed.privateHome, true)
  assert.equal(observed.privateTemporary, true)
  assert.equal(observed.ignoredPresent, false)
  assert.equal(observed.payload, 'committed fixture bytes\n')
  assert.equal(observed.cleanGitConfig, true)
  assert.ok(Object.values(observed.modes).every(mode => mode === 0o700))
  assert.equal(existsSync(observed.root), false)
  assert.deepEqual(readdirSync(f.temporary).filter(name => name.startsWith('fc-')), [])
  return result
}

test('fresh clone excludes ignored and dirty machine files, isolates credentials, uses private paths under umask 002 and cleans up', t => {
  const f = fixture(t)
  const result = isolated(f)
  assert.match(result.stdout, /SKIP \| harness build \(--built; fresh build NOT PROVED\)/)
  assert.deepEqual(f.events().map(event => event.kind), ['verify', 'materialize', 'runtime'])
})

test('release directory names the cloned commit for the real gate grammar; removing the binding fails the regression', t => {
  const f = fixture(t)
  isolated(f)
  const mutant = mutation("release = work / ('release-' + tip[:7])", "release = work / 'release'")
  assert.throws(() => isolated(f, mutant), { name: 'AssertionError' })
  t.diagnostic('MUTATION KILLED release directory commit binding')
})

test('wrong archive hash and Node version refuse before any build; removed guards fail their regression', t => {
  for (const [label, options, status, reason, before, after] of [
    ['archive pin', { badArchive: true }, 1, 'source-digest-mismatch', "if hashlib.sha256(path.read_bytes()).hexdigest() != pin['archiveSha256']:", 'if False:'],
    ['Node pin', { nodeVersion: 'v24.0.0' }, 2, 'UNPERFORMED: node-24.11.1-required', "if version != 'v24.11.1':", 'if False:'],
  ]) {
    const f = fixture(t, options)
    denied(f.run(), status, reason)
    assert.deepEqual(f.events(), [])
    assert.throws(() => denied(f.run(mutation(before, after)), status, reason), { name: 'AssertionError' })
    t.diagnostic('MUTATION KILLED ' + label)
  }
})

test('every nonzero child result refuses; removing exit-status enforcement fails all three regressions', t => {
  const mutant = mutation('if child.returncode:', 'if False:')
  for (const stage of ['build', 'materialize', 'runtime']) {
    const f = fixture(t, { [stage + 'Status']: 7 })
    const args = ['--archive', f.archive]
    denied(f.run(subject, args), 1, stage + '-failed')
    assert.throws(() => denied(f.run(mutant, args), 1, stage + '-failed'), { name: 'AssertionError' })
    t.diagnostic('MUTATION KILLED ' + stage + ' nonzero')
  }
})

test('--built skips only building and always verifies provenance; removed verifier fails the regression', t => {
  const f = fixture(t, { badBuilt: true })
  denied(f.run(), 1, 'build-binding-failed:harness-build-record-mismatch')
  assert.deepEqual(f.events().map(event => event.kind), ['verify'])
  const mutant = mutation('verify_built(built_input, clone, env)', 'pass')
  assert.throws(() => denied(f.run(mutant), 1, 'build-binding-failed'), { name: 'AssertionError' })
  t.diagnostic('MUTATION KILLED supplied build provenance')
})

test('cache hits verify archive and build bytes; corrupt cache and writable cache refuse', t => {
  const f = fixture(t), cache = join(f.scratch, 'cache')
  const args = ['--archive', f.archive, '--cache', cache]
  assert.equal(f.run(subject, args).status, 0)
  const cached = join(cache, readdirSync(cache).find(name => name.includes('-node24.11.1-')))
  write(join(cached, 'receipt.json'), '{"valid": false}')
  denied(f.run(subject, args), 1, 'build-binding-failed:harness-build-record-mismatch')
  const mutant = mutation('verify_built(cache_build, clone, env)', 'pass')
  // The second verifier on the copied build must also refuse the corrupt bytes.
  denied(f.run(mutant, args), 1, 'build-binding-failed:harness-build-record-mismatch')
  const both = mutant.replace('verify_built(harness, clone, env)\n        print', 'pass\n        print')
  assert.throws(() => denied(f.run(both, args), 1, 'build-binding-failed'), { name: 'AssertionError' })
  t.diagnostic('MUTATION KILLED cached build provenance')
  write(join(cached, 'receipt.json'), '{"valid": true}')
  write(join(cache, sha(archiveBytes) + '.tar.gz'), 'corrupted archive')
  denied(f.run(subject, ['--cache', cache]), 1, 'source-digest-mismatch')
  const unpinned = mutation("if hashlib.sha256(path.read_bytes()).hexdigest() != pin['archiveSha256']:", 'if False:')
  assert.throws(() => denied(f.run(unpinned, ['--cache', cache]), 1, 'source-digest-mismatch'), { name: 'AssertionError' })
  t.diagnostic('MUTATION KILLED cached archive pin')
  chmodSync(cache, 0o775)
  denied(f.run(subject, args), 1, 'cache-path-insecure')
  const writable = mutation('cache.stat().st_mode & 0o022', 'False')
  assert.throws(() => denied(f.run(writable, ['--archive', f.archive, '--built', f.built, '--cache', cache]), 1, 'cache-path-insecure'), { name: 'AssertionError' })
  t.diagnostic('MUTATION KILLED cache permissions')
})

test('isolation and cleanup regressions reject individually removed protections', t => {
  for (const [name, before, after] of [
    ['environment whitelist', "env = {key: os.environ[key] for key in ('PATH', 'LANG') if key in os.environ}", 'env = dict(os.environ)'],
    ['private home', 'HOME=str(home)', "HOME=os.environ['HOME']"],
    ['private umask', 'os.umask(0o077)', 'pass'],
    ['committed clone', "run(['git', 'clone', '--quiet', '--no-local', '--', source, str(clone)], 'clone', work, env)", 'shutil.copytree(Path(source), clone)'],
    ['cleanup', 'shutil.rmtree(work, ignore_errors=True)', 'pass'],
  ]) {
    const f = fixture(t)
    isolated(f)
    assert.throws(() => isolated(f, mutation(before, after)), { name: 'AssertionError' }, name)
    // A cleanup mutant is deliberately reaped by its fixture owner.
    for (const event of f.events().filter(event => event.kind === 'runtime')) {
      if (existsSync(event.root)) rmSync(event.root, { recursive: true, force: true })
    }
    t.diagnostic('MUTATION KILLED ' + name)
  }
})

test('unavailable dependency network and runtime listen permission report UNPERFORMED, never PASS', t => {
  const build = fixture(t, { buildNetwork: true })
  denied(build.run(subject, ['--archive', build.archive]), 2, 'UNPERFORMED: build-network-unavailable')
  const listen = fixture(t, { runtimeStatus: 7, runtimeListenUnavailable: true })
  denied(listen.run(), 2, 'UNPERFORMED: loopback-or-ipc-listen-EPERM')
})

test('missing Python/pnpm/compiler/headers and wrong pnpm report UNPERFORMED; removing guards fails regressions', t => {
  for (const [name, options, reason, before, after] of [
    ['Python prerequisite', { missingTool: 'python3' }, 'python3-unavailable', 'if ! command -v python3 >/dev/null 2>&1; then', 'if false; then'],
    ['Node prerequisite', { missingTool: 'node' }, 'node-unavailable', 'if shutil.which(tool) is None:', 'if False:'],
    ['Git prerequisite', { missingTool: 'git' }, 'git-unavailable', 'if shutil.which(tool) is None:', 'if False:'],
    ['pnpm prerequisite', { missingTool: 'pnpm' }, 'pnpm-unavailable', "if shutil.which('pnpm') is None:", 'if False:'],
    ['compiler prerequisite', { missingTool: 'cc' }, 'native-build-C-compiler-unavailable', "if shutil.which('cc') is None:", 'if False:'],
    ['Node headers prerequisite', { nodeVersion: 'v24.11.1' }, 'native-build-node-headers-unavailable', "if not (node.parent.parent / 'include/node/node_api.h').is_file():", 'if False:'],
    ['pnpm pin', { pnpmVersion: '0.0.0' }, 'pinned-pnpm-required', "if 'pnpm@' + manager != pin['packageManager']:", 'if False:'],
  ]) {
    const f = fixture(t, options), args = ['--archive', f.archive]
    denied(f.run(subject, args), 2, 'UNPERFORMED: ' + reason)
    assert.throws(() => denied(f.run(mutation(before, after), args), 2, reason), { name: 'AssertionError' }, name)
    t.diagnostic('MUTATION KILLED ' + name)
  }
})

test('child logs stay private on failure; printing them fails the regression', t => {
  const f = fixture(t, { buildStatus: 7 }), args = ['--archive', f.archive]
  denied(f.run(subject, args), 1, 'build-failed')
  const mutant = mutation("text = log.read_text(errors='replace')\n", "text = log.read_text(errors='replace')\n        print(text, flush=True)\n")
  assert.throws(() => denied(f.run(mutant, args), 1, 'build-failed'), { name: 'AssertionError' })
  t.diagnostic('MUTATION KILLED child output suppression')
})

test('a timed-out build kills descendants; removing deadline or process-group cleanup fails regressions', async t => {
  const shortened = mutation('timeout=660', 'timeout=0.4')
  async function timeoutCheck(code) {
    const f = fixture(t, { buildDescendant: true }), args = ['--archive', f.archive]
    const result = f.run(code, args)
    const descendants = f.events().filter(event => event.kind === 'descendant')
    denied(result, 1, 'build-timeout')
    assert.equal(descendants.length, 1)
    await new Promise(resolve => setTimeout(resolve, 1100))
    assert.equal(f.events().some(event => event.kind === 'descendant-escaped'), false)
  }
  await timeoutCheck(shortened)
  const noDeadline = mutation('if time.monotonic() >= deadline:', 'if False:', shortened)
  await assert.rejects(() => timeoutCheck(noDeadline), { name: 'AssertionError' })
  t.diagnostic('MUTATION KILLED build timeout')
  const noGroup = mutation('os.killpg(child.pid, signal.SIGTERM)', 'child.terminate()', shortened)
  await assert.rejects(() => timeoutCheck(noGroup), { name: 'AssertionError' })
  t.diagnostic('MUTATION KILLED descendant cleanup')
})
