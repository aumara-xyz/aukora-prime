// Example commands refuse unsafe state and keep sign-in secrets out of output.
import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'
import net from 'node:net'
import { spawnSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'

const repository = fileURLToPath(new URL('../', import.meta.url))
const script = path.join(repository, 'scripts/prime-example.py')
const pythonEnvironment = { PATH: process.env.PATH, LANG: 'C', PYTHONDONTWRITEBYTECODE: '1' }

function fixture(t) {
  const base = path.join(repository, '.runtime')
  fs.mkdirSync(base, { recursive: true, mode: 0o700 })
  const root = fs.mkdtempSync(path.join(base, 'prime-example-test-'))
  fs.chmodSync(root, 0o700)
  const cleanup = []
  t.after(() => {
    for (const finish of cleanup.reverse()) finish()
    fs.rmSync(root, { recursive: true, force: true })
  })
  const checkout = path.join(root, 'checkout')
  fs.mkdirSync(checkout, { mode: 0o700 })
  const git = args => {
    const result = spawnSync('git', args, { cwd: checkout, encoding: 'utf8', timeout: 10000,
      env: { ...pythonEnvironment, HOME: root, GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null' } })
    assert.equal(result.status, 0, result.stderr)
    return result.stdout.trim()
  }
  git(['init', '--quiet'])
  fs.writeFileSync(path.join(checkout, 'payload'), 'committed\n', { mode: 0o600 })
  git(['add', '-A'])
  git(['-c', 'user.name=Fixture', '-c', 'user.email=fixture', 'commit', '--quiet', '-m', 'fixture: example input'])
  return { root, checkout, git, cleanup }
}

function python(body, { source = script, args = [] } = {}) {
  const program = String.raw`import importlib.util, json, os, pathlib, sys
sys.path.insert(0, str(pathlib.Path(sys.argv[1]).parent))
spec = importlib.util.spec_from_file_location('example_subject', sys.argv[1])
subject = importlib.util.module_from_spec(spec)
spec.loader.exec_module(subject)
from pathlib import Path
` + body
  const result = spawnSync('python3', ['-c', program, source, ...args], {
    cwd: repository, env: pythonEnvironment, encoding: 'utf8', timeout: 20000,
  })
  assert.equal(result.error, undefined, result.error?.message)
  return result
}

function successful(result) {
  assert.equal(result.status, 0, result.stdout + result.stderr)
  return result
}

function mutation(t, changes, file = 'prime-example.py') {
  let source = fs.readFileSync(path.join(repository, 'scripts', file), 'utf8')
  for (const [before, after, count = 1] of changes) {
    assert.equal(source.split(before).length, count + 1, 'mutation preimage: ' + before)
    source = source.replaceAll(before, after)
  }
  const f = fixture(t), directory = path.join(f.root, 'scripts')
  fs.mkdirSync(directory, { mode: 0o700 })
  for (const name of ['fresh_clone.py', 'prime-example.py']) fs.copyFileSync(path.join(repository, 'scripts', name), path.join(directory, name))
  const target = path.join(directory, 'prime-example.py')
  fs.writeFileSync(path.join(directory, file), source, { mode: 0o600 })
  return target
}

const argumentCases = String.raw`
assert subject.parse_arguments(['up', '--example', '--port', '0']).command == 'up'
assert subject.parse_arguments(['up', '--example', '--port', '65535', '--allow-dirty']).allow_dirty is True
assert subject.parse_arguments(['down', '--example']).command == 'down'
assert subject.parse_arguments(['approve']).command == 'approve'
assert subject.parse_arguments(['refuse', '--dir', '/synthetic']).command == 'refuse'
assert subject.parse_arguments(['verify']).command == 'verify'
for argv in [[], ['up'], ['up', '--example', '--port', '-1'], ['up', '--example', '--port', '65536'],
             ['up', '--example', '--port', 'word'], ['up', '--example', '--unknown'],
             ['down', '--example', '--port', '1'], ['other'], ['verify', '--allow-dirty'],
             ['up', '--example', '--example'], ['up', '--example', '--port', '1', '--port=2'], ['approve', '--example']]:
    try:
        subject.parse_arguments(argv)
    except (SystemExit, subject.Refused):
        pass
    else:
        raise AssertionError('arguments accepted: ' + repr(argv))
`

test('example parser accepts exact commands and refuses malformed or inapplicable options', () => {
  successful(python(argumentCases))
})

test('prime dispatch reaches example argument refusal without invoking NEXT boot or writing bytecode', t => {
  const secret = 'synthetic-argument-signin-secret'
  for (const args of [['up', '--example', '--port', '-1'], ['down', '--example', '--port', '1'], ['example', 'other'],
    ['up', '--example', '--unknown', 'http://127.0.0.1:19444/?token=' + secret]]) {
    const result = spawnSync(path.join(repository, 'prime'), args, {
      cwd: repository, env: pythonEnvironment, encoding: 'utf8', timeout: 10000,
    })
    assert.equal(result.error, undefined)
    assert.notEqual(result.status, 0)
    assert.equal((result.stdout + result.stderr).includes(secret), false, 'argument refusal printed the supplied token')
    assert.doesNotMatch(result.stdout + result.stderr, /root-owned|manifest ancestry|deployment-manifest/)
  }
  const f = fixture(t), launcher = path.join(f.root, 'launcher'), scripts = path.join(launcher, 'scripts')
  fs.mkdirSync(scripts, { recursive: true, mode: 0o700 })
  for (const name of ['prime-example.py', 'fresh_clone.py']) fs.copyFileSync(path.join(repository, 'scripts', name), path.join(scripts, name))
  const executable = path.join(launcher, 'prime'), original = fs.readFileSync(path.join(repository, 'prime'), 'utf8')
  const tools = path.join(f.root, 'bytecode-tools')
  fs.mkdirSync(tools, { mode: 0o700 })
  // Make the normal Python import write observable even when the host disables bytecode globally.
  fs.writeFileSync(path.join(tools, 'python3'), `#!/bin/sh
exec /usr/bin/python3 -B -c 'import os,runpy,sys; args=sys.argv[1:]; private=args[0]=="-B"; args=args[1:] if private else args; sys.dont_write_bytecode=private; sys.pycache_prefix=os.path.join(os.environ["HOME"],"bytecode-cache"); sys.argv=args; sys.path.insert(0,os.path.dirname(args[0])); runpy.run_path(args[0],run_name="__main__")' "$@"
`, { mode: 0o755 })
  function noBytecode(source) {
    fs.writeFileSync(executable, source, { mode: 0o755 })
    const result = spawnSync(executable, ['up', '--example', '--unknown'], {
      env: { PATH: tools + ':' + process.env.PATH, LANG: 'C', HOME: f.root }, encoding: 'utf8', timeout: 10000,
    })
    assert.equal(result.status, 2)
    assert.equal(fs.existsSync(path.join(f.root, 'bytecode-cache')), false, 'entry wrote Python bytecode outside state')
  }
  noBytecode(original)
  assert.ok(original.includes('exec python3 -B'))
  assert.throws(() => noBytecode(original.replaceAll('exec python3 -B', 'exec python3')), assert.AssertionError)
  t.diagnostic('MUTATION KILLED no checkout bytecode')
})

const stateCases = String.raw`
root, checkout = map(Path, sys.argv[2:])
os.umask(0o002)
state = root / 'state'
assert subject.state_directory(state, checkout) == state
assert state.stat().st_mode & 0o777 == 0o700
public_parent = root / 'public-parent'
public_parent.mkdir(mode=0o777)
public_parent.chmod(0o777)
nested = public_parent / 'state'
nested.mkdir(mode=0o700)
try:
    subject.state_directory(nested, checkout)
except subject.Refused as error:
    assert error.code == 'example-state-parent-writable', error.code
else:
    raise AssertionError('private state below writable parent accepted')
for candidate, condition in [(root / 'linked-state', 'symlink'), (root / 'shared-state', 'writable'), (checkout / 'state', 'checkout')]:
    if condition == 'symlink':
        candidate.symlink_to(state, target_is_directory=True)
    elif condition == 'writable':
        candidate.mkdir(mode=0o777)
        candidate.chmod(0o777)
    try:
        subject.state_directory(candidate, checkout)
    except subject.Refused as error:
        assert error.code and condition in error.code, error.code
    else:
        raise AssertionError('unsafe state accepted: ' + condition)
`

test('state directory is private under umask 002 and refuses aliases, public writes and checkout descendants', t => {
  const f = fixture(t)
  successful(python(stateCases, { args: [f.root, f.checkout] }))
})

const dirtyCases = String.raw`
checkout = Path(sys.argv[2])
tip, dirty = subject.checkout_state(checkout)
assert len(tip) == 40 and dirty is False
(checkout / 'payload').write_text('uncommitted\n')
try:
    subject.checkout_state(checkout)
except subject.Refused as error:
    assert 'dirty' in error.code, error.code
else:
    raise AssertionError('dirty checkout accepted')
tip, dirty = subject.checkout_state(checkout, allow_dirty=True)
assert dirty is True
`

test('dirty checkout is refused and explicit opt-in is required for uncommitted bytes', t => {
  const f = fixture(t)
  successful(python(dirtyCases, { args: [f.checkout] }))
})

const privateCases = String.raw`
root = Path(sys.argv[2])
file = root / 'private.json'
subject.write_private(file, {'synthetic': True})
assert file.stat().st_mode & 0o777 == 0o600
assert subject.read_private(file) == {'synthetic': True}
def denied(operation):
    try:
        operation()
    except (subject.Refused, OSError):
        return
    raise AssertionError('unprotected state file accepted')
file.chmod(0o644)
denied(lambda: subject.read_private(file))
file.chmod(0o600)
link = root / 'hardlink'
os.link(file, link)
denied(lambda: subject.read_private(file))
link.unlink()
link.symlink_to(file)
denied(lambda: subject.read_private(link))
link.unlink()
original_fstat = subject.os.fstat
def other_owner(fd):
    import types
    info = original_fstat(fd)
    return types.SimpleNamespace(st_mode=info.st_mode, st_uid=os.getuid() + 1, st_nlink=info.st_nlink)
subject.os.fstat = other_owner
try:
    denied(lambda: subject.read_private(file))
finally:
    subject.os.fstat = original_fstat
with subject.state_lock(root):
    denied(lambda: subject.state_lock(root).__enter__())
lock = root / 'example.lock'
lock.chmod(0o644)
denied(lambda: subject.state_lock(root).__enter__())
lock.chmod(0o600)
os.link(lock, link)
denied(lambda: subject.state_lock(root).__enter__())
link.unlink()
subject.os.fstat = other_owner
try:
    denied(lambda: subject.state_lock(root).__enter__())
finally:
    subject.os.fstat = original_fstat
`

test('private state JSON and nonblocking locks refuse exposed files, aliases and concurrent access', t => {
  const f = fixture(t)
  successful(python(privateCases, { args: [f.root] }))
})

const controlCases = String.raw`
ready = {'controlPort': 19444, 'controlToken': 'a' * 64, 'supervisorPid': 424242}
sent, reply = [], {'ok': True, 'supervisorPid': 424242}
class Channel:
    def __enter__(self):
        return self
    def __exit__(self, *args):
        pass
    def sendall(self, data):
        sent.append(json.loads(data))
    def recv(self, count):
        return json.dumps(reply).encode() + b'\n'
subject.socket.create_connection = lambda *args, **kwargs: Channel()
def refused(operation, code):
    try:
        operation()
    except subject.Refused as error:
        assert error.code == code, error.code
        return
    raise AssertionError('control operation was not refused: ' + code)
assert subject.control(ready, 'status')['ok'] is True
assert sent == [{'op': 'status', 'token': 'a' * 64}]
for broken in [dict(ready, controlPort=0), dict(ready, controlPort=65536), dict(ready, controlPort='19444'),
               dict(ready, controlToken='synthetic-launch-token'), dict(ready, controlToken=None)]:
    refused(lambda: subject.control(broken, 'stop'), 'example-control-invalid')
reply = {'ok': False, 'supervisorPid': 424242}
refused(lambda: subject.control(ready, 'stop'), 'example-supervisor-identity-mismatch')
reply = {'ok': True, 'supervisorPid': 424243}
refused(lambda: subject.control(ready, 'stop'), 'example-supervisor-identity-mismatch')
`

test('stop uses a private capability and refuses malformed or mismatched supervisor replies', () => {
  successful(python(controlCases))
})

const reportCases = String.raw`
root = Path(sys.argv[2])
ready = {'origin': 'http://127.0.0.1:19444', 'launchFile': str(root / 'support/state/launch-url.json'),
         'controlToken': 'synthetic-control-token', 'url': 'http://127.0.0.1:19444/?token=synthetic-launch-token'}
subject.report_ready(ready, root)
for origin in ['http://127.0.0.1:19444/?token=synthetic-launch-token',
               'http://synthetic-launch-token@127.0.0.1:19444', 'http://127.0.0.1:19444/#synthetic-launch-token',
               'http://0.0.0.0:19444', 'https://127.0.0.1:19444', 'http://127.0.0.1:19444/private']:
    try:
        subject.report_ready(dict(ready, origin=origin), root)
    except subject.Refused as error:
        assert error.code == 'example-origin-invalid', error.code
    else:
        raise AssertionError('credential or nonloopback origin accepted')
try:
    subject.report_ready(dict(ready, launchFile=str(root / 'synthetic-launch-token')), root)
except subject.Refused as error:
    assert error.code == 'example-launch-path-invalid', error.code
else:
    raise AssertionError('untrusted launch file accepted')
`

const argumentSecretCases = String.raw`
import contextlib, io
secret = 'synthetic-argument-signin-secret'
for argv in [['up', '--example', '--unknown', 'http://127.0.0.1:19444/?token=' + secret],
             ['up', '--example', '--port', secret], [secret]]:
    output = io.StringIO()
    with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
        try:
            subject.parse_arguments(argv)
        except SystemExit as error:
            assert error.code == 2
        else:
            raise AssertionError('invalid secret-bearing arguments accepted')
    assert secret not in output.getvalue(), 'argument refusal printed caller-supplied secret'
`

test('output shows only the loopback origin and the private sign-in filename', t => {
  const f = fixture(t), result = successful(python(reportCases, { args: [f.root] }))
  assert.match(result.stdout, /^ADDRESS \| http:\/\/127\.0\.0\.1:19444$/m)
  assert.match(result.stdout, /^SIGN-IN FILE \| .*\/support\/state\/launch-url\.json$/m)
  assert.doesNotMatch(result.stdout + result.stderr, /synthetic-(?:control|launch)-token|[?&]token=/)
  successful(python(argumentSecretCases))
})

const lifecycleCases = String.raw`
root, checkout = map(Path, sys.argv[2:])
state = root / 'state'
starts, prepares, controls = [], [], []
tip = '1' * 40
subject.preflight = lambda: None
subject.checkout_state = lambda *_args, **_kwargs: (tip, True)
def prepare(source, root, *args):
    prepares.append(source)
    clone, release = root / 'clone', root / 'release-1111111'
    clone.mkdir(mode=0o700)
    release.mkdir(mode=0o700)
    return {'checkout': clone, 'release': release, 'root': root, 'env': subject.environment(root)}
subject.prepare = prepare
class Child:
    def __init__(self, command, **kwargs):
        starts.append(command)
        ready = {'origin': 'http://127.0.0.1:19444', 'launchFile': str(state / 'support/state/launch-url.json'),
                 'controlPort': 19445, 'controlToken': 'a' * 64, 'supervisorPid': 424242,
                 'version': 1, 'kind': 'aukora-prime-example/v1', 'root': str(state), 'checkout': str(state / 'clone')}
        subject.write_private(state / 'example-ready.json', ready)
    def poll(self):
        return None
subject.subprocess.Popen = Child
def control(ready, op):
    controls.append(op)
    if op == 'stop':
        (state / 'example-ready.json').unlink()
    return {'ok': True, 'supervisorPid': ready['supervisorPid']}
subject.control = control
args = subject.parse_arguments(['up', '--example', '--allow-dirty', '--dir', str(state)])
subject.up(args, checkout)
subject.up(args, checkout)
assert len(starts) == 1 and len(prepares) == 1, (starts, prepares)
manifest_file = state / 'example.json'
manifest = subject.read_private(manifest_file)
def refused(operation, code):
    try:
        operation()
    except subject.Refused as error:
        assert error.code == code, error.code
        return
    raise AssertionError('resumed example did not refuse: ' + code)
for field, value, code in [('source', str(root / 'other-checkout'), 'example-state-for-other-checkout-or-head'),
                           ('sourceHead', '2' * 40, 'example-state-for-other-checkout-or-head'),
                           ('release', str(root / 'release-1111111'), 'example-release-path-invalid'),
                           ('release', str(state / 'release-invalid'), 'example-release-path-invalid')]:
    subject.write_private(manifest_file, dict(manifest, **{field: value}))
    refused(lambda: subject.up(args, checkout), code)
    assert len(starts) == 1, 'bad manifest started another process'
    subject.write_private(manifest_file, manifest)
args.port = 19446
refused(lambda: subject.up(args, checkout), 'example-port-already-selected')
args.port = None
assert len(starts) == 1, 'different resumed port started another process'
stop = subject.parse_arguments(['down', '--example', '--dir', str(state)])
subject.down(stop, checkout)
subject.down(stop, checkout)
assert controls.count('stop') == 1, controls
assert not (state / 'example-ready.json').exists()
assert (state / 'clone').is_dir() and (state / 'example.json').is_file()
`

test('same-state up/down are idempotent in a lifecycle fixture and announce dirty snapshots', t => {
  const f = fixture(t), result = successful(python(lifecycleCases, { args: [f.root, f.checkout] }))
  assert.equal(result.stdout.match(/^PASS \| example up$/gm)?.length, 2)
  assert.match(result.stdout, /WARNING \| --allow-dirty: NOT what is committed/)
  assert.match(result.stdout, /^PASS \| example down \(already stopped\)$/m)
  assert.doesNotMatch(result.stdout + result.stderr, /a{64}|[?&]token=/)
})

const environmentCases = String.raw`
root = Path(sys.argv[2])
subject.environment(root)
assert (root / 'home').stat().st_mode & 0o777 == 0o700
subject.environment(root)
for directory in (root / 'home', root / 'tmp'):
    directory.chmod(0o777)
    try:
        subject.environment(root)
    except subject.Refused as error:
        assert error.code == 'example-environment-path-insecure', error.code
    else:
        raise AssertionError('public example environment accepted')
    directory.chmod(0o700)
`

test('resumed environment stays private and refuses newly exposed home or temporary directories', t => {
  const f = fixture(t)
  successful(python(environmentCases, { args: [f.root] }))
})

const readinessCases = String.raw`
root = Path(sys.argv[2])
assert subject.live_ready(root) is None
launch_state = root / 'support/state'
launch_state.mkdir(parents=True, mode=0o700)
for name in ('launch.json', 'launch-url.json'):
    file = launch_state / name
    subject.write_private(file, {'synthetic': True})
    assert subject.live_ready(root, starting=True) is None
    try:
        subject.live_ready(root)
    except subject.Refused as error:
        assert error.code == 'example-supervisor-missing-with-launch-state', error.code
    else:
        raise AssertionError('missing supervisor with retained launch state was reported as stopped: ' + name)
    file.unlink()
assert subject.live_ready(root) is None
ready = {'version': 1, 'kind': 'aukora-prime-example/v1', 'root': str(root), 'checkout': str(root / 'clone'),
         'launchFile': str(root / 'support/state/launch-url.json')}
calls = []
subject.control = lambda ready, op: calls.append(op)
subject.write_private(root / 'example-ready.json', ready)
assert subject.live_ready(root) == ready
for key, value in [('version', 2), ('kind', 'other'), ('root', str(root.parent)),
                   ('checkout', str(root.parent / 'clone')), ('launchFile', str(root.parent / 'launch-url.json'))]:
    subject.write_private(root / 'example-ready.json', dict(ready, **{key: value}))
    before = len(calls)
    try:
        subject.live_ready(root)
    except subject.Refused as error:
        assert error.code == 'example-readiness-for-other-state', error.code
    else:
        raise AssertionError('copied readiness capability accepted: ' + key)
    assert len(calls) == before, 'foreign capability was contacted'
subject.write_private(root / 'example-ready.json', ready)
def unavailable(*args):
    raise subject.Refused('example-supervisor-unavailable')
subject.control = unavailable
try:
    subject.live_ready(root)
except subject.Refused as error:
    assert error.code == 'example-supervisor-unavailable', error.code
else:
    raise AssertionError('stale readiness was reported as stopped')
`

test('readiness belongs to this state and an unavailable recorded supervisor cannot report stopped', t => {
  const f = fixture(t)
  successful(python(readinessCases, { args: [f.root] }))
})

const logCases = String.raw`
root = Path(sys.argv[2])
log = root / 'runtime.log'
with subject.private_log(log) as output:
    output.write('private fixture')
assert log.stat().st_mode & 0o777 == 0o600
def denied():
    try:
        subject.private_log(log)
    except subject.Refused as error:
        assert error.code == 'example-log-path-insecure', error.code
        return
    raise AssertionError('unsafe output log accepted')
log.chmod(0o644)
denied()
assert log.read_text() == 'private fixture', 'unsafe log was truncated before validation'
log.chmod(0o600)
link = root / 'alias'
os.link(log, link)
denied()
assert log.read_text() == 'private fixture', 'linked log was truncated before validation'
link.unlink()
log.unlink()
log.symlink_to(root / 'elsewhere')
denied()
`

test('child output logs refuse public permissions and aliases before truncation', t => {
  const f = fixture(t)
  successful(python(logCases, { args: [f.root] }))
})

const snapshotCases = String.raw`
root = Path(sys.argv[2])
module = __import__('fresh_clone')
source, clone, elsewhere = root / 'source', root / 'clone', root / 'elsewhere'
for directory in (source, clone, elsewhere):
    directory.mkdir(mode=0o700)
(elsewhere / 'payload').write_text('untouched')
module.subprocess.check_output = lambda *args, **kwargs: b'folder/payload\0'
module.run = lambda *args, **kwargs: None
def denied():
    try:
        module.snapshot_dirty(source, clone, {})
    except module.Refused as error:
        assert error.code == 'dirty-snapshot-symlink', error.code
        return
    raise AssertionError('snapshot followed linked ancestry')
(source / 'folder').symlink_to(elsewhere, target_is_directory=True)
denied()
(source / 'folder').unlink()
(source / 'folder').mkdir(mode=0o700)
(source / 'folder/payload').write_text('snapshot')
(clone / 'folder').symlink_to(elsewhere, target_is_directory=True)
denied()
assert (elsewhere / 'payload').read_text() == 'untouched'
(clone / 'folder').unlink()
module.snapshot_dirty(source, clone, {})
assert (clone / 'folder/payload').read_text() == 'snapshot'
`

test('dirty snapshot refuses linked ancestry on either its read or write side', t => {
  const f = fixture(t)
  successful(python(snapshotCases, { args: [f.root] }))
})

test('state, dirty-tree, private-file, lock, control and secret-output protection mutations fail their assertions', t => {
  const cases = [
    ['option duplicates', [["if len(seen) != len(set(seen)):", 'if False:']], argumentCases, null],
    ['argument error secrecy', [['parser.error = argument_error', 'pass']], argumentSecretCases, null],
    ['example flag', [["if args.command in ('up', 'down') and not args.example:", 'if False:']], argumentCases, null],
    ['inapplicable example flag', [["if args.command not in ('up', 'down') and args.example:", 'if False:']], argumentCases, null],
    ['inapplicable options', [["if args.command != 'up' and (args.archive or args.built or args.port is not None or args.allow_dirty):", 'if False:']], argumentCases, null],
    ['port bounds', [["if args.port is not None and not 0 <= args.port <= 65535:", 'if False:']], argumentCases, null],
    ['state aliases', [['selected.is_symlink()', 'False', 2], ['current.lstat()', 'current.stat()'], ['selected.lstat()', 'selected.stat()']], stateCases, true],
    ['private state root', [['if info.st_mode & 0o077:', 'if False:']], stateCases, true],
    ['state parent permissions', [['if parent_info.st_mode & 0o022 and not parent_info.st_mode & stat.S_ISVTX:', 'if False:']], stateCases, true],
    ['state outside checkout', [['if resolved == checkout or checkout in resolved.parents:', 'if False:']], stateCases, true],
    ['dirty tree', [['if dirty and not allow_dirty:', 'if False:']], dirtyCases, false],
    ['private JSON', [["raise Refused('example-state-file-insecure')", 'pass']], privateCases, false],
    ['JSON no-follow', [['os.open(file, os.O_RDONLY | os.O_NOFOLLOW)', 'os.open(file, os.O_RDONLY)']], privateCases, false],
    ['private lock', [["raise Refused('example-lock-insecure')", 'pass']], privateCases, false],
    ['lock concurrency', [['fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)', 'pass']], privateCases, false],
    ['control capability', [["raise Refused('example-control-invalid')", 'pass']], controlCases, null],
    ['control identity', [["if reply.get('ok') is not True or reply.get('supervisorPid') != ready.get('supervisorPid'):", 'if False:']], controlCases, null],
    ['safe origin', [["raise Refused('example-origin-invalid')", 'pass']], reportCases, false],
    ['trusted sign-in path', [["if launch != root / 'support/state/launch-url.json':", 'if False:']], reportCases, false],
    ['up resume', [['if ready:\n            if args.port', 'if False:\n            if args.port']], lifecycleCases, true],
    ['resumed checkout and HEAD binding', [["if record.get('source') != str(checkout.resolve()) or record.get('sourceHead') != tip:", 'if False:']], lifecycleCases, true],
    ['resumed release path', [["if release.parent != root or not re.fullmatch(r'release-[a-f0-9]{7}', release.name):", 'if False:']], lifecycleCases, true],
    ['resumed port identity', [["if args.port and ready['origin'] != 'http://127.0.0.1:' + str(args.port):", 'if False:']], lifecycleCases, true],
    ['state readiness binding', [["raise Refused('example-readiness-for-other-state')", 'pass']], readinessCases, false],
    ['missing supervisor with launch state', [["if not starting and any((root / 'support/state' / name).exists() for name in ('launch.json', 'launch-url.json')):", 'if False:']], readinessCases, false],
  ]
  for (const [name, changes, exercise, checkoutNeeded] of cases) {
    const f = fixture(t), source = mutation(t, changes)
    const args = checkoutNeeded === null ? [] : checkoutNeeded ? [f.root, f.checkout] : [name === 'dirty tree' ? f.checkout : f.root]
    const result = python(exercise, { source, args })
    assert.equal(result.status, 1, name + ': mutant must fail an assertion')
    assert.match(result.stderr, /AssertionError/, name + ': execution accidents are not mutation evidence')
    t.diagnostic('MUTATION KILLED ' + name)
  }
  const f = fixture(t), source = mutation(t, [["raise Refused('example-environment-path-insecure')", 'pass']], 'fresh_clone.py')
  const result = python(environmentCases, { source, args: [f.root] })
  assert.equal(result.status, 1)
  assert.match(result.stderr, /AssertionError/)
  t.diagnostic('MUTATION KILLED resumed environment privacy')
  const logs = fixture(t), logSource = mutation(t, [["raise Refused('example-log-path-insecure')", 'pass', 2], ['os.close(fd)\n        pass', 'pass']], 'fresh_clone.py')
  const logResult = python(logCases, { source: logSource, args: [logs.root] })
  assert.equal(logResult.status, 1)
  assert.match(logResult.stderr, /AssertionError/)
  t.diagnostic('MUTATION KILLED private output logs')
  const snapshot = fixture(t), snapshotSource = mutation(t, [['if cursor.is_symlink():', 'if False:']], 'fresh_clone.py')
  const snapshotResult = python(snapshotCases, { source: snapshotSource, args: [snapshot.root] })
  assert.equal(snapshotResult.status, 1)
  assert.match(snapshotResult.stderr, /AssertionError/)
  t.diagnostic('MUTATION KILLED dirty snapshot ancestry')
})

let liveUnperformed
if (process.env.AUKORA_EXAMPLE_LIVE === '1') test('real example stays up, refuses, approves, verifies and stops twice', async t => {
  const server = net.createServer()
  try {
    await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve) })
    await new Promise(resolve => server.close(resolve))
  } catch (error) {
    if (!['EPERM', 'EACCES'].includes(error.code)) throw error
    liveUnperformed = 'example-live-loopback-listen-' + error.code
    console.log('UNPERFORMED: ' + liveUnperformed)
    t.skip(liveUnperformed)
    return
  }
  const built = process.env.AUKORA_EXAMPLE_BUILT
  if (!built || !fs.existsSync(built)) {
    liveUnperformed = 'example-live-needs-AUKORA_EXAMPLE_BUILT'
    console.log('UNPERFORMED: ' + liveUnperformed)
    t.skip(liveUnperformed)
    return
  }
  const f = fixture(t), checkout = path.join(f.root, 'full-checkout'), state = path.join(f.root, 'state')
  const gitEnv = { ...pythonEnvironment, HOME: f.root, GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null' }
  const cloned = spawnSync('git', ['clone', '--quiet', '--no-local', '--', repository, checkout], { env: gitEnv, encoding: 'utf8', timeout: 10000 })
  assert.equal(cloned.status, 0)
  const snapshotted = python(String.raw`
import fresh_clone
source, checkout, root = map(Path, sys.argv[2:])
fresh_clone.work = root
fresh_clone.snapshot_dirty(source, checkout, subject.environment(root))
`, { args: [repository, checkout, f.root] })
  successful(snapshotted)
  const run = (args, limit = 25000) => spawnSync(path.join(checkout, 'prime'), args, {
    cwd: checkout, env: gitEnv, encoding: 'utf8', timeout: limit,
  })
  f.cleanup.push(() => run(['down', '--example', '--dir', state]))
  const up = ['up', '--example', '--dir', state, '--archive', path.join(repository, 'vendor/dsh-source.tar.gz'), '--built', built]
  const first = run(up)
  if (first.status === 2 && /^UNPERFORMED: /m.test(first.stdout)) {
    liveUnperformed = first.stdout.match(/^UNPERFORMED: ([a-zA-Z0-9.-]+)/m)?.[1] ?? 'example-live-prerequisite-unavailable'
    console.log('UNPERFORMED: ' + liveUnperformed)
    t.skip(liveUnperformed)
    return
  }
  assert.equal(first.error, undefined, first.error?.code)
  assert.equal(first.status, 0, 'real example up did not pass; private runtime log retained in fixture until cleanup')
  const ready = JSON.parse(fs.readFileSync(path.join(state, 'example-ready.json'), 'utf8'))
  const launch = JSON.parse(fs.readFileSync(ready.launchFile, 'utf8'))
  for (const result of [first, run(up), ...['refuse', 'approve', 'verify'].map(operation => run(['example', operation, '--dir', state]))]) {
    assert.equal(result.error, undefined)
    assert.equal(result.status, 0)
    assert.equal((result.stdout + result.stderr).includes(ready.controlToken), false, 'control token was printed')
    assert.equal((result.stdout + result.stderr).includes(launch.url), false, 'sign-in link was printed')
    assert.match(result.stdout, /^PASS \| /m)
  }
  assert.equal(run(['down', '--example', '--dir', state]).status, 0)
  assert.equal(run(['down', '--example', '--dir', state]).status, 0)
  console.log('PASS | real example repeated up/down and walkthrough commands')
})
test.after(() => { if (liveUnperformed) process.exitCode = 2 })
