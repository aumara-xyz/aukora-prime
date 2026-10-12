// SPDX-License-Identifier: AGPL-3.0-or-later
// Exercise pinned staging and protected publication in a disposable root tree.
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, utimesSync, writeFileSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { spawnSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import test from 'node:test'
// Fixtures stand in for protected system paths. A login shell whose umask leaves group write on (Ubuntu's
// default 002) would make every directory this test creates look unprotected, so the mask is fixed here.
process.umask(0o022)

const repo = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const helper = join(repo, 'ops/node-spawn/stage.py')
const source = readFileSync(helper, 'utf8')
const python = '/usr/bin/python3'
const hash = data => createHash('sha256').update(data).digest('hex')
const tarWriter = String.raw`
import io, sys, tarfile
with tarfile.open(sys.argv[1], 'w:gz') as archive:
    for name, kind, link in __import__('json').loads(sys.argv[2]):
        item = tarfile.TarInfo(name); item.mode = 0o755
        if kind == 'file':
            content = b'#!/bin/sh\nprintf "v24.11.1\\n"\n'; item.size = len(content)
            archive.addfile(item, io.BytesIO(content))
        else:
            item.type = {'symlink': tarfile.SYMTYPE, 'hardlink': tarfile.LNKTYPE,
                         'fifo': tarfile.FIFOTYPE, 'directory': tarfile.DIRTYPE}[kind]
            item.linkname = link; archive.addfile(item)
`
function run(command, args, options = {}) {
  return spawnSync(command, args, { encoding: 'utf8', timeout: 15000, ...options })
}
function pass(result) { assert.equal(result.status, 0, result.stderr) }
function refusal(result, code) {
  assert.notEqual(result.status, 0)
  assert.match(result.stderr, new RegExp(`REFUSED SPAWN_${code}\\n`))
}
function fixture(t, implementation = source, entries = [['node-v24.11.1-linux-x64/bin/node', 'file', '']]) {
  const base = mkdtempSync(join(repo, '.node-spawn-stage-'))
  t.after(() => rmSync(base, { recursive: true, force: true }))
  const checkout = join(base, 'source'), root = join(base, 'root'), script = join(base, 'stage.py')
  mkdirSync(checkout); mkdirSync(root, { mode: 0o700 }); writeFileSync(script, implementation)
  function file(name, data = '{}\n') {
    const path = join(checkout, name)
    mkdirSync(dirname(path), { recursive: true }); writeFileSync(path, data)
    return path
  }
  file('packages/boundary-gate/package.json')
  file('packages/boundary-gate/host/install/gate-bootstrap.py', '# fixture bootstrap\n')
  file('packages/boundary-gate/host/sbx-exec', '# fixture helper\n')
  file('packages/boundary-gate/host/systemd/selfcheck-with-retry', '# fixture selfcheck\n')
  file('packages/boundary-gate/host/openshell/ensure-sandbox.sh', '# fixture sandbox check\n')
  file('packages/owner-key/package.json')
  const harnessArchive = Buffer.from('fixture harness archive')
  file('upstream-dsh.json', JSON.stringify({ archiveSha256: hash(harnessArchive) }))
  pass(run('git', ['init', '--quiet', checkout]))
  pass(run('git', ['-C', checkout, 'add', '.']))
  pass(run('git', ['-C', checkout, '-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid',
    'commit', '--quiet', '-m', 'fixture: staging inputs']))
  const releaseCommit = run('git', ['-C', checkout, 'rev-parse', 'HEAD']).stdout.trim()
  file('vendor/dsh-source.tar.gz', harnessArchive)
  const archive = join(base, 'node.tar.gz')
  pass(run(python, ['-I', '-S', '-c', tarWriter, archive, JSON.stringify(entries)]))
  const built = join(base, 'built'); mkdirSync(built)
  const config = { version: 1, node: 'fixture-node', source_checkout: checkout, release_commit: releaseCommit,
    node_archive: archive, node_archive_sha256: hash(readFileSync(archive)), public_signer_epochs: join(base, 'epochs.json'),
    offer: join(base, 'offer.json'), auma_offer: join(base, 'auma-offer.json'), root: '1'.repeat(64),
    admission: 'https://fixture.invalid/private', door_config: join(base, 'door.json'), built_harness: built }
  for (const key of ['offer', 'auma_offer', 'public_signer_epochs', 'door_config']) writeFileSync(config[key], '{}\n')
  const configPath = join(base, 'config.json')
  const save = () => writeFileSync(configPath, JSON.stringify(config))
  save()
  return { base, root, script, checkout, config, configPath, archive, save,
    call(action, operand = root) { return run(python, ['-I', '-S', script, action, configPath, operand]) },
    probe(program) { return run(python, ['-I', '-S', '-c', program, script, root]) },
  }
}

function mismatch(t, implementation = source) {
  const f = fixture(t, implementation); f.config.release_commit = 'a'.repeat(40); f.save()
  refusal(f.call('precheck'), 'SOURCE_RELEASE_MISMATCH')
}
function dirty(t, implementation = source) {
  const f = fixture(t, implementation); writeFileSync(join(f.checkout, 'packages/owner-key/package.json'), 'changed')
  refusal(f.call('precheck'), 'SOURCE_DIRTY')
}
function archivePin(t, implementation = source) {
  const f = fixture(t, implementation); f.config.node_archive_sha256 = 'b'.repeat(64); f.save()
  refusal(f.call('precheck'), 'NODE_ARCHIVE_PIN_MISMATCH')
}
function archiveGuard(t, implementation, entries, code) {
  const f = fixture(t, implementation, entries)
  refusal(f.call('stage'), code)
}
function custodyGuard(t, implementation = source) {
  const f = fixture(t, implementation); chmodSync(f.root, 0o777)
  refusal(f.call('precheck'), 'INSTALL_UNPROTECTED')
}
function fieldGuard(t, implementation = source) {
  const f = fixture(t, implementation)
  for (const field of ['root', 'admission']) {
    const result = f.call('field', field)
    refusal(result, 'FIELD_FORBIDDEN')
    assert.equal(result.stdout, '')
  }
}
function publishConflict(t, implementation = source) {
  const f = fixture(t, implementation); pass(f.call('stage'))
  const stage = join(f.root, 'var/lib/aukora-spawn/stage')
  writeFileSync(join(stage, 'gate-package-manifest.json'), '{}\n')
  mkdirSync(join(f.root, 'opt/aukora-node'), { recursive: true })
  refusal(f.call('publish'), 'INSTALL_CONFLICT')
  assert.ok(existsSync(join(stage, 'checkout')), 'partial publication moved the launcher')
}
function harnessPin(t, implementation = source) {
  const f = fixture(t, implementation)
  writeFileSync(join(f.checkout, 'vendor/dsh-source.tar.gz'), 'changed archive')
  refusal(f.call('stage'), 'HARNESS_ARCHIVE_PIN_MISMATCH')
}
function harnessRequired(t, implementation = source) {
  const f = fixture(t, implementation); rmSync(f.config.built_harness, { recursive: true })
  refusal(f.call('precheck'), 'HARNESS_REQUIRED')
}
function stageExisting(t, implementation = source) {
  const f = fixture(t, implementation); pass(f.call('stage'))
  const next = f.call('stage')
  refusal(next, 'STAGE_EXISTS')
}
function sourceReadOnly(t, implementation = source) {
  const f = fixture(t, implementation), index = join(f.checkout, '.git/index')
  const before = readFileSync(index)
  utimesSync(join(f.checkout, 'packages/owner-key/package.json'), 1000, 1000)
  pass(f.call('precheck'))
  assert.deepEqual(readFileSync(index), before, 'source Git index was refreshed')
}
const unitProbe = String.raw`
import os, pathlib, runpy, stat, sys, types
s = runpy.run_path(sys.argv[1], run_name='stage_fixture')
root, name = pathlib.Path(sys.argv[2]), sys.argv[3]
def expect(code, action):
    try: action()
    except ValueError as error: assert str(error) == 'SPAWN_' + code
    else: raise AssertionError('STAGE_GUARD_MISSING ' + name)
item = root / 'file'; item.write_text('data'); item.chmod(0o644)
if name == 'shape':
    path = root / 'config'; path.write_text('{}')
    expect('CONFIG_INVALID', lambda: s['config'](path))
elif name == 'duplicate':
    path = root / 'config'; path.write_text(pathlib.Path(sys.argv[4]).read_text().replace('{"version":1,', '{"version":1,"version":1,'))
    expect('CONFIG_INVALID', lambda: s['config'](path))
elif name == 'file-size': expect('INPUT_FILE_INVALID', lambda: s['regular'](item, 2))
elif name == 'file-links':
    os.link(item, root / 'link')
    expect('INPUT_FILE_INVALID', lambda: s['regular'](item))
elif name == 'file-type':
    os.fstat = lambda _: types.SimpleNamespace(st_mode=stat.S_IFIFO | 0o600, st_nlink=1, st_size=4)
    expect('INPUT_FILE_INVALID', lambda: s['regular'](item))
elif name == 'file-nofollow':
    alias = root / 'alias'; alias.symlink_to(item)
    try: s['regular'](alias)
    except OSError: pass
    else: raise AssertionError('STAGE_GUARD_MISSING ' + name)
elif name == 'mapped': expect('INSTALL_PATH_INVALID', lambda: s['mapped'](root, '/../outside'))
elif name == 'root-identity':
    alias = root / 'alias'; alias.symlink_to(root)
    expect('INSTALL_ROOT_INVALID', lambda: s['protected_root'](str(alias)))
elif name == 'root-required':
    os.geteuid = lambda: 123456
    expect('ROOT_REQUIRED', lambda: s['protected_root']('/'))
elif name == 'custody-owner': expect('INSTALL_UNPROTECTED', lambda: s['custody'](item, os.geteuid() + 1, False))
elif name == 'custody-file-type':
    os.lstat = lambda _: types.SimpleNamespace(st_mode=stat.S_IFIFO | 0o600, st_nlink=1, st_uid=os.geteuid())
    expect('INSTALL_UNPROTECTED', lambda: s['custody'](item, os.geteuid(), False))
elif name == 'custody-dir-type': expect('INSTALL_UNPROTECTED', lambda: s['custody'](item, os.geteuid(), True))
elif name == 'custody-links':
    os.link(item, root / 'link')
    expect('INSTALL_UNPROTECTED', lambda: s['custody'](item, os.geteuid(), False))
elif name == 'package-links':
    (root / 'alias').symlink_to(item)
    expect('PACKAGE_LINK_INVALID', lambda: s['tree'](root))
elif name == 'install-conflict':
    target = root / 'target'; target.write_text('different'); target.chmod(0o644)
    expect('INSTALL_CONFLICT', lambda: s['file_install'](root, item, target, 0o644))
elif name == 'install-mode':
    target = root / 'target'; target.write_text('data'); target.chmod(0o600)
    expect('INSTALL_CONFLICT', lambda: s['file_install'](root, item, target, 0o644))
elif name == 'public-modes':
    item.chmod(0o600); root.chmod(0o700)
    s['public_modes'](root)
    assert item.stat().st_mode & 0o777 == 0o644 and root.stat().st_mode & 0o777 == 0o755, 'STAGE_GUARD_MISSING public modes'
elif name == 'node-opened-pin':
    expect('NODE_ARCHIVE_PIN_MISMATCH', lambda: s['node_extract'](item, root / 'out', '0' * 64))
elif name == 'node-binary-type':
    import tarfile
    binary = tarfile.TarInfo('node-v24.11.1-linux-x64/bin/node'); binary.type = tarfile.DIRTYPE
    expect('NODE_BINARY_INVALID', lambda: s['extract_node']([binary], root / 'out'))
else: raise AssertionError('unknown probe')
`
function unit(t, implementation, scenario) {
  const f = fixture(t, implementation)
  const result = run(python, ['-I', '-S', '-c', unitProbe, f.script, f.root, scenario, f.configPath])
  pass(result)
}

function archiveSnapshot(t, implementation = source) {
  const f = fixture(t, implementation)
  const probe = String.raw`
import hashlib, io, pathlib, runpy, sys, tarfile
scope = runpy.run_path(sys.argv[1], run_name='stage_fixture')
root, archive = pathlib.Path(sys.argv[2]), pathlib.Path(sys.argv[3])
expected = hashlib.sha256(archive.read_bytes()).hexdigest()
original_open = tarfile.open
with original_open(archive, 'r:gz') as before:
    original_binary = before.extractfile('node-v24.11.1-linux-x64/bin/node').read()
replacement = io.BytesIO()
with original_open(fileobj=replacement, mode='w:gz') as after:
    binary = tarfile.TarInfo('node-v24.11.1-linux-x64/bin/node')
    changed = b'injected fixture bytes'; binary.size = len(changed); binary.mode = 0o755
    after.addfile(binary, io.BytesIO(changed))
def racing_open(*args, **kwargs):
    archive.write_bytes(replacement.getvalue())
    return original_open(*args, **kwargs)
tarfile.open = racing_open
scope['node_extract'](archive, root / 'node', expected)
assert (root / 'node/bin/node').read_bytes() == original_binary, 'STAGE_GUARD_MISSING archive snapshot'
`
  const result = run(python, ['-I', '-S', '-c', probe, f.script, f.root, f.archive])
  pass(result)
}

test('archive parsing uses only the private bytes hashed before an input-file race', t => {
  archiveSnapshot(t)
  assert.ok(source.includes('snapshot.seek(0)'))
  const mutant = source.replace('snapshot.seek(0)', 'archive_stream.seek(0)')
    .replace('fileobj=snapshot', 'fileobj=archive_stream')
  assert.throws(() => archiveSnapshot(t, mutant), { name: 'AssertionError' })
  t.diagnostic('MUTATION KILLED archive-snapshot')
})

test('staging uses the named clean commit, copied pin, public profiles and runtime binary only', t => {
  const f = fixture(t, source, [['node-v24.11.1-linux-x64/bin/node', 'file', ''],
    ['node-v24.11.1-linux-x64/bin/npm', 'symlink', '../lib/node_modules/npm/bin/npm-cli.js']])
  pass(f.call('precheck')); pass(f.call('stage'))
  const stage = join(f.root, 'var/lib/aukora-spawn/stage')
  assert.equal(run('git', ['-C', join(stage, 'checkout'), 'rev-parse', 'HEAD']).stdout.trim(), f.config.release_commit)
  assert.equal(hash(readFileSync(join(stage, 'checkout/vendor/dsh-source.tar.gz'))), hash(Buffer.from('fixture harness archive')))
  assert.ok(existsSync(join(stage, 'gate-package/package.json')))
  assert.ok(existsSync(join(stage, 'owner-key/package.json')))
  assert.ok(existsSync(join(stage, 'node/bin/node')))
  assert.equal(existsSync(join(stage, 'node/bin/npm')), false)
  refusal(f.call('stage'), 'STAGE_EXISTS')
  writeFileSync(join(stage, 'gate-package-manifest.json'), '{}\n')
  const result = f.call('publish'); pass(result); assert.equal(result.stdout, 'PUBLISHED\n')
  for (const path of ['opt/aukora-genesis/src/.git/HEAD', 'opt/aukora-boundary-gate/package.json',
    'opt/owner-key/package.json', 'opt/aukora-node/bin/node', 'etc/aukora-boundary-gate/gate-package-manifest.json',
    'etc/aukora-boundary-gate/signer-epochs.json', 'usr/local/lib/aukora-boundary/gate-bootstrap',
    'usr/local/lib/aukora-boundary/openshell/ensure-sandbox.sh']) assert.ok(existsSync(join(f.root, path)), path)
  assert.equal(run('git', ['-C', f.checkout, 'status', '--porcelain', '--untracked-files=no']).stdout, '')
})

test('commit, cleanliness, archive pin, custody and secret field refusals precede writes', t => {
  mismatch(t); dirty(t); archivePin(t); custodyGuard(t); fieldGuard(t); publishConflict(t)
})
test('archive traversal, duplicate paths, dangerous links and special types refuse', t => {
  const binary = ['node-v24.11.1-linux-x64/bin/node', 'file', '']
  for (const [entries, code] of [
    [[['../escape', 'file', '']], 'NODE_ARCHIVE_PATH_INVALID'],
    [[binary, binary], 'NODE_ARCHIVE_PATH_INVALID'],
    [[binary, ['node-v24.11.1-linux-x64/bin/npm', 'symlink', '/etc/secret']], 'NODE_ARCHIVE_LINK_INVALID'],
    [[binary, ['node-v24.11.1-linux-x64/bin/npm', 'hardlink', 'bin/node']], 'NODE_ARCHIVE_TYPE_INVALID'],
    [[binary, ['node-v24.11.1-linux-x64/fifo', 'fifo', '']], 'NODE_ARCHIVE_TYPE_INVALID'],
    [[['node-v24.11.1-linux-x64/bin/npm', 'file', '']], 'NODE_BINARY_INVALID'],
  ]) archiveGuard(t, source, entries, code)
})
test('package symlinks and protected ancestor aliases refuse', t => {
  const f = fixture(t); pass(f.call('stage'))
  const stage = join(f.root, 'var/lib/aukora-spawn/stage')
  writeFileSync(join(stage, 'gate-package-manifest.json'), '{}\n')
  symlinkSync(join(stage, 'gate-package/package.json'), join(stage, 'gate-package/alias'))
  refusal(f.call('publish'), 'PACKAGE_LINK_INVALID')
  const alias = join(f.base, 'alias'); symlinkSync(f.root, alias)
  refusal(f.call('precheck', alias), 'INSTALL_ROOT_INVALID')
})
test('input, custody and publication guards are exercised and their mutations fail', t => {
  const cases = [
    ['shape', "refuse('CONFIG_INVALID')\n    return value", 'pass\n    return value'],
    ['duplicate', "if key in result:", 'if False:'],
    ['file-size', 'or info.st_size > maximum', 'or False'],
    ['file-links', 'or info.st_nlink != 1', 'or False'],
    ['file-type', 'not stat.S_ISREG(info.st_mode)', 'False'],
    ['file-nofollow', ' | os.O_NOFOLLOW', ''],
    ['mapped', "or '..' in Path(name).parts", 'or False'],
    ['root-identity', 'or str(root.resolve()) != str(root)', 'or False'],
    ['root-required', "if root == Path('/') and os.geteuid() != 0:", 'if False:'],
    ['custody-owner', 'info.st_uid != uid', 'False'],
    ['custody-file-type', 'not stat.S_ISREG(info.st_mode)', 'False', true],
    ['custody-dir-type', 'not stat.S_ISDIR(info.st_mode)', 'False'],
    ['custody-links', 'or info.st_nlink != 1', 'or False', true],
    ['package-links', "refuse('PACKAGE_LINK_INVALID')", 'pass'],
    ['install-conflict', 'if regular(destination, 16 * 1024 * 1024) != data or destination.stat().st_mode & 0o777 != mode:', 'if False:'],
    ['install-mode', 'or destination.stat().st_mode & 0o777 != mode', 'or False'],
    ['public-modes', 'def public_modes(path):', 'def public_modes(path):\n    return'],
    ['node-opened-pin', 'if digest.hexdigest() != expected:', 'if False:'],
    ['node-binary-type', 'if not member.isfile() or member.size < 1 or member.size > 256 * 1024 * 1024:', 'if False:'],
  ]
  for (const [name, before, after, all] of cases) {
    unit(t, source, name)
    assert.ok(source.includes(before), name)
    let mutant = all ? source.replaceAll(before, after) : source.replace(before, after)
    if (name === 'file-size') mutant = mutant.replace('stream.read(maximum + 1)', 'stream.read()').replace('or len(data) > maximum', 'or False')
    assert.throws(() => unit(t, mutant, name), { name: 'AssertionError' }, name)
    t.diagnostic(`MUTATION KILLED ${name}`)
  }
})
test('staging protections fail when individually removed', t => {
  const binary = ['node-v24.11.1-linux-x64/bin/node', 'file', '']
  const mutants = [
    ['source-release', "if git(source, 'rev-parse', 'HEAD') != value['release_commit']:", 'if False:', mismatch],
    ['source-clean', "if git(source, 'status', '--porcelain', '--untracked-files=no'):", 'if False:', dirty],
    ['source-read-only', "'--no-optional-locks', ", '', sourceReadOnly],
    ['node-pin', "if digest_file(value['node_archive']) != value['node_archive_sha256']:", 'if False:', archivePin],
    ['custody-write', 'info.st_mode & 0o022', 'False', custodyGuard],
    ['field-secrets', 'if operand not in PRINTABLE or operand not in value:', 'if False:', fieldGuard],
    ['archive-path', "any(part in ('', '.', '..') for part in parts)", 'False',
      (t, mutant) => archiveGuard(t, mutant, [['node-v24.11.1-linux-x64/../escape', 'file', '']], 'NODE_ARCHIVE_PATH_INVALID')],
    ['archive-duplicate', 'or name in names', 'or False',
      (t, mutant) => archiveGuard(t, mutant, [['node-v24.11.1-linux-x64/lib/readme', 'file', ''],
        ['node-v24.11.1-linux-x64/lib/readme', 'file', ''], binary], 'NODE_ARCHIVE_PATH_INVALID')],
    ['archive-link', "refuse('NODE_ARCHIVE_LINK_INVALID')", 'pass',
      (t, mutant) => archiveGuard(t, mutant, [binary, ['node-v24.11.1-linux-x64/bin/npm', 'symlink', '/outside']], 'NODE_ARCHIVE_LINK_INVALID')],
    ['archive-type', 'if not member.isdir() and not member.isfile():', 'if False:',
      (t, mutant) => archiveGuard(t, mutant, [binary, ['node-v24.11.1-linux-x64/fifo', 'fifo', '']], 'NODE_ARCHIVE_TYPE_INVALID')],
    ['archive-binary', 'if not found:', 'if False:',
      (t, mutant) => archiveGuard(t, mutant, [['node-v24.11.1-linux-x64/bin/npm', 'file', '']], 'NODE_BINARY_INVALID')],
    ['harness-pin', "if digest_file(archive) != pin.get('archiveSha256'):", 'if False:', harnessPin],
    ['harness-required', "if not Path(value['built_harness']).is_dir():", 'if False:', harnessRequired],
    ['stage-existing', "refuse('STAGE_EXISTS')", 'pass', stageExisting],
    ['publish-conflict', 'if output.exists() or output.is_symlink():', 'if False:', publishConflict],
  ]
  for (const [name, before, after, check] of mutants) {
    assert.ok(source.includes(before), name)
    assert.throws(() => check(t, source.replace(before, after)), { name: 'AssertionError' }, name)
    t.diagnostic(`MUTATION KILLED ${name}`)
  }
})
