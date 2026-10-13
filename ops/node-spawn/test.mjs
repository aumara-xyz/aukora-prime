// SPDX-License-Identifier: AGPL-3.0-or-later
// Exercise plan/refusal guards and their removal using local stubs only.
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync, rmSync, symlinkSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import test from 'node:test'
import { createInvite, redeemInvite, verifyAdmission, createMemoryStore } from '../../packages/invites/index.mjs'
import { publicKeyOf } from '../../plugins/aukora-nostr/lib/event.mjs'

const here = dirname(fileURLToPath(import.meta.url))
const source = readFileSync(join(here, 'spawn.sh'), 'utf8')
assert.equal(process.version, 'v24.11.1')
const admissionSource = readFileSync(join(here, 'admission.mjs'), 'utf8')
const keys = [1, 2, 3].map(n => n.toString(16).padStart(64, '0'))
const networkRoot = publicKeyOf(keys[0]), now = 1_800_000_000
const store = createMemoryStore()
let record
for (let i = 0; i < 2; i++) {
  const invite = createInvite({ root: networkRoot, secretKey: keys[i], now: now + i })
  const redemption = redeemInvite({ invite, secretKey: keys[i + 1], now: now + i })
  record = verifyAdmission({ root: networkRoot, invite, redemption, chain: record?.chain ?? [], state: store, now: now + i }).record
}
store.close()
const expectedConfig = { version: 1, node: 'member-node', network_root_pubkey: networkRoot,
  member_pubkey: publicKeyOf(keys[2]), redemption_id: record.chain.at(-1).redemption.id }


function fixture(t, script = source, helper = admissionSource) {
  const root = mkdtempSync(join(here, '.test-'))
  t.after(() => rmSync(root, { recursive: true, force: true }))
  const bin = join(root, 'bin'), calls = join(root, 'calls'), recordPath = join(root, 'admission.json')
  mkdirSync(bin)
  writeFileSync(calls, '')
  writeFileSync(recordPath, JSON.stringify(record))
  writeFileSync(join(root, 'admission.mjs'), helper.replace("../../packages/invites/index.mjs", new URL('../../packages/invites/index.mjs', import.meta.url).href))
  writeFileSync(join(root, 'spawn.sh'), script)
  writeFileSync(join(bin, 'lxc'), `#!${process.execPath}
import { appendFileSync } from 'node:fs'
appendFileSync(process.env.CALLS, JSON.stringify(process.argv.slice(2)) + '\\n')
process.exit(process.env.RENDER_CAPTURE === '1' ? 0 : 79)
`, { mode: 0o755 })
  writeFileSync(join(bin, 'ss'), '#!/bin/bash\nprintf "%s" "$SS_OUTPUT"\nexit "${SS_EXIT:-0}"\n', { mode: 0o755 })
  writeFileSync(join(bin, 'git'), '#!/bin/bash\nprintf "%s\\n" "$TEST_SHA"\n', { mode: 0o755 })
  writeFileSync(join(bin, 'check-node'), '#!/bin/bash\nprintf "%s\\n" "$TEST_NODE_VERSION"\n', { mode: 0o755 })
  const env = { ...process.env, PATH: `${bin}:${process.env.PATH}`, CALLS: calls, AUKORA_NETWORK_ROOT_PUBKEY: networkRoot, NODE_NO_WARNINGS: '1' }
  function bash(args, extra = {}) {
    return spawnSync('/bin/bash', args, { cwd: root, env: { ...env, ...extra }, encoding: 'utf8', timeout: 15000 })
  }
  return {
    root, record: recordPath,
    run(args = ['--plan', 'member-node', recordPath], extra = {}) { return bash([join(root, 'spawn.sh'), ...args], extra) },
    calls() { return readFileSync(calls, 'utf8').trim().split('\n').filter(Boolean).map(JSON.parse) },
    capture(plan) {
      // Replay printed commands against lxc that only captures argv, never execs.
      const result = bash(['-c', plan], { RENDER_CAPTURE: '1' })
      assert.equal(result.status, 0, result.stderr)
      return this.calls()
    },
    probe(command, extra = {}, operands = []) { return bash(['-c', command, 'probe', ...operands], extra) },
  }
}

function assertRefused(result, code) {
  assert.equal(result.status, 1, result.stderr)
  assert.match(result.stderr, new RegExp(`^REFUSED ${code}(?:\\n|:)`, 'm'))
}

function checkPlan(t, script = source) {
  const f = fixture(t, script), first = f.run(), second = f.run()
  assert.equal(first.status, 0, first.stderr)
  assert.equal(second.stdout, first.stdout)
  assert.deepEqual(f.calls(), [], 'plan invoked lxc')
  assert.match(first.stdout, /SOURCE-ONLY conditional plan/)
  assert.match(first.stdout, /Verified signed path/)
  return { f, output: first.stdout }
}

function checkAdmission(t, script = source, helper = admissionSource) {
  const f = fixture(t, script, helper), empty = join(f.root, 'empty'), link = join(f.root, 'link')
  writeFileSync(empty, '')
  symlinkSync(f.record, link)
  for (const args of [
    ['--plan', 'member-node'], ['member-node'],
    ...['', join(f.root, 'absent'), empty, link, f.root].map(path => ['--plan', 'member-node', path]),
  ]) assertRefused(f.run(args), 'ADMISSION_RECORD_REQUIRED')
  writeFileSync(f.record, JSON.stringify(record) + ' '.repeat(16777216))
  assertRefused(f.run(), 'ADMISSION_RECORD_REQUIRED')
  assert.deepEqual(f.calls(), [])
}

function checkNames(t, script = source, helper = admissionSource) {
  const f = fixture(t, script, helper)
  for (const name of ['remote:node', '-node', 'node/other', 'node;id', 'node\nother', 'node-', 'a'.repeat(64)]) {
    assertRefused(f.run(['--plan', name, f.record]), 'NODE_NAME_INVALID')
  }
  assert.deepEqual(f.calls(), [])
}

function checkExecution(t, script = source) {
  const f = fixture(t, script)
  for (let i = 0; i < 2; i++) assertRefused(f.run(['member-node', f.record]), 'LXD_PROFILE_MISSING')
  writeFileSync(f.record, '{}')
  assertRefused(f.run(['member-node', f.record]), 'ADMISSION_RECORD_INVALID')
  assert.deepEqual(f.calls(), [], 'unverified admission reached LXD')
}

function checkOrder(t, script = source) {
  const { f, output } = checkPlan(t, script), commands = f.capture(output)
  assert.ok(commands.length > 20)
  assert.ok(commands.every(args => args[0] === '--force-local'))
  assert.ok(commands.every(args => !args.includes('--owner-page') && !args.includes('--repin')))
  let previous = -1
  for (const needle of [
    'LXD_PROFILE_MISSING', 'launch ', 'RUNTIME_INSTALL_MISSING', 'PRINCIPAL_INSTALL_MISSING',
    'SOURCE_RELEASE_MISMATCH', 'ops/node-spawn/install-member.py', 'scripts/build-dsh.py', 'scripts/materialize-aukora-release.py --from',
    'OWNER_ENROLLMENT_DERIVATION_MISSING', 'FRESH_KEYS_MISSING', 'GATE_INSTALL_MISSING', 'host/install/generate-manifest.py --package',
    'gate-bootstrap check-package', 'gate-bootstrap check-runtime', 'host/auma-local-deny/install.sh',
    'enable --now aukora-auma-podman.service', 'OPENSHELL_BINARY_PROVENANCE_MISSING', 'enable --now aukora-openshell-gateway.service',
    'GUEST_IMAGE_INPUTS_MISSING', 'guest-image/build.sh', 'SANDBOX_PRODUCER_MISSING', 'enable --now aukora-auma-sandbox.service',
    'NODE_STATE_MISSING', 'enable --now aukora-boundary-gate.service',
    'APPROVAL_RESUME_MISSING', 'gate-bootstrap approval raise', 'OWNER_APPROVAL_REQUIRED',
    'gate-bootstrap approval install', 'RELEASE_ENV_MISSING', 'gate-bootstrap floor check',
    'enable --now aukora-genesis.service', 'AUXILIARY_SETUP_MISSING', 'systemctl is-active',
  ]) {
    const index = output.indexOf(needle, previous + 1)
    assert.ok(index > previous, `missing or misordered: ${needle}`)
    previous = index
  }
  const manifest = commands.find(args => args.includes('--package'))
  for (const flag of ['--signer-epochs', '--owner-key', '--launcher-checkout', '--output']) assert.ok(manifest.includes(flag), flag)
  const builds = commands.filter(args => args.some(arg => /scripts\/(build-dsh|materialize-aukora-release)\.py/.test(arg)))
  assert.equal(builds.length, 2)
  assert.ok(builds.every(args => args.includes('PATH=/opt/aukora-node/bin:/usr/local/bin:/usr/bin:/bin')))
  return { f, commands }
}

function checkListeners(t, script = source) {
  const { f, output } = checkPlan(t, script), commands = f.capture(output)
  const checks = commands.filter(args => args.at(-1).includes('ss -H -lntu'))
  assert.equal(checks.length, 3, 'inspect base image, gateway and final listeners')
  const command = checks[0].at(-1)
  for (const address of ['127.0.0.1:18735', '127.0.0.53:53', '127.0.0.54:53', '127.1.2.3:53', '[::1]:17690', '::1:17792']) {
    assert.equal(f.probe(command, { SS_OUTPUT: `tcp LISTEN 0 128 ${address} *:*\n` }).status, 0)
  }
  for (const address of ['0.0.0.0:22', '[::]:22', '*:3000', '10.0.0.2:18735', '192.168.1.1:17690', '127.999.0.1:53']) {
    for (const type of ['tcp LISTEN', 'udp UNCONN']) {
      assertRefused(f.probe(command, { SS_OUTPUT: `${type} 0 128 ${address} *:*\n` }), 'OFF_LOOPBACK_LISTENER')
    }
  }
  assert.notEqual(f.probe(command, { SS_OUTPUT: '', SS_EXIT: '1' }).status, 0, 'failed ss passed')
  assert.equal(f.probe(command, { SS_OUTPUT: '' }).status, 0)
  assert.ok(commands.some(args => args.includes('http://127.0.0.1:18735/')))
  assert.ok(!commands.some(args => args.includes('proxy') || args.includes('--publish') || args.includes('--privileged')))
}

function checkRevision(t, script = source) {
  const { f, output } = checkPlan(t, script), commands = f.capture(output)
  const checks = commands.filter(args => args.includes('bash') && args.some(arg => arg.includes('SOURCE_RELEASE_MISMATCH')))
  assert.equal(checks.length, 2, 'check before build and before launch')
  for (const args of checks) {
    const command = args[args.indexOf('-c') + 1], sha = 'a'.repeat(40)
    assert.equal(f.probe(command, { TEST_SHA: sha }, [sha]).status, 0)
    assertRefused(f.probe(command, { TEST_SHA: 'b'.repeat(40) }, [sha]), 'SOURCE_RELEASE_MISMATCH')
  }
}

function checkRuntime(t, script = source) {
  const { f, output } = checkPlan(t, script), commands = f.capture(output)
  const args = commands.find(args => args.some(arg => arg.includes('NODE_VERSION_MISMATCH')))
  assert.ok(args)
  const command = args.at(-1).replace('/opt/aukora-node/bin/node', join(f.root, 'bin', 'check-node'))
  assert.equal(f.probe(command, { TEST_NODE_VERSION: 'v24.11.1' }).status, 0)
  for (const version of ['', 'v22.23.0', 'v24.11.0', 'v24.11.2']) {
    assertRefused(f.probe(command, { TEST_NODE_VERSION: version }), 'NODE_VERSION_MISMATCH')
  }
}

function checkVerifiedAdmission(t, helper = admissionSource) {
  const f = fixture(t, source, helper)
  const valid = f.run()
  assert.equal(valid.status, 0, valid.stderr)
  const commands = f.capture(valid.stdout)
  const install = commands.find(args => args.includes('/opt/aukora-genesis/src/ops/node-spawn/install-member.py'))
  assert.deepEqual(JSON.parse(install.at(-1)), expectedConfig)
  assert.ok(!valid.stdout.includes('"chain"') && !valid.stdout.includes('"sig"'))
  const changedName = f.run(['--plan', 'other-node', f.record])
  assert.equal(changedName.status, 0, changedName.stderr)
  assert.ok(changedName.stdout.includes('other-node'))
  for (const root of ['', 'not-a-key', publicKeyOf(keys[1])]) {
    assertRefused(f.run(undefined, { AUKORA_NETWORK_ROOT_PUBKEY: root }),
      root.length === 64 ? 'ADMISSION_RECORD_INVALID' : 'NETWORK_ROOT_REQUIRED')
  }
  for (const bad of [null, {}, { member: expectedConfig.member_pubkey, record },
    { ...record, root: networkRoot }, { chain: record.chain.slice(1) },
    ...record.chain.flatMap((_, i) => ['invite', 'redemption'].map(kind => {
      const copy = structuredClone(record)
      copy.chain[i][kind].sig = '0'.repeat(128)
      return copy
    })),
  ]) {
    writeFileSync(f.record, JSON.stringify(bad))
    for (const mode of [[], ['--plan']]) {
      const before = f.calls().length
      assertRefused(f.run([...mode, 'member-node', f.record]), 'ADMISSION_RECORD_INVALID')
      assert.equal(f.calls().length, before, 'invalid record reached LXD')
    }
  }
}

const provisioningRefusals = ['OWNER_ENROLLMENT_DERIVATION_MISSING',
  'OPENSHELL_BINARY_PROVENANCE_MISSING', 'GUEST_IMAGE_INPUTS_MISSING', 'SANDBOX_PRODUCER_MISSING']
function checkProvisioningRefusals(t, script = source) {
  for (const code of provisioningRefusals) {
    // Skip earlier gaps only in this fixture; lxc records commands without executing them.
    const selected = script.replace('else refuse "$1"; fi', `else [[ "$1" != ${code} ]] || refuse "$1"; fi`)
    const f = fixture(t, selected)
    assertRefused(f.run(['member-node', f.record], { RENDER_CAPTURE: '1' }), code)
    assert.ok(!f.calls().some(args => args.includes('aukora-boundary-gate.service')))
  }
}

test('signed admission binds the exact node, configured root and leaf member', checkVerifiedAdmission)
test('unsupported enrollment and sandbox substeps stop stub LXD execution', checkProvisioningRefusals)
test('sandbox commands use existing scripts, users and exact builder arguments', t => {
  const { commands } = checkOrder(t)
  const build = commands.find(args => args.some(arg => arg.endsWith('/guest-image/build.sh')))
  assert.deepEqual(build, ['--force-local', 'exec', 'member-node', '--', 'sudo', '-n', '-u', 'auma', '-H',
    '/usr/local/lib/aukora-boundary/openshell/guest-image/build.sh', '/opt/aukora-node/bin/node',
    '/opt/aukora-genesis/release-<sha7>/plugins/aukora-openshell-confinement/guest/exec.py',
    '/opt/aukora-genesis/release-<sha7>/packages/ptc-runtime/ptc-runtime-node/lib/process.js'])
  assert.ok(!commands.some(args => args.includes('--bootstrap-profile') || args.includes('sandbox create')))
})
function checkPreloads(t, script = source) {
  const f = fixture(t, script), hook = join(f.root, 'hook.mjs'), marker = join(f.root, 'executed')
  writeFileSync(hook, `import { writeFileSync } from 'node:fs'; writeFileSync(${JSON.stringify(marker)}, 'hook executed')`)
  const result = f.run(undefined, { NODE_OPTIONS: `--import=${hook}` })
  assert.throws(() => readFileSync(marker), { code: 'ENOENT' })
  assertRefused(result, 'NODE_OPTIONS_FORBIDDEN')
  assert.deepEqual(f.calls(), [])
}
test('caller Node preloads refuse before admission or LXD', checkPreloads)
test('admission file and node-name guard mutations are killed', t => {
  for (const [name, before, after, check] of [
    ['admission-no-follow', ' | constants.O_NOFOLLOW', '', checkAdmission],
    ['admission-size', 'stat.size > MAX_RECORD_BYTES', 'false', checkAdmission],
    ['admission-node-name', 'refuse(REFUSE.NODE)', '{}', checkNames],
  ]) {
    let mutant = admissionSource.replaceAll(before, after)
    if (name === 'admission-size') mutant = mutant.replace('if (length > MAX_RECORD_BYTES)', 'if (false)')
    assert.throws(() => check(t, source, mutant), { name: 'AssertionError' }, name)
    t.diagnostic(`MUTATION KILLED ${name}`)
  }
})
function admissionMetadataProbe(t, helper, scenario) {
  const f = fixture(t, source, helper)
  const program = `
    import fs from 'node:fs'; import { syncBuiltinESMExports } from 'node:module';
    const scenario = ${JSON.stringify(scenario)};
    if (scenario === 'version') Object.defineProperty(process, 'version', { value: 'v24.11.0' });
    else {
      const original = fs.fstatSync;
      fs.fstatSync = fd => { const st = original(fd); return { ...st,
        size: scenario === 'empty' ? 0 : st.size, isFile: () => scenario !== 'regular' }; };
      syncBuiltinESMExports();
    }
    const { runCli } = await import(${JSON.stringify(join(f.root, 'admission.mjs'))});
    process.exitCode = runCli(['member-node', ${JSON.stringify(f.record)}]);`
  return spawnSync(process.execPath, ['--input-type=module', '-e', program], {
    encoding: 'utf8', env: { ...process.env, AUKORA_NETWORK_ROOT_PUBKEY: networkRoot, NODE_NO_WARNINGS: '1' },
  })
}
test('host Node version and file metadata checks refuse; their mutants fail', t => {
  // Synthetic metadata/version isolates redundant guards without another runtime or special files.
  for (const [name, before, after, code] of [
    ['version', "process.version !== 'v24.11.1'", 'false', 'NODE_VERSION_MISMATCH'],
    ['regular', '!stat.isFile() || ', '', 'ADMISSION_RECORD_REQUIRED'],
    ['empty', 'stat.size < 1 || ', '', 'ADMISSION_RECORD_REQUIRED'],
  ]) {
    assertRefused(admissionMetadataProbe(t, admissionSource, name), code)
    assert.ok(admissionSource.includes(before))
    const mutant = admissionMetadataProbe(t, admissionSource.replace(before, after), name)
    assert.equal(mutant.status, 0, mutant.stderr)
    assert.throws(() => assertRefused(mutant, code), { name: 'AssertionError' })
    t.diagnostic(`MUTATION KILLED admission-${name}`)
  }
})
test('admission verification mutations are killed', t => {
  for (const [name, before, after] of [
    ['signed-path', ';({ member } = verifyRecord({ root, record }))', ';({ member } = { member: record.chain.at(-1).redemption.pubkey })'],
    ['configured-root', 'verifyRecord({ root, record })', 'verifyRecord({ root: record.chain[0].invite.pubkey, record })'],
    ['member-binding', 'member_pubkey: member', 'member_pubkey: root'],
    ['node-binding', 'version: 1, node,', "version: 1, node: 'other-node',"],
    ['redemption-binding', 'record.chain.at(-1).redemption.id', 'record.chain[0].redemption.id'],
  ]) {
    assert.ok(admissionSource.includes(before), name)
    assert.throws(() => checkVerifiedAdmission(t, admissionSource.replace(before, after)), { name: 'AssertionError' }, name)
    t.diagnostic(`MUTATION KILLED ${name}`)
  }
})

test('plan is repeatable and never calls stub lxc', checkPlan)
test('missing, empty, symlink and nonregular admission refuse', checkAdmission)
test('names cannot select a remote or inject arguments', checkNames)
test('execution verifies admission then stops at unsupported LXD provisioning', checkExecution)
test('known commands preserve provisioning and owner approval order', checkOrder)
test('planned listener checks reject off-loopback TCP/UDP and failed inspection', checkListeners)
test('planned launcher checks refuse different release commits', checkRevision)
test('planned runtime check requires exactly Node v24.11.1', checkRuntime)
test('admission contents and shell characters are inert and never printed', t => {
  const f = fixture(t), path = join(f.root, 'record $(touch SHOULD_NOT_EXIST); `id`')
  writeFileSync(path, 'SYNTHETIC_SECRET_DO_NOT_PRINT\n$(touch SHOULD_NOT_EXIST)\n')
  const result = f.run(['--plan', 'member-node', path])
  assertRefused(result, 'ADMISSION_RECORD_INVALID')
  assert.ok(!(result.stdout + result.stderr).includes('SYNTHETIC_SECRET_DO_NOT_PRINT'))
  assert.deepEqual(f.calls(), [])
  assert.throws(() => readFileSync(join(f.root, 'SHOULD_NOT_EXIST')), { code: 'ENOENT' })
  writeFileSync(path, JSON.stringify(record))
  const valid = f.run(['--plan', 'member-node', path])
  assert.equal(valid.status, 0, valid.stderr)
  f.capture(valid.stdout)
  assert.throws(() => readFileSync(join(f.root, 'SHOULD_NOT_EXIST')), { code: 'ENOENT' })
})

test('guard mutations are killed by the corresponding regressions', t => {
  const mutations = [
    ['plan-no-execution', 'then printf \'%q \' "$@"; printf \'\\n\'; else "$@";', 'then "$@"; else "$@";', checkPlan],
    ['admission-verifier', 'member_config=$(node', 'member_config=$(true', checkExecution],
    ['node-preload', '|| refuse NODE_OPTIONS_FORBIDDEN', '|| true', checkPreloads],
    ...provisioningRefusals.map(code => [code, `gap ${code}`, `# removed ${code}`, checkProvisioningRefusals]),
    ['local-lxd', 'lxc --force-local', 'lxc', checkOrder],
    ['owner-approval', "gap OWNER_APPROVAL_REQUIRED 'owner", "# gap REMOVED_OWNER_BARRIER 'owner", checkOrder],
    ['approval-resume', "gap APPROVAL_RESUME_MISSING 'first", "# gap REMOVED_RESUME_BARRIER 'first", checkOrder],
    ['off-loopback', 'exit 1 } }', 'exit 0 } }', checkListeners],
    ['listener-read-failure', "listener_check='set -euo pipefail", "listener_check='set -eu", checkListeners],
    ['source-release-equality', ' = "$1" ||', ' = "$(git -C /opt/aukora-genesis/src rev-parse HEAD)" ||', checkRevision],
    ['build-runtime', 'PATH=/opt/aukora-node/bin:/usr/local/bin:/usr/bin:/bin', 'PATH=/usr/local/bin:/usr/bin:/bin', checkOrder],
    ['node-version', 'test "$(/opt/aukora-node/bin/node --version)" = v24.11.1', 'true', checkRuntime],
  ]
  for (const [name, before, after, check] of mutations) {
    assert.ok(source.includes(before), `mutation target missing: ${name}`)
    const mutant = source.replaceAll(before, after)
    assert.throws(() => check(t, mutant), { name: 'AssertionError' }, `survived: ${name}`)
    t.diagnostic(`MUTATION KILLED ${name}`)
  }
})

const memberInstallerSource = readFileSync(join(here, 'install-member.py'), 'utf8')
const memberInstallerProbe = String.raw`
import json, os, pathlib, runpy, stat, sys, types
scope = runpy.run_path(sys.argv[1], run_name='member_fixture')['install'].__globals__
base, scenario, value = pathlib.Path(sys.argv[2]), sys.argv[3], json.loads(sys.argv[4])
install = scope['install']
def expect(code, action):
    try:
        action()
    except ValueError as error:
        assert str(error) == code, 'MEMBER_GUARD_REFUSAL ' + str(error)
    else:
        raise AssertionError('MEMBER_GUARD_MISSING ' + code)
def setup(name):
    root = base / name
    root.mkdir(mode=0o755); (root / 'etc').mkdir(mode=0o755)
    scope.update(ROOT=str(root), UID=os.geteuid())
    return root, root / 'etc/aukora-node/member.json'
def run(name):
    root, target = setup(name)
    if name == 'shape':
        for bad in [dict(value, extra=True), dict(value, version=True), dict(value, node='../other'),
                    dict(value, member_pubkey='Z' * 64), dict(value, redemption_id=None)]:
            expect('MEMBER_CONFIG_INVALID', lambda: install(bad))
        assert not target.exists(), 'MEMBER_GUARD_INVALID_WRITE'
        return
    if name == 'root-required':
        scope['UID'] += 1
        protected = scope['protected']; scope['protected'] = lambda *_: None
        try:
            expect('MEMBER_CONFIG_ROOT_REQUIRED', lambda: install(value))
        finally:
            scope['protected'] = protected
        return
    install(value)
    assert json.loads(target.read_text()) == value, 'MEMBER_GUARD_CONFIG'
    assert target.stat().st_mode & 0o777 == 0o644, 'MEMBER_GUARD_FILE_MODE'
    assert target.parent.stat().st_mode & 0o777 == 0o755, 'MEMBER_GUARD_DIR_MODE'
    if name == 'install':
        os.utime(target, (1000, 1000)); before = target.stat()
        install(value); after = target.stat()
        assert (before.st_ino, before.st_mtime_ns) == (after.st_ino, after.st_mtime_ns), 'MEMBER_GUARD_OVERWRITE'
        print(json.dumps(json.loads(target.read_text()), sort_keys=True)); return
    if name == 'conflict':
        before = target.read_bytes()
        expect('MEMBER_CONFIG_CONFLICT', lambda: install(dict(value, member_pubkey='d' * 64)))
        assert target.read_bytes() == before, 'MEMBER_GUARD_REBOUND'
        return
    if name.endswith('-mode'):
        path = {'root-mode': root, 'etc-mode': root / 'etc', 'dir-mode': target.parent, 'file-mode': target}[name]
        path.chmod(0o777)
        expect('MEMBER_CONFIG_UNPROTECTED', lambda: install(value)); return
    if name.endswith('-link'):
        path = {'root-link': root, 'etc-link': root / 'etc', 'dir-link': target.parent, 'file-link': target}[name]
        moved = path.with_name(path.name + '-real'); path.rename(moved); path.symlink_to(moved)
        expect('MEMBER_CONFIG_IO', lambda: install(value)); return
    if name == 'hardlink':
        os.link(target, root / 'second-link')
        expect('MEMBER_CONFIG_UNPROTECTED', lambda: install(value)); return
    if name == 'size':
        with target.open('a') as output: output.write(' ' * 5000)
        expect('MEMBER_CONFIG_UNPROTECTED', lambda: install(value)); return
    if name in ('directory-owner', 'file-owner', 'directory-type', 'file-type'):
        original = os.fstat
        def metadata(fd):
            info = original(fd)
            if stat.S_ISDIR(info.st_mode) == name.startswith('directory'):
                fields = {key: getattr(info, key) for key in ('st_uid', 'st_mode', 'st_nlink', 'st_size')}
                fields['st_uid' if name.endswith('owner') else 'st_mode'] = scope['UID'] + 1 if name.endswith('owner') else stat.S_IFIFO | 0o644
                return types.SimpleNamespace(**fields)
            return info
        os.fstat = metadata
        try:
            expect('MEMBER_CONFIG_UNPROTECTED', lambda: install(value))
        finally:
            os.fstat = original
        return
    raise AssertionError('unknown scenario')
scenarios = ['install', 'shape', 'root-required', 'conflict', 'root-mode', 'etc-mode', 'dir-mode', 'file-mode',
             'root-link', 'etc-link', 'dir-link', 'file-link', 'hardlink', 'size',
             'directory-owner', 'file-owner', 'directory-type', 'file-type']
for name in scenarios if scenario == 'all' else [scenario]: run(name)
`

function checkMemberInstaller(t, installer = memberInstallerSource, scenario = 'all') {
  const f = fixture(t), path = join(f.root, 'install-member.py'), container = join(f.root, 'container')
  writeFileSync(path, installer)
  mkdirSync(container)
  return spawnSync('/usr/bin/python3', ['-I', '-S', '-c', memberInstallerProbe, path, container, scenario, JSON.stringify(expectedConfig)],
    { encoding: 'utf8', timeout: 15000 })
}

test('member config is immutable, repeatable and refuses unsafe custody', t => {
  const result = checkMemberInstaller(t)
  assert.equal(result.status, 0, result.stderr)
  assert.deepEqual(JSON.parse(result.stdout), expectedConfig)
})

test('member installer protection mutations fail the relevant regression', t => {
  const mutations = [
    ['member-shape', "refuse('MEMBER_CONFIG_INVALID')", 'pass', 'shape'],
    ['member-root', 'if os.geteuid() != UID:', 'if False:', 'root-required'],
    ['member-conflict', "refuse('MEMBER_CONFIG_CONFLICT')", 'pass', 'conflict'],
    ['member-owner', 'info.st_uid != UID', 'False', 'file-owner'],
    ['member-directory-owner', 'info.st_uid != UID', 'False', 'directory-owner'],
    ['member-write-mode', 'or info.st_mode & 0o022', 'or False', 'file-mode'],
    ['member-directory-mode', 'or info.st_mode & 0o022', 'or False', 'etc-mode'],
    ['member-file-type', 'stat.S_ISREG(info.st_mode)', 'True', 'file-type'],
    ['member-directory-type', 'stat.S_ISDIR(info.st_mode)', 'True', 'directory-type'],
    ['member-hardlink', 'info.st_nlink != 1', 'False', 'hardlink'],
    ['member-size', 'info.st_size > 4096', 'False', 'size'],
    ['member-no-follow', ' | os.O_NOFOLLOW', '', 'file-link'],
    ['member-directory-no-follow', ' | os.O_NOFOLLOW', '', 'etc-link'],
    ['member-exclusive-create', ' | os.O_EXCL', '', 'install'],
    ['member-created-file-mode', 'os.fchmod(file, 0o644)', 'os.fchmod(file, 0o640)', 'install'],
    ['member-created-directory-mode', 'os.fchmod(directory, 0o755)', 'os.fchmod(directory, 0o700)', 'install'],
  ]
  for (const [name, before, after, scenario] of mutations) {
    assert.ok(memberInstallerSource.includes(before), `mutation target missing: ${name}`)
    const result = checkMemberInstaller(t, memberInstallerSource.replaceAll(before, after), scenario)
    assert.notEqual(result.status, 0, `survived: ${name}`)
    assert.match(result.stderr, /AssertionError: MEMBER_GUARD_/, `not a regression assertion: ${name}: ${result.stderr}`)
    t.diagnostic(`MUTATION KILLED ${name}`)
  }
})
