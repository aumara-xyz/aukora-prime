// SPDX-License-Identifier: AGPL-3.0-or-later
// Exercise plan/refusal guards and their removal using local stubs only.
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync, rmSync, symlinkSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import test from 'node:test'

const here = dirname(fileURLToPath(import.meta.url))
const source = readFileSync(join(here, 'spawn.sh'), 'utf8')
assert.equal(process.version, 'v24.11.1')

function fixture(t, script = source) {
  const root = mkdtempSync(join(here, '.test-'))
  t.after(() => rmSync(root, { recursive: true, force: true }))
  const bin = join(root, 'bin'), calls = join(root, 'calls'), record = join(root, 'admission.json')
  mkdirSync(bin)
  writeFileSync(calls, '')
  writeFileSync(record, '{"synthetic":"not a verified invite"}\n')
  writeFileSync(join(root, 'spawn.sh'), script)
  writeFileSync(join(bin, 'lxc'), `#!${process.execPath}
import { appendFileSync } from 'node:fs'
appendFileSync(process.env.CALLS, JSON.stringify(process.argv.slice(2)) + '\\n')
process.exit(process.env.RENDER_CAPTURE === '1' ? 0 : 79)
`, { mode: 0o755 })
  writeFileSync(join(bin, 'ss'), '#!/bin/bash\nprintf "%s" "$SS_OUTPUT"\nexit "${SS_EXIT:-0}"\n', { mode: 0o755 })
  writeFileSync(join(bin, 'git'), '#!/bin/bash\nprintf "%s\\n" "$TEST_SHA"\n', { mode: 0o755 })
  writeFileSync(join(bin, 'node'), '#!/bin/bash\nprintf "%s\\n" "$TEST_NODE_VERSION"\n', { mode: 0o755 })
  const env = { ...process.env, PATH: `${bin}:${process.env.PATH}`, CALLS: calls }
  function bash(args, extra = {}) {
    return spawnSync('/bin/bash', args, { cwd: root, env: { ...env, ...extra }, encoding: 'utf8', timeout: 15000 })
  }
  return {
    root, record,
    run(args = ['--plan', 'member-node', record]) { return bash([join(root, 'spawn.sh'), ...args]) },
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
  assert.match(result.stderr, new RegExp(`^REFUSED ${code}(?:\\n|:)`))
}

function checkPlan(t, script = source) {
  const f = fixture(t, script), first = f.run(), second = f.run()
  assert.equal(first.status, 0, first.stderr)
  assert.equal(second.stdout, first.stdout)
  assert.deepEqual(f.calls(), [], 'plan invoked lxc')
  assert.match(first.stdout, /SOURCE-ONLY conditional plan/)
  assert.match(first.stdout, /record presence is not authorization/)
  return { f, output: first.stdout }
}

function checkAdmission(t, script = source) {
  const f = fixture(t, script), empty = join(f.root, 'empty'), link = join(f.root, 'link')
  writeFileSync(empty, '')
  symlinkSync(f.record, link)
  for (const args of [
    ['--plan', 'member-node'], ['member-node'],
    ...['', join(f.root, 'absent'), empty, link, f.root].map(path => ['--plan', 'member-node', path]),
  ]) assertRefused(f.run(args), 'ADMISSION_RECORD_REQUIRED')
  assert.deepEqual(f.calls(), [])
}

function checkNames(t, script = source) {
  const f = fixture(t, script)
  for (const name of ['remote:node', '-node', 'node/other', 'node;id', 'node\nother', 'node-', 'a'.repeat(64)]) {
    assertRefused(f.run(['--plan', name, f.record]), 'NODE_NAME_INVALID')
  }
  assert.deepEqual(f.calls(), [])
}

function checkExecution(t, script = source) {
  const f = fixture(t, script)
  for (let i = 0; i < 2; i++) assertRefused(f.run(['member-node', f.record]), 'INVITE_ADMISSION_VERIFIER_MISSING')
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
    'SOURCE_RELEASE_MISMATCH', 'scripts/build-dsh.py', 'scripts/materialize-aukora-release.py --from',
    'FRESH_KEYS_MISSING', 'GATE_INSTALL_MISSING', 'host/install/generate-manifest.py --package',
    'gate-bootstrap check-package', 'gate-bootstrap check-runtime', 'host/auma-local-deny/install.sh',
    'enable --now aukora-auma-podman.service', 'enable --now aukora-openshell-gateway.service',
    'SANDBOX_PRODUCER_MISSING', 'enable --now aukora-auma-sandbox.service',
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
  const command = args.at(-1).replace('/opt/aukora-node/bin/node', join(f.root, 'bin', 'node'))
  assert.equal(f.probe(command, { TEST_NODE_VERSION: 'v24.11.1' }).status, 0)
  for (const version of ['', 'v22.23.0', 'v24.11.0', 'v24.11.2']) {
    assertRefused(f.probe(command, { TEST_NODE_VERSION: version }), 'NODE_VERSION_MISMATCH')
  }
}

test('plan is repeatable and never calls stub lxc', checkPlan)
test('missing, empty, symlink and nonregular admission refuse', checkAdmission)
test('names cannot select a remote or inject arguments', checkNames)
test('real execution always refuses unverified admission without side effects', checkExecution)
test('known commands preserve provisioning and owner approval order', checkOrder)
test('planned listener checks reject off-loopback TCP/UDP and failed inspection', checkListeners)
test('planned launcher checks refuse different release commits', checkRevision)
test('planned runtime check requires exactly Node v24.11.1', checkRuntime)
test('admission contents and shell characters are inert and never printed', t => {
  const f = fixture(t), path = join(f.root, 'record $(touch SHOULD_NOT_EXIST); `id`')
  writeFileSync(path, 'SYNTHETIC_SECRET_DO_NOT_PRINT\n$(touch SHOULD_NOT_EXIST)\n')
  const result = f.run(['--plan', 'member-node', path])
  assert.equal(result.status, 0, result.stderr)
  assert.ok(!result.stdout.includes('SYNTHETIC_SECRET_DO_NOT_PRINT'))
  assert.deepEqual(f.calls(), [])
  f.capture(result.stdout)
  assert.throws(() => readFileSync(join(f.root, 'SHOULD_NOT_EXIST')), { code: 'ENOENT' })
})

test('guard mutations are killed by the corresponding regressions', t => {
  const mutations = [
    ['node-name', '|| refuse NODE_NAME_INVALID', '|| true', checkNames],
    ['admission-file', '|| refuse ADMISSION_RECORD_REQUIRED', '|| true', checkAdmission],
    ['plan-no-execution', 'then printf \'%q \' "$@"; printf \'\\n\'; else "$@";', 'then "$@"; else "$@";', checkPlan],
    ['admission-verifier', "gap INVITE_ADMISSION_VERIFIER_MISSING 'record", "# gap INVITE_ADMISSION_VERIFIER_MISSING 'record", checkExecution],
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
