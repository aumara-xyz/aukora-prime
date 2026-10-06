// bin/selfcheck.mjs: the deployed, fail-closed self-check. Exit 0 only when every forbidden action is refused, the
// egress probe passes AND the result is recorded in the gate ledger. Stubs replace the sandbox runner and gate RPC.
import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { main, parseArgs, hostProbes, hostLayout } from '../bin/selfcheck.mjs'

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'scbin-'))
for (const r of ['release-aaaaaaa', 'release-bbbbbbb', 'not-a-release']) fs.mkdirSync(path.join(tmp, r, 'plugins'), { recursive: true })
const ARGS = ['--run', '/run/aukora-gate', '--gate-home', '/home/aukora-gate', '--target-root', '/var/lib/aukora-boundary/targets', '--release-parent', tmp]
const pass = async () => ({ exit_code: 0, stdout: 'blocked x\nPROBE_DONE fail=0\n', stderr: '' })
const failEgress = async () => ({ exit_code: 0, stdout: 'REACHABLE 10.0.0.1:22\nPROBE_DONE fail=1\n', stderr: '' })
const refused = () => { throw Object.assign(new Error('x'), { code: 'EACCES' }) }
const allRefused = () => [['a', refused], ['b', refused]]
const recorder = () => { const calls = []; const rpc = async (sock, op, args) => { if (op === 'selfcheck') { calls.push({ sock, args }); return { ok: true } } throw Object.assign(new Error('refused'), { code: 'EACCES' }) }; return { calls, rpc } }
const quiet = { out: () => {} }

test('passes, and records, when everything forbidden is refused and egress passes', async () => {
  const r = recorder()
  assert.equal(await main(ARGS, { run: pass, rpc: r.rpc, probesFor: allRefused, ...quiet }), 0)
  assert.equal(r.calls.length, 1); assert.equal(r.calls[0].sock, '/run/aukora-gate/gate.sock'); assert.equal(r.calls[0].args.result.ok, true)
  const acts = r.calls[0].args.result.forbidden.map(f => f.action)
  assert.ok(acts.includes('connect gate owner socket (approve channel)') && acts.includes('approve on the propose socket'), 'gate channel probes run')
})
test('a forbidden action that SUCCEEDS fails closed, and the failure is still recorded', async () => {
  const r = recorder()
  assert.equal(await main(ARGS, { run: pass, rpc: r.rpc, probesFor: () => [['a', refused], ['write gate target', () => 'opened']], ...quiet }), 1)
  assert.equal(r.calls[0].args.result.ok, false)
})
test('egress probe failure fails closed', async () => {
  assert.equal(await main(ARGS, { run: failEgress, rpc: recorder().rpc, probesFor: allRefused, ...quiet }), 1)
})
test('a passing check that cannot be recorded in the ledger fails closed', async () => {
  const rpc = async (s, op) => { if (op === 'selfcheck') throw new Error('gate unavailable (ENOENT); fail closed'); throw Object.assign(new Error('x'), { code: 'EACCES' }) }
  assert.equal(await main(ARGS, { run: pass, rpc, probesFor: allRefused, ...quiet }), 1)
})
test('a probe list that throws (e.g. no release found) fails closed and is recorded', async () => {
  const r = recorder()
  assert.equal(await main(ARGS, { run: pass, rpc: r.rpc, probesFor: () => { throw new Error('no release-* directory') }, ...quiet }), 1)
  assert.match(r.calls[0].args.result.error, /no release/)
})
test('arguments: unknown, duplicated, relative or missing paths are refused (exit 2)', async () => {
  for (const bad of [[...ARGS, '--x', '/y'], [...ARGS, '--run', '/r'], ARGS.map(a => a === tmp ? 'rel/dir' : a), ARGS.slice(2)])
    assert.equal(await main(bad, { run: pass, rpc: recorder().rpc, probesFor: allRefused, ...quiet }), 2)
})
test('host probes: the gate paths, every release-* plugins dir, and each --forbid-write path', () => {
  const o = parseArgs([...ARGS, '--forbid-write', '/opt/aukora-boundary-gate/bin/gate.mjs'])
  const names = hostProbes(o, hostLayout(o)).map(([n]) => n)
  assert.ok(names.includes('drop file into release-aaaaaaa/plugins') && names.includes('drop file into release-bbbbbbb/plugins'))
  assert.ok(!names.some(n => n.includes('not-a-release')))
  assert.ok(names.includes('write /opt/aukora-boundary-gate/bin/gate.mjs'))
  assert.ok(names.includes('read gate receipt key') && names.includes('sudo to root'))
  const empty = fs.mkdtempSync(path.join(os.tmpdir(), 'scbin-empty-'))
  assert.throws(() => hostProbes({ ...o, releaseParent: empty }), /no release-\* directory/)
  assert.equal(hostLayout(o).gateHome, '/home/aukora-gate'); assert.equal(hostLayout(o).targetRoot, '/var/lib/aukora-boundary/targets')
})
test('the Linux unit runs it as ExecStartPre before the launcher, and the timer path stops the runtime on failure', () => {
  const unit = fs.readFileSync(new URL('../host/systemd/aukora-genesis.service', import.meta.url), 'utf8')
  const pre = unit.indexOf('ExecStartPre=/usr/local/lib/aukora-boundary/selfcheck-with-retry -- --run'), start = unit.indexOf('ExecStart=/usr/bin/python3')
  assert.ok(pre > 0 && pre < start, 'the spaced-retry wrapper precedes the launcher')
  const wrapper = fs.readFileSync(new URL('../host/systemd/selfcheck-with-retry', import.meta.url), 'utf8')
  assert.match(wrapper, /\/opt\/aukora-node\/bin\/node \/opt\/aukora-boundary-gate\/bin\/selfcheck\.mjs/, 'the wrapper runs the exact self-check binary')
  assert.match(wrapper, /sleep 45/, 'one spaced retry before failing closed')
  assert.match(unit, /StartLimitBurst=3/)
  const svc = fs.readFileSync(new URL('../host/systemd/aukora-selfcheck.service', import.meta.url), 'utf8')
  const periodic = fs.readFileSync(new URL('../host/systemd/aukora-selfcheck-periodic.service', import.meta.url), 'utf8')
  // Separate handler instances retain the failed selfcheck's MONITOR_* provenance; a shared handler loses that binding.
  for (const selfcheck of [svc, periodic])
    assert.deepEqual(selfcheck.split('\n').filter(line => /^\s*OnFailure\s*=/u.test(line)),
      ['OnFailure=aukora-genesis-failclosed@%n.service'], 'one exact invocation-aware failure handler')
  assert.match(svc, /User=aukora-host/)
  assert.match(svc, /RemainAfterExit=yes/, 'a completed oneshot stays active for the Genesis BindsTo')
  const handler = fs.readFileSync(new URL('../host/systemd/aukora-genesis-failclosed@.service', import.meta.url), 'utf8')
  assert.deepEqual(handler.split('\n').filter(line => /^\s*User\s*=/u.test(line)), ['User=root'])
  assert.deepEqual(handler.split('\n').filter(line => /^\s*ExecStart\s*=/u.test(line)),
    ['ExecStart=/usr/bin/python3 -I -S /usr/local/lib/aukora-boundary/genesis-recover-probe failclosed %i'])
  const recovery = fs.readFileSync(new URL('../host/systemd/genesis-recover-probe', import.meta.url), 'utf8')
  assert.match(recovery, /^SYSTEMCTL = "\/usr\/bin\/systemctl"$/mu)
  assert.match(recovery, /^GENESIS = "aukora-genesis\.service"$/mu)
  const failureStart = recovery.indexOf('def failclosed(source):\n'), recoveryStart = recovery.indexOf('\ndef recover():\n')
  assert.ok(failureStart >= 0 && recoveryStart > failureStart, 'the failclosed helper body is present')
  assert.match(recovery.slice(failureStart, recoveryStart),
    /^        require\(command\(\[SYSTEMCTL, "stop", GENESIS\], timeout=180\)\.returncode == 0, "stop-refused"\)$/mu,
    'the invocation-aware handler requires the fixed Genesis stop')
  assert.match(fs.readFileSync(new URL('../host/systemd/aukora-genesis-failclosed.service', import.meta.url), 'utf8'), /systemctl stop aukora-genesis\.service/)
})
