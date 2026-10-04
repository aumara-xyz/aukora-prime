// Source checks for the boundary foundation: layout, sudo rule, host scripts, sandbox wrapper, runner and
// fail-closed self-check. No network, sudo or OpenShell is used; the wrapper runs against a local stub.
import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { spawn, spawnSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import { resolveLayout, sudoersRule, DEFAULT_LAYOUT } from '../src/layout.mjs'
import { clampTimeout, sandboxArgv, runInSandbox, egressProbeScript, probePassed, OUT_CAP } from '../src/sandbox.mjs'
import { runForbidden, selfCheck } from '../src/selfcheck.mjs'

const PKG = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const HOST = path.join(PKG, 'host')
const read = (p) => fs.readFileSync(path.join(PKG, p), 'utf8')
const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'boundary-host-'))

test('layout: three distinct principals, validated paths, unknown keys refuse', () => {
  const l = resolveLayout()
  assert.equal(l.sbxExec, '/usr/local/lib/aukora-boundary/sbx-exec')
  assert.equal(l.proposeSocket, '/run/aukora-boundary-gate/gate.sock')
  assert.equal(l.ownerSocket, '/run/aukora-boundary-gate/owner.sock')
  assert.ok(Object.isFrozen(l) && Object.isFrozen(l.users) && Object.isFrozen(DEFAULT_LAYOUT))
  assert.throws(() => resolveLayout({ users: { gate: 'aukora-host' } }), /three distinct/)
  assert.throws(() => resolveLayout({ root: 'relative/dir' }), /absolute/)
  assert.throws(() => resolveLayout({ root: '/srv/../etc' }), /normalized/)
  assert.throws(() => resolveLayout({ root: '/' }), /absolute/)
  assert.throws(() => resolveLayout({ sandbox: 'a b' }), /sandbox/)
  assert.throws(() => resolveLayout({ users: { agent: 'Root;x' } }), /invalid agent/)
  assert.throws(() => resolveLayout({ gatewayPort: 80 }), /unprivileged/)
  assert.throws(() => resolveLayout({ extra: 1 }), /unknown key/)
})

test('sudo: the template is exactly one rule, host -> agent, only the wrapper', () => {
  const t = read('host/sudoers.template')
  assert.equal(t, sudoersRule())
  const lines = t.split('\n').filter(Boolean)
  assert.equal(lines.length, 1)
  assert.match(lines[0], /^aukora-host ALL=\(auma\) NOPASSWD: \/usr\/local\/lib\/aukora-boundary\/sbx-exec$/)
  assert.doesNotMatch(t, /ALL\s*$|\(ALL|\(root|SETENV|\*/)
})

test('host scripts: bash syntax, fixed sandbox identity, network-none refusal', () => {
  for (const f of ['host/sbx-exec', 'host/openshell/podman-service.sh', 'host/openshell/gateway.sh', 'host/openshell/ensure-sandbox.sh']) {
    const r = spawnSync('bash', ['-n', path.join(PKG, f)], { encoding: 'utf8' })
    assert.equal(r.status, 0, `${f}: ${r.stderr}`)
    assert.ok(fs.statSync(path.join(PKG, f)).mode & 0o100, `${f} executable`)
  }
  const ensure = read('host/openshell/ensure-sandbox.sh')
  assert.match(ensure, /sandbox create --name auma-ws "\$\{FROM\[@\]\}" --no-auto-providers --no-tty --detach/)
  assert.match(ensure, /IMG=localhost\/aukora-guest:current/)
  assert.match(ensure, /runs another image than \$IMG: snapshot, recreate/)
  assert.match(ensure, /\[ "\$net" = none \] \|\| \{ echo "REFUSING: sandbox network mode/)
  assert.match(ensure, /exit 3/)
  const gw = read('host/openshell/gateway.sh')
  assert.match(gw, /OPENSHELL_COMPUTE_DRIVER=podman/)
  assert.match(gw, /OPENSHELL_TELEMETRY_ENABLED=false/)
  const meta = JSON.parse(read('host/openshell/gateway-metadata.json'))
  assert.equal(meta.auth_mode, 'mtls'); assert.equal(meta.is_remote, false)
  assert.equal(new URL(meta.gateway_endpoint).hostname, '127.0.0.1')
  const setup = read('host/SETUP.md')
  assert.match(setup, /OpenShell \| `openshell` \/ `openshell-gateway` 0\.1\.2/)
  assert.match(setup, /Podman \| 5\.4\.2, rootless/)
})

// A copy of sbx-exec whose /usr/bin/openshell is a stub. mode 'args' prints the argv; mode 'exec' runs the
// inner `bash -c <cleanup script> aukora-boundary exec <cmd>` locally (only ever inside a private PID namespace).
// The applied-policy check (`info check`) queries the real OpenShell/Podman and is observed on the pilot and pinned
// by tests/aukora-openshell-confinement.test.mjs; here it is replaced, and the host lock goes to a temp directory.
function stubWrapper(mode, { guestRoot } = {}) {
  const d = tmp(), stub = path.join(d, 'openshell'), w = path.join(d, 'sbx-exec')
  fs.writeFileSync(stub, mode === 'args'
    ? '#!/bin/bash\nfor a in "$@"; do printf "%s\\0" "$a"; done\n'
    : '#!/bin/bash\nwhile [ "$#" -gt 0 ] && [ "$1" != "--" ]; do shift; done; shift; exec "$@"\n', { mode: 0o755 })
  const src = read('host/sbx-exec')
  assert.equal(src.split('/usr/bin/openshell sandbox exec').length, 3, 'one exec for the command, one for cancel cleanup')
  assert.equal(src.split('info check || exit 125').length, 2, 'exactly one applied-policy check before the command')
  fs.writeFileSync(w, src.replaceAll('/usr/bin/openshell sandbox exec', stub + ' sandbox exec')
    .replace('info check || exit 125', 'true').replace('"$XDG_RUNTIME_DIR/aukora-sbx-exec.lock"', JSON.stringify(path.join(d, 'lock')))
    .replace('cd /sandbox ||', guestRoot ? `cd ${guestRoot} ||` : 'cd /sandbox ||')
    .replace('CARRIER="/usr/bin/python3 -I /usr/lib/aukora/exec.py "', 'CARRIER="sleep 503 "'), { mode: 0o755 })
  return w
}

test('sbx-exec: timeout validation and clamping, fixed flags, command passed as one argument', () => {
  const w = stubWrapper('args')
  const run = (...a) => spawnSync('bash', [w, ...a], { encoding: 'utf8' })
  for (const bad of ['abc', '-5', '1e3', '10 ', ' ']) { const r = run(bad, 'true'); assert.equal(r.status, 2, `timeout ${JSON.stringify(bad)}`); assert.match(r.stderr, /bad timeout/) }
  const argv = (t) => run(t, 'echo "a b"; id').stdout.split('\0').filter(Boolean)
  for (const [t, want] of [['20', '20'], ['300', '300'], ['301', '300'], ['0', '1'], ['99999999999999999999', '300']]) {
    const a = argv(t)
    assert.deepEqual(a.slice(0, 10), ['sandbox', 'exec', '--name', 'auma-ws', '--no-tty', '--no-login-shell', '--timeout', want, '--', 'bash'], `timeout ${t}`)
    assert.deepEqual(a.slice(-3), ['aukora-boundary', 'exec', 'echo "a b"; id'])
  }
  // order in the real wrapper: host lock, then the applied-policy re-check, then the one command exec
  const src = read('host/sbx-exec')
  const lock = src.indexOf('/usr/bin/flock -w'), check = src.indexOf('info check || exit 125'), exec = src.indexOf('aukora-boundary exec "$2"')
  assert.ok(lock > 0 && check > lock && exec > check)
  assert.ok(!src.includes('SKSBX'), 'no argv marker an agent could forge')
})

const userns = spawnSync('unshare', ['--user', '--map-current-user', '--pid', '--fork', '--mount-proc', 'true']).status === 0

test('sbx-exec cleanup script: leftovers killed, OpenShell login shell spared, calls serialized by the host lock', { skip: userns ? false : 'unprivileged user+PID namespaces unavailable (SKIPPED, not passed)' }, () => {
  // the guest workspace is checked: without /sandbox the command never runs
  const missing = spawnSync('unshare', ['--user', '--map-current-user', '--pid', '--fork', '--mount-proc', 'bash', stubWrapper('exec'), '5', 'echo RAN'], { encoding: 'utf8', timeout: 30000 })
  if (!fs.existsSync('/sandbox')) {
    assert.equal(missing.status, 125); assert.doesNotMatch(missing.stdout, /RAN/)
    assert.match(missing.stderr, /aukora-openshell-confinement: guest-workspace-unavailable/)
  }
  const w = stubWrapper('exec', { guestRoot: tmp() })
  // Runs as PID 1 of a fresh PID namespace, so the wrapper's process sweep only ever sees this test's processes.
  // Every wrapper call is started directly by PID 1 (no command-substitution subshell in between), matching
  // OpenShell's exec layout; output goes to files.
  const W = JSON.stringify(w)
  const script = `
set -u
mkfifo /tmp/fifo; exec 3<>/tmp/fifo
(exec -a /bin/bash bash -l <&3 >/dev/null 2>&1) & infra=$!
sleep 0.3
bash ${W} 30 'setsid sleep 500 & nohup sleep 501 >/dev/null 2>&1 & (sleep 502 &) ; echo hello' >/tmp/o0 2>/tmp/e0; echo "rc=$? out=$(cat /tmp/o0)"
echo "err=$(cat /tmp/e0)"
echo "leftover=$(pgrep -c -x sleep)"
kill -0 $infra 2>/dev/null && echo infra=alive || echo infra=dead
bash ${W} 30 'sleep 1; echo first-done' >/tmp/o1 2>/dev/null
bash ${W} 30 'echo second-done' >/tmp/o2 2>/dev/null
echo "c1=$(cat /tmp/o1) c2=$(cat /tmp/o2)"
bash -c 'sleep 504 & exec sleep 503' & carrier=$!
sleep 0.3
bash ${W} 30 'sleep 505 & echo ordinary' >/dev/null 2>&1
kill -0 $carrier 2>/dev/null && echo carrier=alive || echo carrier=dead
echo "carrier-tree=$(pgrep -c -f '^sleep 504$') stray=$(pgrep -c -f '^sleep 505$')"
kill $carrier 2>/dev/null; pkill -f '^sleep 504$'
bash ${W} 30 'exit 7' >/dev/null 2>&1; echo "code=$?"
bash ${W} 30 'head -c 3000000 /dev/zero | tr "\\\\0" x' >/tmp/o3 2>/dev/null; echo "big=$(wc -c < /tmp/o3)"
bash ${W} 30 'head -c 30000000 /dev/zero > /tmp/f; echo "w=$?"; stat -c %s /tmp/f' >/tmp/o4 2>/dev/null; echo "fsz=$(tr '\\n' ' ' < /tmp/o4)"
`
  const r = spawnSync('unshare', ['--user', '--map-current-user', '--pid', '--fork', '--mount-proc', 'bash', '-c', script], { encoding: 'utf8', timeout: 60000 })
  const o = r.stdout
  assert.match(o, /rc=0 out=hello/)
  assert.match(o, /err=\[sandbox: killed [1-9][0-9]* leftover process\(es\) after this call\]/)
  assert.match(o, /leftover=0/)
  assert.match(o, /infra=alive/)
  assert.match(o, /c1=first-done c2=second-done/)
  assert.match(o, /carrier=alive/); assert.match(o, /carrier-tree=1 stray=0/)
  assert.match(o, /code=7/)
  assert.match(o, /big=1048576/)
  assert.match(o, /fsz=w=1\d\d? 20971520 /)
})

function fakeSpawn(script) {
  return (file, args, opts) => { fakeSpawn.last = { file, args, opts }; return spawn(process.execPath, ['-e', script], { stdio: ['ignore', 'pipe', 'pipe'] }) }
}

test('runner: argv through sudo as the agent, clamped timeout, 64 KiB caps, kill on abort/timeout', async () => {
  assert.equal(clampTimeout('x'), 60); assert.equal(clampTimeout(0), 1); assert.equal(clampTimeout(1e9), 300); assert.equal(clampTimeout(12.9), 12)
  assert.deepEqual(sandboxArgv('id', 900), ['/usr/bin/sudo', ['-n', '-u', 'auma', '/usr/local/lib/aukora-boundary/sbx-exec', '300', 'id']])
  assert.throws(() => sandboxArgv(''), /non-empty/); assert.throws(() => sandboxArgv('a\0b'), /NUL/)
  const big = await runInSandbox('x', { spawnImpl: fakeSpawn('process.stdout.write("a".repeat(300000)); process.stderr.write("b".repeat(70000)); process.exit(3)') })
  assert.equal(big.exit_code, 3); assert.equal(big.stdout.length, OUT_CAP); assert.equal(big.stderr.length, OUT_CAP)
  assert.deepEqual(fakeSpawn.last.opts.env, { PATH: '/usr/bin:/bin' })
  const ac = new AbortController(); const p = runInSandbox('x', { signal: ac.signal, spawnImpl: fakeSpawn('setTimeout(()=>{}, 60000)') }); ac.abort()
  const ab = await p; assert.equal(ab.killed, 'aborted'); assert.equal(ab.signal, 'SIGKILL')
  const to = await runInSandbox('x', { timeoutS: 1, graceS: -0.8, spawnImpl: fakeSpawn('setTimeout(()=>{}, 60000)') })
  assert.equal(to.killed, 'timeout')
})

test('egress probe: operator targets validated, script parses, verdict parsing is strict', () => {
  const s = egressProbeScript({ targets: ['example.invalid:443'], dnsNames: ['example.invalid'], interfaces: { lo: [{ family: 'IPv4', address: '127.0.0.1' }] } })
  assert.equal(spawnSync('bash', ['-n'], { input: s }).status, 0)
  assert.match(s, /'127\.0\.0\.1:17690'/); assert.match(s, /'localhost:3091'/); assert.match(s, /'example\.invalid:443'/)
  assert.throws(() => egressProbeScript({ targets: ["x:1'; touch /tmp/p; '"] }), /refused/)
  assert.throws(() => egressProbeScript({ dnsNames: ['a b'] }), /refused/)
  assert.equal(probePassed({ exit_code: 0, stdout: 'blocked a:1\nPROBE_DONE fail=0\n' }), true)
  assert.equal(probePassed({ exit_code: 0, stdout: 'REACHABLE a:1\nPROBE_DONE fail=0\n' }), false)
  assert.equal(probePassed({ exit_code: 0, stdout: 'DNS REAL ADDRESS n -> x\nPROBE_DONE fail=0\n' }), false)
  assert.equal(probePassed({ exit_code: 0, stdout: 'PROBE_DONE fail=1\n' }), false)
  assert.equal(probePassed({ exit_code: 1, stdout: 'PROBE_DONE fail=0\n' }), false)
  assert.equal(probePassed({ exit_code: 0, stdout: 'blocked\n' }), false)
})

test('self-check fails closed on any successful forbidden action, extra probe or failed egress probe', async () => {
  const d = tmp(); const refused = () => fs.readFileSync(path.join(d, 'missing'))
  assert.equal(runForbidden([['a', refused]]).ok, true)
  const bad = runForbidden([['a', refused], ['b', () => fs.openSync(path.join(d, 'made'), 'wx')]])
  assert.equal(bad.ok, false); assert.equal(bad.results[1].result, 'SUCCEEDED (BAD)')
  const pass = async () => ({ exit_code: 0, stdout: 'PROBE_DONE fail=0\n', stderr: '' })
  const fail = async () => ({ exit_code: 0, stdout: 'REACHABLE x:1\nPROBE_DONE fail=1\n', stderr: '' })
  assert.equal((await selfCheck({ probes: [['a', refused]], run: pass })).ok, true)
  assert.equal((await selfCheck({ probes: [['a', refused]], run: fail })).ok, false)
  assert.equal((await selfCheck({ probes: [['a', refused]], extraProbes: [['owner channel', async () => 1]], run: pass })).ok, false)
  const ok = await selfCheck({ probes: [['a', refused]], extraProbes: [['owner channel', async () => { throw Object.assign(new Error('x'), { code: 'EACCES' }) }]], run: pass })
  assert.equal(ok.ok, true); assert.equal(ok.forbidden[1].result, 'refused (EACCES)')
})

// ── R2 stream route: sbx-exec --stream <seconds> ─────────────────────────────────────────────────────────────────────
// A copy whose ssh is a stub (prints the guest sentinel on stderr, then behaves per STUB_MODE) and whose policy
// observations are fixed; the host lock goes to a temp file.
function streamWrapper({ second = 'gen-1 1' } = {}) {
  const d = tmp(), ssh = path.join(d, 'ssh'), idstub = path.join(d, 'id'), w = path.join(d, 'sbx-exec'), lock = path.join(d, 'lock')
  fs.writeFileSync(ssh, `#!/bin/bash
printf '%s\\n' "$*" > ${JSON.stringify(path.join(d, 'argv'))}
case "$STUB_MODE" in
  nosentinel) echo 'connect failed' >&2; exit 255;;
  lockprobe) printf 'AUKORA-STREAM-ADMITTED\\n' >&2; sleep 0.5; if flock -n ${JSON.stringify(lock)} true; then echo LOCK-FREE; else echo LOCK-HELD; fi;;
  hang) printf 'AUKORA-STREAM-ADMITTED\\n' >&2; sleep 30;;
  *) printf 'pre-diag\\nAUKORA-STREAM-ADMITTED\\n' >&2; exec cat;;
esac
`, { mode: 0o755 })
  fs.writeFileSync(idstub, `#!/bin/bash\necho '${second}'\n`, { mode: 0o755 })
  const src = read('host/sbx-exec')
  for (const must of ['id1=$(info id) || exit 125', '"/usr/bin/ssh"', '[self, "--confinement-id"]', '"$XDG_RUNTIME_DIR/aukora-sbx-exec.lock"'])
    assert.ok(src.includes(must), must)
  fs.writeFileSync(w, src.replace('id1=$(info id) || exit 125', 'id1="gen-1 1"').replace('"/usr/bin/ssh"', JSON.stringify(ssh))
    .replace('[self, "--confinement-id"]', `[${JSON.stringify(idstub)}]`).replaceAll('"$XDG_RUNTIME_DIR/aukora-sbx-exec.lock"', JSON.stringify(lock)), { mode: 0o755 })
  return { w, d }
}
const runStream = (w, args, input, mode, timeout = 20000) => spawnSync('bash', [w, '--stream', ...args], { input, env: { ...process.env, STUB_MODE: mode ?? '' }, timeout })

test('sbx-exec --stream: argument validation (1..300 integer, no leading zero, exactly one argument)', () => {
  const { w } = streamWrapper()
  for (const bad of [['0'], ['301'], ['007'], ['5s'], [''], ['5', 'x'], []]) assert.equal(runStream(w, bad, '').status, 2, JSON.stringify(bad))
  assert.equal(runStream(w, ['300'], '').status, 0)
})
test('sbx-exec --stream: host stdin/stdout reach the carrier RAW (binary-exact), diagnostics only on stderr', () => {
  const { w, d } = streamWrapper()
  const bytes = Buffer.from([...Array(256).keys(), 10, 0, 13, 10, 255])
  const r = runStream(w, ['20'], bytes)
  assert.equal(r.status, 0, String(r.stderr)); assert.ok(Buffer.compare(r.stdout, bytes) === 0, 'stdout is exactly the bytes sent')
  assert.match(String(r.stderr), /pre-diag/); assert.doesNotMatch(String(r.stderr), /AUKORA-STREAM-ADMITTED/)
  const argv = fs.readFileSync(path.join(d, 'argv'), 'utf8')
  for (const f of ['-F /dev/null', '-T', '-e none', 'BatchMode=yes', 'RequestTTY=no', 'ForwardAgent=no', 'ClearAllForwardings=yes',
    'ProxyCommand=/usr/bin/openshell ssh-proxy --gateway-name openshell --name auma-ws --workspace default', 'openshell-auma-ws.default',
    'exec /usr/bin/python3 -I /usr/lib/aukora/exec.py']) assert.ok(argv.includes(f), f)
})
test('sbx-exec --stream: the admission lock is released once the session is admitted (streams are not serialized)', () => {
  const { w } = streamWrapper()
  const r = runStream(w, ['20'], '', 'lockprobe')
  assert.equal(r.status, 0); assert.equal(String(r.stdout).trim(), 'LOCK-FREE')
})
test('sbx-exec --stream: a different instance/revision after the session starts refuses (125), nothing on stdout', () => {
  const { w } = streamWrapper({ second: 'gen-2 1' })
  const r = runStream(w, ['20'], 'data\n')
  assert.equal(r.status, 125); assert.equal(String(r.stdout), ''); assert.match(String(r.stderr), /aukora-openshell-confinement: applied-policy-unavailable/)
})
test('sbx-exec --stream: no guest session (no sentinel) refuses 125 sandbox-unavailable; the deadline closes the session (124)', () => {
  const { w } = streamWrapper()
  const r = runStream(w, ['20'], '', 'nosentinel')
  assert.equal(r.status, 125); assert.match(String(r.stderr), /sandbox-unavailable/)
  const t0 = Date.now(), h = runStream(w, ['1'], '', 'hang')
  assert.equal(h.status, 124); assert.ok(Date.now() - t0 < 15000)
})
test('sbx-exec --stream: source invariants (lock fd closed in the child, released only after the second check, no cleanup sweep)', () => {
  const src = read('host/sbx-exec'), stream = src.slice(src.indexOf('if [ "${1:-}" = --stream ]'), src.indexOf("' \"$t\" \"$id1\" \"$0\""))
  assert.ok(stream.includes('close_fds=True'))
  assert.ok(stream.indexOf('threading.Thread(target=feed') > stream.indexOf('os.close(9)'), 'caller stdin is fed only after admission is bound')
  assert.ok(stream.indexOf('os.close(9)') > stream.indexOf('chk.stdout.decode().strip() != id1'))
  assert.doesNotMatch(stream, /skclean|cleanup/)
})
