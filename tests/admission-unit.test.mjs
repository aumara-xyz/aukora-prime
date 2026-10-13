// Checks opt-in admission installation, private modes and loopback service inspection.
import test from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync, chmodSync, symlinkSync, rmSync, statSync, existsSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { spawnSync } from 'node:child_process'

const repo = dirname(dirname(fileURLToPath(import.meta.url)))
const here = join(repo, 'ops/buzz-relay')
const installer = readFileSync(join(here, 'install.sh'), 'utf8')
const unit = readFileSync(join(here, 'units/aukora-admission.service'), 'utf8')
const blocks = text => [...text.matchAll(/^if \[ "\$WITH_ADMISSION" = 1 \]; then\n[\s\S]*?^fi$/gm)].map(match => match[0])
const checkoutGuard = installer.match(/^  \[ -f "\$HERE\/admission-server\.mjs" \][\s\S]*?full-checkout-required[^\n]*\n/m)?.[0]
const quote = value => `'${value.replaceAll("'", "'\\''")}'`
const stub = `#!${process.execPath} --
import { appendFileSync, readFileSync, writeFileSync } from 'node:fs'
import { basename } from 'node:path'
import { spawnSync } from 'node:child_process'
const name = basename(process.argv[1]), args = process.argv.slice(2), env = process.env
appendFileSync(env.CALLS, JSON.stringify([name, ...args]) + '\\n')
const run = argv => process.exit(spawnSync(argv[0], argv.slice(1), { env, stdio: 'inherit' }).status ?? 1)
if (name === 'sudo') run(args)
if (name === 'install') {
  for (let i = args.length - 1; i >= 0; i--) if (['-o', '-g'].includes(args[i])) args.splice(i, 2)
  // BSD install refuses /dev/stdin; the fixture retains Linux install's stdin-copy behavior.
  if (args.includes('/dev/stdin')) {
    const file = env.CALLS + '.stdin'
    writeFileSync(file, readFileSync(0), { mode: 0o600 })
    args[args.indexOf('/dev/stdin')] = file
  }
  run(['/usr/bin/install', ...args])
}
if (name === 'id') { console.log('1002'); process.exit(env.ACCOUNT_PRESENT === '1' ? 0 : 1) }
if (name === 'getent') { console.log('aukora-admission:x:1002:1002::' + (env.ACCOUNT_HOME || env.STATE) + ':/usr/sbin/nologin'); process.exit(0) }
if (name === 'useradd') process.exit(0)
if (name === 'systemctl') { console.log(env.SERVICE_STATE || 'active'); process.exit(0) }
if (name === 'ss') { process.stdout.write(env.LISTEN || ''); process.exit(env.SS_FAIL === '1' ? 1 : 0) }
if (name === 'stat') { console.log(env.LISTENER_UID || '1002'); process.exit(0) }
if (name === 'node') {
  if (args[0] === '--version') { console.log(env.NODE_VERSION || 'v24.11.1'); process.exit(0) }
  if (!args.includes('verify-closed')) run([env.REAL_NODE, ...args])
  console.log(JSON.stringify({ state: env.ACTUAL || (env.VERIFY_CLOSED === '1' ? 'CLOSED' : 'UNKNOWN') }))
  process.exit(env.VERIFY_CLOSED === '1' ? 0 : 1)
}
process.exit(1)
`

function fixture(t) {
  const root = mkdtempSync(join(repo, '.admission-unit-'))
  t.after(() => rmSync(root, { recursive: true, force: true }))
  const bin = join(root, 'bin'), lib = join(root, 'lib'), state = join(root, 'state'), systemd = join(root, 'systemd'), buzz = join(root, 'buzz')
  for (const dir of [bin, lib, systemd, buzz]) mkdirSync(dir, { mode: 0o700 })
  writeFileSync(join(buzz, 'node.env'), 'PORT=3000\nINTENDED_MEMBERSHIP=closed\n')
  const mock = join(bin, 'mock.mjs'), calls = join(root, 'calls')
  writeFileSync(mock, stub); chmodSync(mock, 0o755); writeFileSync(calls, '')
  for (const name of ['sudo', 'install', 'id', 'getent', 'useradd', 'systemctl', 'ss', 'stat', 'node']) symlinkSync(mock, join(bin, name))
  writeFileSync(join(root, 'read-setting.sh'), readFileSync(join(here, 'read-setting.sh')))
  const transform = source => source.replaceAll('/var/lib/aukora-admission', state)
    .replaceAll('/etc/systemd/system/aukora-admission.service', join(systemd, 'aukora-admission.service'))
    .replaceAll('/var/lib/aukora-buzz', buzz).replaceAll('/proc/', `${root}/proc/`)
  return { root, lib, state, systemd, buzz, transform,
    run(source, extra = {}) {
      const script = join(root, 'run.sh'); writeFileSync(script, transform(source))
      return spawnSync('bash', [script], { encoding: 'utf8', timeout: 10000,
        env: { ...process.env, PATH: `${bin}:${process.env.PATH}`, CALLS: calls, STATE: state, REAL_NODE: process.execPath, ...extra } })
    },
    calls() { return readFileSync(calls, 'utf8').trim().split('\n').filter(Boolean).map(JSON.parse) },
  }
}

const protectedSettings = {
  User: 'aukora-admission', Group: 'aukora-admission', UMask: '0077',
  Environment: 'HOME=/var/lib/aukora-admission',
  UnsetEnvironment: 'NODE_OPTIONS NODE_PATH LD_PRELOAD LD_LIBRARY_PATH LD_AUDIT',
  NoNewPrivileges: 'yes', CapabilityBoundingSet: '', AmbientCapabilities: '',
  PrivateTmp: 'yes', PrivateDevices: 'yes', ProtectSystem: 'strict', ProtectHome: 'yes',
  ProtectKernelTunables: 'yes', ProtectKernelModules: 'yes', ProtectKernelLogs: 'yes', ProtectControlGroups: 'yes',
  RestrictSUIDSGID: 'yes', ReadWritePaths: '/var/lib/aukora-admission',
  RestrictAddressFamilies: 'AF_UNIX AF_INET AF_INET6', IPAddressDeny: 'any', IPAddressAllow: 'localhost',
  LockPersonality: 'yes', LimitCORE: '0', KillMode: 'control-group',
  MemoryMax: '256M', TasksMax: '32', LimitNOFILE: '256',
}
function checkUnit(text) {
  const settings = Object.fromEntries(text.split('\n').filter(line => /^[A-Za-z]+=/u.test(line)).map(line => [line.slice(0, line.indexOf('=')), line.slice(line.indexOf('=') + 1)]))
  for (const [name, value] of Object.entries(protectedSettings)) assert.equal(settings[name], value, name)
  assert.equal(settings.Requires, 'aukora-buzz.service')
  assert.match(settings.ExecStart, /^\/usr\/local\/lib\/aukora-buzz\/node-v24\.11\.1\/node /u)
  assert.match(settings.ExecStart, / --key-file \/var\/lib\/aukora-admission\/owner\.key --store \/var\/lib\/aukora-admission\/store --host 127\.0\.0\.1 --port 3100 --relay http:\/\/localhost:@RELAY_PORT@$/u)
  assert.ok(!settings.ExecStart.includes('--behind-tls-proxy'))
}

test('admission unit isolates its user, files and loopback network; every omitted protection is detected', () => {
  checkUnit(unit)
  for (const [name, value] of Object.entries(protectedSettings)) {
    const anchor = `${name}=${value}\n`
    assert.ok(unit.includes(anchor), name)
    assert.throws(() => checkUnit(unit.replace(anchor, '')), assert.AssertionError, name)
  }
  for (const anchor of ['Requires=aukora-buzz.service\n', '--host 127.0.0.1', '--key-file /var/lib/aukora-admission/owner.key', '/node-v24.11.1/node']) {
    assert.ok(unit.includes(anchor)); assert.throws(() => checkUnit(unit.replace(anchor, '')), assert.AssertionError)
  }
  assert.doesNotMatch(installer, /systemctl (?:enable|start|restart).*admission/u)
  assert.doesNotMatch(readFileSync(join(here, 'aukora-buzz.service'), 'utf8'), /^Wants=.*admission/mu)
})

function installPrefix(f, enabled = 1) {
  return `set -euo pipefail\nHERE=${quote(here)}\nLIB=${quote(f.lib)}\nWITH_ADMISSION=${enabled}\nPORT=3000\nADMISSION_NODE=$(command -v node)\n`
}

function checkPreflight(t, text = installer) {
  assert.equal(blocks(text).length, 2)
  for (const [extra, code, prefix = ''] of [[{ NODE_VERSION: 'v24.0.0' }, 'node-24.11.1-required'], [{ ACCOUNT_PRESENT: '1', ACCOUNT_HOME: '/somewhere-else' }, 'account-exists'], [{ ACCOUNT_PRESENT: '1' }, 'account-exists'], [{}, 'port-conflict', 'PORT=3100\n']]) {
    const f = fixture(t), r = f.run(installPrefix(f) + prefix + blocks(text)[0], extra)
    assert.equal(r.status, 2, r.stderr); assert.match(r.stderr, new RegExp(`buzz-admission:${code}`))
    assert.equal(f.calls().some(call => ['install', 'useradd', 'systemctl'].includes(call[0])), false)
  }
  const missing = fixture(t), absent = missing.run(installPrefix(missing) + `HERE=${quote(missing.root)}\n` + blocks(text)[0])
  assert.equal(absent.status, 2); assert.match(absent.stderr, /buzz-admission:full-checkout-required/u)
  checkDefault(t, blocks(text).join('\n'))
}
function checkDefault(t, text) {
  const f = fixture(t), r = f.run(installPrefix(f, 0) + text)
  assert.equal(r.status, 0, r.stderr)
  assert.equal(f.calls().some(call => ['sudo', 'install', 'useradd', 'systemctl'].includes(call[0])), false)
}
test('admission installer is opt-in and refuses another account, port conflict or Node version before writes', t => checkPreflight(t))
for (const [name, from, to] of [
  ['pinned runtime', '[ "$("$ADMISSION_NODE" --version)" = v24.11.1 ] || { echo \'buzz-admission:node-24.11.1-required\' >&2; exit 2; }', ':'],
  ['port separation', '[ "$PORT" != 3100 ] || { echo \'buzz-admission:port-conflict\' >&2; exit 2; }', ':'],
  ['account collision', 'if id aukora-admission >/dev/null 2>&1 && {', 'if false && {'],
  ['full checkout', checkoutGuard, '  :\n'],
]) test(`mutation: admission installer ${name} removal dies`, t => {
  assert.ok(installer.includes(from))
  assert.throws(() => checkPreflight(t, installer.replace(from, to)), assert.AssertionError)
})
test('mutation: implicit admission installation dies', t => {
  assert.throws(() => checkDefault(t, blocks(installer).join('\n').replaceAll('if [ "$WITH_ADMISSION" = 1 ]; then', 'if true; then')), assert.AssertionError)
})

test('admission installer retains its import closure and private state under umask 002', t => {
  const previous = process.umask(0o002)
  try {
    const f = fixture(t)
    const memberBlock = installer.match(/^if \[ -f "\$HERE\/\.\.\/\.\.\/plugins\/aukora-buzz-door\/lib\/index\.mjs" \]; then\n[\s\S]*?^fi$/m)?.[0]
    assert.ok(memberBlock)
    const r = f.run(installPrefix(f) + blocks(installer)[0] + '\n' + memberBlock + '\n' + blocks(installer)[1])
    assert.equal(r.status, 0, r.stderr)
    assert.equal(statSync(f.state).mode & 0o777, 0o700)
    assert.equal(statSync(join(f.lib, 'node-v24.11.1/node')).mode & 0o777, 0o755)
    assert.equal(statSync(join(f.systemd, 'aukora-admission.service')).mode & 0o777, 0o644)
    assert.equal(existsSync(join(f.state, 'owner.key')), false, 'installer creates no owner key')
    assert.ok(readFileSync(join(f.systemd, 'aukora-admission.service'), 'utf8').includes('--relay http://localhost:3000'))
    const help = spawnSync(process.execPath, [join(f.lib, 'member/ops/buzz-relay/admission-server.mjs'), '--help'], { encoding: 'utf8', timeout: 10000 })
    assert.equal(help.status, 0, help.stderr); assert.match(help.stdout, /--behind-tls-proxy/u)
    assert.equal(f.calls().some(call => call[0] === 'systemctl'), false)
    const weakened = installer.replace('-m 0700 /var/lib/aukora-admission', '-m 0775 /var/lib/aukora-admission')
    assert.notEqual(weakened, installer)
    const mutant = fixture(t), result = mutant.run(installPrefix(mutant) + memberBlock + '\n' + blocks(weakened)[1])
    assert.equal(result.status, 0, result.stderr)
    assert.throws(() => assert.equal(statSync(mutant.state).mode & 0o777, 0o700), assert.AssertionError, 'private-state removal dies')
  } finally { process.umask(previous) }
})

const listener = 'LISTEN 0 128 127.0.0.1:3100 0.0.0.0:* users:(("node",pid=4321,fd=10))\n'
function checkAdmission(t, mutation) {
  const f = fixture(t)
  let source = readFileSync(join(here, 'check.sh'), 'utf8')
  if (mutation) { assert.ok(source.includes(mutation.from)); source = source.replace(mutation.from, mutation.to) }
  const invoke = extra => f.run(source.replace('MODE="${1:-full}"', 'MODE=--admission'), { ACCOUNT_PRESENT: '1', LISTEN: listener, VERIFY_CLOSED: '1', ...extra })
  const good = invoke({}); assert.equal(good.status, 0, good.stderr); assert.match(good.stdout, /PASS  admission relay closed/u)
  for (const extra of [{ SERVICE_STATE: 'inactive' }, { LISTENER_UID: '1003' }, { LISTEN: listener.replace('127.0.0.1:3100', '0.0.0.0:3100') },
    { LISTEN: listener + listener.replace('127.0.0.1:3100', '0.0.0.0:3101') }, { VERIFY_CLOSED: '0' }, { SS_FAIL: '1' }]) {
    const bad = invoke(extra); assert.equal(bad.status, 1, `${JSON.stringify(extra)}: ${bad.stdout} ${bad.stderr}`)
  }
  writeFileSync(join(f.buzz, 'node.env'), 'PORT=3000\nINTENDED_MEMBERSHIP=open-acknowledged\n')
  const open = invoke({ ACTUAL: 'OPEN', VERIFY_CLOSED: '0' })
  assert.equal(open.status, 1, open.stdout + open.stderr); assert.match(open.stdout, /admission relay closure not proved/)
  writeFileSync(join(f.buzz, 'node.env'), 'PORT=3000\n')
  const undeclared = invoke({})
  assert.equal(undeclared.status, 1, undeclared.stdout + undeclared.stderr); assert.match(undeclared.stdout, /intended-membership-required/)
  assert.equal(f.calls().some(call => call[0] === 'systemctl' && call.some(arg => /^(?:restart|start|enable)$/u.test(arg))), false)
}
test('admission check requires the active service, its loopback listener and closed relay without restarting', t => checkAdmission(t))
for (const [name, from, to] of [
  ['inactive service', "|| say FAIL 'aukora-admission.service not active'", "|| say PASS 'aukora-admission.service not active'"],
  ['off-loopback listener', '[ "$off_loopback" = 0 ] && [ "$admission_port" = 1 ]', '[ "$admission_port" = 1 ]'],
  ['listener ownership', '[ "$owner" = "$UID_ADMISSION" ] || continue', ':'],
  ['owned port', '[ "$off_loopback" = 0 ] && [ "$admission_port" = 1 ]', '[ "$off_loopback" = 0 ]'],
  ['socket inspection', 'if LISTEN=$(sudo ss -ltnpH) && [ -n "$LISTEN" ]; then', 'if LISTEN=$(sudo ss -ltnpH) || [ -n "$LISTEN" ]; then'],
  ['closed relay', "|| say FAIL 'admission relay closure not proved'", "|| say PASS 'admission relay closure not proved'"],
]) test(`mutation: admission check ${name} removal dies`, t => {
  assert.throws(() => checkAdmission(t, { from, to }), assert.AssertionError)
})
