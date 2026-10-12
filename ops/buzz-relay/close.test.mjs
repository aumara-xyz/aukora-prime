// Stub commands exercise closing, backup order, rollback and repeated attempts without a node.
import assert from 'node:assert/strict'
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync, chmodSync, symlinkSync, rmSync, readdirSync, statSync, existsSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { spawnSync } from 'node:child_process'
import test from 'node:test'
import { publicKeyOf } from '../../plugins/aukora-nostr/lib/event.mjs'

const here = dirname(fileURLToPath(import.meta.url)), repo = join(here, '../..')
const owner = 'a'.repeat(64), secret = '1'.repeat(64), agent = publicKeyOf(secret)
const open = 'RELAY_URL=ws://localhost:3000\nRUST_LOG=warn\nKEEP_SETTING=yes\n'
const stub = `#!${process.execPath} --
import { appendFileSync, readFileSync, writeFileSync, readdirSync, existsSync, statSync } from 'node:fs'
import { basename, join } from 'node:path'
import { spawnSync } from 'node:child_process'
const name = basename(process.argv[1]), args = process.argv.slice(2), env = process.env
appendFileSync(env.CALLS, JSON.stringify([name, ...args]) + '\\n')
const run = (argv, extra = {}) => process.exit(spawnSync(argv[0], argv.slice(1), { stdio: 'inherit', env: { ...env, ...extra } }).status ?? 1)
if (name === 'sudo') {
  let user
  if (args[0] === '-u') { user = args[1]; args.splice(0, 2) }
  if (args[0] === '-H') args.shift()
  if (env.WRITER_FAIL === '1' && args.includes(env.WRITER)) process.exit(1)
  if (user === 'aukora-buzz' && args[0] === 'bash' && args.includes('-s') && env.RESTORE_FAIL === '1'
    && readFileSync(env.STATE + '/relay.env', 'utf8').includes('BUZZ_REQUIRE_RELAY_MEMBERSHIP')) process.exit(1)
  run(args, user === 'door' ? { HOME: env.DOOR_HOME } : {})
}
if (name === 'id') { console.log(args.length === 1 ? '0' : '1001'); process.exit(0) }
if (name === 'stat') { console.log('door'); process.exit(0) }
if (name === 'flock') process.exit(env.LOCK_FAIL === '1' ? 1 : 0)
if (name === 'sleep') process.exit(0)
if (name === 'timeout') run(args.slice(1))
if (name === 'node') {
  if (args.includes('verify-closed')) {
    if (env.VERIFY_ERROR === '1') process.exit(1)
    // Exercise the real member.mjs CLI with either route accepted in a subprocess.
    run([env.REAL_NODE, '--import', env.FETCH_STUB, ...args])
  }
  run([env.REAL_NODE, ...args])
}
if (name === 'curl') process.exit(env.HEALTH_FAIL === '1' ? 1 : 0)
if (name === 'systemctl') {
  if (args[0] === 'is-active') { console.log('active'); process.exit(0) }
  const n = Number(readFileSync(env.RESTARTS, 'utf8')) + 1
  writeFileSync(env.RESTARTS, String(n))
  const setting = readFileSync(env.STATE + '/relay.env', 'utf8')
  writeFileSync(env.STATE + '/restart-' + n, setting)
  process.exit(env.RESTART_FAIL === 'all' || (env.RESTART_FAIL === 'first' && n === 1) ? 1 : 0)
}
if (name === 'podman') {
  if (args[0] === 'pod') { console.log(env.BINDING || '127.0.0.1:3000->3000/tcp '); process.exit(0) }
  if (args.includes('pg_dump')) {
    if (env.DUMP_FAIL === '1') { console.error('private dump error'); process.exit(1) }
    if (env.EMPTY_DUMP !== '1') console.log('logical dump: existing channels and messages')
    process.exit(0)
  }
  if (args[0] === 'inspect') console.log('true')
  if (args[0] === 'exec' && args.includes('buzz-redis')) console.log('PONG')
  process.exit(0)
}
if (name === 'ss') { console.log('LISTEN 0 128 127.0.0.1:3000 0.0.0.0:*'); process.exit(0) }
process.exit(1)
`

function fixture(t, mutation) {
  const root = mkdtempSync(join(here, '.close-test-'))
  t.after(() => rmSync(root, { recursive: true, force: true }))
  const scripts = join(root, 'ops/buzz-relay'), state = join(root, 'state'), bin = join(root, 'bin'), home = join(root, 'door-home')
  for (const dir of [scripts, state, bin, home]) mkdirSync(dir, { recursive: true, mode: 0o700 })
  symlinkSync(join(repo, 'plugins'), join(root, 'plugins'))
  for (const name of ['close.sh', 'write-settings.sh', 'check.sh', 'read-setting.sh', 'member.mjs']) {
    let source = readFileSync(join(here, name), 'utf8')
    if (mutation?.file === name) {
      assert.ok(source.includes(mutation.from), `mutation missing: ${mutation.from}`)
      source = source.replace(mutation.from, mutation.to)
    }
    writeFileSync(join(scripts, name), source.replaceAll('/var/lib/aukora-buzz', state).replace('/run/aukora-buzz-close.lock', join(root, 'lock')))
  }
  const mock = join(bin, 'mock.mjs'); writeFileSync(mock, stub); chmodSync(mock, 0o755)
  for (const cmd of ['sudo', 'id', 'stat', 'flock', 'sleep', 'timeout', 'node', 'curl', 'systemctl', 'podman', 'ss']) symlinkSync(mock, join(bin, cmd))
  const calls = join(root, 'calls'), restarts = join(root, 'restarts'), keyFile = join(home, 'door.key'), fetchStub = join(root, 'fetch.mjs')
  writeFileSync(fetchStub, `globalThis.fetch = async url => {
    const route = new URL(url).pathname
    const open = process.env.ACCEPT_ROUTE === route
    return new Response(JSON.stringify(open ? { accepted: true } : { error: 'relay_membership_required' }), { status: open ? 200 : 403 })
  }`)
  writeFileSync(calls, ''); writeFileSync(restarts, '0')
  writeFileSync(keyFile, secret, { mode: 0o600 })
  writeFileSync(join(state, 'relay.env'), open); writeFileSync(join(state, 'node.env'), 'PORT=3000\n')
  mkdirSync(join(state, 'data')); writeFileSync(join(state, 'data/rows'), 'channels and messages')
  return {
    root, scripts, state, keyFile,
    run(extra = {}, args = ['--owner-pubkey', owner, '--key-file', keyFile], file = 'close.sh') {
      return spawnSync('bash', [join(scripts, file), ...args], { encoding: 'utf8', timeout: 30000,
        env: { ...process.env, PATH: `${bin}:${process.env.PATH}`, CALLS: calls, STATE: state, RESTARTS: restarts,
          DOOR_HOME: home, REAL_NODE: process.execPath, FETCH_STUB: fetchStub, WRITER: join(scripts, 'write-settings.sh'), ...extra } })
    },
    calls() { return readFileSync(calls, 'utf8').trim().split('\n').filter(Boolean).map(JSON.parse) },
    backups() { return readdirSync(state).filter(n => n.startsWith('close-backup.')).map(n => join(state, n)) },
    settings() { return readFileSync(join(state, 'relay.env'), 'utf8') },
    restarts() { return Number(readFileSync(restarts, 'utf8')) },
  }
}
const noKeys = r => {
  for (const key of [owner, secret, agent]) assert.ok(!(r.stdout + r.stderr).includes(key), 'printed a key')
}
const closed = f => {
  assert.equal(f.settings(), open + `RELAY_OWNER_PUBKEY=${owner}\nBUZZ_REQUIRE_RELAY_MEMBERSHIP=true\n`)
  assert.equal(readFileSync(join(f.state, 'data/rows'), 'utf8'), 'channels and messages')
}

const checks = {
  input(t, m) {
    for (const args of [[], ['--owner-pubkey', owner], ['--key-file', '/missing'], ['--owner-pubkey', 'wrong', '--key-file', '/missing'], ['--unknown', 'value']]) {
      const f = fixture(t, m), r = f.run({}, args)
      assert.notEqual(r.status, 0); assert.match(r.stderr, /buzz-close:/); assert.equal(f.calls().length, 0)
    }
  },
  key(t, m) {
    for (const mode of ['missing', 'invalid', 'public', 'symlink']) {
      const f = fixture(t, m)
      if (mode === 'missing') rmSync(f.keyFile)
      if (mode === 'invalid') writeFileSync(f.keyFile, '0'.repeat(64))
      if (mode === 'public') chmodSync(f.keyFile, 0o644)
      if (mode === 'symlink') { rmSync(f.keyFile); symlinkSync(join(f.state, 'relay.env'), f.keyFile) }
      const r = f.run(); assert.notEqual(r.status, 0); assert.match(r.stderr, /invalid-door-key/)
      assert.equal(f.backups().length, 0); assert.equal(f.restarts(), 0); noKeys(r)
    }
  },
  preflight(t, m) {
    for (const extra of [{ LOCK_FAIL: '1' }, { BINDING: '0.0.0.0:3000->3000/tcp ' }, { BINDING: '127.0.0.1:3001->3000/tcp ' }]) {
      const f = fixture(t, m), r = f.run(extra)
      assert.notEqual(r.status, 0); assert.equal(f.backups().length, 0); assert.equal(f.restarts(), 0)
    }
    const f = fixture(t, m); writeFileSync(join(f.state, 'relay.env'), open + `RELAY_OWNER_PUBKEY=${'b'.repeat(64)}\n`)
    const r = f.run(); assert.notEqual(r.status, 0); assert.match(r.stderr, /different-owner/); assert.equal(f.backups().length, 0)
  },
  backup(t, m) {
    for (const extra of [{ DUMP_FAIL: '1' }, { EMPTY_DUMP: '1' }]) {
      const f = fixture(t, m), r = f.run(extra)
      assert.notEqual(r.status, 0); assert.match(r.stderr, /backup-failed/); assert.equal(f.settings(), open); assert.equal(f.restarts(), 0)
      assert.ok(!r.stderr.includes('private dump error'))
    }
  },
  success(t, m) {
    const f = fixture(t, m), r = f.run(); assert.equal(r.status, 0, r.stderr); closed(f); noKeys(r)
    assert.equal(f.restarts(), 1); assert.match(r.stdout, /PASS closed/)
    const [backup] = f.backups(); assert.ok(backup)
    assert.equal(readFileSync(join(backup, 'relay.env'), 'utf8'), open)
    assert.match(readFileSync(join(backup, 'relay.dump'), 'utf8'), /existing channels and messages/)
    assert.equal(readFileSync(join(backup, 'agent.pubkey'), 'utf8').trim(), agent)
    assert.equal(statSync(backup).mode & 0o777, 0o700)
    for (const file of ['relay.env', 'relay.dump', 'agent.pubkey', 'owner.pubkey']) assert.equal(statSync(join(backup, file)).mode & 0o777, 0o600)
    assert.equal(statSync(join(f.state, 'relay.env')).mode & 0o777, 0o600)
    const calls = f.calls(), dump = calls.findIndex(c => c[0] === 'podman' && c.includes('pg_dump'))
    const writer = calls.findIndex(c => c[0] === 'sudo' && c.includes(join(f.scripts, 'write-settings.sh')))
    const restart = calls.findIndex(c => c[0] === 'systemctl'), health = calls.findIndex(c => c[0] === 'curl'), verify = calls.findIndex(c => c[0] === 'node' && c.includes('verify-closed'))
    assert.ok(dump >= 0 && dump < writer && writer < restart && restart < health && health < verify)
    assert.ok(calls.some(c => c.join(' ') === 'systemctl restart aukora-buzz.service'))
    assert.match(r.stdout, /member.mjs add .*--role member/); assert.match(r.stdout, /member.mjs put-user .*--role bot/)
    assert.match(r.stdout, /bootstrapped/); assert.match(r.stdout, /Existing channel members need relay admission/)
    assert.match(r.stdout, /does not inherit channel authority/)
  },
  rollback(t, m) {
    for (const extra of [{ ACCEPT_ROUTE: '/query' }, { ACCEPT_ROUTE: '/events' }, { VERIFY_ERROR: '1' }, { HEALTH_FAIL: '1' }, { RESTART_FAIL: 'first' }, { WRITER_FAIL: '1' }]) {
      const f = fixture(t, m), r = f.run(extra)
      assert.notEqual(r.status, 0); assert.equal(f.settings(), open); assert.equal(f.restarts(), extra.WRITER_FAIL ? 1 : 2)
      assert.match(r.stderr, /settings-restored/); assert.ok(!r.stdout.includes('PASS closed')); noKeys(r)
      assert.equal(readFileSync(join(f.state, 'data/rows'), 'utf8'), 'channels and messages')
      if (extra.HEALTH_FAIL) assert.equal(f.calls().some(c => c.includes('verify-closed')), false)
    }
  },
  rollbackFailure(t, m) {
    for (const [extra, code] of [[{ RESTART_FAIL: 'all' }, 'rollback-restart-failed'], [{ ACCEPT_ROUTE: '/query', RESTORE_FAIL: '1' }, 'rollback-settings-failed']]) {
      const f = fixture(t, m), r = f.run(extra)
      assert.notEqual(r.status, 0); assert.match(r.stderr, new RegExp(code)); assert.ok(!r.stdout.includes('PASS closed'))
    }
  },
  resume(t, m) {
    const f = fixture(t, m)
    assert.notEqual(f.run({ ACCEPT_ROUTE: '/events' }).status, 0)
    assert.equal(f.run().status, 0); closed(f)
    assert.equal(f.run().status, 0); closed(f)
    const backups = f.backups(); assert.equal(backups.length, 3)
    assert.equal(backups.filter(b => readFileSync(join(b, 'relay.env'), 'utf8') === open).length, 2)
    // A retry from already written settings (e.g. interruption before verification) remains closed on failure.
    assert.notEqual(f.run({ VERIFY_ERROR: '1' }).status, 0); closed(f)
  },
  interrupted(t, m) {
    const f = fixture(t, m)
    assert.notEqual(f.run({ RESTART_FAIL: 'all' }).status, 0)
    assert.equal(existsSync(join(f.state, 'close-pending')), true)
    // Postgres is stopped after an interrupted/failed restart; recover using the complete snapshot.
    const r = f.run({ DUMP_FAIL: '1' }); assert.equal(r.status, 0, r.stderr); closed(f)
    assert.equal(f.backups().length, 1); assert.equal(existsSync(join(f.state, 'close-pending')), false)
  },
  pending(t, m) {
    for (const bad of ['path', 'dump', 'owner', 'agent']) {
      const f = fixture(t, m)
      assert.notEqual(f.run({ RESTART_FAIL: 'all' }).status, 0)
      const [backup] = f.backups(), before = f.restarts()
      if (bad === 'path') writeFileSync(join(f.state, 'close-pending'), '../state/' + backup.split('/').at(-1))
      if (bad === 'dump') rmSync(join(backup, 'relay.dump'))
      if (bad === 'owner') writeFileSync(join(backup, 'owner.pubkey'), 'b'.repeat(64))
      if (bad === 'agent') writeFileSync(join(backup, 'agent.pubkey'), 'c'.repeat(64))
      const r = f.run(); assert.notEqual(r.status, 0); assert.equal(f.restarts(), before)
    }
  },
  check(t, m) {
    for (const extra of [{}, { ACCEPT_ROUTE: '/query' }, { ACCEPT_ROUTE: '/events' }, { VERIFY_ERROR: '1' }]) {
      const f = fixture(t, m), r = f.run(extra, [], 'check.sh')
      assert.equal(r.status, 0, r.stderr + r.stdout)
      assert.match(r.stdout, Object.keys(extra).length ? /OPEN  closed/ : /PASS  closed/)
      const health = f.run(extra, ['--health'], 'check.sh'); assert.equal(health.status, 0)
      assert.ok(!health.stdout.includes('closed'))
    }
  },
  writer(t, m) {
    const f = fixture(t, m), run = (args, env = {}) => spawnSync('bash', [join(f.scripts, 'write-settings.sh'), f.state, ...args], { encoding: 'utf8', env: { ...process.env, ...env } })
    assert.equal(run(['', '3000']).status, 0); assert.ok(!f.settings().includes('RELAY_OWNER_PUBKEY'))
    assert.equal(run([owner, '3000']).status, 0)
    const installed = f.settings(); assert.ok(installed.includes('BUZZ_REQUIRE_RELAY_MEMBERSHIP=true'))
    assert.equal(run(['', '3000']).status, 0); assert.equal(f.settings(), installed)
    assert.equal(run([owner, '3000'], { AUKORA_BUZZ_RELAY_URL: 'ws://localhost:3001' }).status, 0)
    assert.ok(f.settings().includes('RELAY_URL=ws://localhost:3001'))
  },
}
for (const [name, check] of Object.entries(checks)) test(`close: ${name}`, t => check(t))

const mutations = [
  ['interrupted', 'close.sh', 'if sudo -u "$U" test -e "$PENDING"; then', 'if false; then'],
  ['pending', 'close.sh', '[[ "$SAVED" =~ ^close-backup\\.[a-zA-Z0-9]{6}$ ]] || refuse invalid-pending-backup', ':'],
  ['pending', 'close.sh', 'sudo -u "$U" test -s "$BACKUP/relay.env" && sudo -u "$U" test -s "$BACKUP/relay.dump" || refuse invalid-pending-backup', ':'],
  ['pending', 'close.sh', '[ "$(sudo -u "$U" cat "$BACKUP/owner.pubkey")" = "$OWNER" ] || refuse pending-owner-mismatch', ':'],
  ['pending', 'close.sh', '[ "$(sudo -u "$U" cat "$BACKUP/agent.pubkey")" = "$AGENT" ] || refuse pending-agent-mismatch', ':'],
  ['input', 'close.sh', '[[ "$OWNER" =~ ^[0-9a-fA-F]{64}$ && "$KEY_FILE" = /* ]] || refuse owner-and-door-key-required', ':'],
  ['key', 'close.sh', ') || refuse invalid-door-key', ') || AGENT=' + 'a'.repeat(64)],
  ['preflight', 'close.sh', 'flock -n 9 || refuse already-running', ':'],
  ['preflight', 'close.sh', '[ "$PUB" = "127.0.0.1:${PORT}->3000/tcp " ] || refuse loopback-required', ':'],
  ['preflight', 'close.sh', '[[ -z "$EXISTING" || "$EXISTING" = "$OWNER" ]] || refuse different-owner', ':'],
  ['backup', 'close.sh', "<<'EOS' || refuse backup-failed", "<<'EOS' || true"],
  ['backup', 'close.sh', 'test -s "$2/relay.dump.partial"', ':'],
  ['success', 'close.sh', 'chmod 0600 "$2/relay.env"', 'chmod 0644 "$2/relay.env"'],
  ['success', 'close.sh', 'pg_dump -U buzz -d buzz --format=custom', 'pg_isready -U buzz -d buzz'],
  ['success', 'close.sh', 'sudo systemctl restart aukora-buzz.service >/dev/null 2>&1 || refuse restart-failed', ':'],
  ['rollback', 'close.sh', '[ "$healthy" = 1 ] || refuse health-timeout', ':'],
  ['rollback', 'close.sh', '"$NODE" "$HERE/member.mjs" verify-closed --relay "http://localhost:$PORT" >/dev/null 2>&1 || refuse closed-not-proved', ':'],
  ['rollback', 'close.sh', 'mv -f "$NEXT" "$1/relay.env"', ':'],
  ['rollback', 'close.sh', 'if sudo systemctl restart aukora-buzz.service >/dev/null 2>&1; then', 'if true; then'],
  ['success', 'write-settings.sh', "echo 'BUZZ_REQUIRE_RELAY_MEMBERSHIP=true'", ':'],
  ['success', 'write-settings.sh', 'echo "RELAY_OWNER_PUBKEY=$OWNER"', ':'],
  ['success', 'close.sh', "trap - EXIT HUP INT TERM\nprintf 'PASS", "trap - EXIT HUP INT TERM\necho \"$AGENT\"\nprintf 'PASS"],
  ['writer', 'write-settings.sh', 'if [ -z "$OWNER" ] && [ -f relay.env ]; then OWNER=$(sed -n \'s/^RELAY_OWNER_PUBKEY=//p\' relay.env); fi', ':'],
  ['check', 'check.sh', 'if node "$MEMBER" verify-closed --relay "http://localhost:${PORT}" >/dev/null 2>&1; then', 'if true; then'],
]
if (process.argv.includes('--mutate')) for (const [index, [name, file, from, to]] of mutations.entries()) {
  test(`mutation ${index + 1}: ${name} protection weakened`, t => {
    assert.ok(readFileSync(join(here, file), 'utf8').includes(from), 'mutation anchor must exist')
    assert.throws(() => checks[name](t, { file, from, to }), error => error instanceof assert.AssertionError)
  })
}

test('installed verifier loads its copied imports and reports closed without a checkout fallback', t => {
  const f = fixture(t), lib = join(f.root, 'lib')
  const installer = readFileSync(join(here, 'install.sh'), 'utf8')
  const block = installer.match(/^if \[ -f "\$HERE\/\.\.\/\.\.\/plugins\/aukora-buzz-door\/lib\/index\.mjs" \]; then\n[\s\S]*?^fi$/m)?.[0]
  assert.ok(block, 'installer verifier-copy block is present')
  const options = { encoding: 'utf8', timeout: 30000, env: {
    ...process.env, PATH: `${join(f.root, 'bin')}:${process.env.PATH}`, CALLS: join(f.root, 'calls'),
    REAL_NODE: process.execPath, FETCH_STUB: join(f.root, 'fetch.mjs'), HERE: here, LIB: lib,
  } }
  const copied = spawnSync('bash', ['-euc', block], options)
  assert.equal(copied.status, 0, copied.stderr)
  const member = join(lib, 'member/ops/buzz-relay/member.mjs')
  const help = spawnSync(process.execPath, [member, '--help'], options)
  assert.equal(help.status, 0, help.stderr)
  assert.match(help.stdout, /verify-closed/)
  const verified = spawnSync(process.execPath, ['--import', options.env.FETCH_STUB, member, 'verify-closed'], options)
  assert.equal(verified.status, 0, verified.stderr)
  assert.equal(JSON.parse(verified.stdout).closed, true)
  for (const name of ['licenses/noble-curves.LICENSE', 'licenses/noble-hashes.LICENSE', 'upstream-noble-curves.json']) {
    const source = join(repo, 'plugins/aukora-nostr/lib/vendor/noble-curves', name)
    const installed = join(lib, 'member/plugins/aukora-nostr/lib/vendor/noble-curves', name)
    assert.ok(readFileSync(installed).equals(readFileSync(source)), `retained ${name}`)
  }
  for (const name of ['check.sh', 'read-setting.sh']) writeFileSync(join(lib, name), readFileSync(join(f.scripts, name)))
  assert.equal(existsSync(join(lib, 'member.mjs')), false, 'no source-layout fallback exists')
  const checked = spawnSync('bash', [join(lib, 'check.sh')], options)
  assert.equal(checked.status, 0, checked.stderr + checked.stdout)
  assert.match(checked.stdout, /PASS  closed/)
  assert.ok(f.calls().some(args => args[0] === 'node' && args[1] === member && args[2] === 'verify-closed'))
})
