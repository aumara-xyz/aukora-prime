// Stub commands exercise closing, backup order, rollback and repeated attempts without a node.
import assert from 'node:assert/strict'
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync, chmodSync, symlinkSync, rmSync, readdirSync, statSync, existsSync, constants } from 'node:fs'
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
  if (['closed', 'close-failed'].includes(args.at(-1))) run([env.REAL_NODE, '--import', env.PARENT_STUB, '--import', env.MARKER_STUB, ...args])
  if (args.includes('verify-closed')) {
    if (env.VERIFY_ERROR === '1') process.exit(1)
    // Exercise the real member.mjs CLI with either route accepted in a subprocess.
    run([env.REAL_NODE, '--import', env.PARENT_STUB, '--import', env.FETCH_STUB, ...args])
  }
  run([env.REAL_NODE, '--import', env.PARENT_STUB, ...args])
}
if (name === 'curl') process.exit(env.HEALTH_FAIL === '1' ? 1 : 0)
if (name === 'systemctl') {
  if (args[0] === 'show') { console.log(env.SERVICE_STATE || 'active'); process.exit(0) }
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
  writeFileSync(fetchStub, `import { readFileSync } from 'node:fs'
  globalThis.fetch = async (url, options) => {
    const route = new URL(url).pathname
    const open = process.env.ACCEPT_ROUTE === route || (process.env.SIGNED_OPEN === '1' && options.headers.Authorization) || (process.env.RELAY_TEST_STATE && !readFileSync(process.env.RELAY_TEST_STATE + '/relay.env', 'utf8').includes('BUZZ_REQUIRE_RELAY_MEMBERSHIP=true'))
    const payload = JSON.parse(options.body)
    return new Response(JSON.stringify(open ? route === '/query' ? [] : { accepted: true, event_id: payload.id } : { error: 'relay_membership_required' }), { status: open ? 200 : 403 })
  }`)
  const markerStub = join(root, 'marker.mjs')
  const parentStub = join(root, 'parents.mjs'), ancestors = []
  for (let directory = here; ; directory = dirname(directory)) {
    const st = statSync(directory)
    if (st.mode & 0o022) ancestors.push(`${st.dev}:${st.ino}`)
    if (directory === '/') break
  }
  writeFileSync(parentStub, `import fs from 'node:fs'
import { syncBuiltinESMExports } from 'node:module'
const ancestors = ${JSON.stringify(ancestors)}
for (const name of ['fstatSync', 'lstatSync']) {
  const original = fs[name]
  fs[name] = (...args) => {
    const st = original(...args)
    if (st?.isDirectory() && ancestors.includes(st.dev + ':' + st.ino)) st.mode &= ~0o022
    return st
  }
}
syncBuiltinESMExports()
`)
  writeFileSync(markerStub, `import fs from 'node:fs'
import { syncBuiltinESMExports } from 'node:module'
const log = fs.openSync(process.env.CALLS, 'a')
const record = (...args) => fs.writeSync(log, JSON.stringify(['marker', ...args]) + '\\n')
for (const name of ['openSync', 'writeFileSync', 'fchmodSync', 'fsyncSync', 'renameSync']) {
  const original = fs[name]
  fs[name] = (...args) => {
    record(name, ...args, name === 'fsyncSync' ? fs.fstatSync(args[0]).isDirectory() : null)
    return original(...args)
  }
}
// Only root ownership is simulated; descriptor writes, permissions, sync and rename use the real filesystem.
fs.fchownSync = (...args) => record('fchownSync', ...args)
syncBuiltinESMExports()
`)
  writeFileSync(calls, ''); writeFileSync(restarts, '0')
  writeFileSync(keyFile, secret, { mode: 0o600 })
  writeFileSync(join(state, 'relay.env'), open); writeFileSync(join(state, 'node.env'), 'PORT=3000\n')
  mkdirSync(join(state, 'data')); writeFileSync(join(state, 'data/rows'), 'channels and messages')
  return {
    root, scripts, state, keyFile,
    run(extra = {}, args = ['--owner-pubkey', owner, '--key-file', keyFile], file = 'close.sh') {
      return spawnSync('bash', [join(scripts, file), ...args], { encoding: 'utf8', timeout: 30000,
        env: { ...process.env, PATH: `${bin}:${process.env.PATH}`, CALLS: calls, STATE: state, RELAY_TEST_STATE: state, RESTARTS: restarts,
          DOOR_HOME: home, REAL_NODE: process.execPath, FETCH_STUB: fetchStub, MARKER_STUB: markerStub, PARENT_STUB: parentStub, WRITER: join(scripts, 'write-settings.sh'), ...extra } })
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
      assert.equal(existsSync(join(f.state, 'closed')), false)
      assert.equal(existsSync(join(f.state, 'close-failed')), true)
      assert.equal(readFileSync(join(f.state, 'close-failed'), 'utf8'), 'close-failed\n')
      assert.match(r.stderr.trim().split('\n').at(-1), extra.VERIFY_ERROR ? /relay state UNKNOWN/ : /relay is OPEN/)
      assert.equal(readFileSync(join(f.state, 'data/rows'), 'utf8'), 'channels and messages')
      assert.ok(f.calls().some(c => c.includes('verify-closed')))
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
      const f = fixture(t, m)
      writeFileSync(join(f.state, 'relay.env'), open + 'BUZZ_REQUIRE_RELAY_MEMBERSHIP=true\n')
      writeFileSync(join(f.state, 'node.env'), 'PORT=3000\nINTENDED_MEMBERSHIP=closed\n')
      const r = f.run(extra, [], 'check.sh')
      assert.equal(r.status, Object.keys(extra).length ? 1 : 0, r.stderr + r.stdout)
      assert.match(r.stdout, extra.VERIFY_ERROR ? /membership UNKNOWN/ : extra.ACCEPT_ROUTE ? /membership OPEN/ : /PASS  membership CLOSED/)
      const health = f.run(extra, ['--health'], 'check.sh'); assert.equal(health.status, r.status)
      assert.match(health.stdout, /membership (CLOSED|OPEN|UNKNOWN)/)
    }
  },
  membership(t, m) {
    for (const intended of ['closed', 'open-acknowledged', '']) {
      for (const [actual, extra] of [['CLOSED', {}], ['OPEN', { SIGNED_OPEN: '1' }], ['UNKNOWN', { VERIFY_ERROR: '1' }]]) {
        const f = fixture(t, m)
        writeFileSync(join(f.state, 'relay.env'), open + 'BUZZ_REQUIRE_RELAY_MEMBERSHIP=true\n')
        writeFileSync(join(f.state, 'node.env'), 'PORT=3000\n' + (intended ? `INTENDED_MEMBERSHIP=${intended}\n` : ''))
        for (const mode of actual === 'UNKNOWN' ? [['--health'], ['--watch']] : [['--health']]) {
          const r = f.run(extra, mode, 'check.sh')
          const matches = (actual === 'CLOSED' && intended === 'closed') || (actual === 'OPEN' && intended === 'open-acknowledged')
          assert.equal(r.status, matches ? 0 : 1, `${actual}/${intended || 'missing'}/${mode}: ${r.stderr}${r.stdout}`)
          assert.match(r.stdout, new RegExp(`membership ${actual}`))
          if (!intended) assert.match(r.stdout, /intended-membership-required:.*close\.sh --owner-pubkey.*close\.sh --acknowledge-open/)
        }
        assert.equal(f.restarts(), 0, 'membership alarms do not reopen or restart the relay')
      }
    }
    const f = fixture(t, m), before = f.settings()
    const r = f.run({}, ['--acknowledge-open'])
    assert.equal(r.status, 0, r.stderr)
    assert.equal(f.settings(), before); assert.equal(f.restarts(), 0)
    assert.equal(readFileSync(join(f.state, 'node.env'), 'utf8'), 'PORT=3000\nINTENDED_MEMBERSHIP=open-acknowledged\n')
    assert.equal(statSync(join(f.state, 'node.env')).mode & 0o777, 0o600)
    const checked = f.run({}, ['--watch'], 'check.sh')
    assert.equal(checked.status, 0, checked.stderr + checked.stdout)
    assert.match(checked.stdout, /PASS  membership OPEN/)
  },
  markers(t, m) {
    const f = fixture(t, m)
    writeFileSync(join(f.state, 'close-failed'), 'close-failed\n')
    const r = f.run(); assert.equal(r.status, 0, r.stderr)
    assert.equal(readFileSync(join(f.state, 'node.env'), 'utf8'), 'PORT=3000\nINTENDED_MEMBERSHIP=closed\n')
    assert.equal(statSync(join(f.state, 'node.env')).mode & 0o777, 0o600)
    assert.equal(existsSync(join(f.state, 'closed')), true)
    assert.equal(readFileSync(join(f.state, 'closed'), 'utf8'), 'closed\n')
    assert.equal(statSync(join(f.state, 'closed')).mode & 0o777, 0o600)
    assert.equal(existsSync(join(f.state, 'close-failed')), false)
    const calls = f.calls(), verify = calls.findIndex(c => c.includes('verify-closed'))
    const marker = calls.findIndex(c => c[0] === 'marker' && c[1] === 'fchownSync' && c[3] === 0 && c[4] === 0)
    assert.ok(marker > verify && verify >= 0, 'root ownership is set only after closure passes')
    const writes = calls.filter(c => c[0] === 'marker')
    const created = writes.find(c => c[1] === 'openSync')
    assert.equal(created[3] & (constants.O_EXCL | constants.O_NOFOLLOW), constants.O_EXCL | constants.O_NOFOLLOW)
    assert.equal(created[4], 0o600)
    assert.equal(typeof writes.find(c => c[1] === 'writeFileSync')[2], 'number', 'writes retain the opened descriptor')
    assert.deepEqual(writes.filter(c => c[1] === 'fsyncSync').map(c => c.at(-1)), [false, true])
    assert.ok(writes.findIndex(c => c[1] === 'fsyncSync') < writes.findIndex(c => c[1] === 'renameSync'))
    const failed = f.run({ VERIFY_ERROR: '1' }); assert.notEqual(failed.status, 0)
    assert.equal(readFileSync(join(f.state, 'closed'), 'utf8'), 'closed\n')
    assert.equal(statSync(join(f.state, 'close-failed')).mode & 0o777, 0o600)
    assert.equal(f.calls().filter(c => c[0] === 'marker' && c[1] === 'fchownSync').length, 2)
  },
  commands(t, m) {
    const f = fixture(t, m)
    assert.equal(f.run().status, 0)
    writeFileSync(join(f.state, 'close-failed'), 'close-failed\n')
    const before = f.settings(), restarts = f.restarts()
    const ack = f.run({}, ['--acknowledge']); assert.equal(ack.status, 0, ack.stderr)
    assert.equal(existsSync(join(f.state, 'close-failed')), false)
    assert.equal(existsSync(join(f.state, 'closed')), true)
    assert.equal(f.settings(), before); assert.equal(f.restarts(), restarts)
    writeFileSync(join(f.state, 'close-failed'), 'close-failed\n')
    const reopen = f.run({}, ['--reopen']); assert.equal(reopen.status, 0, reopen.stderr)
    assert.equal(readFileSync(join(f.state, 'node.env'), 'utf8'), 'PORT=3000\nINTENDED_MEMBERSHIP=open-acknowledged\n')
    assert.equal(f.settings(), open); assert.equal(f.restarts(), restarts + 1)
    assert.equal(existsSync(join(f.state, 'closed')), false)
    assert.equal(existsSync(join(f.state, 'close-failed')), true)
    for (const args of [['--acknowledge', 'extra'], ['--reopen', '--owner-pubkey', owner]]) {
      assert.notEqual(f.run({}, args).status, 0)
    }
    const pending = fixture(t, m)
    writeFileSync(join(pending.state, 'close-pending'), 'close-backup.pending\n')
    assert.notEqual(pending.run({}, ['--reopen']).status, 0)
    assert.equal(pending.restarts(), 0)
    const failed = fixture(t, m)
    assert.equal(failed.run().status, 0)
    assert.notEqual(failed.run({ RESTART_FAIL: 'all' }, ['--reopen']).status, 0)
    assert.equal(existsSync(join(failed.state, 'closed')), true)
  },
  markerSymlink(t, m) {
    const f = fixture(t, m), target = join(f.root, 'unrelated')
    mkdirSync(target)
    writeFileSync(join(target, 'keep'), 'unchanged')
    symlinkSync(target, join(f.state, 'closed'))
    symlinkSync(join(target, 'keep'), join(f.state, 'close-failed'))
    const r = f.run({ ACCEPT_ROUTE: '/query' })
    assert.notEqual(r.status, 0)
    assert.equal(readFileSync(join(target, 'keep'), 'utf8'), 'unchanged')
    assert.equal(readFileSync(join(f.state, 'close-failed'), 'utf8'), 'close-failed\n')
    const success = f.run(); assert.equal(success.status, 0, success.stderr)
    assert.equal(statSync(join(f.state, 'closed')).isFile(), true)
    assert.equal(readFileSync(join(f.state, 'closed'), 'utf8'), 'closed\n')
    assert.deepEqual(readdirSync(target), ['keep'])
  },
  writer(t, m) {
    const f = fixture(t, m), run = (args, env = {}) => spawnSync('bash', [join(f.scripts, 'write-settings.sh'), f.state, ...args], { encoding: 'utf8', env: { ...process.env, ...env } })
    assert.equal(run(['', '3000']).status, 0); assert.ok(!f.settings().includes('RELAY_OWNER_PUBKEY'))
    assert.equal(run([owner, '3000']).status, 0)
    const installed = f.settings(); assert.ok(installed.includes('BUZZ_REQUIRE_RELAY_MEMBERSHIP=true'))
    assert.equal(run(['', '3000']).status, 0); assert.equal(f.settings(), installed)
    assert.equal(run([owner, '3000'], { AUKORA_BUZZ_RELAY_URL: 'ws://localhost:3001' }).status, 0)
    assert.ok(f.settings().includes('RELAY_URL=ws://localhost:3001'))
    rmSync(join(f.state, 'node.env'))
    assert.equal(run(['', '3000']).status, 0)
    assert.equal(readFileSync(join(f.state, 'node.env'), 'utf8'), 'PORT=3000\nINTENDED_MEMBERSHIP=closed\n')
    assert.equal(statSync(join(f.state, 'node.env')).mode & 0o777, 0o600)
    writeFileSync(join(f.state, 'node.env'), 'PORT=3000\nINTENDED_MEMBERSHIP=open-acknowledged\n')
    assert.equal(run(['', '3001']).status, 0)
    assert.equal(readFileSync(join(f.state, 'node.env'), 'utf8'), 'PORT=3001\nINTENDED_MEMBERSHIP=open-acknowledged\n')
    writeFileSync(join(f.state, 'node.env'), 'PORT=3000\n')
    assert.equal(run(['', '3000']).status, 0)
    assert.equal(readFileSync(join(f.state, 'node.env'), 'utf8'), 'PORT=3000\n', 'reinstall cannot acknowledge an existing open relay')
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
  ['rollback', 'close.sh', 'cp "$2/relay.env" "$NEXT"\nchmod 0600 "$NEXT"\nmv -f "$NEXT" "$1/relay.env"', 'cp "$2/relay.env" "$NEXT"\nchmod 0600 "$NEXT"'],
  ['rollback', 'close.sh', 'if sudo systemctl restart aukora-buzz.service >/dev/null 2>&1; then', 'if true; then'],
  ['success', 'write-settings.sh', "echo 'BUZZ_REQUIRE_RELAY_MEMBERSHIP=true'", ':'],
  ['success', 'write-settings.sh', 'echo "RELAY_OWNER_PUBKEY=$OWNER"', ':'],
  ['success', 'close.sh', "trap - EXIT HUP INT TERM\nprintf 'PASS", "trap - EXIT HUP INT TERM\necho \"$AGENT\"\nprintf 'PASS"],
  ['writer', 'write-settings.sh', 'if [ -z "$OWNER" ] && [ -f relay.env ]; then OWNER=$(sed -n \'s/^RELAY_OWNER_PUBKEY=//p\' relay.env); fi', ':'],
  ['check', 'check.sh', 'UNKNOWN:*) say FAIL', 'UNKNOWN:*) say PASS'],
  ['membership', 'check.sh', 'UNKNOWN:*) say FAIL', 'UNKNOWN:*) say PASS'],
  ['membership', 'check.sh', '*) say FAIL "buzz-check:membership-mismatch:', '*) say PASS "buzz-check:membership-mismatch:'],
  ['membership', 'member.mjs', "['query', '/query', query, key], ['events', '/events', event, key],", ''],
  ['membership', 'close.sh', 'write_intent open-acknowledged || refuse open-acknowledgement-failed', ':'],
  ['writer', 'write-settings.sh', 'INTENDED_MEMBERSHIP=closed', "INTENDED_MEMBERSHIP=''"],
  ['writer', 'write-settings.sh', 'chmod 0600 "$NODE_NEXT"', 'chmod 0644 "$NODE_NEXT"'],
  ['markers', 'close.sh', 'write_marker closed || refuse closed-marker-failed', ':'],
  ['markers', 'close.sh', 'fchownSync(fd, 0, 0)', ';'],
  ['markers', 'close.sh', 'fchmodSync(fd, 0o600)', 'fchmodSync(fd, 0o644)'],
  ['markers', 'close.sh', 'constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW', 'constants.O_CREAT | constants.O_WRONLY'],
  ['markers', 'close.sh', "writeFileSync(fd, marker + '\\n')", "writeFileSync(next, marker + '\\n')"],
  ['markers', 'close.sh', 'fsyncSync(fd)\n  closeSync(fd)', 'closeSync(fd)'],
  ['markers', 'close.sh', 'fd = openSync(root, constants.O_RDONLY | constants.O_DIRECTORY)\n  fsyncSync(fd)', 'fd = openSync(root, constants.O_RDONLY | constants.O_DIRECTORY)'],
  ['markers', 'close.sh', 'rm -f "$ROOT/close-failed" || refuse failure-marker-cleanup-failed', ':'],
  ['rollback', 'close.sh', "write_marker close-failed || echo 'buzz-close:close-failed-marker-failed' >&2", ':'],
  ['rollback', 'close.sh', 'if RESULT=$("$NODE" "$HERE/member.mjs" verify-closed --relay "http://localhost:$PORT" 2>/dev/null); then', 'if RESULT=; then'],
  ['commands', 'close.sh', 'rm -f "$ROOT/closed" || refuse reopen-marker-failed', ':'],
  ['commands', 'close.sh', 'rm -f "$ROOT/close-failed" || refuse acknowledgement-failed', ':'],
  ['commands', 'close.sh', 'sudo -u "$U" test ! -e "$ROOT/close-pending" || refuse close-pending', ':'],
  ['commands', 'close.sh', 'sudo systemctl restart aukora-buzz.service >/dev/null 2>&1 || refuse reopen-restart-failed', ':'],
  ['markerSymlink', 'close.sh', 'renameSync(next, `${root}/${marker}`)', 'writeFileSync(`${root}/${marker}`, marker)'],
  ['markers', 'close.sh', 'write_intent closed || refuse closed-intent-failed', ':'],
  ['commands', 'close.sh', 'write_intent open-acknowledged || refuse reopen-intent-failed', ':'],
  ['markers', 'close.sh', 'chmod 0600 "$NEXT"', 'chmod 0644 "$NEXT"'],
  ['writer', 'write-settings.sh', 'if [ -f node.env ]; then', 'if false; then'],
]
if (process.argv.includes('--mutate') || process.env.AUKORA_BUZZ_CLOSE_MUTATIONS === '1') for (const [index, [name, file, from, to]] of mutations.entries()) {
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
    REAL_NODE: process.execPath, FETCH_STUB: join(f.root, 'fetch.mjs'), PARENT_STUB: join(f.root, 'parents.mjs'), HERE: here, LIB: lib,
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
  writeFileSync(join(f.state, 'node.env'), 'PORT=3000\nINTENDED_MEMBERSHIP=closed\n')
  assert.equal(existsSync(join(lib, 'member.mjs')), false, 'no source-layout fallback exists')
  const checked = spawnSync('bash', [join(lib, 'check.sh')], options)
  assert.equal(checked.status, 0, checked.stderr + checked.stdout)
  assert.match(checked.stdout, /PASS  membership CLOSED/)
  assert.ok(f.calls().some(args => args[0] === 'node' && args[1] === member && args[2] === 'verify-closed'))
})
