import assert from 'node:assert/strict'
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync, chmodSync, symlinkSync, unlinkSync, rmSync, existsSync, statSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { spawnSync } from 'node:child_process'
import test from 'node:test'

const here = dirname(fileURLToPath(import.meta.url))
const image = 'localhost/aukora-buzz-relay:123456789abc'
const stub = `#!${process.execPath} --
import { appendFileSync, readFileSync, writeFileSync } from 'node:fs'
import { basename } from 'node:path'
import { spawnSync } from 'node:child_process'
const name = basename(process.argv[1]), args = process.argv.slice(2), env = process.env
appendFileSync(env.CALLS, JSON.stringify([name, ...args]) + '\\n')
const run = (argv) => process.exit(spawnSync(argv[0], argv.slice(1), { stdio: 'inherit', env }).status ?? 1)
if (name === 'sudo') {
  if (args[0] === '-u') args.splice(0, 2)
  if (args[0] === '-H') args.shift()
  run(args)
}
if (name === 'timeout') run(args.slice(1))
if (name === 'id') { console.log('1001'); process.exit(env.ACCOUNT_ABSENT === '1' ? 1 : 0); }
if (name === 'ss') { process.stdout.write(env.LISTEN || ''); process.exit(env.SS_FAIL === '1' ? 1 : 0); }
if (name === 'stat') { console.log(env.LISTENER_UID || '1001'); process.exit(0); }
if (name === 'find') { if (env.FIND_FAIL === '1') process.exit(1); run(['/usr/bin/find', ...args]); }
if (name === 'sleep') process.exit(0)
if (name === 'curl') process.exit(env.CURL_FAIL === '1' ? 1 : 0)
if (name === 'redis-cli') {
  writeFileSync(env.PROBE_INPUT, readFileSync(0))
  writeFileSync(env.PROBE_ENV, JSON.stringify(Object.keys(env).filter((key) => ['REDISCLI_AUTH', 'REDIS_PASSWORD'].includes(key))))
  console.log('OK\\nPONG'); process.exit(0)
}
if (name === 'systemctl') {
  if (args[0] === 'show') console.log(env.SERVICE_STATE || 'active')
  process.exit(0)
}
if (name === 'podman') {
  if (args[0] === 'pod' && args[1] === 'inspect') {
    if (env.POD_ABSENT === '1') process.exit(1)
    console.log(args.at(-1) === '{{.InfraContainerID}}' ? 'a'.repeat(64) : env.POD_BINDING || '127.0.0.1:3000->3000/tcp ')
  }
  if (args[0] === 'inspect') console.log(args.at(-1) === '{{.State.ConmonPid}}' ? '9876' : env.CONTAINER_FAIL === args[1] ? 'false' : 'true')
  if (args[0] === 'exec' && args[1] === 'buzz-postgres') process.exit(env.POSTGRES_FAIL === '1' ? 1 : 0)
  if (args[0] === 'exec' && args[1] === 'buzz-redis') {
    const count = Number(readFileSync(env.REDIS_COUNT, 'utf8')) + 1
    writeFileSync(env.REDIS_COUNT, String(count))
    console.log(env.REDIS_FAIL === '1' || count <= Number(env.REDIS_DELAY || 0) ? 'LOADING' : 'PONG')
  }
  process.exit(0)
}
process.exit(1)
`

function fixture(t) {
  const root = mkdtempSync(join(tmpdir(), 'buzz-ops-test-'))
  t.after(() => rmSync(root, { recursive: true, force: true }))
  const state = join(root, 'state'), bin = join(root, 'bin')
  mkdirSync(state); mkdirSync(bin)
  for (const pid of ['4321', '9876']) mkdirSync(join(root, 'proc', pid, 'fd'), { recursive: true })
  symlinkSync('pipe:[12345]', join(root, 'proc/4321/fd/3'))
  symlinkSync('pipe:[12345]', join(root, 'proc/9876/fd/5'))
  for (const file of ['up.sh', 'check.sh', 'install.sh', 'read-setting.sh', 'check-port.sh', 'prepare-secrets.sh', 'write-settings.sh']) {
    writeFileSync(join(root, file), readFileSync(join(here, file), 'utf8')
      .replaceAll('/var/lib/aukora-buzz', state).replaceAll('/proc/', `${root}/proc/`))
  }
  const mock = join(bin, 'mock.mjs')
  writeFileSync(mock, stub); chmodSync(mock, 0o755)
  for (const name of ['sudo', 'podman', 'curl', 'systemctl', 'id', 'sleep', 'timeout', 'ss', 'stat', 'find', 'redis-cli']) symlinkSync(mock, join(bin, name))
  const calls = join(root, 'calls'), redisCount = join(root, 'redis-count')
  writeFileSync(calls, ''); writeFileSync(redisCount, '0')
  writeFileSync(join(state, 'node.env'), 'PORT=3000\n')
  writeFileSync(join(state, 'image.env'), `IMAGE=${image}\nSOURCE_SHA=${'a'.repeat(40)}\n`)
  mkdirSync(join(state, 'secrets'))
  writeFileSync(join(state, 'secrets/postgres-password'), `${'1'.repeat(48)}\n`)
  writeFileSync(join(state, 'secrets/redis.conf'), `appendonly yes\nrequirepass ${'2'.repeat(48)}\n`)
  return {
    root, state,
    run(file, args = [], extra = {}) {
      return spawnSync('bash', [join(root, file), ...args], {
        encoding: 'utf8', timeout: 20000,
        env: { ...process.env, PATH: `${bin}:${process.env.PATH}`, CALLS: calls, REDIS_COUNT: redisCount, AUKORA_BUZZ_MEMORY_LIMITS: '0', ...extra },
      })
    },
    calls() { return readFileSync(calls, 'utf8').trim().split('\n').filter(Boolean).map(JSON.parse); },
  }
}

function parse(setting, input) {
  return spawnSync('bash', [join(here, 'read-setting.sh'), setting], { input, encoding: 'utf8' })
}

test('settings accept only canonical local images and safe numeric ports', () => {
  for (const port of ['1', '03000', '32767', '61000', '65535']) {
    const result = parse('PORT', `PORT=${port}\n`)
    assert.equal(result.status, 0, result.stderr)
    assert.equal(result.stdout.trim(), String(Number(port)))
  }
  for (const port of ['0', '65536', '999999999999', '32768', '50000', '60999', '3e3', '-1', '3000 ', '3000\nPORT=3001']) {
    assert.notEqual(parse('PORT', `PORT=${port}\n`).status, 0, port)
  }
  assert.equal(parse('IMAGE', `IMAGE=${image}\nSOURCE_SHA=${'b'.repeat(40)}\n`).status, 0)
  for (const value of ['evil.example/relay:latest', `${image};id`, `${image} --privileged`, 'localhost/aukora-buzz-relay:latest', `${image}\nIMAGE=${image}`]) {
    assert.notEqual(parse('IMAGE', `IMAGE=${value}\n`).status, 0, value)
  }
})

test('check and startup never evaluate service-owned settings', (t) => {
  const f = fixture(t), marker = join(f.root, 'executed')
  for (const attack of [`$(touch ${marker})`, `\`touch ${marker}\``, `3000; touch ${marker}`, `3000\ntouch ${marker}`]) {
    writeFileSync(join(f.state, 'node.env'), `PORT=${attack}\n`)
    for (const [file, args] of [['check.sh', ['--health']], ['up.sh', []]]) {
      const result = f.run(file, args)
      assert.notEqual(result.status, 0)
      assert.equal(existsSync(marker), false, `${file} evaluated configuration`)
    }
  }
  writeFileSync(join(f.state, 'node.env'), 'PORT=3000\n')
  for (const attack of [`${image}; touch ${marker}`, `$(touch ${marker})`, `${image}\ntouch ${marker}`]) {
    writeFileSync(join(f.state, 'image.env'), `IMAGE=${attack}\n`)
    assert.notEqual(f.run('up.sh').status, 0)
    assert.equal(existsSync(marker), false)
  }
  assert.equal(f.calls().some(([name]) => name === 'podman' || name === 'curl'), false)
})

test('install refuses firewall-allowed ports before any administrator action', (t) => {
  const f = fixture(t)
  for (const port of ['32768', '45000', '60999']) {
    const result = f.run('install.sh', [], { AUKORA_BUZZ_PORT: port })
    assert.notEqual(result.status, 0)
    assert.match(result.stderr, /sandbox firewall.*ephemeral range/)
  }
  assert.equal(f.calls().length, 0)
})

const listener = 'LISTEN 0 128 127.0.0.1:3000 0.0.0.0:* users:(("rootlessport",pid=4321,fd=10))\n'
test('port preflight permits an unused port and a listener linked to this pod, including reinstall', (t) => {
  for (const extra of [{ ACCOUNT_ABSENT: '1' }, {}, { LISTEN: listener }]) {
    const f = fixture(t), result = f.run('check-port.sh', ['3000'], extra)
    assert.equal(result.status, 0, result.stderr)
    assert.ok(f.calls().some((args) => args[0] === 'ss' && args.includes('sport = :3000')))
    if (!extra.LISTEN) assert.equal(f.calls().some((args) => args[0] === 'podman'), false)
    else assert.ok(f.calls().some((args) => args[0] === 'podman' && args.at(-1) === '{{.State.ConmonPid}}'))
  }
})

test('install refuses foreign, unidentifiable and uninspectable listeners even with the existing user', (t) => {
  for (const extra of [
    { LISTENER_UID: '2002' }, { POD_ABSENT: '1' }, { ACCOUNT_ABSENT: '1' },
    { POD_BINDING: '0.0.0.0:3000->3000/tcp ' }, { SS_FAIL: '1' },
    { LISTEN: listener.replace('127.0.0.1', '0.0.0.0') },
    { LISTEN: listener.replace(/ users:.*\n/, '\n') },
    { LISTEN: listener + listener.replace('4321', '4322') },
  ]) {
    const f = fixture(t), result = f.run('install.sh', [], { LISTEN: listener, ...extra })
    assert.notEqual(result.status, 0)
    assert.match(result.stderr, /port 3000.*ownership cannot be verified/)
    assert.equal(f.calls().some((args) => ['systemctl', 'useradd', 'usermod', 'loginctl'].includes(args[0])), false)
  }
})

test('a same-user unrelated listener cannot borrow this pods valid published-port setting', (t) => {
  const f = fixture(t)
  unlinkSync(join(f.root, 'proc/9876/fd/5'))
  symlinkSync('pipe:[99999]', join(f.root, 'proc/9876/fd/5'))
  const result = f.run('install.sh', [], { LISTEN: listener })
  assert.notEqual(result.status, 0)
  assert.match(result.stderr, /ownership cannot be verified/)
})

function legacyCredentials(state) {
  const files = {
    'postgres.env': `POSTGRES_DB=buzz\nPOSTGRES_USER=buzz\nPOSTGRES_PASSWORD=${'1'.repeat(48)}\nPGDATA=/var/lib/postgresql/data/pgdata\n`,
    'redis.env': `REDIS_PASSWORD=${'2'.repeat(48)}\n`,
    'relay-secrets.env': `DATABASE_URL=postgres://buzz:${'1'.repeat(48)}@127.0.0.1:5432/buzz\nREDIS_URL=redis://:${'2'.repeat(48)}@127.0.0.1:6379\nBUZZ_RELAY_PRIVATE_KEY=${'3'.repeat(64)}\nBUZZ_GIT_HOOK_HMAC_SECRET=${'4'.repeat(64)}\n`,
  }
  for (const [name, content] of Object.entries(files)) writeFileSync(join(state, name), content)
  return files
}

test('secret migration preserves existing credentials and database bytes across reinstalls', (t) => {
  const f = fixture(t), originals = legacyCredentials(f.state)
  for (const database of ['postgres', 'redis']) {
    mkdirSync(join(f.state, 'data', database), { recursive: true })
    writeFileSync(join(f.state, 'data', database, 'existing-data'), 'keep existing database')
  }
  for (let attempt = 0; attempt < 2; attempt++) {
    const result = f.run('prepare-secrets.sh', [f.state])
    assert.equal(result.status, 0, result.stderr)
    assert.equal(result.stdout, '')
    for (const [name, content] of Object.entries(originals)) {
      assert.ok(readFileSync(join(f.state, name), 'utf8') === content, `${name} was changed`)
      assert.equal(statSync(join(f.state, name)).mode & 0o777, 0o600)
    }
    assert.ok(readFileSync(join(f.state, 'secrets/postgres-password'), 'utf8') === `${'1'.repeat(48)}\n`)
    assert.ok(readFileSync(join(f.state, 'secrets/redis.conf'), 'utf8') === `appendonly yes\nrequirepass ${'2'.repeat(48)}\n`)
    assert.equal(statSync(join(f.state, 'secrets')).mode & 0o777, 0o700)
    for (const name of ['postgres-password', 'redis.conf']) assert.equal(statSync(join(f.state, 'secrets', name)).mode & 0o777, 0o444)
    for (const database of ['postgres', 'redis']) assert.equal(readFileSync(join(f.state, 'data', database, 'existing-data'), 'utf8'), 'keep existing database')
    assert.equal(f.run('up.sh').status, 0)
  }
})

test('fresh secret files are generated silently and reused, while partial or lost sets fail closed', (t) => {
  const fresh = fixture(t), result = fresh.run('prepare-secrets.sh', [fresh.state])
  assert.equal(result.status, 0, result.stderr)
  assert.equal(result.stdout + result.stderr, '')
  const original = readFileSync(join(fresh.state, 'relay-secrets.env'))
  assert.equal(fresh.run('prepare-secrets.sh', [fresh.state]).status, 0)
  assert.ok(readFileSync(join(fresh.state, 'relay-secrets.env')).equals(original))
  for (const missing of ['partial', 'all']) {
    const f = fixture(t)
    mkdirSync(join(f.state, 'data/postgres'), { recursive: true })
    writeFileSync(join(f.state, 'data/postgres/PG_VERSION'), '17')
    if (missing === 'partial') writeFileSync(join(f.state, 'postgres.env'), 'preserve this')
    const failed = f.run('prepare-secrets.sh', [f.state])
    assert.notEqual(failed.status, 0)
    assert.match(failed.stderr, /incomplete secret files|data exists without secret files/)
    assert.equal(existsSync(join(f.state, 'relay-secrets.env')), false)
    assert.equal(readFileSync(join(f.state, 'data/postgres/PG_VERSION'), 'utf8'), '17')
  }
})

test('secret migration treats old env files as data and rejects malformed or duplicate passwords', (t) => {
  for (const invalid of ['$(touch MARKER)', 'ab\nPOSTGRES_PASSWORD=' + '1'.repeat(48), '1'.repeat(48) + '\nPOSTGRES_PASSWORD=' + '2'.repeat(48)]) {
    const f = fixture(t), marker = join(f.root, 'executed')
    legacyCredentials(f.state)
    writeFileSync(join(f.state, 'postgres.env'), `POSTGRES_PASSWORD=${invalid.replace('MARKER', marker)}\n`)
    const result = f.run('prepare-secrets.sh', [f.state])
    assert.notEqual(result.status, 0)
    assert.equal(existsSync(marker), false)
    assert.match(result.stderr, /invalid|duplicate/)
  }
})

test('unreadable or symlinked database data never permits replacement credentials', (t) => {
  for (const link of [false, true]) {
    const f = fixture(t)
    mkdirSync(join(f.state, 'data'), { recursive: true })
    if (link) symlinkSync(f.root, join(f.state, 'data/postgres'))
    else mkdirSync(join(f.state, 'data/postgres'))
    const result = f.run('prepare-secrets.sh', [f.state], { FIND_FAIL: '1' })
    assert.notEqual(result.status, 0)
    assert.match(result.stderr, /cannot inspect.*database data/)
    for (const name of ['postgres.env', 'redis.env', 'relay-secrets.env']) assert.equal(existsSync(join(f.state, name)), false)
  }
})

test('database container launches mount credentials read-only without password env or argv', (t) => {
  const f = fixture(t), result = f.run('up.sh')
  assert.equal(result.status, 0, result.stderr)
  const runs = f.calls().filter((args) => args[0] === 'podman' && args[1] === 'run')
  const pg = runs.find((args) => args.includes('buzz-postgres'))
  const redis = runs.find((args) => args.includes('buzz-redis'))
  assert.ok(pg.includes('POSTGRES_PASSWORD_FILE=/run/secrets/postgres-password'))
  assert.ok(pg.includes(`${f.state}/secrets/postgres-password:/run/secrets/postgres-password:ro`))
  assert.ok(pg.includes(`${f.state}/data/postgres:/var/lib/postgresql/data`))
  assert.ok(pg.includes('PGDATA=/var/lib/postgresql/data/pgdata'))
  assert.ok(redis.includes(`${f.state}/secrets/redis.conf:/run/secrets/redis.conf:ro`))
  assert.ok(redis.includes(`${f.state}/data/redis:/data`))
  assert.deepEqual(redis.slice(-2), ['redis-server', '/run/secrets/redis.conf'])
  for (const args of [pg, redis]) {
    assert.equal(args.includes('--env-file'), false)
    assert.equal(args.some((arg) => /POSTGRES_PASSWORD=|REDIS_PASSWORD|REDISCLI_AUTH=|requirepass/.test(arg)), false)
  }
  const relay = runs.find((args) => args.includes('buzz-relay'))
  assert.ok(relay.includes(`${f.state}/relay-secrets.env`), 'pinned relay requires env credentials')
})

test('Redis startup and health probes authenticate via stdin and health still accepts a pre-migration container', (t) => {
  for (const [script, legacy] of [['up.sh', false], ['check.sh', false], ['check.sh', true]]) {
    const f = fixture(t)
    assert.equal(f.run(script, script === 'check.sh' ? ['--health'] : []).status, 0)
    const probe = f.calls().find((args) => args[0] === 'podman' && args[1] === 'exec' && args[2] === 'buzz-redis').at(-1)
    const input = join(f.root, 'probe-input'), env = join(f.root, 'probe-env')
    writeFileSync(join(f.root, 'probe.sh'), probe.replaceAll('/run/secrets/redis.conf', join(f.state, legacy ? 'missing.conf' : 'secrets/redis.conf')))
    const result = f.run('probe.sh', [], {
      PROBE_INPUT: input, PROBE_ENV: env, REDISCLI_AUTH: undefined,
      REDIS_PASSWORD: legacy ? '2'.repeat(48) : undefined,
    })
    assert.equal(result.status, 0, result.stderr)
    assert.equal(result.stdout.trim(), 'PONG')
    assert.ok(readFileSync(input, 'utf8') === `AUTH ${'2'.repeat(48)}\nPING\n`, 'probe sent the original password on stdin')
    assert.deepEqual(JSON.parse(readFileSync(env, 'utf8')), legacy ? ['REDIS_PASSWORD'] : [])
    assert.ok(f.calls().filter((args) => args[0] === 'redis-cli').every((args) => args.join(' ') === 'redis-cli --raw'))
  }
})

test('startup refuses missing credential mounts before removing any existing container', (t) => {
  const f = fixture(t)
  rmSync(join(f.state, 'secrets/redis.conf'))
  const result = f.run('up.sh')
  assert.notEqual(result.status, 0)
  assert.match(result.stderr, /run install.sh before starting/)
  assert.equal(f.calls().some((args) => args[0] === 'podman'), false)
})

test('startup recreates every container with always restart and optional memory bounds after Redis readiness', (t) => {
  const f = fixture(t)
  const result = f.run('up.sh', [], { AUKORA_BUZZ_MEMORY_LIMITS: '1', REDIS_DELAY: '2' })
  assert.equal(result.status, 0, result.stderr)
  const calls = f.calls(), runs = calls.filter(([name, command]) => name === 'podman' && command === 'run')
  assert.equal(runs.length, 3)
  for (const [name, memory] of [['buzz-postgres', '1g'], ['buzz-redis', '256m'], ['buzz-relay', '1g']]) {
    const run = runs.find((args) => args.includes(name))
    assert.ok(run.includes('--restart=always'), name)
    assert.equal(run[run.indexOf('--memory') + 1], memory)
    const removal = calls.findIndex((args) => args[0] === 'podman' && args[1] === 'rm' && args.includes(name))
    assert.ok(removal >= 0 && removal < calls.indexOf(run), `${name} retains old settings`)
  }
  const relay = calls.indexOf(runs.find((args) => args.includes('buzz-relay')))
  const probes = calls.slice(0, relay).filter((args) => args[0] === 'podman' && args[1] === 'exec' && args[2] === 'buzz-redis')
  assert.ok(probes.length >= 3)
  assert.ok(probes.every((args) => args.at(-1).includes('/run/secrets/redis.conf') && !args.at(-1).includes('REDISCLI_AUTH=')))
  assert.ok(calls.some((args) => args[0] === 'curl' && args.includes('--max-time') && args.includes('--connect-timeout')))
})

test('memory limits remain opt-in and invalid choices fail closed', (t) => {
  const f = fixture(t)
  assert.equal(f.run('up.sh').status, 0)
  assert.ok(f.calls().filter((args) => args[0] === 'podman' && args[1] === 'run').every((args) => !args.includes('--memory')))
  assert.notEqual(f.run('up.sh', [], { AUKORA_BUZZ_MEMORY_LIMITS: 'yes' }).status, 0)
})

test('startup refuses to launch the relay while Redis is unready', (t) => {
  const f = fixture(t), result = f.run('up.sh', [], { REDIS_FAIL: '1' })
  assert.notEqual(result.status, 0)
  assert.match(result.stderr, /Redis did not become ready/)
  assert.equal(f.calls().some((args) => args[0] === 'podman' && args[1] === 'run' && args.includes('buzz-relay')), false)
})

test('health detects failed containers, databases and HTTP even when other checks pass', (t) => {
  for (const extra of [{ CONTAINER_FAIL: 'buzz-relay' }, { POSTGRES_FAIL: '1' }, { REDIS_FAIL: '1' }, { CURL_FAIL: '1' }]) {
    const f = fixture(t), result = f.run('check.sh', ['--health'], extra)
    assert.notEqual(result.status, 0)
    assert.match(result.stdout, /FAIL/)
    assert.equal(f.calls().some((args) => args[0] === 'systemctl'), false)
    assert.ok(f.calls().some((args) => args[0] === 'timeout' && args[1] === '10s'))
    assert.ok(f.calls().some((args) => args[0] === 'curl' && args.includes('--max-time') && args.includes('--connect-timeout')))
  }
})

test('watch recovers failed starts and unhealthy services, skipping intentional stops and transitions', (t) => {
  for (const [extra, restart] of [
    [{}, false],
    [{ CURL_FAIL: '1' }, true],
    [{ SERVICE_STATE: 'failed' }, true],
    ...['inactive', 'activating', 'deactivating'].map((state) => [{ SERVICE_STATE: state, CURL_FAIL: '1' }, false]),
  ]) {
    const f = fixture(t)
    const result = f.run('check.sh', ['--watch'], extra)
    assert.equal(result.status, restart ? 1 : 0, result.stderr)
    assert.equal(f.calls().some((args) => args.join(' ') === 'systemctl --no-block restart aukora-buzz.service'), restart)
    if (extra.SERVICE_STATE && extra.SERVICE_STATE !== 'failed') {
      assert.equal(f.calls().some((args) => ['sudo', 'podman', 'curl'].includes(args[0])), false)
    }
  }
  const unit = readFileSync(join(here, 'aukora-buzz.service'), 'utf8')
  const timer = readFileSync(join(here, 'aukora-buzz-watch.timer'), 'utf8')
  const watch = readFileSync(join(here, 'aukora-buzz-watch.service'), 'utf8')
  assert.match(unit, /^Wants=.*aukora-buzz-watch\.timer$/m)
  assert.match(timer, /^PartOf=aukora-buzz\.service$/m)
  assert.match(timer, /^OnActiveSec=5min$/m)
  assert.match(timer, /^OnUnitActiveSec=5min$/m)
  assert.match(timer, /^Unit=aukora-buzz-watch\.service$/m)
  assert.match(watch, /^ExecStart=\/usr\/local\/lib\/aukora-buzz\/check\.sh --watch$/m)
  const install = readFileSync(join(here, 'install.sh'), 'utf8')
  assert.match(install, /sudo install -m 0644.*aukora-buzz-watch\.service.*aukora-buzz-watch\.timer/)
})
