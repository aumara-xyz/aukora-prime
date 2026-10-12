import assert from 'node:assert/strict'
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync, chmodSync, symlinkSync, rmSync, existsSync } from 'node:fs'
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
if (name === 'id') { console.log('1001'); process.exit(0); }
if (name === 'sleep') process.exit(0)
if (name === 'curl') process.exit(env.CURL_FAIL === '1' ? 1 : 0)
if (name === 'systemctl') {
  if (args[0] === 'show') console.log(env.SERVICE_STATE || 'active')
  process.exit(0)
}
if (name === 'podman') {
  if (args[0] === 'pod' && args[1] === 'inspect') console.log('127.0.0.1:3000->3000/tcp ')
  if (args[0] === 'inspect') console.log(env.CONTAINER_FAIL === args[1] ? 'false' : 'true')
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
  for (const file of ['up.sh', 'check.sh', 'install.sh', 'read-setting.sh']) {
    writeFileSync(join(root, file), readFileSync(join(here, file), 'utf8').replaceAll('/var/lib/aukora-buzz', state))
  }
  const mock = join(bin, 'mock.mjs')
  writeFileSync(mock, stub); chmodSync(mock, 0o755)
  for (const name of ['sudo', 'podman', 'curl', 'systemctl', 'id', 'sleep', 'timeout']) symlinkSync(mock, join(bin, name))
  const calls = join(root, 'calls'), redisCount = join(root, 'redis-count')
  writeFileSync(calls, ''); writeFileSync(redisCount, '0')
  writeFileSync(join(state, 'node.env'), 'PORT=3000\n')
  writeFileSync(join(state, 'image.env'), `IMAGE=${image}\nSOURCE_SHA=${'a'.repeat(40)}\n`)
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
  assert.ok(probes.every((args) => args.at(-1) === 'REDISCLI_AUTH="$REDIS_PASSWORD" redis-cli ping'))
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
