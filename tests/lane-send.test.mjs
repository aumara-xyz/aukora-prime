// SPDX-License-Identifier: AGPL-3.0-or-later
// Checks client refusals and advisory findings with synthetic state and transport.
import assert from 'node:assert/strict'
import { test } from 'node:test'
import { chmodSync, copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs'
import { createServer } from 'node:http'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { spawnSync } from 'node:child_process'

const HERE = dirname(fileURLToPath(import.meta.url))
const ROOT = resolve(HERE, '..')
const SUBJECT = join(ROOT, 'scripts/lane-send.mjs')
const selected = process.argv.indexOf('--subject')
const { listSessions, resolveTitle, completionConditionOfGoal, permissionsCarriedByGoal, isGoalSubcommand, sendLane, main } =
  await import(pathToFileURL(selected < 0 ? SUBJECT : process.argv[selected + 1]))
const SESSION = 'session-00000000-0000-0000-0000-000000000001'
const OTHER = 'session-00000000-0000-0000-0000-000000000002'
const TOKEN = 'synthetic-lane-token'
const TEXT = 'synthetic-private-message'
const accepted = (kind = 'prompt', session = SESSION) => ({ ok: true, kind, session, backend: { text: TEXT, token: TOKEN } })
const json = (body = accepted(), status = 200) => new Response(JSON.stringify(body), { status })
const code = expected => error => error.code === expected

function fixture(t) {
  const stateRoot = mkdtempSync(join(HERE, '.lane-send-'))
  t.after(() => rmSync(stateRoot, { recursive: true, force: true }))
  const door = join(stateRoot, 'lane-door')
  mkdirSync(door)
  writeFileSync(join(door, 'door.token'), TOKEN, { mode: 0o600 })
  writeFileSync(join(door, 'port'), '12345\n')
  return { stateRoot, lane: 'fixture', session: SESSION, text: TEXT, fetchImpl: async () => json() }
}

test('projection lookup skips incomplete records, sorts, and refuses ambiguity', t => {
  const options = fixture(t)
  assert.deepEqual(listSessions(options.stateRoot), [])
  const directory = join(options.stateRoot, 'home/storages/session_projcache/sessions')
  mkdirSync(directory, { recursive: true })
  const record = (title, lastPromptAt) => JSON.stringify({ record: { rows: { title: { val: title }, sessionListMetadata: { val: { lastPromptAt } } } } })
  writeFileSync(join(directory, `${SESSION}.json`), record('task', 1))
  writeFileSync(join(directory, `${OTHER}.json`), record('task extra', 2))
  writeFileSync(join(directory, 'session-00000000-0000-0000-0000-000000000003.json'), '{')
  writeFileSync(join(directory, 'not-a-session.json'), record('task', 3))
  const rows = listSessions(options.stateRoot)
  assert.deepEqual(rows.map(row => row.session), [OTHER, SESSION])
  assert.equal(resolveTitle(rows, 'task'), SESSION)
  assert.equal(resolveTitle(rows, 'extra'), OTHER)
  assert.throws(() => resolveTitle(rows, 'tas'), code('lane.ambiguous-session'))
  assert.throws(() => resolveTitle([...rows, rows[1]], 'task'), code('lane.ambiguous-session'))
  assert.throws(() => resolveTitle(rows, 'missing'), code('lane.no-such-session'))
})

// The donor has no dedicated tests; these retain its documented examples and review probe.
test('goal examples and every repeated verb occurrence remain advisory findings', () => {
  for (const text of ['no push', 'do not push', 'never merge', 'without spending', 'push is forbidden',
    'do not push, merge or cut over', 'pushed and merged', 'scripts/ci/push.sh', 'desktop-cutover.mjs',
    'tests/aukora-cutover-transaction.test.mjs', 'push/config']) {
    assert.deepEqual(permissionsCarriedByGoal(`/goal ${text}`), [], text)
  }
  for (const text of ['Do not push. Then push', 'no push, but push', 'push is forbidden; push',
    'do not push and then push', 'do not push\npush']) {
    assert.deepEqual(permissionsCarriedByGoal(`/goal ${text}`), ['push'], text)
  }
  assert.deepEqual(permissionsCarriedByGoal('/goal do not push, but merge it'), ['merge'])
  assert.deepEqual(permissionsCarriedByGoal('/goal push, merge, cut over, publish, tag a release, spend'),
    ['push', 'merge', 'cutover', 'publish', 'release-cut', 'spend'])
  assert.deepEqual(permissionsCarriedByGoal('push then merge'), [])
  for (const subcommand of ['clear', 'resume', 'status', 'pause', 'stop', 'list']) {
    assert.equal(isGoalSubcommand(`/goal ${subcommand}`), true)
    assert.equal(completionConditionOfGoal(`/goal ${subcommand}`), null)
  }
  assert.equal(isGoalSubcommand('/goal clear the task'), false)
  assert.equal(completionConditionOfGoal('/goal test\nDONE WHEN: suite passes'), 'suite passes')
  assert.equal(completionConditionOfGoal('/goal test DONE WHEN:   '), null)
  assert.equal(completionConditionOfGoal('/goal test DONE WHEN:\nnot the condition'), null)
  assert.equal(completionConditionOfGoal('DONE WHEN: suite passes'), null)
})

test('request validates lane, session, text and UTF-8 payload size before sending', async t => {
  const options = fixture(t)
  let calls = 0
  options.fetchImpl = async () => { calls += 1; return json() }
  for (const [override, expected] of [
    [{ lane: '../fixture' }, 'lane.bad-origin'], [{ session: 'other' }, 'lane.bad-session'],
    [{ text: '   ' }, 'lane.text-required'], [{ text: '界'.repeat(23_000) }, 'lane.body-too-large'],
  ]) await assert.rejects(sendLane({ ...options, ...override }), code(expected))
  assert.equal(calls, 0)
})

test('token reader refuses insecure or absent synthetic credentials before fetch', async t => {
  const options = fixture(t)
  let calls = 0
  options.fetchImpl = async () => { calls += 1; return json() }
  const path = join(options.stateRoot, 'lane-door/door.token')
  chmodSync(path, 0o644)
  await assert.rejects(sendLane(options), code('lane.token-file-mode'))
  chmodSync(path, 0o600)
  writeFileSync(path, '')
  await assert.rejects(sendLane(options), code('lane.token-file-empty'))
  rmSync(path)
  symlinkSync(join(options.stateRoot, 'lane-door/port'), path)
  await assert.rejects(sendLane(options), code('lane.token-file-symlink'))
  rmSync(path)
  await assert.rejects(sendLane(options), code('lane.token-file-absent'))
  assert.equal(calls, 0)
})

test('port must be a complete decimal port in range', async t => {
  const options = fixture(t)
  for (const value of ['12345junk', '1e3', '1.5', '0', '65536', '-1', '']) {
    writeFileSync(join(options.stateRoot, 'lane-door/port'), value)
    await assert.rejects(sendLane(options), code('lane.port-invalid'))
  }
  rmSync(join(options.stateRoot, 'lane-door/port'))
  await assert.rejects(sendLane(options), code('lane.port-absent'))
})

test('one bounded loopback POST carries exact bytes and projects only known response fields', async t => {
  const options = fixture(t)
  let calls = 0
  let request
  options.fetchImpl = async (url, init) => {
    calls += 1
    request = { url, init, abortedAtDispatch: init.signal.aborted }
    return json()
  }
  assert.deepEqual(await sendLane(options), { ok: true, kind: 'prompt', session: SESSION })
  assert.equal(request.url, 'http://127.0.0.1:12345/lane/send')
  assert.equal(request.init.method, 'POST')
  assert.equal(request.init.redirect, 'manual')
  assert.equal(request.init.headers.authorization === `Bearer ${TOKEN}`, true)
  assert.equal(request.init.headers['content-type'], 'application/json')
  assert.deepEqual(JSON.parse(request.init.body), { session: SESSION, text: TEXT, origin: 'fixture' })
  assert.equal(request.abortedAtDispatch, false)
  assert.equal(calls, 1)
})

test('redirect responses are refused before their bodies are used', async t => {
  const options = fixture(t)
  options.fetchImpl = async () => json(accepted(), 307)
  await assert.rejects(sendLane(options), code('lane.redirect-refused'))
})

test('deadline covers delayed headers without retry', async t => {
  const options = fixture(t)
  let calls = 0
  options.fetchImpl = async (_url, { signal }) => new Promise((resolve, reject) => {
    calls += 1
    const timer = setTimeout(() => resolve(json()), 60)
    signal.addEventListener('abort', () => { clearTimeout(timer); reject(new Error('synthetic abort')) }, { once: true })
  })
  await assert.rejects(sendLane({ ...options, timeoutMs: 10 }), code('lane.send-timeout'))
  assert.equal(calls, 1)
})

test('deadline stays armed while response body stalls', async t => {
  const options = fixture(t)
  options.fetchImpl = async (_url, { signal }) => new Response(new ReadableStream({
    start(controller) {
      const timer = setTimeout(() => {
        controller.enqueue(Buffer.from(JSON.stringify(accepted())))
        controller.close()
      }, 60)
      signal.addEventListener('abort', () => { clearTimeout(timer); controller.error(new Error('synthetic abort')) }, { once: true })
    },
  }))
  await assert.rejects(sendLane({ ...options, timeoutMs: 10 }), code('lane.send-timeout'))
})

test('response ceiling counts streamed UTF-8 bytes and cancels oversized body', async t => {
  const options = fixture(t)
  let canceled = false
  const payload = Buffer.from(JSON.stringify({ ...accepted(), padding: '界'.repeat(23_000) }))
  options.fetchImpl = async () => {
    let offset = 0
    return new Response(new ReadableStream({
      pull(controller) {
        if (offset >= payload.length) { controller.close(); return }
        controller.enqueue(payload.subarray(offset, offset + 32_000))
        offset += 32_000
      },
      cancel() { canceled = true },
    }, { highWaterMark: 0 }), { headers: { 'content-length': '1' } })
  }
  await assert.rejects(sendLane(options), code('lane.response-too-large'))
  assert.equal(canceled, true)
})

test('unconfirmed responses and errors expose no arbitrary server text or credentials', async t => {
  const options = fixture(t)
  for (const response of [
    new Response('not json'), json({ ok: true, kind: TEXT, session: SESSION }),
    json(accepted('prompt', OTHER)), json(accepted(), 503),
    json({ ok: false, code: TOKEN, detail: TEXT }, 403),
  ]) {
    const lines = []
    const exit = await main(['--lane', 'fixture', '--session', SESSION, TEXT], {
      ...options, fetchImpl: async () => response, stdout: line => lines.push(line), stderr: line => lines.push(line),
    })
    assert.equal(exit, 1)
    assert.equal(lines.some(line => line.includes(TOKEN) || line.includes(TEXT)), false)
    assert.match(lines.join('\n'), /no automatic retry/u)
  }
  await assert.rejects(sendLane({ ...options, fetchImpl: async () => json({ ok: false, code: 'lane.approval-open', detail: TEXT }, 409) }), code('lane.approval-open'))
  await assert.rejects(sendLane({ ...options, fetchImpl: async () => json({ ...accepted(), ok: false, code: 'lane.approval-open' }) }), code('lane.approval-open'))
  const lines = []
  assert.equal(await main(['--lane', 'fixture', '--session', SESSION, TEXT], {
    ...options, fetchImpl: async () => { throw new Error(`${TOKEN} ${TEXT}`) }, stderr: line => lines.push(line),
  }), 1)
  assert.equal(lines.some(line => line.includes(TOKEN) || line.includes(TEXT)), false)
  const brokenRoot = join(options.stateRoot, TOKEN)
  const parent = join(brokenRoot, 'home/storages/session_projcache')
  mkdirSync(parent, { recursive: true })
  writeFileSync(join(parent, 'sessions'), '')
  assert.equal(await main(['--list'], { stateRoot: brokenRoot, stderr: line => lines.push(line) }), 1)
  assert.equal(lines.some(line => line.includes(TOKEN) || line.includes(TEXT)), false)
})

test('CLI validates selectors and treats goal prose as warnings only', async t => {
  const options = fixture(t)
  const lines = []
  const io = { ...options, stdout: line => lines.push(line), stderr: line => lines.push(line) }
  for (const [args, expected] of [
    [[], 'lane.lane-required'], [['--lane'], 'lane.arguments'], [['--wat'], 'lane.arguments'],
    [['--lane', 'fixture'], 'lane.session-required'],
    [['--lane', 'fixture', '--lane', 'another', '--session', SESSION, TEXT], 'lane.arguments'],
    [['--lane', 'fixture', '--session', SESSION, '--title', 'task', TEXT], 'lane.arguments'],
    [['--list', TEXT], 'lane.arguments'],
  ]) {
    assert.equal(await main(args, io), 1)
    assert.ok(lines.at(-1).startsWith(`${expected}:`))
  }
  assert.equal(await main(['--list'], io), 0)
  assert.ok(lines.includes('no sessions in the projection cache'))
  lines.length = 0
  assert.equal(await main(['--lane', 'fixture', '--session', SESSION, '/goal Do not push. Then push'], {
    ...io, fetchImpl: async () => json(accepted('command:goal')),
  }), 0)
  assert.equal(lines.filter(line => line.startsWith('advisory ')).length, 2)
  assert.ok(lines.some(line => line.includes('goal-carries-permission: push')))
  assert.ok(lines.some(line => line.includes('lane accepted: command:goal')))
  assert.equal(lines.some(line => line.includes(TOKEN) || line.includes(TEXT)), false)
  const directory = join(options.stateRoot, 'home/storages/session_projcache/sessions')
  mkdirSync(directory, { recursive: true })
  writeFileSync(join(directory, `${SESSION}.json`), JSON.stringify({ record: { rows: { title: { val: 'chosen task' } } } }))
  let sent
  assert.equal(await main(['--lane', 'fixture', '--title', 'chosen task', '--', TEXT], {
    ...io, fetchImpl: async (_url, init) => { sent = JSON.parse(init.body); return json() },
  }), 0)
  assert.deepEqual(sent, { session: SESSION, text: TEXT, origin: 'fixture' })
})

test('entry point lists an empty synthetic cache without a running door', t => {
  const options = fixture(t)
  const result = spawnSync(process.execPath, [selected < 0 ? SUBJECT : process.argv[selected + 1], '--list'], {
    env: { ...process.env, AUKORA_STATE_ROOT: options.stateRoot }, encoding: 'utf8', timeout: 2_000,
  })
  assert.equal(result.status, 0)
  assert.equal(result.stdout, 'no sessions in the projection cache\n')
  assert.equal(result.stderr, '')
})

test('native fetch sends once to a synthetic loopback door', async t => {
  const options = fixture(t)
  let calls = 0
  const server = createServer(async (req, res) => {
    calls += 1
    const chunks = []
    for await (const chunk of req) chunks.push(chunk)
    assert.equal(req.url, '/lane/send')
    assert.equal(req.headers.authorization === `Bearer ${TOKEN}`, true)
    assert.deepEqual(JSON.parse(Buffer.concat(chunks)), { session: SESSION, text: TEXT, origin: 'fixture' })
    res.end(JSON.stringify(accepted()))
  })
  try {
    await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve) })
  } catch (error) {
    if (!['EPERM', 'EACCES'].includes(error.code)) throw error
    t.skip(`UNPERFORMED: loopback listen refused (${error.code})`)
    return
  }
  t.after(() => { server.closeAllConnections(); return new Promise(resolve => server.close(resolve)) })
  writeFileSync(join(options.stateRoot, 'lane-door/port'), String(server.address().port))
  assert.deepEqual(await sendLane({ ...options, fetchImpl: fetch }), { ok: true, kind: 'prompt', session: SESSION })
  assert.equal(calls, 1)
})

if (process.argv.includes('--mutate')) test('each removed protection fails its regression', t => {
  const directory = mkdtempSync(join(HERE, '.lane-send-mutations-'))
  t.after(() => rmSync(directory, { recursive: true, force: true }))
  for (const path of ['scripts/lane-send.mjs', 'plugins/aukora-eye/lib/token-file.mjs', 'apps/aukora-desktop/lane-dispatch.mjs']) {
    const target = join(directory, path)
    mkdirSync(dirname(target), { recursive: true })
    copyFileSync(join(ROOT, path), target)
  }
  const source = readFileSync(SUBJECT, 'utf8')
  const mutant = join(directory, 'scripts/lane-send.mjs')
  const mutations = [
    ['repeated verb', '[...text.matchAll(pattern)].some', '[...text.matchAll(pattern)].slice(0, 1).some', 'goal examples'],
    ['same-line condition', '[^\\S\\r\\n]*', '\\s*', 'goal examples'],
    ['title ambiguity', 'if (matches.length > 1)', 'if (false)', 'projection lookup'],
    ['missing title', "if (matches.length === 0) refuse('lane.no-such-session')", '', 'projection lookup'],
    ['candidate session', " || !SESSION.test(name.slice(0, -5))", '', 'projection lookup'],
    ['lane shape', "if (typeof lane !== 'string' || !LANE.test(lane))", 'if (false)', 'request validates'],
    ['session shape', "if (typeof session !== 'string' || !SESSION.test(session))", 'if (false)', 'request validates'],
    ['nonempty text', "if (typeof text !== 'string' || text.trim() === '')", 'if (false)', 'request validates'],
    ['request bytes', 'Buffer.byteLength(payload) > LIMIT_BYTES', 'false', 'request validates'],
    ['token custody', "readTokenFile({ path: join(directory, 'door.token'), prefix: 'lane' })", "'synthetic-bypass'", 'token reader'],
    ['decimal port', '!/^[0-9]{1,5}$/u.test(value)', 'false', 'port must'],
    ['port range', 'Number(value) < 1 || Number(value) > 65535', 'false', 'port must'],
    ['loopback address', 'http://127.0.0.1:${port}/lane/send', 'http://localhost:${port}/lane/send', 'one bounded loopback'],
    ['bearer header', 'authorization: `Bearer ${token}`', "authorization: 'absent'", 'one bounded loopback'],
    ['redirect policy', "redirect: 'manual'", "redirect: 'follow'", 'one bounded loopback'],
    ['redirect refusal', 'response.status >= 300 && response.status < 400', 'false', 'redirect responses'],
    ['header deadline', 'setTimeout(() => controller.abort(), timeoutMs)', 'setTimeout(() => {}, timeoutMs)', 'deadline covers'],
    ['body deadline', 'reader = response.body?.getReader()', 'clearTimeout(timer); reader = response.body?.getReader()', 'deadline stays'],
    ['response bytes', 'bytes > LIMIT_BYTES', 'false', 'response ceiling'],
    ['cancel oversized body', 'void reader?.cancel().catch(() => {})', '', 'response ceiling'],
    ['response session', 'body.session !== session', 'false', 'unconfirmed responses'],
    ['response kind', "!['prompt', 'command:goal', 'command:compact'].includes(body.kind)", 'false', 'unconfirmed responses'],
    ['HTTP success', '!response.ok || body?.ok !== true', 'body?.ok !== true', 'unconfirmed responses'],
    ['body success', '!response.ok || body?.ok !== true', '!response.ok', 'unconfirmed responses'],
    ['output projection', 'return { ok: true, kind: body.kind, session }', 'return body', 'one bounded loopback'],
    ['error redaction', 'stderr(`${code}: send not confirmed;', 'stderr(`${error.message}: send not confirmed;', 'unconfirmed responses'],
    ['selector conflict', 'options.session !== undefined && options.title !== undefined', 'false', 'CLI validates'],
    ['duplicate flags', 'options[key] !== undefined || ', '', 'CLI validates'],
    ['missing flag value', "!value || value.startsWith('--')", 'false', 'CLI validates'],
    ['unknown flag', "else if (arg.startsWith('--')) refuse('lane.arguments')", '', 'CLI validates'],
    ['list conflict', 'options.list && (options.lane || options.session || options.title || options.text.length)', 'false', 'CLI validates'],
  ]
  for (const [label, from, to, name] of mutations) {
    assert.equal(source.split(from).length, 2, `unique mutation anchor: ${label}`)
    writeFileSync(mutant, source.replace(from, to))
    const probe = spawnSync(process.execPath, ['--input-type=module', '-e', `await import(${JSON.stringify(pathToFileURL(mutant).href)})`], { encoding: 'utf8', timeout: 2_000 })
    assert.equal(probe.status, 0, `loadable mutant: ${label}`)
    const result = spawnSync(process.execPath, ['--test-reporter=tap', `--test-name-pattern=${name}`, fileURLToPath(import.meta.url), '--subject', mutant], { encoding: 'utf8', timeout: 4_000 })
    assert.equal(result.status, 1, `mutation must fail assertions: ${label}`)
    assert.match(result.stdout, /code: 'ERR_ASSERTION'/u, `assertion failure: ${label}`)
    assert.ok(result.stdout.includes(`not ok 1 - ${name}`), `intended regression: ${label}`)
    console.log(`# MUTATION caught: ${label}`)
  }
  console.log(`# MUTATION ${mutations.length}/${mutations.length} caught`)
})
