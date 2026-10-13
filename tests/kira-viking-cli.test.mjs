#!/usr/bin/env node
/** The Viking CLI selects one authenticated loopback door and accepts only its documented success statuses. */
import assert from 'node:assert/strict'
import { chmodSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { registerHooks } from 'node:module'
import { join } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { spawnSync } from 'node:child_process'

const root = mkdtempSync(fileURLToPath(new URL('../.kira-viking-cli-', import.meta.url)))
const production = fileURLToPath(new URL('../scripts/kira/viking-cli.mjs', import.meta.url))
const olderIds = ['rem:' + 'a'.repeat(64), 'rem:' + 'b'.repeat(64)]
const newerId = 'rem:' + 'c'.repeat(64), linkAt = '2026-10-14T00:00:00.000Z'
const credential = join(root, 'door.key'), token = 'synthetic-door-token'
writeFileSync(credential, token + '\n', { mode: 0o600 }); chmodSync(credential, 0o600)
const preload = join(root, 'fetch.mjs')
writeFileSync(preload, `
globalThis.fetch = async (url, options) => {
  const parsed = new URL(url)
  if (parsed.protocol !== 'http:' || parsed.hostname !== '127.0.0.1') throw new Error('non-loopback request')
  if (parsed.port !== process.env.EXPECTED_PORT) throw new Error('wrong door port')
  if (options.headers.authorization !== 'Bearer synthetic-door-token') throw new Error('wrong credential')
  if (process.env.EXPECTED_BODY && options.body !== process.env.EXPECTED_BODY) throw new Error('wrong request body')
  return Response.json(process.env.FIXTURE_RESULT ? JSON.parse(process.env.FIXTURE_RESULT)
    : { remembered: 1, ids: ['rem:synthetic'], index: { pending: 0 } }, { status: Number(process.env.FIXTURE_STATUS) })
}
`)

const run = (entry, { port, status, command = ['remember', 'Waiting on Peter: choose the signer.'], expectedBody, result }) => {
  const env = { ...process.env, ROOM_ME: 'CLAUDE', AUKORA_VIKING_DOOR_KEY_FILE: credential,
    EXPECTED_PORT: port ?? '8766', FIXTURE_STATUS: String(status),
    EXPECTED_BODY: expectedBody ? JSON.stringify(expectedBody) : '', FIXTURE_RESULT: result ? JSON.stringify(result) : '' }
  if (port === undefined) delete env.AUKORA_VIKING_DOOR_PORT
  else env.AUKORA_VIKING_DOOR_PORT = port
  return spawnSync(process.execPath, ['--import', preload, entry, ...command], { encoding: 'utf8', env })
}

const suite = entry => {
  for (const fixture of [{ port: undefined, status: 200 }, { port: '18766', status: 201 }]) {
    const result = run(entry, fixture)
    assert.equal(result.status, 0, result.stderr)
    assert.match(result.stdout, new RegExp(`door ${fixture.port ?? '8766'}\\.`))
    assert.ok(!(result.stdout + result.stderr).includes(token))
  }
  const extraSuccess = run(entry, { port: '18766', status: 202 })
  assert.notEqual(extraSuccess.status, 0)
  assert.match(extraSuccess.stderr, /HTTP 202/u)
  for (const port of ['0', '65536', '8766@198.51.100.1']) {
    const refused = run(entry, { port, status: 201 })
    assert.notEqual(refused.status, 0)
    assert.match(refused.stderr, /viking\.cli:invalid-door-port/u)
    assert.ok(!(refused.stdout + refused.stderr).includes(token))
  }
  const text = 'The restriction has landed.'
  const linked = run(entry, { status: 201, command: ['remember', text, '--supersedes', ...olderIds],
    expectedBody: { from: 'CLAUDE', text, supersedes: olderIds } })
  assert.equal(linked.status, 0, linked.stderr)
  for (const rest of [['--supersedes'], ['--supersedes', 'missing'], ['--supersedes', olderIds[0], '--supersedes'], ['--updates', olderIds[0]]]) {
    const refused = run(entry, { status: 201, command: ['remember', text, ...rest] })
    assert.notEqual(refused.status, 0)
    assert.match(refused.stderr, /viking\.cli:invalid-supersedes/u)
  }
  const recalled = run(entry, { status: 200, command: ['recall', 'restriction'], expectedBody: { q: 'restriction' },
    result: { state: 'found', method: 'lexical-bm25-bigram', semantic: { available: false }, notes: [
      { id: olderIds[0], text: 'The restriction was parked.', score: 1, uri: 'viking://synthetic', supersededBy: [{ id: newerId, at: linkAt }] },
      { id: olderIds[1], text: 'A migrated older note.', score: 0.5, uri: 'viking://legacy', supersededBy: [newerId] },
      { id: 'scalar', text: 'A scalar legacy link.', score: 0.4, uri: 'viking://legacy', supersededBy: newerId },
      { id: 'mixed', text: 'A mixed legacy link.', score: 0.3, uri: 'viking://legacy', supersededBy: [null, 42, {}, { id: 7 }, '', newerId] },
    ] } })
  assert.equal(recalled.status, 0, recalled.stderr)
  assert.ok(recalled.stdout.includes(`id: ${olderIds[0]}\n`))
  assert.ok(recalled.stdout.includes(`superseded by ${newerId} (${linkAt})\n`))
  assert.ok(recalled.stdout.includes(`superseded by ${newerId} (date unknown)\n`))
  assert.equal(recalled.stdout.match(new RegExp(`superseded by ${newerId} \\(date unknown\\)`, 'gu')).length, 3)
  assert.equal(recalled.stdout.match(/superseded by /gu).length, 4, 'invalid legacy entries must not create markers')
}

const interfaceMutants = {
  'door-supersedes': ['viking-door.mjs', '...(body.supersedes === undefined ? {} : { supersedes: body.supersedes })', '...{}'],
  'tool-supersedes': ['index.js', '...(args.supersedes === undefined ? {} : { supersedes: args.supersedes })', '...{}'],
  'tool-schema': ['index.js', "supersedes: { type: 'array', items: { type: 'string' }, description: 'IDs of earlier notes this note replaces; same subject only.' }", ''],
  'tool-final-supersession': ['index.js', 'governTrackedMemory(policyRecords, live, { ...policy, ...recallContext(agent)', 'governRecords(policyRecords, { ...policy, ...recallContext(agent)'],
  'service-final-supersession': ['index.js', 'governTrackedMemory(policyRecords, live, { ...currentPolicy,', 'governRecords(policyRecords, { ...currentPolicy,'],
  'selected-supersession': ['index.js', '            const note = governTrackedMemory(live.notes, live, { ...currentPolicy,', '            const note = governRecords(live.notes, { ...currentPolicy,'],
  'cite-supersession': ['index.js', '                const note = governTrackedMemory(live.notes, live, { ...currentPolicy,', '                const note = governRecords(live.notes, { ...currentPolicy,'],
  'final-marker-refresh': ['index.js', '...(note.supersededBy ? { supersededBy: note.supersededBy } : { supersededBy: [] }), ...recallAnnotations(note)', '...recallAnnotations(note)'],
  'injection-supersession': ['index.js', '...(note.supersededBy ? { supersededBy: note.supersededBy } : {}) }))', '...{} }))'],
  'injection-marker': ['injection.mjs', '...supersessionMarks(snippet.supersededBy).map(newer =>', '...[].map(newer =>'],
  'injection-legacy-scalar': ['injection.mjs', "typeof value === 'string' ? [value] : Array.isArray(value) ? value : []", 'Array.isArray(value) ? value : []'],
  'injection-legacy-invalid': ['injection.mjs', "if (typeof id !== 'string' || !id) return []", 'if (false) return []'],
}

const interfaceSuite = async (mutation, entry = production) => {
  let applied = false
  const hook = registerHooks({ load(url, context, next) {
    const loaded = next(url, context)
    const target = interfaceMutants[mutation]
    let source = String(loaded.source)
    if (url === new URL('../plugins/aukora-kira/lib/index.js', import.meta.url).href) {
      const before = 'describe: async () => ({ subject: memoryOwner.subject, policyRevision: memoryOwner.policyRevision,\n      permittedPrivacy: memoryOwner.permittedPrivacy }),'
      assert.equal(source.split(before).length, 2, 'fixture owner-policy await target')
      source = source.replace(before, 'describe: async () => { await globalThis.__kiraSupersessionOnPolicy?.(); return { subject: memoryOwner.subject, policyRevision: memoryOwner.policyRevision, permittedPrivacy: memoryOwner.permittedPrivacy } },')
    }
    if (url === new URL('../plugins/aukora-kira/lib/injection.mjs', import.meta.url).href) {
      const before = '  const id = newId ?? (() => globalThis.crypto.randomUUID())'
      assert.equal(source.split(before).length, 2, 'fixture injection provider target')
      source = source.replace(before, '  globalThis.__kiraSupersessionInjection = { remembered, beforePublish }\n' + before)
    }
    if (target && url === new URL(`../plugins/aukora-kira/lib/${target[0]}`, import.meta.url).href) {
      assert.equal(source.split(target[1]).length, 2, `${mutation} mutation target`)
      applied = true
      source = source.replace(target[1], target[2])
    }
    return source === String(loaded.source) ? loaded : { ...loaded, source }
  } })
  const disposers = [], oldHome = process.env.AUKORA_OPENVIKING_HOME, oldRoom = process.env.AUKORA_ROOM_LOG
  process.env.AUKORA_OPENVIKING_HOME = join(root, 'empty-openviking')
  process.env.AUKORA_ROOM_LOG = join(root, 'absent-room.log')
  try {
    const { createVikingDoor } = await import('../plugins/aukora-kira/lib/viking-door.mjs')
    let captured
    const door = createVikingDoor({ authToken: token, memory: { remember: async input => {
      captured = input
      if (input.supersedes === 'invalid') throw new Error('memory-supersedes-invalid')
      return { remembered: 1 }
    } } })
    await door.remember({ from: 'CLAUDE', text: 'The restriction has landed.', supersedes: olderIds })
    assert.equal(captured.supersedes, olderIds, 'door must pass supersedes unchanged')
    await assert.rejects(door.remember({ from: 'CLAUDE', text: 'Valid text.', supersedes: 'invalid' }), /memory-supersedes-invalid/u)
    const { apply } = await import('../plugins/aukora-kira/lib/index.js')
    const { createTrackedMemory, memoryChain } = await import('../plugins/aukora-kira/lib/tracked-memory.mjs')
    const tools = new Map(), services = new Map(), stateDir = join(root, 'tool-memory'), subject = 'aukora:1:' + '37'.repeat(32)
    await apply({ tools: { register: tool => tools.set(tool.name, tool) }, sessions: { get: () => undefined },
      provide: (name, value) => services.set(name, value),
      effect: fn => { const dispose = fn(); if (typeof dispose === 'function') disposers.push(dispose) },
      on: () => () => {}, inject: () => {}, reflect: { get: () => undefined }, logger: { info() {}, warn() {}, debug() {} },
    }, { memoryOwner: { stateDir, subject } })
    const remember = tools.get('kira_remember')
    assert.deepEqual(remember.parameters.properties.supersedes?.items, { type: 'string' }, 'remember schema must expose supersedes IDs')
    assert.equal(remember.parameters.properties.supersedes.type, 'array')
    const before = await remember.execute({ text: 'The amber restriction is parked.' }, {})
    const after = await remember.execute({ text: 'The amber restriction has landed.', supersedes: before.ids }, {})
    assert.ok(memoryChain(stateDir).some(entry => entry.op === 'supersede' && entry.id === after.ids[0]
      && JSON.stringify(entry.supersedes) === JSON.stringify(before.ids)), 'remember tool must persist supplied supersession IDs')
    const memory = createTrackedMemory({ stateDir, subject })
    const recalled = await memory.recall({ question: 'amber restriction', lexical: true })
    assert.ok(recalled.notes.some(note => note.id === after.ids[0]))
    assert.ok(!recalled.notes.some(note => note.id === before.ids[0]))
    await assert.rejects(remember.execute({ text: 'A rejected replacement.', supersedes: ['rem:' + 'f'.repeat(64)] }, {}))
    const parked = await remember.execute({ text: 'The violet restriction is parked.' }, {})
    const landed = await remember.execute({ text: 'The violet restriction has landed.', supersedes: parked.ids },
      { agent: { session: { id: 'unmapped-project', header: { cwd: join(root, 'unmapped') } } } })
    const ineligible = await memory.recall({ question: 'violet restriction', lexical: true })
    const marked = ineligible.notes.find(note => note.id === parked.ids[0])
    assert.ok(marked, 'older note remains visible when the replacement scope is ineligible')
    assert.ok(!ineligible.notes.some(note => note.id === landed.ids[0]))
    const shown = run(entry, { status: 200, command: ['recall', 'violet restriction'], result: ineligible })
    assert.equal(shown.status, 0, shown.stderr)
    assert.ok(shown.stdout.includes(`id: ${parked.ids[0]}\n`))
    assert.ok(shown.stdout.includes(`superseded by ${landed.ids[0]} (${marked.supersededBy[0].at})\n`),
      'CLI must mark the returned older note when the replacement is ineligible')
    const query = tools.get('kira_recall'), service = services.get('kira.recall')
    const native = await query.execute({ text: 'violet restriction', lexical: true }, {})
    assert.equal(native.remembered.notes.find(note => note.id === parked.ids[0]).supersededBy[0].id, landed.ids[0])
    for (const surface of ['tool', 'service', 'mark']) {
      const old = await memory.remember({ text: `The ${surface} quartz restriction is parked.` })
      let calls = 0, replacement
      globalThis.__kiraSupersessionOnPolicy = async () => {
        if (++calls !== 3) return
        replacement = await memory.remember({ text: `The ${surface} quartz restriction has landed.`, supersedes: old.ids,
          scope: surface === 'mark' ? 'project:unresolved' : 'owner' })
      }
      let final
      try { final = surface === 'service' ? await service.recall(`${surface} quartz restriction`)
        : (await query.execute({ text: `${surface} quartz restriction`, lexical: true }, {})).remembered }
      finally { delete globalThis.__kiraSupersessionOnPolicy }
      assert.ok(replacement, `${surface} fixture must link during final owner-policy await`)
      if (surface === 'mark') assert.equal(final.notes.find(note => note.id === old.ids[0])?.supersededBy?.[0]?.id, replacement.ids[0],
        'final tool publication must refresh a newly linked marker')
      else assert.ok(!final.notes.some(note => note.id === old.ids[0]), `${surface} final reader must hide a newly superseded note`)
    }
    const associated = await memory.remember({ text: 'The copper boundary fixture is parked.' },
      { auraSource: { source: { journal_id: 'aukora-gate-pilot', position: 7, hash: 'a'.repeat(64) } } })
    assert.ok(await service.referenceForRecord(associated.ids[0]))
    await memory.remember({ text: 'The copper boundary fixture has landed.', supersedes: associated.ids })
    assert.equal(await service.referenceForRecord(associated.ids[0]), null, 'selected association must withhold a superseded note')
    assert.equal((await service.citeRemembered(associated.ids[0])).reason, 'record-unavailable', 'citation must withhold a superseded note before reading its source')
    const owner = await memory.remember({ text: 'The silver restriction is parked.', scope: 'owner' }, { attributedTo: 'owner' })
    const newer = await memory.remember({ text: 'The silver restriction has landed.', scope: 'project:unresolved', supersedes: owner.ids })
    const injected = await globalThis.__kiraSupersessionInjection.remembered('silver restriction', {})
    assert.equal(injected.snippets.find(note => note.recordId === owner.ids[0])?.supersededBy?.[0]?.id, newer.ids[0],
      'automatic query projection must preserve the supersession link')
    const { renderQueryPart } = await import('../plugins/aukora-kira/lib/injection.mjs')
    const finalInjected = (await globalThis.__kiraSupersessionInjection.beforePublish(injected, undefined, {}))[0]
    assert.ok(renderQueryPart(finalInjected).includes(`superseded by ${newer.ids[0]} (`), 'automatic remembered rendering must show the dated supersession marker')
    for (const supersededBy of [newerId, [null, 42, {}, { id: 7 }, '', newerId]]) {
      const legacyRendered = renderQueryPart({ ...finalInjected, snippets: [{ ...finalInjected.snippets[0], supersededBy }] })
      assert.ok(legacyRendered.includes(`superseded by ${newerId} (date unknown)`), 'legacy scalar and mixed links must retain the real ID')
      assert.equal(legacyRendered.match(/superseded by /gu)?.length, 1, 'invalid legacy injection entries must not create markers')
    }
    if (mutation) assert.equal(applied, true, `${mutation} production mutation must apply`)
  } finally {
    for (const dispose of disposers.reverse()) dispose()
    if (oldHome === undefined) delete process.env.AUKORA_OPENVIKING_HOME; else process.env.AUKORA_OPENVIKING_HOME = oldHome
    if (oldRoom === undefined) delete process.env.AUKORA_ROOM_LOG; else process.env.AUKORA_ROOM_LOG = oldRoom
    hook.deregister()
    delete globalThis.__kiraSupersessionOnPolicy
    delete globalThis.__kiraSupersessionInjection
  }
}

try {
  const candidateAt = process.argv.indexOf('--candidate')
  const interfaceAt = process.argv.indexOf('--interface-mutant')
  if (interfaceAt >= 0) await interfaceSuite(process.argv[interfaceAt + 1])
  else if (candidateAt >= 0) {
    suite(process.argv[candidateAt + 1])
    await interfaceSuite(undefined, process.argv[candidateAt + 1])
  }
  else {
    suite(production)
    await interfaceSuite()
    const auth = pathToFileURL(fileURLToPath(new URL('../scripts/kira/viking-auth.mjs', import.meta.url))).href
    const source = readFileSync(production, 'utf8').replace("'./viking-auth.mjs'", JSON.stringify(auth))
    const mutants = [
      ['door-port', 'const port = doorPort(process.env.AUKORA_VIKING_DOOR_PORT)', 'const port = 8766'],
      ['success-status', 'if (![200, 201].includes(response.status))', 'if (!response.ok)'],
      ['loopback-injection', "const doorPort = value => {\n  if (value === undefined) return 8766\n  if (!/^[1-9][0-9]{0,4}$/u.test(value) || Number(value) > 65535) throw new Error('viking.cli:invalid-door-port')\n  return Number(value)\n}", 'const doorPort = value => Number(value ?? 8766)'],
      ['supersedes-body', '...(supersedes.length === 0 ? {} : { supersedes })', '...{}'],
      ['supersedes-arguments', "if (args.length > 1 && (args[1] !== '--supersedes' || supersedes.length === 0\n      || supersedes.some(id => !/^rem:[0-9a-f]{64}$/u.test(id))))", 'if (false)'],
      ['recall-id', '`id: ${plain(hit.id)}\\n${plain(hit.text)}\\n`', '`${plain(hit.text)}\\n`'],
      ['superseded-mark', 'for (const newer of supersessionMarks(hit.supersededBy))', 'for (const newer of [])'],
      ['legacy-scalar', "typeof value === 'string' ? [value] : Array.isArray(value) ? value : []", 'Array.isArray(value) ? value : []'],
      ['legacy-invalid', "if (typeof id !== 'string' || !id) return [];", 'if (false) return [];'],
    ]
    for (const [name, before, after] of mutants) {
      assert.equal(source.split(before).length, 2, `${name} mutation target`)
      const mutant = join(root, `${name}.mjs`)
      writeFileSync(mutant, source.replace(before, after))
      const result = spawnSync(process.execPath, [fileURLToPath(import.meta.url), '--candidate', mutant], { encoding: 'utf8' })
      assert.notEqual(result.status, 0, `${name} mutation survived`)
      console.log(`kira-viking-cli mutation ${name}: CAUGHT`)
    }
    for (const name of Object.keys(interfaceMutants)) {
      const result = spawnSync(process.execPath, [fileURLToPath(import.meta.url), '--interface-mutant', name], { encoding: 'utf8' })
      assert.notEqual(result.status, 0, `${name} mutation survived`)
      assert.match(result.stderr, /AssertionError/u, `${name} must fail an assertion`)
      console.log(`kira-viking-cli mutation ${name}: CAUGHT`)
    }
    console.log('kira-viking-cli: 17 groups passed, 0 failed (mocked fetch and local store; no listener)')
  }
} finally { rmSync(root, { recursive: true, force: true }) }
