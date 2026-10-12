#!/usr/bin/env node
// Mounted Kira saves before indexing and recalls across fresh processes.
import assert from 'node:assert/strict'
import { fork } from 'node:child_process'
import { registerHooks } from 'node:module'
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync, rmSync } from 'node:fs'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { createOpenVikingHttpFixture, loopbackListenUnavailable } from './support/openviking-http.mjs'

const mutations = {
  'vector-success': ['recall-openviking.mjs', "result?.vector_status !== 'complete'", 'false'],
  'auth-refusal': ['recall-openviking.mjs', '[401, 403].includes(httpStatus)', 'false'],
  'pending-fallback': ['recall-openviking.mjs', '!hits.length && (synced.failed?.length || synced.pending > 0 || dropped.unreadable.length)', 'false'],
  'legacy-retry': ['recall-openviking.mjs', "acknowledged(entry) && entry.vectorStatus === 'complete'", 'acknowledged(entry)'],
  'legacy-integrity': ['recall-openviking.mjs', '!matchesDocument(notes[0], uri, bytes)', 'false'],
  'pending-deletion': ['recall-openviking.mjs', "ackMany([[uri, { ...ackValue(uri, notes.map(note => note.id), hashOf(notes[0])), status: 'pending' }]])", 'void 0'],
  'migration-budget': ['recall-openviking.mjs', "if (budget < 2) failed.push('index-migration-budget-too-small')", 'void 0'],
  'home-used': ['index.js', 'normalized.openVikingHome ?? openVikingHome(normalized.memoryOwner.stateDir)', 'openVikingHome(normalized.memoryOwner.stateDir)'],
  'home-absolute': ['index.js', '!isAbsolute(record.openVikingHome)', 'false'],
  'home-owner': ['index.js', 'record.memoryOwner === undefined', 'false'],
  'home-controls': ['index.js', '/[\\u0000-\\u001f\\u007f]/u.test(record.openVikingHome)', 'false'],
}
const child = process.argv.includes('--child')
const mutantAt = process.argv.indexOf('--mutant'), mutant = mutantAt < 0 ? null : process.argv[mutantAt + 1]
if (mutant) assert.ok(mutations[mutant], 'known mutant')

if (child) {
  let applied = 0
  if (mutant) registerHooks({ load(url, context, next) {
    const loaded = next(url, context), [file, before, after] = mutations[mutant]
    if (!url.endsWith(`/plugins/aukora-kira/lib/${file}`)) return loaded
    const source = String(loaded.source)
    assert.equal(source.split(before).length, 2, 'mutation must match production once')
    applied++
    return { ...loaded, source: source.replace(before, after) }
  } })
  process.once('message', async input => {
    const disposers = []
    try {
      const kira = await import('../plugins/aukora-kira/lib/index.js')
      let result
      if (input.action === 'config') {
        for (const config of [
          { ...input.config, openVikingHome: 'relative' },
          { ...input.config, openVikingHome: '/bad\npath' },
          { retrieval: 'lexical', readOwner: { module: './reader.mjs' }, openVikingHome: '/absolute' },
        ]) assert.throws(() => kira.readConfig(config), { code: 'kira.config:openviking-home-invalid' })
        result = { checked: true }
      } else if (input.action === 'forget-index') {
        const { createOpenVikingRecall, readBridgeConfig } = await import('../plugins/aukora-kira/lib/recall-openviking.mjs')
        result = await createOpenVikingRecall({ stateDir: input.config.memoryOwner.stateDir,
          config: readBridgeConfig(input.config.openVikingHome) }).forget(input.text)
      } else {
        const tools = new Map(), services = new Map()
        const ctx = { tools: { register: tool => tools.set(tool.name, tool) }, sessions: new Map(),
          on: () => () => {}, inject() {}, emit() {}, logger: { warn() {}, info() {} },
          effect: create => disposers.push(create()), provide: (name, value) => services.set(name, value),
          reflect: { get: name => services.get(name) } }
        const { createGateCaptureHostPlugin } = await import('../plugins/aukora-kira/lib/gate-capture-host.mjs')
        await createGateCaptureHostPlugin({ platform: 'fixture', preflight: async () => false,
          loadKira: async () => kira, loadAura: async () => ({}), loadCapture: async () => ({}), gateCall: async () => ({}) }).apply(ctx, input.config)
        if (input.action === 'remember') result = await tools.get('kira_remember').execute({ text: input.text })
        else if (input.action === 'recall') result = await tools.get('kira_recall').execute({ text: input.text }, {})
        else throw Error('unknown fixture action')
      }
      if (mutant) assert.equal(applied, 1)
      process.send({ result }, () => process.disconnect())
    } catch (error) { process.send({ error: error.message }, () => process.disconnect()); process.exitCode = 1 }
    finally { disposers.forEach(dispose => dispose?.()) }
  })
} else {
  const assertListenRefusals = classify => {
    for (const code of ['EPERM', 'EACCES']) assert.equal(classify({ syscall: 'listen', code }), true)
    for (const error of [{ syscall: 'listen', code: 'EADDRINUSE' }, { syscall: 'listen', code: 'EINVAL' }, { syscall: 'open', code: 'EPERM' }, {}]) {
      assert.equal(classify(error), false)
    }
  }
  assertListenRefusals(loopbackListenUnavailable)
  const helperSource = readFileSync(new URL('./support/openviking-http.mjs', import.meta.url), 'utf8')
  for (const [before, after] of [
    ["error?.syscall === 'listen' && ", ''],
    ["['EPERM', 'EACCES'].includes(error?.code)", 'true'],
    ["error?.syscall === 'listen' && ['EPERM', 'EACCES'].includes(error?.code)", 'false'],
  ]) {
    assert.equal(helperSource.split(before).length, 2, 'listener mutation must match once')
    const changed = Buffer.from(helperSource.replace(before, after)).toString('base64')
    const mutated = await import(`data:text/javascript;base64,${changed}`)
    assert.throws(() => assertListenRefusals(mutated.loopbackListenUnavailable), undefined, 'listener classifier mutant survived')
  }
  console.log('PASS loopback listen refusal classifier; 3/3 source mutants killed')
  const root = mkdtempSync(join(fileURLToPath(new URL('.', import.meta.url)), '.kira-http-')), home = join(root, 'openviking'), stateDir = join(root, 'state/kira')
  const statement = 'Miso, a feline companion, curls beside me.', question = 'Which animal lives indoors?'
  assert.equal(statement.toLowerCase().split(/\W+/u).filter(Boolean).some(word => question.toLowerCase().split(/\W+/u).includes(word)), false)
  let fixture
  try {
    fixture = await createOpenVikingHttpFixture({ statement, question })
  } catch (error) {
    rmSync(root, { recursive: true, force: true })
    if (!loopbackListenUnavailable(error)) throw error
    console.log(`UNPERFORMED: kira-openviking-http loopback listen refused (${error.code}); no HTTP checks ran`)
    process.exit(2)
  }
  const { url, files, vectors, calls, controls } = fixture
  mkdirSync(home, { recursive: true })
  const bridge = { url, account: 'aukora', user: 'owner', timeoutMs: 1000, syncBatch: 8 }
  const writeBridge = () => writeFileSync(join(home, 'aukora-bridge.json'), JSON.stringify(bridge))
  writeBridge(); writeFileSync(join(home, 'root.key'), 'synthetic-key')
  writeFileSync(join(home, 'ov.conf'), JSON.stringify({ embedding: { dense: { provider: 'openai', api_base: 'http://127.0.0.1:1934/v1' } } }))
  const config = { retrieval: 'lexical', openVikingHome: home,
    memoryOwner: { stateDir, subject: `aukora:1:${'3c'.repeat(32)}`, permittedPrivacy: ['local'] } }
  const run = (action, text) => new Promise((resolve, reject) => {
    const env = { ...process.env, AUKORA_ROOM_LOG: join(root, 'absent-room'), AUKORA_OPENVIKING_HOME: join(root, 'wrong-default') }
    delete env.AUKORA_STATE; delete env.AUKORA_SUPPORT_ROOT; delete env.NODE_OPTIONS
    const processChild = fork(fileURLToPath(import.meta.url), ['--child', ...(mutant ? ['--mutant', mutant] : [])], { env, stdio: ['ignore', 'ignore', 'pipe', 'ipc'] })
    let result, error = '', completed = false
    processChild.stderr.on('data', chunk => { error += chunk })
    processChild.on('message', message => { result = message.result; error += message.error ?? ''; completed = true })
    processChild.on('error', reject)
    processChild.on('exit', code => code === 0 && completed ? resolve(result) : reject(Error(error || `worker exit ${code}`)))
    processChild.send({ action, text, config })
  })
  let passed = 0
  const check = async (name, action) => { await action(); passed++; console.log(`PASS ${name}`) }
  try {
    await check('explicit bridge home validates owner, absolute path and control characters', () => run('config'))
    await check('mounted remember indexes exact bytes with tenant and key; fresh process recalls by meaning', async () => {
      const saved = await run('remember', statement)
      assert.equal(saved.remembered, 1); assert.equal(saved.index.added, 1); assert.equal(saved.index.pending, 0)
      assert.equal(files.size, 1); assert.equal([...files.values()][0], statement)
      const recalled = await run('recall', question)
      assert.equal(recalled.retrieval.method, 'openviking-semantic'); assert.equal(recalled.snippets[0].text, statement)
    })
    await check('embedder outage returns lexical data and explicit degraded flag in a fresh process', async () => {
      controls.embeddingDown = true
      const recalled = await run('recall', 'feline companion')
      assert.equal(recalled.retrieval.degraded, true); assert.equal(recalled.retrieval.method, 'lexical-bm25-bigram')
      assert.equal(recalled.snippets[0].text, statement); controls.embeddingDown = false
    })
    await check('wrong key is a named refusal, without erasing local recall', async () => {
      writeFileSync(join(home, 'root.key'), 'wrong-key')
      const recalled = await run('recall', 'feline companion')
      assert.equal(recalled.remembered.semantic.reason, 'openviking-auth-refused'); assert.equal(recalled.retrieval.degraded, true)
      assert.equal(recalled.snippets[0].text, statement)
      writeFileSync(join(home, 'root.key'), 'synthetic-key')
    })
    await check('HTTP 200 failed, skipped and queued vectors stay pending; successful save retries in a fresh process', async () => {
      for (const status of ['failed', 'skipped', 'queued', undefined]) {
        controls.vectorStatus = status
        const saved = await run('remember', `The cobalt telescope is beside orchard number ${passed}-${status}.`)
        assert.equal(saved.remembered, 1); assert.ok(saved.index.pending > 0); assert.ok(saved.index.failed.includes('index-write-failed'))
        const recalled = await run('recall', 'cobalt telescope')
        assert.equal(recalled.retrieval.degraded, true); assert.equal(recalled.remembered.semantic.reason, 'openviking-index-pending')
        assert.ok(recalled.snippets.length > 0)
      }
      controls.vectorStatus = 'complete'
      const recovered = await run('recall', question)
      assert.equal(recovered.remembered.index.pending, 0); assert.equal(recovered.snippets[0].text, statement)
    })
    await check('slow indexing stays saved and pending after client timeout', async () => {
      controls.slow = true; bridge.timeoutMs = 40; writeBridge()
      const saved = await run('remember', 'The amber sundial stands beside a shaded pond.')
      assert.equal(saved.remembered, 1); assert.ok(saved.index.pending > 0); assert.ok(saved.index.failed.length)
      controls.slow = false; bridge.timeoutMs = 1000; writeBridge()
      assert.equal((await run('recall', question)).remembered.index.pending, 0)
    })
    await check('old false acknowledgements are repaired, but changed index bytes are never overwritten', async () => {
      const ackFile = join(stateDir, 'remembered/index/ack.json'), ack = JSON.parse(readFileSync(ackFile, 'utf8'))
      for (const entry of Object.values(ack)) delete entry.vectorStatus
      writeFileSync(ackFile, JSON.stringify(ack)); vectors.clear()
      bridge.syncBatch = 1; writeBridge()
      const bounded = await run('recall', question)
      assert.ok(bounded.remembered.index.failed.includes('index-migration-budget-too-small'))
      bridge.syncBatch = 8; writeBridge()
      let repaired
      for (let batch = 0; batch < Object.keys(ack).length; batch++) {
        repaired = await run('recall', question)
        if (repaired.remembered.index?.pending === 0) break
      }
      assert.equal(repaired.remembered.index.pending, 0)
      assert.equal(repaired.snippets[0].text, statement)
      const current = JSON.parse(readFileSync(ackFile, 'utf8')), uri = [...files.keys()][0]
      delete current[uri].vectorStatus; writeFileSync(ackFile, JSON.stringify(current)); files.set(uri, 'changed index bytes')
      const before = calls.filter(call => call.path === '/api/v1/content/write').length
      await run('recall', question)
      assert.equal(files.get(uri), 'changed index bytes')
      assert.equal(calls.filter(call => call.path === '/api/v1/content/write').length, before)
    })
    await check('incomplete writes retain a deletion target across process exit', async () => {
      controls.vectorStatus = 'failed'
      const saved = await run('remember', 'The silver compass is stored inside a brass container.')
      assert.equal(saved.remembered, 1); assert.ok(saved.index.pending > 0)
      const uri = [...files.keys()].find(uri => files.get(uri).includes('silver compass'))
      assert.ok(uri)
      assert.equal((await run('forget-index', saved.ids[0])).reached, true)
      assert.equal(files.has(uri), false)
    })
    console.log(`kira-openviking-http: ${passed} passed, 0 failed; transport=http; synthetic scores only`)
  } catch (error) { console.error(`FAIL ${error.message}`); process.exitCode = 1 }
  finally { await fixture.close(); rmSync(root, { recursive: true, force: true }) }
}
