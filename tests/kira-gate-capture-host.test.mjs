// SPDX-License-Identifier: AGPL-3.0-or-later
// Disposable source fixtures; no installed host, socket, owner or private custody.
import test from 'node:test'
import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import { resolve } from 'node:path'
import { pathToFileURL } from 'node:url'
import { createHash, generateKeyPairSync, sign } from 'node:crypto'
import { createGateCaptureHostPlugin, name, inject, PROPOSE_SOCKET, AURA_CONFIGURATION,
  AURA_MODULE, AURA_JSON_MODULE, AURA_READ_LIFECYCLE, CAPTURE_MODULE } from '../plugins/aukora-kira/lib/gate-capture-host.mjs'
import { verifyCompletedGateCapture, gateCompletedResultDigest, gateCaptureSigningBytes }
  from '../packages/boundary-gate/src/ledger.mjs'
import { proposeTheme } from '../plugins/aukora-auma-theme/lib/propose.mjs'

const sha = bytes => createHash('sha256').update(bytes).digest('hex')
const wrapperUrl = new URL('../plugins/aukora-kira/lib/gate-capture-host.mjs', import.meta.url)
const proposal = '01234567-89ab-4cde-8fab-0123456789ab'
const proposalToolResult = await proposeTheme(PROPOSE_SOCKET, { accent: '#123456', why: 'disposable fixture', session: 'fixture' },
  async (socket, op) => {
    assert.equal(socket, PROPOSE_SOCKET)
    if (op === 'read') return { content: '{"accent": "default"}', sha256: 'absent' }
    assert.equal(op, 'propose')
    return { id: proposal, expires: Date.now() + 60_000 }
  })
const pair = generateKeyPairSync('ed25519')
const publicKey = pair.publicKey.export({ type: 'spki', format: 'pem' }).toString()
const keyHash = sha(pair.publicKey.export({ type: 'spki', format: 'der' }))
const ownerSubject = `aukora:1:${'1'.repeat(64)}`
const contextSha256 = '8'.repeat(64), releaseSha = '9'.repeat(40)
const genesisInstanceId = '11234567-89ab-4cde-8fab-0123456789ab'
const configuration = Object.freeze({ owner_subject: ownerSubject, source: Object.freeze({ source_id: 'aukora-gate-pilot',
  public_key_pem: publicKey, key_sha256: keyHash }) })
const existingConfig = Object.freeze({ retrieval: 'lexical', memoryOwner: Object.freeze({
  stateDir: '/disposable/kira-memory', subject: ownerSubject, permittedPrivacy: ['local'] }) })

// Only the explicitly selected D closure supplies executable scope and JSON
// helpers. There is no Git fallback or copied implementation. These pins are
// the coordinator's reviewed final D source closure.
const selectedDSourceHashes = Object.freeze({
  context: '99acebb5f35c2305a070e9161e0f0915a3dc5b5c529ce1e93c879ce3805986c5',
  scope: '51cec57511f379622c07fb93d6d0a24715f030063af377db250b261037c014e3',
  json: '068aa14d3be101413cb028dc5f39e442130b4eeb87c40e18209ddce3ffce4639',
})
let selectedDHelpers
async function loadSelectedDHelpers() {
  selectedDHelpers ??= (async () => {
    const requested = process.env.AUKORA_TEST_AURA_SOURCE
      ?? new URL('../packages/boundary-gate/host/aura/context.mjs', import.meta.url)
    const contextURL = requested instanceof URL ? requested : pathToFileURL(resolve(requested))
    let contextSource, scopeSource, jsonSource
    try {
      [contextSource, scopeSource, jsonSource] = await Promise.all([
        readFile(contextURL, 'utf8'),
        readFile(new URL('./records-provider.mjs', contextURL), 'utf8'),
        readFile(new URL('../../../../packages/contracts/src/json.mjs', contextURL), 'utf8'),
      ])
    } catch { throw Error('missing-dependency:accepted-aura-context-or-helper-closure') }
    for (const [name, source] of Object.entries({ context: contextSource, scope: scopeSource, json: jsonSource })) {
      assert.equal(sha(source), selectedDSourceHashes[name], `missing-dependency:accepted-aura-${name}-sha256`)
    }
    const dataURL = source => `data:text/javascript;base64,${Buffer.from(source).toString('base64')}`
    const [scope, json] = await Promise.all([import(dataURL(scopeSource)), import(dataURL(jsonSource))])
    return { ...scope, ...json }
  })()
  return selectedDHelpers
}

function fixtureLifecycle() {
  return { version: 1, kind: 'aukora-aura-read-lifecycle/v1', context_sha256: contextSha256,
    release_sha: releaseSha, genesis_instance_id: genesisInstanceId }
}

async function createPublicAuraFixture(state, calls) {
  const D = await loadSelectedDHelpers()
  const failure = () => { throw Error('fixture:protected-read-unavailable') }
  const validate = (actualConfiguration, scope) => {
    assert.equal(actualConfiguration, state.configuration)
    assert.equal(D.isRetainedProposalReadScope(scope), true)
    scope.checkOwner(state.configuration.owner_subject)
    const completed = state.signedResult
    const verified = verifyCompletedGateCapture(completed, { journal_id: state.configuration.source.source_id,
      gate_public_key_pem: state.configuration.source.public_key_pem,
      gate_pubkey_sha256: state.configuration.source.key_sha256 })
    const bound = scope.bound
    assert.equal(bound.owner_subject, state.configuration.owner_subject)
    assert.equal(bound.context_sha256, state.contextSha256)
    assert.equal(bound.proposal_id, completed.receipt.proposal)
    assert.deepEqual(bound.source, { ...verified.source, key_sha256: state.configuration.source.key_sha256 })
    assert.equal(bound.receipt_sha256, sha(D.canonicalJson(completed.receipt)))
    scope.checkOwner(state.configuration.owner_subject)
    state.validations.push(scope)
    return state.validationResult
  }
  return {
    canonicalJson: D.canonicalJson, parseStrictJson: D.parseStrictJson,
    loadAuraPublicConfiguration() { calls.push('public-config'); return state.configuration },
    auraConfigurationSha256(actualConfiguration) {
      assert.equal(actualConfiguration, state.configuration); calls.push('context-hash'); return state.contextSha256
    },
    readProtectedAuraData(file) {
      assert.equal(file, AURA_READ_LIFECYCLE); calls.push('lifecycle')
      if (state.lifecycle === null) failure()
      return state.lifecycleText ?? JSON.stringify(state.lifecycle)
    },
    createProtectedAuraProposalReadScope(actualConfiguration, binding, options) {
      assert.equal(actualConfiguration, state.configuration)
      state.bindings.push(binding)
      if (state.grant === undefined) {
        // INTERIM synthetic root data is confined to this disposable fixture.
        const issued = state.now()
        state.grant = { ...structuredClone(binding), version: 1, kind: 'aukora-aura-proposal-read-grant/v1',
          issued_at_ms: issued, expires_at_ms: issued + 60_000, grants_authority: false, custody: 'INTERIM' }
      }
      if (state.changeGrant) state.changeGrant(state.grant, binding)
      const scope = D.createRetainedProposalReadScope(binding, {
        isLive: options.isLive, now: state.now,
        readGrant: () => { if (state.grant === null) failure(); return state.grant },
        readLifecycle: () => {
          if (state.contextSha256 !== binding.context_sha256 || state.lifecycle === null) failure()
          return state.lifecycle
        },
      })
      state.scopes.push(scope)
      validate(actualConfiguration, scope)
      return scope
    },
    validateAuraPublicProposalReadScope: validate,
    loadAuraContext: () => assert.fail('private context must not be loaded'),
  }
}

function completedResult(receiptOverrides = {}) {
  const receipt = { v: 3, kind: 'change', proposal, target: 'plugins/auma-theme/theme.json', base_sha: 'absent',
    new_sha: '2'.repeat(64), applied_at: '2026-10-04T12:00:00.000Z', approver: `aukora:1:${'1'.repeat(64)}`,
    pubkey_fp: keyHash.slice(0, 16), gate_pubkey_sha256: keyHash,
    owner_authorization: { version: 1, kind: 'aukora-owner-authorization-ref/v1', authorization_id: '3'.repeat(64), proof_sha256: '4'.repeat(64) },
    owner_accepted_at_ms: 1791115200000,
    owner_consumption: { ledger_seq: 2, ledger_hash: '5'.repeat(64), review_issue: { ledger_seq: 1, ledger_hash: '6'.repeat(64) } },
    ...receiptOverrides }
  const core = { applied: true, state: 'applied', entry: 'theme.json', receipt,
    receipt_sig: sign(null, Buffer.from(JSON.stringify(receipt)), pair.privateKey).toString('base64'),
    ledger_seq: 3, ledger_hash: '7'.repeat(64), message: 'applied' }
  const capture = { version: 1, kind: 'aukora-gate-capture/v1', source: { journal_id: 'aukora-gate-pilot', position: core.ledger_seq, hash: core.ledger_hash },
    proposal_id: proposal, gate_pubkey_sha256: keyHash, completed_result_sha256: gateCompletedResultDigest(core) }
  return { ...core, gate_capture: { capture, signature_base64: sign(null, gateCaptureSigningBytes(capture), pair.privateKey).toString('base64') } }
}

function fixture(overrides = {}, factory = createGateCaptureHostPlugin) {
  const calls = [], warnings = [], received = [], answer = Object.freeze({ mounted: true })
  const effects = []
  const auraState = { configuration, contextSha256, lifecycle: fixtureLifecycle(), grant: undefined,
    now: () => Date.now(), signedResult: completedResult(), bindings: [], scopes: [], validations: [], validationResult: true }
  const { configureAura, ...dependencyOverrides } = overrides
  configureAura?.(auraState)
  const dependencies = { platform: 'linux', preflight: async () => { calls.push('preflight'); return true },
    loadAura: async () => { calls.push('aura'); return createPublicAuraFixture(auraState, calls) },
    loadCapture: async () => { calls.push('capture'); return { verifyCompletedGateCapture } },
    loadKira: async () => { calls.push('kira'); return { readConfig: config => config,
      apply: async (...args) => { received.push(args); return answer } } },
    gateCall: async (...args) => { calls.push(args); return completedResult() }, ...dependencyOverrides }
  return { plugin: factory(dependencies), calls, warnings, received, answer, auraState,
    ctx: { logger: { warn: warning => warnings.push(warning) },
      effect(create) { const cleanup = create(); if (typeof cleanup === 'function') effects.push(cleanup) } },
    dispose() { for (const cleanup of effects.splice(0).reverse()) cleanup() },
  }
}

test('default host preserves Kira identity, existing config and exact third-argument pins', async () => {
  await loadSelectedDHelpers() // Missing physical D source fails by its named dependency.
  assert.equal(name, 'aukora-kira'); assert.deepEqual(inject, ['tools', 'sessions'])
  const f = fixture()
  assert.equal(await f.plugin.apply(f.ctx, existingConfig), f.answer)
  assert.deepEqual(f.calls, ['preflight', 'aura', 'capture', 'public-config', 'context-hash', 'kira', 'lifecycle'])
  const [ctx, config, host] = f.received[0]
  assert.equal(ctx, f.ctx); assert.equal(config, existingConfig); assert.equal(f.warnings.length, 0)
  assert.deepEqual(Object.keys(host).sort(), ['capturePins', 'isCaptureScopeLive', 'proposalFromToolResult', 'stateForProposal', 'verifyCompletedGateCapture'])
  assert.deepEqual(host.capturePins, { journal_id: 'aukora-gate-pilot', gate_public_key_pem: publicKey, gate_pubkey_sha256: keyHash })
  assert.ok(Object.isFrozen(host)); assert.ok(Object.isFrozen(host.capturePins))
  assert.notEqual(host.verifyCompletedGateCapture, verifyCompletedGateCapture)
  const completed = await host.stateForProposal(proposal)
  assert.deepEqual(f.calls.at(-1), [PROPOSE_SOCKET, 'state', { id: proposal }])
  assert.deepEqual(host.verifyCompletedGateCapture(completed, host.capturePins), { source: completed.gate_capture.capture.source })
  const D = await loadSelectedDHelpers()
  assert.deepEqual(f.auraState.bindings, [{ owner_subject: ownerSubject, proposal_id: proposal,
    source: { ...completed.gate_capture.capture.source, key_sha256: keyHash },
    receipt_sha256: sha(D.canonicalJson(completed.receipt)), context_sha256: contextSha256,
    release_sha: releaseSha, genesis_instance_id: genesisInstanceId }])
  assert.equal(f.auraState.scopes.length, 1)
  assert.equal(f.auraState.scopes[0].checkOwner(ownerSubject), true)
  await assert.rejects(host.stateForProposal(proposal.slice(0, 8)))
  const tampered = structuredClone(completed); tampered.receipt.target = 'different-target'
  assert.throws(() => host.verifyCompletedGateCapture(tampered, host.capturePins))
})

test('Mac ordinary Kira does not load preflight, public context or verifier', async () => {
  const f = fixture({ platform: 'darwin' })
  await f.plugin.apply(f.ctx, existingConfig)
  assert.deepEqual(f.calls, ['kira']); assert.equal(f.received[0][1], existingConfig)
  assert.equal(f.received[0][2], undefined); assert.deepEqual(f.warnings, [])
})

test('missing preflight, module, protected config or pins leaves ordinary Kira mounted', async () => {
  const failures = [
    { preflight: async () => false },
    { preflight: async () => { throw Error('/private/test-only/path') } },
    { loadAura: async () => { throw Error('missing public module') } },
    { loadAura: async () => ({}) },
    { loadCapture: async () => ({}) },
    { loadAura: async () => ({ loadAuraPublicConfiguration: () => { throw Error('missing config') } }) },
    { loadAura: async () => ({ loadAuraPublicConfiguration: () => { throw Error('invalid config') } }) },
    ...[undefined, { ...configuration.source, key_sha256: '0'.repeat(64) },
      { ...configuration.source, source_id: '' }, { ...configuration.source, source_id: 'other-journal' },
      { ...configuration.source, public_key_pem: 'not a key' }]
      .map(source => ({ configureAura: state => { state.configuration = { ...configuration, source } } })),
  ]
  for (const failure of failures) {
    const f = fixture(failure)
    assert.equal(await f.plugin.apply(f.ctx, existingConfig), f.answer)
    assert.equal(f.received[0][1], existingConfig); assert.equal(f.received[0][2], undefined)
    assert.equal(f.warnings.length, 1)
    assert.equal(f.warnings[0], 'aukora-kira: gate capture unavailable (kira-aura-capture:host-unavailable)')
    if (failure.preflight) assert.deepEqual(f.calls, ['kira'])
  }
})

test('ordinary Kira configuration errors remain errors from actual mount', async () => {
  const rejected = Error('kira.config: ordinary fault')
  const f = fixture({ loadKira: async () => ({ readConfig: () => { throw rejected },
    apply: async () => assert.fail('readConfig error must remain the original refusal') }) })
  await assert.rejects(f.plugin.apply(f.ctx, existingConfig), error => error === rejected)
})

test('materializer changes exactly two Kira names and retains the original rows/config/socket', async () => {
  const bytes = await readFile(new URL('../scripts/materialize-aukora-release.py', import.meta.url))
  const source = bytes.toString('utf8'), entry = './plugins/aukora-kira/lib/gate-capture-host.mjs'
  assert.equal(source.split(entry).length - 1, 2)
  assert.equal(source.includes('./plugins/aukora-kira/lib/index.js'), false)
  assert.equal(sha(Buffer.from(source.replaceAll(entry, './plugins/aukora-kira/lib/index.js'))),
    '81c20572772229916a17b57f5ebb1b22d8c8143e3a33349e8a7125d62ff2b8cd')
  assert.equal(source.split('proposeSocket: /run/aukora-gate/gate.sock').length - 1, 1)
})

test('fixed protected paths and public-only bootstrap precede dynamic installed imports', async () => {
  assert.equal(AURA_CONFIGURATION, '/etc/aukora-boundary-gate/aura-context.json')
  assert.equal(AURA_MODULE, '/opt/aukora-aura/packages/boundary-gate/host/aura/context.mjs')
  assert.equal(AURA_JSON_MODULE, '/opt/aukora-aura/packages/contracts/src/json.mjs')
  assert.equal(AURA_READ_LIFECYCLE, '/etc/aukora-boundary-gate/aura-read-lifecycle.json')
  assert.equal(CAPTURE_MODULE, '/opt/aukora-boundary-gate/src/ledger.mjs')
  const source = await readFile(wrapperUrl, 'utf8')
  assert.match(source, /execute\('\/usr\/bin\/python3', \['-I', '-S',[\s\S]*'\/usr\/local\/lib\/aukora-boundary\/gate-bootstrap', 'check-runtime-aura'\]/u)
  assert.match(source, /env: \{\}, timeout: 10_000/u)
  assert.match(source, /stdout\.trim\(\) !== 'RUNTIME_AURA_VERIFIED'/u)
  assert.equal(source.includes('loadAuraContext('), false)
  assert.equal(source.includes('ctx.provide'), false); assert.equal(source.includes('ctx.reflect'), false)
})

test('negative guard mutants are detected by unavailable-capture controls', async () => {
  const source = await readFile(wrapperUrl, 'utf8')
  const mutant = async replaced => import(`data:text/javascript;base64,${Buffer.from(replaced).toString('base64')}`)
  const guard = "if (await preflight() !== true) throw new Error(captureUnavailable.reason)"
  assert.ok(source.includes(guard))
  const missingPreflight = await mutant(source.replace(guard, ''))
  const unguarded = fixture({ preflight: async () => false }, missingPreflight.createGateCaptureHostPlugin)
  await unguarded.plugin.apply(unguarded.ctx, existingConfig)
  assert.notEqual(unguarded.received[0][2], undefined, 'control must detect lost preflight')
  const pinGuard = "|| createHash('sha256').update(key.export({ type: 'spki', format: 'der' })).digest('hex') !== source.key_sha256"
  assert.ok(source.includes(pinGuard))
  const missingPinGuard = await mutant(source.replace(pinGuard, ''))
  const mismatched = fixture({ configureAura: state => {
    state.configuration = { ...configuration, source: { ...configuration.source, key_sha256: '0'.repeat(64) } }
  } }, missingPinGuard.createGateCaptureHostPlugin)
  await mismatched.plugin.apply(mismatched.ctx, existingConfig)
  assert.notEqual(mismatched.received[0][2], undefined, 'control must detect lost public pin binding')
})

// Execute the accepted E body and real association/recall helpers. Only module
// import specifiers change; storage, routes and other services are disposable
// in-memory dependencies. Missing selected physical source fails by name.
let acceptedEFixtureSequence = 0
async function createAcceptedEFixture() {
  const [{ readFileSync: readE }, { resolve: resolveE }, { pathToFileURL: fileE }] = await Promise.all([
    import('node:fs'), import('node:path'), import('node:url'),
  ])
  const requested = process.env.AUKORA_TEST_KIRA_SOURCE ?? new URL('../plugins/aukora-kira/lib/index.js', import.meta.url)
  const indexURL = requested instanceof URL ? requested : fileE(resolveE(requested))
  let indexSource, associationSource, recallSource, qualitySource, recallStateSource, projectIdentitySource
  try {
    indexSource = readE(indexURL, 'utf8')
    associationSource = readE(new URL('./aura-association.mjs', indexURL), 'utf8')
    recallSource = readE(new URL('./aura-recall.mjs', indexURL), 'utf8')
    qualitySource = readE(new URL('./memory-quality.mjs', indexURL), 'utf8')
    recallStateSource = readE(new URL('./recall-state.mjs', indexURL), 'utf8')
    projectIdentitySource = readE(new URL('./project-identity.mjs', indexURL), 'utf8')
  } catch { throw Error('missing-dependency:accepted-kira-index-or-helper-closure') }
  assert.equal(sha(indexSource), 'c899150a23fb20ace1a4f658b0982b657cb3cbd29c063cf2facc5be8fb89e13e',
    'missing-dependency:accepted-kira-index-sha256')
  assert.equal(sha(associationSource), '67dfed9006ae1bb2b094b791b417290403941648e33d8c0a26f9158fc53fdb17',
    'missing-dependency:accepted-kira-association-sha256')
  assert.equal(sha(recallSource), '3e9d3c0751b3241ce93419dcdfd4c67a4dbeeb1f3d8f93f420202c6d06d80cc6',
    'missing-dependency:accepted-kira-recall-sha256')
  assert.equal(sha(qualitySource), 'd8245578a2553040c2974e63040e58a4ca2c2a61a68bc5c0bba5b0445b93ca42',
    'missing-dependency:accepted-kira-quality-sha256')
  assert.equal(sha(recallStateSource), 'ed00c677d931972cabe36d29d952c0462f36259bf4ebf8b77c39931a72feb5bf',
    'missing-dependency:accepted-kira-recall-state-sha256')
  assert.equal(sha(projectIdentitySource), '2da15b5b87ef5154f9bc02f2eb8b896e97719c7e7d44e12aacb088f0daf8725b',
    'missing-dependency:accepted-kira-project-identity-sha256')
  const dataURL = text => `data:text/javascript;base64,${Buffer.from(text).toString('base64')}`
  const associationURL = dataURL(associationSource)
  // memory-tiers.mjs pulls the vendor envelope/ingest/canonical closure; the accepted-E
  // fixture needs only sha256Hex, supplied here with the identical implementation.
  const tiersStubURL = dataURL("import { createHash } from 'node:crypto'\n"
    + "export function sha256Hex(text) {\n"
    + "  return createHash('sha256').update(Buffer.from(text, 'utf8')).digest('hex')\n"
    + "}\n")
  const qualityURL = dataURL(qualitySource.replace('./memory-tiers.mjs', tiersStubURL))
  const recallStateURL = dataURL(recallStateSource)
  const projectIdentityURL = dataURL(projectIdentitySource)
  const association = await import(associationURL)
  const recallURL = dataURL(recallSource.replace('./aura-association.mjs', associationURL).replace('./memory-quality.mjs', qualityURL))
  const observations = { remembers: [], memoryConstructions: [], mounts: [], injects: [], warnings: [], reflectReads: [] }
  const notes = [], provided = new Map(), listeners = new Map(), effects = [], tools = new Map()
  let disposed = false, memoryOptions
  const liveRead = () => ({ complete: true, notes: [...notes], chain: [], states: {}, forgotten: new Set() })
  const memory = {
    async remember(input, options = {}) {
      observations.remembers.push({ input, options })
      const policy = await memoryOptions.policyOf()
      if (options.isCaptureLive && !options.isCaptureLive()) return { remembered: 0, ids: [], reason: 'capture-paused' }
      const id = `rem:${sha(JSON.stringify({ input, source: options.auraSource }))}`
      const source = options.auraSource?.source
      const note = { id, subject: policy.subject, privacy: policy.privacy, statement: input.text,
        origin: { by: input.from }, scope: input.scope, observedAt: input.at, grantsAuthority: false,
        source: source ? { aura_source: { ...source } } : {} }
      if (source) note.auraAssociation = association.createAuraAssociation(id, source)
      notes.push(note)
      return { remembered: 1, ids: [id] }
    },
    referenceForRecord: async id => association.referenceForAssociatedNote(notes.find(note => note.id === id)),
    read: liveRead, retry: async () => {},
    recall: async () => ({ state: notes.length ? 'found' : 'empty', notes: [...notes], memory: {} }),
    bridge: { forget: async () => ({ reached: true }) },
  }
  const ctx = {
    logger: { warn: value => observations.warnings.push(value), info() {} }, sessions: new Map(),
    provide: (service, value) => provided.set(service, value),
    reflect: { get: (service, required) => { observations.reflectReads.push([service, required]); return provided.get(service) } },
    on(event, callback) {
      if (!listeners.has(event)) listeners.set(event, new Set())
      listeners.get(event).add(callback)
      return () => listeners.get(event)?.delete(callback)
    },
    emit(event, ...args) { for (const callback of [...(listeners.get(event) ?? [])]) callback(...args) },
    inject(services, callback) { observations.injects.push(services); callback({}) },
    effect(create) { const cleanup = create(); if (typeof cleanup === 'function') effects.push(cleanup) },
    tools: { register(definition) { tools.set(definition.name, definition) } },
  }
  const noop = () => undefined, UNLINKED_SUBJECT = 'did:fixture:unlinked'
  const overrides = {
    resolveMemoryIdentity: ({ stateDir, subject }) => ({ stateDir, subject }),
    RETRIEVAL_OPTIONS: [{ id: 'lexical', status: 'implemented' }], RETRIEVAL_LIMITS: {},
    UNLINKED_SUBJECT, NOT_LINKED: { error: 'fixture:not-linked' },
    readOwnerPolicy: policy => policy,
    createPartialFailureLedger: () => ({ failure: noop, record: noop }), PARTIAL_FAILURE_SERVICE: 'kira.partial-failure',
    readBridgeConfig: () => ({}), openVikingHome: stateDir => stateDir,
    createTrackedMemory: options => { observations.memoryConstructions.push(options); memoryOptions = options; return memory },
    readTrackedMemory: liveRead,
    projectScopeOf: agent => agent?.fixtureProject ?? null, sessionIdOfAgent: agent => agent?.session?.id,
    captureScopeOf: agent => {
      const scope = agent?.fixtureProject ?? null
      if (scope !== null) return scope
      const cwd = agent?.session?.header?.cwd
      return typeof cwd === 'string' && cwd.startsWith('/') ? 'project:unresolved' : 'owner'
    },
    defaultRoomLog: () => [], captureRoom: async () => {},
    provideKiraCite: () => ({ provided: true }),
    registerRememberedCapture: noop, registerAumaTurnCapture: noop, registerRecallInjection: noop,
    mountKiraRoutes: () => { observations.mounts.push('linked'); return { mounted: ['/fixture/kira'] } },
    mountUnlinkedKiraRoutes: () => { observations.mounts.push('unlinked'); return { mounted: ['/fixture/kira'] } },
    buildRouteDeps: () => ({ forgetNote: async () => ({ forgotten: false }), recallCandidates: () => [], liveRemembered: liveRead }),
    recallTool: execute => ({ name: 'kira_recall', execute }),
    governRecords: records => records, recallAnnotations: () => ({}),
  }
  const fixtureId = `accepted-e-${++acceptedEFixtureSequence}`
  const tableKey = Symbol.for('aukora.tests.acceptedE.dependencies')
  const table = globalThis[tableKey] ??= new Map()
  const dependencies = Object.create(null)
  table.set(fixtureId, dependencies)
  try {
    const rewritten = indexSource.replace(/import\s*\{([\s\S]*?)\}\s*from\s*(['"])([^'"]+)\2/gu,
      (statement, bindings, _quote, specifier) => {
        if (specifier === './aura-association.mjs') return statement.replace(specifier, associationURL)
        if (specifier === './aura-recall.mjs') return statement.replace(specifier, recallURL)
        if (specifier === './recall-state.mjs') return statement.replace(specifier, recallStateURL)
        if (specifier === './project-identity.mjs') return statement.replace(specifier, projectIdentityURL)
        const exports = bindings.split(',').map(value => value.trim()).filter(Boolean)
        dependencies[specifier] = Object.fromEntries(exports.map(binding => {
          if (!/^[A-Za-z_$][\w$]*$/u.test(binding)) throw Error('fixture-import-binding-unhandled')
          return [binding, Object.hasOwn(overrides, binding) ? overrides[binding]
            : () => { throw Error(`fixture-dependency-unconfigured:${binding}`) }]
        }))
        const body = `const d = globalThis[Symbol.for('aukora.tests.acceptedE.dependencies')].get(${JSON.stringify(fixtureId)})[${JSON.stringify(specifier)}];\n`
          + exports.map(binding => `export const ${binding} = d.${binding};`).join('\n')
        return statement.replace(specifier, dataURL(body))
      })
    const E = await import(dataURL(rewritten + `\n//# sourceURL=accepted-e-fixture-${acceptedEFixtureSequence}.mjs`))
    return { E, association, ctx, memory, notes, provided, observations, tools, UNLINKED_SUBJECT,
      observerCount: () => listeners.get('tools/result')?.size ?? 0,
      dispose() { if (disposed) return; disposed = true; for (const cleanup of effects.reverse()) cleanup(); listeners.clear(); tools.clear() },
    }
  } finally { table.delete(fixtureId); if (table.size === 0) delete globalThis[tableKey] }
}

const tick = () => new Promise(resolve => setImmediate(resolve))
function emitProposal(e, returned = {}) {
  e.ctx.emit('tools/result', { name: 'aukora_gate_propose', callId: 'fixture-call', rootCallId: 'fixture-root', agent: { fixtureProject: 'fixture-project' } },
    { isError: false, value: JSON.stringify({ ...proposalToolResult, ...returned }) })
}
async function drainTicks() { for (let i = 0; i < 8; i++) await tick() }

test('trusted proposal decoder selects only the actual full proposeTheme result and current owner', async () => {
  const config = structuredClone(existingConfig), f = fixture()
  try {
    await f.plugin.apply(f.ctx, config)
    const host = f.received[0][2]
    const execution = { name: 'aukora_gate_propose', arguments: { proposal_id: 'model-chosen-id' } }
    const selected = host.proposalFromToolResult(proposalToolResult, execution)
    assert.deepEqual(selected, { id: proposal, expires: Date.parse(proposalToolResult.expires) })
    assert.ok(Object.isFrozen(selected))
    const missingId = { ...proposalToolResult }; delete missingId.proposal_id
    const invalid = [
      ['missing ID', missingId], ['display ID only', { ...proposalToolResult, proposal_id: proposal.slice(0, 8) }],
      ['mismatched ID', { ...proposalToolResult, proposal_id: '11234567-89ab-4cde-8fab-0123456789ab' }],
      ['wrong display', { ...proposalToolResult, proposal: 'ffffffff' }],
      ['wrong target', { ...proposalToolResult, target: 'model-selected-target' }],
      ['wrong state', { ...proposalToolResult, state: 'REFUSED' }], ['failed result', { ...proposalToolResult, ok: false }],
      ['missing expiry', { ...proposalToolResult, expires: null }],
      ['expired result', { ...proposalToolResult, expires: new Date(Date.now() - 1).toISOString() }],
      ['noncanonical expiry', { ...proposalToolResult, expires: '2099-01-01' }],
      ['lowercase accent', { ...proposalToolResult, accent: '#abcdef' }],
      ['wrong message', { ...proposalToolResult, message: 'model-provided-message' }],
      ['extra fields', { ...proposalToolResult, model_id: proposal }],
    ]
    for (const [label, returned] of invalid)
      assert.throws(() => host.proposalFromToolResult(returned, execution), /host-unavailable/u, label)
    let getterReads = 0
    const accessor = { ...proposalToolResult }
    Object.defineProperty(accessor, 'proposal_id', { enumerable: true, get() { getterReads++; return proposal } })
    assert.throws(() => host.proposalFromToolResult(accessor, execution), /host-unavailable/u)
    assert.equal(getterReads, 0)
    assert.throws(() => host.proposalFromToolResult(proposalToolResult, { name: 'model_other_tool', arguments: { proposal_id: proposal } }))
    assert.equal(f.auraState.scopes.length, 0, 'decoding never creates a grant or reads a proposal')
    config.memoryOwner.permittedPrivacy.push('private')
    assert.throws(() => host.proposalFromToolResult(proposalToolResult, execution), /host-unavailable/u)
  } finally { f.dispose() }
})

test('actual E193 native observer refuses missing, short, tampered and model-only proposal IDs', async () => {
  const e = await createAcceptedEFixture(), stateCalls = []
  try {
    const f = fixture({ loadKira: async () => e.E,
      gateCall: async (...args) => { stateCalls.push(args); return completedResult() } })
    await f.plugin.apply(e.ctx, existingConfig)
    const execution = { name: 'aukora_gate_propose', arguments: { proposal_id: proposal }, callId: 'fixture-call', agent: {} }
    const missingId = { ...proposalToolResult }; delete missingId.proposal_id
    for (const returned of [missingId, { ...proposalToolResult, proposal_id: proposal.slice(0, 8) },
      { ...proposalToolResult, proposal_id: '11234567-89ab-4cde-8fab-0123456789ab' },
      { ...proposalToolResult, target: 'model-target' }, { ...proposalToolResult, extra_id: proposal }])
      e.ctx.emit('tools/result', execution, { isError: false, value: JSON.stringify(returned) })
    e.ctx.emit('tools/result', { ...execution, name: 'other_tool' }, { isError: false, value: JSON.stringify(proposalToolResult) })
    e.ctx.emit('tools/result', execution, { isError: true, value: JSON.stringify(proposalToolResult) })
    e.ctx.emit('tools/result', execution, { isError: false, value: proposalToolResult })
    await drainTicks()
    assert.deepEqual(stateCalls, []); assert.equal(e.notes.length, 0); assert.equal(e.observations.remembers.length, 0)
    emitProposal(e); await drainTicks()
    assert.deepEqual(stateCalls, [[PROPOSE_SOCKET, 'state', { id: proposal }]])
    assert.equal(e.notes.length, 1)
  } finally { e.dispose() }
})

test('accepted E apply receives trusted host and associates the actual native tool result', async () => {
  const e = await createAcceptedEFixture()
  try {
    const retained = completedResult(), verifierInputs = [], stateCalls = [], providerReads = []
    const f = fixture({ loadKira: async () => e.E,
      loadCapture: async () => ({ verifyCompletedGateCapture: (result, pins) => {
        verifierInputs.push(result); return verifyCompletedGateCapture(result, pins)
      } }),
      gateCall: async (...args) => { stateCalls.push(args); return retained },
    })
    await f.plugin.apply(e.ctx, existingConfig)
    assert.equal(e.observerCount(), 1); assert.deepEqual(e.observations.mounts, ['linked'])
    assert.ok(e.tools.has('kira_remember')); assert.ok(e.tools.has('kira_recall'))
    // A shortened display ID or a refused/error result cannot start capture.
    emitProposal(e, { proposal_id: proposal.slice(0, 8) })
    emitProposal(e, { state: 'REFUSED' })
    await drainTicks(); assert.equal(e.notes.length, 0)
    emitProposal(e)
    await drainTicks()
    assert.equal(e.notes.length, 1)
    assert.deepEqual(stateCalls, [[PROPOSE_SOCKET, 'state', { id: proposal }]])
    assert.equal(verifierInputs.length, 5)
    assert.equal(new Set(verifierInputs).size, 5)
    assert.ok(verifierInputs.every(result => result !== retained && Object.isFrozen(result) && Object.isFrozen(result.receipt)))
    assert.ok(verifierInputs.every(result => JSON.stringify(result) === JSON.stringify(retained)))
    const note = e.notes[0]
    assert.equal(note.statement, `Boundary gate applied proposal ${proposal} for plugins/auma-theme/theme.json.`)
    assert.equal(note.scope, 'fixture-project'); assert.equal(note.grantsAuthority, false)
    assert.deepEqual(e.association.referenceForAssociatedNote(note), { source: completedResult().gate_capture.capture.source })
    assert.equal(e.observations.remembers[0].options.isCaptureLive(), true)
    // Actual E already resolves the existing provider; this wrapper adds none.
    const provider = Object.freeze({ referenceForRecord: id => e.memory.referenceForRecord(id),
      readCitation: async selector => {
        providerReads.push(selector)
        return { ok: false, status: 'incomplete', reason: 'aura-citation:fixture-incomplete',
          grants_authority: false, citation: null, verification: null }
      },
    })
    e.provided.set('aura.records', provider)
    const answer = await e.provided.get('kira.recall').recall('fixture question')
    assert.deepEqual(providerReads, [{ source: retained.gate_capture.capture.source }])
    assert.equal(answer.auraCitations[0].status, 'undetermined')
    assert.equal(answer.auraCitations[0].reason, 'aura-citation:fixture-incomplete')
    assert.ok(e.observations.reflectReads.some(([service, required]) => service === 'aura.records' && required === false))
    assert.equal(e.provided.get('aura.records'), provider)
    e.dispose(); assert.equal(e.observerCount(), 0)
    assert.equal(e.observations.remembers[0].options.isCaptureLive(), false)
    emitProposal(e); await drainTicks(); assert.equal(e.notes.length, 1)
  } finally { e.dispose() }
})

test('accepted E preserves unlinked policy and config refusal through the new wrapper', async () => {
  const e = await createAcceptedEFixture()
  try {
    const f = fixture({ loadKira: async () => e.E })
    const unlinked = { ...existingConfig, memoryOwner: { ...existingConfig.memoryOwner, subject: e.UNLINKED_SUBJECT } }
    await f.plugin.apply(e.ctx, unlinked)
    assert.deepEqual(e.observations.mounts, ['unlinked']); assert.equal(e.observerCount(), 0)
    assert.equal(e.observations.memoryConstructions.length, 0); assert.equal(e.tools.size, 0)
    emitProposal(e); await drainTicks(); assert.equal(e.notes.length, 0)
    await assert.rejects(f.plugin.apply(e.ctx, { ...existingConfig, gateCaptureHost: () => true }),
      error => error.code === 'kira.config:config-field-unknown')
  } finally { e.dispose() }
})

test('accepted E mounts ordinary memory without observer or note when trusted prerequisites fail', async () => {
  for (const failure of [
    { preflight: async () => false },
    { configureAura: state => { state.configuration = { ...configuration, source: undefined } } },
    { configureAura: state => { state.configuration = { ...configuration, source: { ...configuration.source, key_sha256: '0'.repeat(64) } } } },
    { configureAura: state => { state.configuration = { ...configuration, source: { ...configuration.source, source_id: 'other-journal' } } } },
    { configureAura: state => { state.configuration = { ...configuration, owner_subject: `aukora:1:${'0'.repeat(64)}` } } },
    { configureAura: state => { state.lifecycle = null } },
    { configureAura: state => { state.lifecycle.extra = true } },
    { configureAura: state => { state.lifecycle.context_sha256 = '0'.repeat(64) } },
    { configureAura: state => { state.lifecycle.release_sha = '0'.repeat(64) } },
    { configureAura: state => { state.lifecycle.genesis_instance_id = 'not-a-uuid' } },
    { configureAura: state => { state.lifecycleText = '{"version":1,"version":1}' } },
  ]) {
    const e = await createAcceptedEFixture()
    try {
      const f = fixture({ ...failure, loadKira: async () => e.E })
      await f.plugin.apply(e.ctx, existingConfig)
      assert.deepEqual(e.observations.mounts, ['linked']); assert.ok(e.tools.has('kira_remember'))
      assert.equal(e.observerCount(), 0)
      emitProposal(e); await drainTicks(); assert.equal(e.notes.length, 0)
    } finally { e.dispose() }
  }
})

test('accepted E disposal prevents a pending exact state reply from publishing a late note', async () => {
  const e = await createAcceptedEFixture()
  let deliver
  try {
    const f = fixture({ loadKira: async () => e.E, gateCall: () => new Promise(resolve => { deliver = resolve }) })
    await f.plugin.apply(e.ctx, existingConfig)
    emitProposal(e); await drainTicks(); assert.equal(typeof deliver, 'function')
    assert.equal(e.notes.length, 0); e.dispose()
    deliver(completedResult()); await drainTicks()
    assert.equal(e.observerCount(), 0); assert.equal(e.notes.length, 0)
    assert.equal(e.observations.remembers.length, 0)
  } finally { e.dispose() }
})

test('accepted E rejects missing, altered or unavailable retained completions without a note', async () => {
  const altered = completedResult(); altered.receipt.target = 'different-target'
  const missingCapture = completedResult(); delete missingCapture.gate_capture
  const otherProposal = completedResult(); otherProposal.receipt.proposal = '11234567-89ab-4cde-8fab-0123456789ab'
  for (const reply of [altered, missingCapture, otherProposal,
    { state: 'applied', gate_capture_status: 'UNAVAILABLE' }, { state: 'incomplete' }, null]) {
    const e = await createAcceptedEFixture()
    try {
      const f = fixture({ loadKira: async () => e.E, gateCall: async () => reply })
      await f.plugin.apply(e.ctx, existingConfig); emitProposal(e); await drainTicks()
      assert.equal(e.observations.remembers.length, 0); assert.equal(e.notes.length, 0)
    } finally { e.dispose() }
  }
  const e = await createAcceptedEFixture()
  let stateCalls = 0
  try {
    const f = fixture({ loadKira: async () => e.E, gateCall: async () => { stateCalls++; throw Error('fixture-state-unavailable') } })
    await f.plugin.apply(e.ctx, existingConfig); emitProposal(e); await drainTicks()
    assert.equal(stateCalls, 1); assert.equal(e.observations.remembers.length, 0)
    e.dispose(); await drainTicks(); assert.equal(e.notes.length, 0)
  } finally { e.dispose() }
})

test('actual D closed grants reject missing or mismatched proposal bindings before accepted E remembers', async () => {
  const cases = [
    ['missing grant', state => { state.grant = null }],
    ['wrong owner', state => { state.changeGrant = grant => { grant.owner_subject = `aukora:1:${'0'.repeat(64)}` } }],
    ['wrong proposal UUID', state => { state.changeGrant = grant => { grant.proposal_id = 'not-a-uuid' } }],
    ['different proposal', state => { state.changeGrant = grant => { grant.proposal_id = genesisInstanceId } }],
    ['wrong source coordinate', state => { state.changeGrant = grant => { grant.source.hash = '0'.repeat(64) } }],
    ['wrong source key', state => { state.changeGrant = grant => { grant.source.key_sha256 = '0'.repeat(64) } }],
    ['wrong receipt digest', state => { state.changeGrant = grant => { grant.receipt_sha256 = '0'.repeat(64) } }],
    ['wrong protected configuration digest', state => { state.changeGrant = grant => { grant.context_sha256 = '0'.repeat(64) } }],
    ['wrong release', state => { state.changeGrant = grant => { grant.release_sha = '0'.repeat(40) } }],
    ['wrong lifecycle epoch', state => { state.changeGrant = grant => { grant.genesis_instance_id = proposal } }],
    ['extra grant field', state => { state.changeGrant = grant => { grant.extra = true } }],
    ['wrong custody', state => { state.changeGrant = grant => { grant.custody = 'OWNER' } }],
    ['authority claim', state => { state.changeGrant = grant => { grant.grants_authority = true } }],
    ['grant TTL over five minutes', state => { state.changeGrant = grant => { grant.expires_at_ms = grant.issued_at_ms + 300_001 } }],
    ['expired grant', state => { state.changeGrant = grant => {
      grant.issued_at_ms = Date.now() - 2; grant.expires_at_ms = grant.issued_at_ms + 1
    } }],
    ['future grant', state => { state.changeGrant = grant => {
      grant.issued_at_ms = Date.now() + 60_000; grant.expires_at_ms = grant.issued_at_ms + 60_000
    } }],
    ['protected configuration changed after mount', state => { state.contextSha256 = '0'.repeat(64) }],
    ['release changed after mount', state => { state.lifecycle.release_sha = '0'.repeat(40) }],
    ['epoch changed after mount', state => { state.lifecycle.genesis_instance_id = proposal }],
    ['signed public source differs', state => { state.signedResult = completedResult({ target: 'different-signed-target' }) }],
    ['D validation returns a truthy object', state => { state.validationResult = {} }],
  ]
  for (const [label, change] of cases) {
    const e = await createAcceptedEFixture()
    let host
    try {
      const f = fixture({ loadKira: async () => ({ ...e.E,
        apply: (...args) => { host = args[2]; return e.E.apply(...args) } }) })
      await f.plugin.apply(e.ctx, existingConfig)
      assert.ok(host, label)
      change(f.auraState)
      await assert.rejects(host.stateForProposal(proposal),
        error => error.message === 'kira-aura-capture:host-unavailable', label)
      emitProposal(e); await drainTicks()
      assert.equal(e.observations.remembers.length, 0, label)
      assert.equal(e.notes.length, 0, label)
    } finally { e.dispose() }
  }
})

test('actual D grant revocation remains permanent for the mounted owner scope', async () => {
  const e = await createAcceptedEFixture()
  let host
  try {
    const f = fixture({ loadKira: async () => ({ ...e.E,
      apply: (...args) => { host = args[2]; return e.E.apply(...args) } }) })
    await f.plugin.apply(e.ctx, existingConfig)
    const completed = await host.stateForProposal(proposal)
    const retained = f.auraState.grant
    f.auraState.grant = null
    assert.throws(() => host.verifyCompletedGateCapture(completed, host.capturePins),
      error => error.message === 'kira-aura-capture:host-unavailable')
    f.auraState.grant = retained
    await assert.rejects(host.stateForProposal(proposal),
      error => error.message === 'kira-aura-capture:host-unavailable')
    assert.equal(f.auraState.scopes.length, 1)
    emitProposal(e); await drainTicks()
    assert.equal(e.observations.remembers.length, 0); assert.equal(e.notes.length, 0)
  } finally { e.dispose() }
})

test('synchronous capture fence accepts only an unchanged live retained scope', async () => {
  const cases = [
    ['revoked grant', (f) => { f.auraState.grant = null }],
    ['disposed mount', f => f.dispose()],
    ['owner mutation', (_f, config) => { config.memoryOwner.permittedPrivacy.push('private') }],
    ['owner replacement', (_f, config) => { config.memoryOwner = { ...config.memoryOwner } }],
    ['context changed', f => { f.auraState.contextSha256 = '0'.repeat(64) }],
    ['release changed', f => { f.auraState.lifecycle.release_sha = '0'.repeat(40) }],
    ['epoch changed', f => { f.auraState.lifecycle.genesis_instance_id = proposal }],
    ['expired grant', f => { f.auraState.clockShift = 300_001 }],
    ['truthy validation', f => { f.auraState.validationResult = {} }],
    ['asynchronous validation', f => { f.auraState.validationResult = Promise.resolve(true) }],
  ]
  for (const [label, change] of cases) {
    const config = structuredClone(existingConfig), f = fixture({
      configureAura: state => { state.now = () => Date.now() + (state.clockShift ?? 0) },
    })
    try {
      await f.plugin.apply(f.ctx, config)
      const host = f.received[0][2]
      assert.equal(host.isCaptureScopeLive(completedResult()), false, 'missing retained scope')
      assert.equal(f.auraState.scopes.length, 0, 'fence must not create scopes')
      const completed = await host.stateForProposal(proposal)
      assert.equal(host.isCaptureScopeLive(completed), true, label)
      const tampered = structuredClone(completed); tampered.receipt.target = 'different-target'
      assert.equal(host.isCaptureScopeLive(tampered), false, 'mutated result')
      assert.equal(host.isCaptureScopeLive(undefined), false, 'missing result')
      assert.equal(f.auraState.scopes.length, 1)
      change(f, config)
      const result = host.isCaptureScopeLive(completed)
      assert.equal(result, false, label)
      assert.equal(typeof result, 'boolean', label)
      assert.equal(f.auraState.scopes.length, 1, 'fence must not replace scopes')
    } finally { f.dispose() }
  }
})

test('normalized owner drift and disposal refuse applied state before accepted E remembers', async () => {
  for (const change of ['subject', 'stateDir', 'dispose']) {
    const e = await createAcceptedEFixture()
    let host
    const mutableConfig = structuredClone(existingConfig)
    try {
      const f = fixture({ loadKira: async () => ({ ...e.E,
        apply: (...args) => { host = args[2]; return e.E.apply(...args) } }) })
      await f.plugin.apply(e.ctx, mutableConfig)
      if (change === 'dispose') e.dispose()
      else mutableConfig.memoryOwner[change] = change === 'subject' ? `aukora:1:${'0'.repeat(64)}` : '/disposable/other-memory'
      await assert.rejects(host.stateForProposal(proposal),
        error => error.message === 'kira-aura-capture:host-unavailable', change)
      emitProposal(e); await drainTicks()
      assert.equal(e.observations.remembers.length, 0, change); assert.equal(e.notes.length, 0, change)
    } finally { e.dispose() }
  }
})

test('operator owner alias changes only the subject in a frozen clone passed through actual E normalization', async () => {
  const e = await createAcceptedEFixture()
  let forwarded, host
  const original = { retrieval: 'lexical', maxSessions: 17, autoStage: false, readOwner: undefined,
    memoryOwner: { ...structuredClone(existingConfig.memoryOwner), subject: 'aumlok:subject:owner',
      policyRevision: 'fixture-policy', grantFile: undefined, approverDid: undefined } }
  const before = structuredClone(original)
  try {
    const f = fixture({ loadKira: async () => ({ ...e.E,
      apply: (ctx, config, trusted) => { forwarded = config; host = trusted; return e.E.apply(ctx, config, trusted) } }) })
    await f.plugin.apply(e.ctx, original)
    const expected = { ...before, memoryOwner: { ...before.memoryOwner, subject: ownerSubject } }
    assert.deepEqual(forwarded, expected)
    assert.equal(JSON.stringify(forwarded), JSON.stringify(expected))
    assert.deepEqual(original, before)
    assert.equal(original.memoryOwner.subject, 'aumlok:subject:owner')
    assert.notEqual(forwarded, original); assert.notEqual(forwarded.memoryOwner, original.memoryOwner)
    assert.notEqual(forwarded.memoryOwner.permittedPrivacy, original.memoryOwner.permittedPrivacy)
    assert.ok(Object.isFrozen(forwarded)); assert.ok(Object.isFrozen(forwarded.memoryOwner))
    assert.ok(Object.isFrozen(forwarded.memoryOwner.permittedPrivacy))
    assert.equal(Object.hasOwn(forwarded, 'readOwner'), true)
    assert.equal(Object.hasOwn(forwarded.memoryOwner, 'grantFile'), true)
    assert.equal(e.E.readConfig(forwarded).memoryOwner.subject, ownerSubject)
    assert.equal(e.E.readConfig(forwarded).memoryOwner.stateDir, original.memoryOwner.stateDir)
    assert.ok(host); assert.equal(e.observerCount(), 1)
    emitProposal(e); await drainTicks()
    assert.equal(e.notes.length, 1)
    assert.equal(e.notes[0].subject, ownerSubject)
    assert.deepEqual(original, before)
  } finally { e.dispose() }
})

test('wrong aliases and explicit owner mismatches remain unchanged and cannot receive capture authority', async () => {
  for (const subject of ['aumlok:subject:other', 'aumlok:subject:owner ', `aukora:1:${'0'.repeat(64)}`]) {
    const original = { ...existingConfig, memoryOwner: { ...existingConfig.memoryOwner, subject } }
    const f = fixture()
    await f.plugin.apply(f.ctx, original)
    assert.equal(f.received[0][1], original, subject)
    assert.equal(f.received[0][2], undefined, subject)
    assert.equal(original.memoryOwner.subject, subject)
    assert.deepEqual(f.warnings, ['aukora-kira: gate capture unavailable (kira-aura-capture:host-unavailable)'])
  }
})

test('missing protected profile forwards the original owner alias untouched', async () => {
  for (const failure of [{ platform: 'darwin' }, { preflight: async () => false },
    { loadAura: async () => { throw Error('fixture:protected-profile-missing') } }]) {
    const original = { ...existingConfig, memoryOwner: { ...existingConfig.memoryOwner, subject: 'aumlok:subject:owner' } }
    const f = fixture(failure)
    await f.plugin.apply(f.ctx, original)
    assert.equal(f.received[0][1], original)
    assert.equal(f.received[0][2], undefined)
    assert.equal(original.memoryOwner.subject, 'aumlok:subject:owner')
  }
})

test('raw alias owner replacement or data mutation during state await returns no applied DTO or accepted E note', async () => {
  const changes = [
    ['owner object replacement', config => { config.memoryOwner = { ...config.memoryOwner } }],
    ['raw subject mutation', config => { config.memoryOwner.subject = ownerSubject }],
    ['raw state directory mutation', config => { config.memoryOwner.stateDir = '/disposable/other-memory' }],
    ['raw privacy mutation', config => { config.memoryOwner.permittedPrivacy.push('private') }],
    ['raw undefined field addition', config => { config.memoryOwner.grantFile = undefined }],
  ]
  for (const [label, change] of changes) {
    const e = await createAcceptedEFixture(), replies = []
    const original = { ...existingConfig, memoryOwner: { ...structuredClone(existingConfig.memoryOwner), subject: 'aumlok:subject:owner' } }
    let host
    try {
      const f = fixture({ loadKira: async () => ({ ...e.E,
        apply: (...args) => { host = args[2]; return e.E.apply(...args) } }),
        gateCall: () => new Promise(resolve => replies.push(resolve)),
      })
      await f.plugin.apply(e.ctx, original)
      const pending = assert.rejects(host.stateForProposal(proposal),
        error => error.message === 'kira-aura-capture:host-unavailable', label)
      emitProposal(e); await drainTicks()
      assert.equal(replies.length, 2, label)
      change(original)
      for (const reply of replies) reply(completedResult())
      await pending; await drainTicks()
      assert.equal(f.auraState.scopes.length, 0, label)
      assert.equal(e.observations.remembers.length, 0, label); assert.equal(e.notes.length, 0, label)
    } finally { e.dispose() }
  }
})

test('raw alias owner mutation is rechecked by every completion verification callback', async () => {
  const original = { ...existingConfig, memoryOwner: { ...structuredClone(existingConfig.memoryOwner), subject: 'aumlok:subject:owner' } }
  const f = fixture()
  try {
    await f.plugin.apply(f.ctx, original)
    const host = f.received[0][2], completed = await host.stateForProposal(proposal)
    assert.deepEqual(host.verifyCompletedGateCapture(completed, host.capturePins), { source: completed.gate_capture.capture.source })
    original.memoryOwner.permittedPrivacy.push('private')
    assert.throws(() => host.verifyCompletedGateCapture(completed, host.capturePins),
      error => error.message === 'kira-aura-capture:host-unavailable')
  } finally { f.dispose() }
})

test('accepted E must not remember after grant revocation following its first poll verification', async () => {
  const e = await createAcceptedEFixture()
  let verifications = 0, f
  try {
    f = fixture({ loadKira: async () => e.E,
      loadCapture: async () => ({ verifyCompletedGateCapture: (result, pins) => {
        const verified = verifyCompletedGateCapture(result, pins)
        if (++verifications === 3) f.auraState.grant = null
        return verified
      } }),
    })
    await f.plugin.apply(e.ctx, existingConfig)
    emitProposal(e); await drainTicks()
    assert.equal(verifications, 3)
    assert.equal(e.observations.remembers.length, 0,
      'write-time grant refusal must prevent an ordinary unassociated capture note')
    assert.equal(e.notes.length, 0)
  } finally { e.dispose() }
})

test('actual E193 revalidates the retained H scope after awaited write policy before a note is persisted', async () => {
  for (const change of ['unchanged', 'grant revoked', 'owner privacy changed', 'mount disposed']) {
    const e = await createAcceptedEFixture(), config = structuredClone(existingConfig), verifierInputs = []
    let releasePolicy, rememberedResult
    const policyRelease = new Promise(resolve => { releasePolicy = resolve })
    try {
      const f = fixture({ loadKira: async () => e.E,
        loadCapture: async () => ({ verifyCompletedGateCapture: (result, pins) => {
          verifierInputs.push(result); return verifyCompletedGateCapture(result, pins)
        } }),
      })
      await f.plugin.apply(e.ctx, config); await drainTicks()
      const options = e.observations.memoryConstructions[0]
      assert.ok(options, 'actual E must construct the disposable memory dependency')
      let policyEntered = false
      const originalPolicy = options.policyOf
      options.policyOf = async () => {
        const policy = await originalPolicy()
        policyEntered = true; await policyRelease; return policy
      }
      const originalRemember = e.memory.remember
      e.memory.remember = async (...args) => { rememberedResult = await originalRemember(...args); return rememberedResult }
      emitProposal(e); await drainTicks()
      assert.equal(policyEntered, true, change)
      assert.equal(e.observations.remembers.length, 1, change)
      assert.equal(e.notes.length, 0, 'policy is still outstanding')
      assert.equal(verifierInputs.length, 4, 'state and ingestion verification precede the policy await')
      assert.equal(f.auraState.scopes.length, 1)
      if (change === 'grant revoked') f.auraState.grant = null
      if (change === 'owner privacy changed') config.memoryOwner.permittedPrivacy.push('private')
      if (change === 'mount disposed') e.dispose()
      releasePolicy(); await drainTicks()
      if (change === 'unchanged') {
        assert.equal(e.notes.length, 1); assert.equal(rememberedResult.remembered, 1)
        assert.equal(verifierInputs.length, 5, 'fresh synchronous scope verification precedes persistence')
      } else {
        assert.equal(e.notes.length, 0, change)
        assert.deepEqual(rememberedResult, { remembered: 0, ids: [], reason: 'capture-paused' }, change)
        assert.equal(verifierInputs.length, change === 'grant revoked' ? 5 : 4, change)
      }
      assert.equal(f.auraState.scopes.length, 1, 'the write fence never replaces the retained grant')
    } finally { releasePolicy(); e.dispose() }
  }
})

// Execute the selected CLI body with the real option parser and path grammar.
// Process, filesystem, gate state, key loading and server imports are fixtures.
const binURL = new URL('../packages/boundary-gate/bin/gate.mjs', import.meta.url)
const unitURL = new URL('../packages/boundary-gate/host/systemd/aukora-boundary-gate.service', import.meta.url)
let gateCliFixtureSequence = 0
async function runGateCli(args, source) {
  source ??= await readFile(binURL, 'utf8')
  const observed = { calls: [], gates: [], servers: [], messages: [], exit: null, error: null }
  const exit = Object.freeze({ fixture: 'process-exit' }), owner = Object.freeze({ fixture: 'owner' })
  const fixture = {
    process: { argv: ['node', 'gate.mjs', ...args],
      umask: value => { observed.calls.push(['umask', value]); return 0o022 },
      exit: code => { observed.exit = code; throw exit },
      on: signal => observed.calls.push(['signal', signal]),
    },
    console: { log: (...values) => observed.messages.push(values), error: (...values) => observed.messages.push(values) },
    fs: { readFileSync: () => { observed.calls.push(['read-file']); return 'fixture public bytes' } },
    createPublicKey: () => { observed.calls.push(['public-key']); return 'fixture-public-key' },
    loadOwnerSecret: home => { observed.calls.push(['owner', home]); return owner },
    rotateBearer: (home, actualOwner) => { assert.equal(actualOwner, owner); observed.calls.push(['bearer', home]); return { fixture: 'bearer-info' } },
    gateTargets: (root, options) => { observed.calls.push(['targets', root, options]); return { fixtureTarget: {} } },
    gateStore: options => { observed.calls.push(['store', options]); return { fixture: 'store' } },
    createGate: options => {
      observed.gates.push(options)
      return { fp: 'fixture-fingerprint', targets: options.targets,
        startup: args => { observed.calls.push(['startup', args]); return { ok: true } }, close() {} }
    },
    serveGate: async (gate, options) => {
      observed.servers.push({ gate, options })
      return { proposeSocket: '/fixture/propose.sock', ownerSocket: '/fixture/owner.sock', port: null, close: async () => {} }
    },
    loadOrCreateKey: home => { observed.calls.push(['load-key', home]); return { pub: 'fixture-public-key' } },
    openDb: (file, options) => { observed.calls.push(['db', file, options]); return { fixture: 'db' } },
    verifyLedger: () => { observed.calls.push(['verify-ledger']); return { ok: true } },
    keyFingerprint: () => 'fixture-fingerprint', verifyReceipt: () => ({ ok: true }),
  }
  const key = Symbol.for('aukora.tests.gateCli.dependencies'), table = globalThis[key] ??= new Map()
  const id = `gate-cli-${++gateCliFixtureSequence}`
  table.set(id, fixture)
  const dataURL = text => `data:text/javascript;base64,${Buffer.from(text).toString('base64')}`
  const dependency = `globalThis[Symbol.for('aukora.tests.gateCli.dependencies')].get(${JSON.stringify(id)})`
  let rewritten = source.replace(/^#![^\n]*\n/u, '').replace(/import fs from 'node:fs'/u,
    `import fs from '${dataURL(`export default ${dependency}.fs;`)}'`)
  rewritten = rewritten.replace(/import\s*\{([^}]+)\}\s*from\s*(['"])([^'"]+)\2/gu,
    (statement, bindings, _quote, specifier) => {
      if (specifier === 'node:util') return statement
      const exports = bindings.split(',').map(value => value.trim()).filter(Boolean)
      assert.ok(exports.every(binding => Object.hasOwn(fixture, binding)), 'all non-parser imports are disposable fixtures')
      const body = `const fixture = ${dependency};\n` + exports.map(binding => `export const ${binding} = fixture.${binding};`).join('\n')
      return statement.replace(specifier, dataURL(body))
    })
  try {
    await import(dataURL(`const fixture = ${dependency}; const process = fixture.process, console = fixture.console;\n${rewritten}`))
  } catch (error) { if (error !== exit) observed.error = error }
  finally { table.delete(id); if (table.size === 0) delete globalThis[key] }
  return observed
}
const serveArgs = ['serve', '--home', '/fixture/gate', '--run', '/fixture/run', '--target-root', '/fixture/targets']

test('gate CLI binds only the optional exact operator journal while legacy serve stays unchanged', async () => {
  const legacy = await runGateCli(serveArgs)
  assert.equal(legacy.error, null); assert.equal(legacy.exit, null); assert.equal(legacy.gates.length, 1)
  assert.deepEqual(Object.keys(legacy.gates[0]).sort(), ['home', 'owner', 'store', 'targets'])
  assert.equal(Object.hasOwn(legacy.gates[0], 'journalId'), false)
  const selected = await runGateCli([...serveArgs, '--journal-id', 'aukora-gate-pilot'])
  assert.equal(selected.error, null); assert.equal(selected.exit, null); assert.equal(selected.gates.length, 1)
  assert.equal(selected.gates[0].journalId, 'aukora-gate-pilot')
  assert.deepEqual(selected.servers[0].options, legacy.servers[0].options)
  assert.deepEqual(selected.calls, legacy.calls)
  const equals = await runGateCli([...serveArgs, '--journal-id=aukora-gate-pilot'])
  assert.equal(equals.error, null); assert.equal(equals.gates[0].journalId, 'aukora-gate-pilot')
})

test('gate CLI refuses wrong, missing, repeated and non-serve journal arguments before gate state', async () => {
  const rejected = [
    [...serveArgs, '--journal-id', 'other-journal'], [...serveArgs, '--journal-id', ''],
    [...serveArgs, '--journal-id=other-journal'],
    [...serveArgs, '--journal-id'], [...serveArgs, '--journal-id', 'aukora-gate-pilot', '--journal-id', 'aukora-gate-pilot'],
    [...serveArgs, '--journal-id', 'other-journal', '--journal-id', 'aukora-gate-pilot'],
    ['verify', '--home', '/fixture/gate', '--journal-id', 'aukora-gate-pilot'],
    ['verify-receipt', '--db', '/fixture/db', '--pub', '/fixture/pub', '--receipt', '/fixture/receipt', '--journal-id', 'aukora-gate-pilot'],
    ['unknown', '--journal-id', 'aukora-gate-pilot'],
  ]
  for (const args of rejected) {
    const refused = await runGateCli(args)
    assert.ok(refused.exit === 2 || refused.error?.code === 'ERR_PARSE_ARGS_INVALID_OPTION_VALUE')
    assert.deepEqual(refused.calls, [['umask', 0o027]])
    assert.equal(refused.gates.length, 0); assert.equal(refused.servers.length, 0)
  }
})

test('source gate unit adds only the journal argument and supplies the actual CLI binding', async () => {
  const source = await readFile(unitURL, 'utf8'), append = ' --journal-id aukora-gate-pilot'
  assert.equal(source.split(append).length - 1, 1)
  assert.equal(sha(source.replace(append, '')), '2e0098d22f217a76f847018585a7502e5f95ececec3cfc71849dd58143468861')
  const starts = source.split('\n').filter(line => line.startsWith('ExecStart='))
  assert.equal(starts.length, 1)
  const argv = starts[0].slice('ExecStart='.length).split(' ')
  assert.deepEqual(argv.slice(0, 4), ['/usr/bin/python3', '-I', '-S', '/usr/local/lib/aukora-boundary/gate-bootstrap'])
  assert.equal(argv[4], 'serve')
  const selected = await runGateCli(argv.slice(4))
  assert.equal(selected.error, null); assert.equal(selected.gates[0].journalId, 'aukora-gate-pilot')
  const refused = await runGateCli(argv.slice(4).map(value => value === 'aukora-gate-pilot' ? 'other-journal' : value))
  assert.equal(refused.exit, 2); assert.equal(refused.gates.length, 0)
})

test('gate CLI negative controls detect lost command, literal and duplicate journal guards', async () => {
  const source = await readFile(binURL, 'utf8')
  const command = "cmd !== 'serve' || ", literal = "o['journal-id'] !== 'aukora-gate-pilot'"
  const duplicate = "|| tokens.filter(token => token.kind === 'option' && token.name === 'journal-id').length !== 1"
  assert.ok([command, literal, duplicate].every(guard => source.includes(guard)))
  const missingCommand = await runGateCli(['verify', '--home', '/fixture/gate', '--journal-id', 'aukora-gate-pilot'], source.replace(command, ''))
  assert.equal(missingCommand.exit, 0); assert.ok(missingCommand.calls.some(([call]) => call === 'load-key'))
  const missingLiteral = await runGateCli([...serveArgs, '--journal-id', 'other-journal'], source.replace(literal, 'false'))
  assert.equal(missingLiteral.gates[0].journalId, 'other-journal')
  const missingDuplicate = await runGateCli([...serveArgs, '--journal-id', 'other-journal', '--journal-id', 'aukora-gate-pilot'], source.replace(duplicate, ''))
  assert.equal(missingDuplicate.gates[0].journalId, 'aukora-gate-pilot')
})
