// SPDX-License-Identifier: AGPL-3.0-or-later
// Disposable functional checks. Fixed toy keys are in memory only; no network,
// live store, credential, approval, build or installed-runtime qualification.
import assert from 'node:assert/strict'
import { createPrivateKey, createPublicKey, sign } from 'node:crypto'
import { appendFileSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { execFileSync } from 'node:child_process'
import { registerHooks } from 'node:module'
import { tmpdir } from 'node:os'
import { join, relative } from 'node:path'
import { fileURLToPath } from 'node:url'
import { DatabaseSync } from 'node:sqlite'

const root = fileURLToPath(new URL('../', import.meta.url))
const primeBase = 'f6c398869f709000233a2fe7962837d5ee2e2a13'
// Isolated source fixtures read only already-owned E and immutable D Git objects.
const citationBase = process.env.AUKORA_AURA_CITATION_BASE ?? 'c3f07af37d8e5dd291a655d0ba22f67115288d36'
const git = process.env.AUKORA_PRIME_CHECK_GIT ?? root
const citationGit = process.env.AUKORA_AURA_CHECK_GIT ?? git
const mutant = process.argv.includes('--mutant') ? process.argv[process.argv.indexOf('--mutant') + 1] : null
const mutations = {
  source: ["|| !sameSource(query.source, cited.source)", ''],
  owner: ['|| cited.owner_subject !== initial.subject', ''],
  id: ['|| (query.record_id !== undefined && query.record_id !== cited.record_id)', ''],
  current: ['|| !sameRecallRecord(record, finalRecord)', ''],
  reference: ['if (!sameSelector(query, currentQuery))', 'if (false)'],
  provider: ['getProvider?.() !== provider', 'false'],
  ordering: ['const finalRecord = await currentRecord(record.id)\n      if (getProvider?.() !== provider || !sameRecallRecord(record, finalRecord))',
    'if (getProvider?.() !== provider || !sameRecallRecord(record, await currentRecord(record.id)))'],
  wiring: ['recallAuraCitations(result.notes, {', 'recallAuraCitations([], {'],
  report: [', { dropped: 0, reasons: {} })', ')'],
  annotations: ['.map(note => ({ ...note, ...recallAnnotations(current.get(note.id)) }))', ''],
}
if (mutant && !mutations[mutant]) throw Error('unknown focused mutant')
let applied = false
registerHooks({
  resolve(specifier, context, next) {
    if (specifier.startsWith('node:')) return next(specifier, context)
    try { return next(specifier, context) } catch (error) {
      if (!context.parentURL || !specifier.startsWith('.')) throw error
      const url = new URL(specifier, context.parentURL)
      if (url.protocol !== 'file:') throw error
      const path = relative(root, fileURLToPath(url)).replaceAll('\\', '/')
      if (path.startsWith('../') || !git) throw error
      return { url: url.href, shortCircuit: true }
    }
  },
  load(url, context, next) {
    let loaded
    const missingPath = url.startsWith('file:') && !existsSync(fileURLToPath(url))
      ? relative(root, fileURLToPath(url)).replaceAll('\\', '/') : null
    if (missingPath && !missingPath.startsWith('../')) {
      const path = missingPath
      if (path.includes('..') || !git) throw Error('pinned Git source required')
      loaded = { format: path.endsWith('.json') ? 'json' : 'module', shortCircuit: true,
        source: execFileSync('git', ['show', (path === 'scripts/aura/collect-gate.mjs' ? citationBase : primeBase) + ':' + path],
          { cwd: path === 'scripts/aura/collect-gate.mjs' ? citationGit : git, encoding: 'utf8', maxBuffer: 8 * 1024 * 1024,
            env: { ...process.env, GIT_NO_LAZY_FETCH: '1' } }) }
    } else loaded = next(url, context)
    if (url.endsWith('/lib/index.js')) {
      // Disposable scheduling seam for a changed note/provider during the
      // existing final owner reread. Production files are never modified.
      const original = typeof loaded.source === 'string' ? loaded.source : Buffer.from(loaded.source).toString('utf8')
      const before = 'const currentRecords = async () => {\n              const currentPolicy = readOwnerPolicy(await owner.describe())'
      const after = before.replace('async () =>', 'async phase =>') + '\n              await globalThis.__kiraAuraFinalReadFixture?.(phase)'
      assert(original.includes(before), 'actual final reread seam must exist')
      loaded = { ...loaded, source: original.replace(before, after)
        .replace('new Map((await currentRecords()).map', "new Map((await currentRecords('outer')).map") }
    }
    if (mutant && ((['wiring', 'report', 'annotations'].includes(mutant) && url.endsWith('/lib/index.js'))
      || (!['wiring', 'report', 'annotations'].includes(mutant) && url.endsWith('/lib/aura-recall.mjs')))) {
      const [before, after] = mutations[mutant]
      const original = typeof loaded.source === 'string' ? loaded.source : Buffer.from(loaded.source).toString('utf8')
      const changed = mutant === 'provider' ? original.replaceAll(before, after) : original.replace(before, after)
      assert.notEqual(changed, original, 'production guard must exist')
      loaded = { ...loaded, source: changed }; applied = true
    }
    return loaded
  },
})
const { recallAuraCitations, AURA_RECALL_PROVIDER } = await import('../plugins/aukora-kira/lib/aura-recall.mjs')
const subject = 'aukora:1:' + '1'.repeat(64)
const h = n => String(n).repeat(64)
const note = { id: 'rem:' + h('a'), subject, statement: 'Synthetic gate observation for citation tests.',
  contentHash: h('b'), entryHash: h('c'), grantsAuthority: false,
  source: { state: 'UNLINKED', aura_source: { journal_id: 'aukora-gate-pilot', position: 1, hash: h('d') } },
  auraAssociation: { v: 1, kind: 'aukora-kira-aura-association/v1', note_id: 'rem:' + h('a'),
    source: { journal_id: 'aukora-gate-pilot', position: 1, hash: h('d') } }, aura: { index: 1, entryHash: h('c') } }
const query = { source: { journal_id: 'aukora-gate-pilot', position: 1, hash: h('d') }, record_id: h('e') }
const summary = { ok: true, status: 'complete', source: { journal_id: 'aukora-gate-pilot', key_sha256: h('f') },
  aura_head: { sequence: 1, id: h('e') }, coverage: { position: 1, hash: h('d') }, grants_authority: false,
  selected_head: { position: 1, hash: h('d') }, anchor_scope: 'provided-data-consistency-only; retrieval, provenance and witness independence unperformed',
  anchor_status: 'verified', anchors_checked: 1, anchored_head: { position: 1, hash: h('d') } }
const complete = { ok: true, status: 'verified', reason: null, grants_authority: false,
  citation: { record_id: h('e'), source: query.source, key_sha256: h('f'), owner_subject: subject,
    owner_pubkey_hex: h('2'), binding_digest: h('3'), grants_authority: false }, verification: summary }
const call = async (provider, options = {}) => (await recallAuraCitations([note],
  { getProvider: () => provider, currentRecord: async () => note, ...options }))[0]
const provider = { referenceForRecord: async id => id === note.id ? structuredClone(query) : null,
  readCitation: async () => structuredClone(complete) }
assert.equal((await call(provider)).status, 'verified')
assert.equal((await call(undefined)).reason, 'aura-recall:provider-unavailable')
assert.equal((await call({ ...provider, referenceForRecord: () => null })).reason, 'aura-recall:source-association-unavailable')
assert.equal((await call({ ...provider, readCitation: () => { throw Error('not public'); } })).status, 'undetermined')
console.log('PASS exact selector and explicit unavailable provenance')
for (const change of [
  r => { r.citation.source.hash = h('4') },
  r => { r.citation.owner_subject = 'aukora:1:' + h('5') },
  r => { r.citation.record_id = h('6') },
  r => { r.entry_body = 'PRIVATE fixture sentinel' },
  r => { r.grants_authority = true },
]) {
  const bad = { ...provider, readCitation: () => { const r = structuredClone(complete); change(r); return r } }
  assert.equal((await call(bad)).status, 'undetermined')
}
console.log('PASS wrong record/source/owner and private-result refusal')
let reads = 0
const changedRecord = { ...provider, readCitation: async () => { reads++; return structuredClone(complete) } }
assert.equal((await call(changedRecord, { currentRecord: async () => reads ? { ...note, contentHash: h('7') } : note })).status, 'undetermined')
let refs = 0
assert.equal((await call({ ...provider, referenceForRecord: () => (++refs === 1 ? query : { source: { ...query.source, hash: h('8') } }) })).status, 'undetermined')
let replacement = provider
const replaced = { ...provider, readCitation: async () => { replacement = provider; return structuredClone(complete) } }
replacement = replaced
assert.equal((await call(replaced, { getProvider: () => replacement })).status, 'undetermined')
let lookupCount = 0, eligible = true
assert.equal((await call({ ...provider, referenceForRecord: async () => {
  if (++lookupCount === 2) eligible = false
  return query
} }, { currentRecord: async () => eligible ? note : undefined })).status, 'undetermined')
lookupCount = 0
let mounted
mounted = { ...provider, referenceForRecord: async () => {
  if (++lookupCount === 2) mounted = undefined
  return query
} }
assert.equal((await call(mounted, { getProvider: () => mounted })).status, 'undetermined')
let currentReads = 0
mounted = provider
assert.equal((await call(provider, { getProvider: () => mounted, currentRecord: async () => {
  if (++currentReads === 2) mounted = undefined
  return note
} })).status, 'undetermined', 'provider identity must be checked after the final record await')
const incomplete = { ok: false, status: 'incomplete', reason: 'aura-collected:anchor-unperformed',
  grants_authority: false, citation: null, verification: { ...summary, ok: false, status: 'incomplete',
    reason: 'aura-collected:anchor-unperformed', anchor_status: 'unperformed', anchors_checked: 0 } }
delete incomplete.verification.anchored_head
assert.equal((await call({ ...provider, readCitation: () => incomplete })).reason, incomplete.reason)
console.log('PASS record/reference/provider freshness and incomplete anchor status')

const scratch = mkdtempSync(join(tmpdir(), 'kira-aura-check-'))
const savedEnv = new Map(['AUKORA_STATE', 'AUKORA_ROOM_LOG', 'AUKORA_OPENVIKING_HOME'].map(name => [name, process.env[name]]))
let db
try {
  process.env.AUKORA_STATE = scratch
  process.env.AUKORA_ROOM_LOG = join(scratch, 'absent-room.jsonl')
  process.env.AUKORA_OPENVIKING_HOME = join(scratch, 'absent-openviking')
  const { createTrackedMemory } = await import('../plugins/aukora-kira/lib/tracked-memory.mjs')
  const { apply } = await import('../plugins/aukora-kira/lib/index.js')
  const stateDir = join(scratch, 'memory')
  const memory = createTrackedMemory({ stateDir, subject })
  const remembered = await memory.remember({ text: 'The synthetic gate fixture records a refused action for citation testing.', from: 'fixture' })
  assert.equal(remembered.remembered, 1)
  let tracked = memory.read().notes[0]
  const historicalId = tracked.id
  const foreignMemory = createTrackedMemory({ stateDir, subject: 'aukora:1:' + h('9') })
  await foreignMemory.remember({ text: 'Foreign synthetic record must be excluded by the existing owner read policy.', from: 'fixture' })
  const services = new Map()
  let mountedProvider
  const ctx = { tools: { register: () => () => {} }, sessions: { get: () => undefined },
    effect: fn => { const dispose = fn(); dispose?.() }, on: () => () => {}, inject: () => {},
    emit: () => {}, logger: { warn: () => {} }, provide: (name, service) => services.set(name, service),
    reflect: { get: name => name === AURA_RECALL_PROVIDER ? mountedProvider : undefined } }
  await apply(ctx, { memoryOwner: { stateDir, subject, permittedPrivacy: ['local'] } })
  await Promise.resolve()
  const recall = services.get('kira.recall')
  assert(recall, 'actual active plugin must provide kira.recall')
  const missing = await recall.recall('synthetic gate fixture')
  assert.equal(missing.status, 'match'); assert.equal(missing.records.length, 1)
  assert.equal(missing.auraCitations.length, 1, 'active path must report provenance for the recalled record')
  assert.equal(missing.auraCitations[0].status, 'undetermined')
  assert.deepEqual(missing.records[0].rememberedChain, tracked.aura, 'tracked-chain annotation remains intact')
  assert.equal(typeof recall.citeRemembered, 'function')
  console.log('PASS actual active index wiring preserves tracked recall when provider absent')

  // Exact D source and B cryptography; host association is an explicit synthetic
  // fixture input, not a claim that deployed Kira already owns this association.
  const { createNostrCollectorCodec, createCollectorCitationReader, collectGateOnce } =
    await import('../scripts/aura/collect-gate.mjs')
  const { gateEntryBody, gateEntryHash, gatePublicKeySha256 } = await import('../scripts/aura/gate-snapshot.mjs')
  const records = await import('../plugins/aukora-nostr/lib/records.mjs')
  const identity = await import('../plugins/aukora-nostr/lib/identity.mjs')
  const events = await import('../plugins/aukora-nostr/lib/event.mjs')
  const toyPrivate = byte => createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.alloc(32, byte)]),
    format: 'der', type: 'pkcs8' })
  const gatePrivate = toyPrivate(1), gatePublic = createPublicKey(gatePrivate)
  const controllerPrivate = toyPrivate(2), controllerPublic = createPublicKey(controllerPrivate)
  const controllerHex = controllerPublic.export({ type: 'spki', format: 'der' }).subarray(-32).toString('hex')
  const authorSecretKeyHex = (3).toString(16).padStart(64, '0'), ownerSecret = (4).toString(16).padStart(64, '0')
  const authorPubkeyHex = events.publicKeyOf(authorSecretKeyHex), ownerPubkeyHex = events.publicKeyOf(ownerSecret)
  const statement = { subject, npub: identity.npubEncode(authorPubkeyHex), nostrPubkeyHex: authorPubkeyHex,
    handle: 'TEST', createdAt: '2026-01-01T00:00:00Z', safetyVersion: 2 }
  const binding = { domain: identity.NOSTR_BINDING_DOMAIN, statement,
    signature: sign(null, identity.bindingPreimage(statement), controllerPrivate).toString('hex'),
    approvalKeyDid: 'did:key:' + controllerHex, label: 'TEST' }
  const codec = await createNostrCollectorCodec({ records, authorSecretKeyHex, binding, controllerKeyHex: controllerHex,
    ownerSubject: subject, authorPubkeyHex, ownerPubkeyHex })
  const dbPath = join(scratch, 'source.db')
  db = new DatabaseSync(dbPath)
  db.exec('CREATE TABLE ledger(seq INTEGER PRIMARY KEY,at TEXT,event TEXT,proposal TEXT,target TEXT,base_sha TEXT,new_sha TEXT,detail TEXT,prev TEXT,hash TEXT,sig TEXT)')
  const entry = { seq: 1, at: '2026-01-01T00:00:00Z', event: 'refused', proposal: 'fixture-action',
    target: 'fixture.json', base_sha: null, new_sha: null, detail: '{"fixture":true}', prev: 'GENESIS' }
  entry.hash = gateEntryHash(gateEntryBody(entry)); entry.sig = sign(null, Buffer.from(entry.hash, 'hex'), gatePrivate).toString('base64')
  db.prepare('INSERT INTO ledger VALUES(?,?,?,?,?,?,?,?,?,?,?)').run(...Object.values(entry))
  const snapshotOptions = { dbPath, sourceId: 'aukora-gate-pilot', publicKeyPem: gatePublic.export({ type: 'spki', format: 'pem' }).toString(),
    expectedKeySha256: gatePublicKeySha256(gatePublic) }
  const storeDir = join(scratch, 'collector')
  assert.equal((await collectGateOnce({ snapshotOptions, storeDir, codec, now: () => 1767225600 })).ok, true)
  const record = JSON.parse(readFileSync(join(storeDir, 'gate-observations.nostr.jsonl'), 'utf8').trim())
  const anchors = [{ seq: 1, head: entry.hash, gate_fp: snapshotOptions.expectedKeySha256.slice(0, 16),
    entry_at: entry.at, anchored_at: '2026-01-01T00:01:00Z' }]
  // These are explicit disposable fixture capabilities, never production grants.
  const fixtureReadGuards = { isLive: () => true, hasReadGrant: owner => owner === subject }
  const reader = createCollectorCitationReader({ storeDir, snapshotOptions, codec, anchors }, fixtureReadGuards)
  const selected = { source: { journal_id: snapshotOptions.sourceId, position: 1, hash: entry.hash }, record_id: record.id }
  const associated = await memory.remember({ text: 'The synthetic gate fixture records a refused action for citation testing.', from: 'fixture' },
    { auraSource: { source: selected.source } })
  tracked = memory.read().notes.find(note => note.id === associated.ids[0])
  assert.notEqual(tracked.id, historicalId, 'new source-bound identity must not rewrite historical memory')
  const citeFor = result => result.auraCitations.find(citation => citation.recordId === tracked.id)
  mountedProvider = Object.freeze({
    referenceForRecord: id => memory.referenceForRecord(id),
    readCitation: selector => reader.readCitation(subject, selector),
  })
  const found = await recall.recall('synthetic gate fixture')
  assert.equal(found.auraCitations.length, 2)
  assert.equal(found.auraCitations.find(citation => citation.recordId === historicalId).status, 'undetermined')
  assert.equal(citeFor(found).status, 'verified', citeFor(found).reason)
  assert.equal(citeFor(found).citation.record_id, record.id)
  assert.deepEqual(citeFor(found).citation.source, selected.source)
  assert.equal(citeFor(found).ownerStatus, 'INTERIM')
  assert.equal(citeFor(found).citation.grants_authority, false)
  assert.deepEqual(found.records.find(note => note.id === tracked.id).rememberedChain, tracked.aura)
  assert(!JSON.stringify(found.auraCitations).includes('entry_body'))
  console.log('PASS active Kira -> actual pinned D/B cold reader, exact record and gate entry')

  // A remembered note remains valid when its advisory association disappears.
  // The final reread must retain the note and downgrade its earlier sidecar.
  const notePath = join(stateDir, 'remembered', tracked.id.slice(4) + '.json')
  const noteBytes = readFileSync(notePath)
  for (const change of ['association', 'provider']) {
    let stage = 'idle', selectedReads = 0
    mountedProvider = { referenceForRecord: async id => {
      const reference = await memory.referenceForRecord(id)
      if (id === tracked.id && ++selectedReads === 2) stage = 'helper-final'
      return reference
    }, readCitation: s => reader.readCitation(subject, s) }
    globalThis.__kiraAuraFinalReadFixture = () => {
      if (stage === 'helper-final') { stage = 'outer-final'; return }
      if (stage !== 'outer-final') return
      stage = 'changed'
      if (change === 'provider') mountedProvider = undefined
      else {
        const stored = JSON.parse(noteBytes)
        delete stored.auraAssociation
        writeFileSync(notePath, JSON.stringify(stored) + '\n')
      }
    }
    try {
      const finalChanged = await recall.recall('synthetic gate fixture')
      assert.equal(stage, 'changed', 'fixture change occurs in the outer final reread')
      assert(finalChanged.records.some(note => note.id === tracked.id), 'ordinary remembered note survives')
      assert.equal(citeFor(finalChanged).status, 'undetermined')
      assert.equal(citeFor(finalChanged).citation, null)
      assert.equal(citeFor(finalChanged).reason, change === 'provider' ? 'aura-recall:provider-changed' : 'aura-recall:reference-changed')
    } finally {
      delete globalThis.__kiraAuraFinalReadFixture
      writeFileSync(notePath, noteBytes)
    }
  }
  console.log('PASS final reread retains memory and downgrades changed association/provider sidecars')

  const churnChainPath = join(stateDir, 'remembered/aura.jsonl')
  const churnJournalPath = join(stateDir, 'remembered/journal.jsonl')
  const churnChain = readFileSync(churnChainPath), churnJournal = readFileSync(churnJournalPath)
  const secondAssociation = await memory.remember({ text: 'A second synthetic gate fixture observation tests a provider remount.', from: 'fixture-second' },
    { auraSource: { source: selected.source } })
  let secondProviderReads = 0
  const secondProvider = { referenceForRecord: id => memory.referenceForRecord(id),
    readCitation: s => { secondProviderReads++; return reader.readCitation(subject, s) } }
  const firstProvider = { referenceForRecord: id => memory.referenceForRecord(id), readCitation: async s => {
    const result = await reader.readCitation(subject, s)
    mountedProvider = secondProvider
    return result
  } }
  mountedProvider = firstProvider
  globalThis.__kiraAuraFinalReadFixture = phase => {
    if (phase === 'outer') mountedProvider = firstProvider
  }
  try {
    const churn = await recall.recall('synthetic gate fixture')
    assert.equal(secondProviderReads, 0, 'one recall batch must not select a remounted provider')
    assert(churn.records.some(note => note.id === secondAssociation.ids[0]))
    assert(churn.auraCitations.every(citation => citation.status === 'undetermined'))
  } finally {
    delete globalThis.__kiraAuraFinalReadFixture
    for (const id of secondAssociation.ids) rmSync(join(stateDir, 'remembered', id.slice(4) + '.json'))
    writeFileSync(churnChainPath, churnChain); writeFileSync(churnJournalPath, churnJournal)
  }
  console.log('PASS one recall batch stays on one provider during remount and return')

  const unanchored = createCollectorCitationReader({ storeDir, snapshotOptions, codec }, fixtureReadGuards)
  mountedProvider = { referenceForRecord: id => memory.referenceForRecord(id), readCitation: s => unanchored.readCitation(subject, s) }
  const missingAnchor = await recall.recall('synthetic gate fixture')
  assert.equal(missingAnchor.status, 'match')
  assert.equal(citeFor(missingAnchor).status, 'undetermined')
  assert.equal(citeFor(missingAnchor).citation, null)
  assert.equal(citeFor(missingAnchor).verification.anchor_status, 'unperformed')
  const missingStore = createCollectorCitationReader({ storeDir: join(scratch, 'absent-store'), snapshotOptions, codec, anchors }, fixtureReadGuards)
  mountedProvider = { referenceForRecord: id => memory.referenceForRecord(id), readCitation: s => missingStore.readCitation(subject, s) }
  assert.equal(citeFor(await recall.recall('synthetic gate fixture')).status, 'undetermined')
  assert(!existsSync(join(scratch, 'absent-store')))
  console.log('PASS actual cold missing anchor/store preserves memory and explicit incomplete provenance')

  const { nextEntry } = await import('../plugins/aukora-kira/lib/memory-journal.mjs')
  const journalPath = join(stateDir, 'remembered/journal.jsonl')
  let expireOnRead = true
  mountedProvider = { referenceForRecord: id => memory.referenceForRecord(id), readCitation: async s => {
    const checked = await reader.readCitation(subject, s)
    if (expireOnRead) {
      expireOnRead = false
      const entries = readFileSync(journalPath, 'utf8').trim().split('\n').map(JSON.parse)
      const expiry = nextEntry({ previous: entries.at(-1), op: 'expire', id: tracked.id,
        objectDigest: entries.find(e => e.id === tracked.id).objectDigest, actor: 'fixture',
        reason: 'synthetic expiry during lookup', at: '2026-10-04T00:00:00.000Z' })
      appendFileSync(journalPath, JSON.stringify(expiry) + '\n')
    }
    return checked
  } }
  const stale = await recall.recall('synthetic gate fixture')
  assert.equal(stale.records.find(note => note.id === tracked.id).staleness.flagged, true)
  assert.equal(citeFor(stale).status, 'verified', 'verification does not promote stale text to truth')
  const chainPath = join(stateDir, 'remembered/aura.jsonl')
  const chainBytes = readFileSync(chainPath)
  mountedProvider = { referenceForRecord: () => selected, readCitation: async s => {
    const checked = await reader.readCitation(subject, s)
    appendFileSync(chainPath, 'broken synthetic fixture line\n')
    return checked
  } }
  try {
    const unreadable = await recall.recall('synthetic gate fixture')
    assert.equal(unreadable.status, 'undetermined')
    assert.equal(unreadable.reason, 'aura-recall:memory-unavailable')
    assert.equal(unreadable.records.length, 0)
  } finally { writeFileSync(chainPath, chainBytes) }
  mountedProvider = { referenceForRecord: () => selected, readCitation: s => reader.readCitation(subject, s) }
  assert.equal(citeFor(await recall.recall('synthetic gate fixture')).status, 'verified')
  console.log('PASS filtered-note handling, fresh stale annotations, reread failure and unchanged recovery')
} finally {
  db?.close()
  delete globalThis.__kiraAuraFinalReadFixture
  for (const [name, value] of savedEnv) { if (value === undefined) delete process.env[name]; else process.env[name] = value }
  rmSync(scratch, { recursive: true, force: true })
}
if (mutant) assert(applied, 'focused mutation must be applied')
console.log('PASS 9 functional groups; source fixture only, host association/provider still required')
