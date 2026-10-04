// SPDX-License-Identifier: AGPL-3.0-or-later
// Actual collector + SQLite + pinned Nostr implementation; synthetic source only.
// No credentials are generated/persisted, no source services or network are used.
// node scripts/aura/checks/collector.mjs [--mutant NAME]
// Optional AUKORA_RECORDS_MODULE names B's source during the pre-merge join.
// Missing pinned dependencies are evaluated from the SAME existing Git store,
// never copied into a runtime/vendor tree. Normal installed checks use local files.
import assert from 'node:assert/strict'
import { createPrivateKey, createPublicKey, sign, createHash } from 'node:crypto'
import { mkdtempSync, readFileSync, writeFileSync, existsSync, rmSync, mkdirSync, symlinkSync, linkSync } from 'node:fs'
import { join, relative, resolve } from 'node:path'
import { tmpdir } from 'node:os'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { execFileSync, spawnSync } from 'node:child_process'
import { registerHooks } from 'node:module'
import { DatabaseSync } from 'node:sqlite'

const root = fileURLToPath(new URL('../../../', import.meta.url))
const base = '6f9e6f433924800e365c7e400a6c4bdb30bcdc79'
const recordFile = resolve(process.env.AUKORA_RECORDS_MODULE ?? join(root, 'plugins/aukora-nostr/lib/records.mjs'))
const recordRoot = recordFile.endsWith('/plugins/aukora-nostr/lib/records.mjs')
  ? recordFile.slice(0, -'/plugins/aukora-nostr/lib/records.mjs'.length) : root
const mutantAt = process.argv.indexOf('--mutant')
const mutant = mutantAt < 0 ? null : process.argv[mutantAt + 1]
const mutants = {
  dedupe: ['collect-gate.mjs', 'for (let i = retained.coverage.position; i < input.records.length; i++)',
    'for (let i = 0; i < input.records.length; i++)'],
  checkpoint: ['collect-gate.mjs', 'checkCheckpoint(store.checkpoint, input.source, retained, events, bytes)', 'void 0'],
  signature: ['gate-snapshot.mjs', "if (!verify(null, Buffer.from(entry.hash, 'hex'), publicKeyOf(publicKey), signature))", 'if (false)'],
  sequence: ['gate-snapshot.mjs', "if (entry.seq !== verified_head.position + 1) return incomplete('sequence-gap')", 'void 0'],
  history: ['collect-gate.mjs', /    if \(retained\.coverage\.position > input\.selected_head\.position\)[\s\S]*?    let appended = 0/,
    '    let appended = 0'],
  ordering: ['collect-gate.mjs', /      const written = await store\.append\(line\)[\s\S]*?      await store\.checkpointWrite\(checkpointAt\(input\.source, retained, events, bytes, record\.position\)\)/,
    `      events.push(event); bytes.push(bytes.at(-1) + Buffer.byteLength(line)); retained = candidate; appended++
      await store.checkpointWrite(checkpointAt(input.source, retained, events, bytes, record.position))
      await afterAppend?.({ position: record.position, event_id: event.id })
      await store.append(line)`],
  anchor: ['verify-collected.mjs', "if (record.hash !== anchor.head || record.entry.at !== anchor.entry_at) refuse('anchor-source-mismatch')", 'void 0'],
  hardlink: ['collect-gate.mjs', ' or info.st_nlink!=1', ''],
  'citation-owner': ['collect-gate.mjs', "if (typeof authenticatedOwnerSubject !== 'string' || authenticatedOwnerSubject !== scope.owner_subject)", 'if (false)'],
  'citation-brand': ['collect-gate.mjs', 'if (!scope) throw', 'if (false) throw'],
  'citation-source': ['verify-collected.mjs', '&& record.source.position === requested.position && record.source.hash === requested.hash', '&& record.source.position === requested.position'],
  'citation-id': ['verify-collected.mjs', 'if (record_id !== null && match.record_id !== record_id)', 'if (false)'],
  'citation-anchor': ['verify-collected.mjs', "if (anchorResult.anchor_status === 'unperformed')", 'if (false)'],
  'citation-live': ['collect-gate.mjs', /if \(disposed \|\| !synchronousTrue\(isLive\) \|\| disposed\)/g, 'if (false)'],
  'citation-grant': ['collect-gate.mjs', 'if (!synchronousTrue(hasReadGrant, authenticatedOwnerSubject))', 'if (false)'],
  'citation-final-access': ['collect-gate.mjs', 'if (after !== null) return refused(after)', 'void 0'],
  'provider-live': ['records-provider.mjs', /if \(disposed \|\| !synchronousTrue\(isLive\) \|\| disposed\)/g, 'if (false)'],
  'provider-grant': ['records-provider.mjs', 'if (!synchronousTrue(hasReadGrant, ownerSubject))', 'if (false)'],
  'provider-final': ['records-provider.mjs', 'const result = await Reflect.apply(read, reader, [ownerSubject, selected])\n        checkAccess()',
    'const result = await Reflect.apply(read, reader, [ownerSubject, selected])'],
  'context-pin': ['context.mjs', 'gatePublicKeySha256(source.public_key_pem) !== source.key_sha256', 'false'],
  'context-material': ['context.mjs', 'publicKeyOf(authorSecretKeyHex) !== configuration.nostr.author_pubkey_hex', 'false'],
  'capture-source': ['context.mjs', 'row.hash !== selected.ledger_hash', 'false'],
  'capture-receipt': ['context.mjs', 'canonicalJson(detail.receipt) !== receiptBytes', 'false'],
  'citation-reentrant': ['collect-gate.mjs', /!synchronousTrue\(isLive\) \|\| disposed/g, '!synchronousTrue(isLive)'],
  'provider-reentrant': ['records-provider.mjs', /!synchronousTrue\(isLive\) \|\| disposed/g, '!synchronousTrue(isLive)'],
  'scope-disposal': ['records-provider.mjs', 'const assertOpen = () => { if (revoked !== null) refuse(revoked) }', 'const assertOpen = () => {}'],
  'scope-expiry': ['records-provider.mjs', "if (time >= grant.expires_at_ms) fail('read-grant-expired')", 'void 0'],
  'scope-lifecycle': ['records-provider.mjs', 'lifecycle.genesis_instance_id !== bound.genesis_instance_id', 'false'],
  'scope-summary': ['records-provider.mjs', 'const verification = publicColdSummary(envelope.verification, bound)',
    'const verification = envelope.verification'],
  'scope-failure-summary': ['records-provider.mjs', 'const verification = envelope.verification === null ? null : publicColdSummary(envelope.verification, scope.bound)',
    'const verification = envelope.verification'],
  'capture-getter': ['context.mjs', "const receiptProposal = Object.getOwnPropertyDescriptor(selected.receipt, 'proposal')",
    'const receiptProposal = { value: selected.receipt.proposal, enumerable: true }'],
}
if (mutant && !mutants[mutant]) throw Error('Unknown focused mutant')
let mutationApplied = false
const sourcePath = url => {
  if (url.startsWith('aukora-git:///')) return url.slice('aukora-git:///'.length)
  if (!url.startsWith('file:')) return null
  const path = fileURLToPath(url)
  for (const prefix of [root, recordRoot]) {
    const rel = relative(prefix, path)
    if (!rel.startsWith('../') && !rel.startsWith('..\\') && !rel.startsWith('/')) return rel.replaceAll('\\', '/')
  }
  return null
}
registerHooks({
  resolve(specifier, context, next) {
    if (specifier.startsWith('node:')) return next(specifier, context)
    if (context.parentURL?.startsWith('aukora-git:') && (specifier.startsWith('.') || specifier.startsWith('/')))
      return { url: new URL(specifier, context.parentURL).href, shortCircuit: true }
    try { return next(specifier, context) } catch (error) {
      if (!context.parentURL || (!specifier.startsWith('.') && !specifier.startsWith('file:'))) throw error
      const url = new URL(specifier, context.parentURL).href, rel = sourcePath(url)
      if (!rel || !/^(plugins\/aukora-(nostr|aumlok)\/|packages\/contracts\/src\/)/u.test(rel)) throw error
      return { url: `aukora-git:///${rel}`, shortCircuit: true }
    }
  },
  load(url, context, next) {
    let loaded
    if (url.startsWith('aukora-git:///')) {
      const rel = sourcePath(url)
      loaded = { format: 'module', shortCircuit: true,
        source: execFileSync('git', ['show', `${base}:${rel}`], { cwd: root, encoding: 'utf8', maxBuffer: 4 * 1024 * 1024 }) }
    } else loaded = next(url, context)
    if (mutant && [`/scripts/aura/${mutants[mutant][0]}`,
      `/packages/boundary-gate/host/aura/${mutants[mutant][0]}`].some(suffix => url.endsWith(suffix))) {
      const [file, match, replacement] = mutants[mutant]
      const text = typeof loaded.source === 'string' ? loaded.source : Buffer.from(loaded.source).toString('utf8')
      const altered = text.replace(match, replacement)
      assert.notEqual(altered, text, `focused ${file} guard must exist`)
      loaded = { ...loaded, source: altered }; mutationApplied = true
    }
    return loaded
  },
})

const { collectGateOnce, createNostrCollectorCodec, createCollectorCitationReader, openCollectorStore } = await import('../collect-gate.mjs')
const { readGateSnapshot, gateEntryBody, gateEntryHash, gatePublicKeySha256 } = await import('../gate-snapshot.mjs')
const { verifyCollectorStore, verifyCollected } = await import('../verify-collected.mjs')
const { parseAuraConfiguration, createAuraCollectorContext, createConfiguredAuraRecords, createRetainedAuraReadScope, readProtectedAuraData,
  createGateCaptureReferenceResolver, auraConfigurationSha256, createProtectedAuraProposalReadScope,
  validateAuraPublicProposalReadScope } =
  await import('../../../packages/boundary-gate/host/aura/context.mjs')
const { createAuraRecordsProvider, createRetainedProposalReadScope, createProposalScopedAuraRecordsProvider } =
  await import('../../../packages/boundary-gate/host/aura/records-provider.mjs')
const { canonicalJson } = await import('../../../packages/contracts/src/json.mjs')
const { runAuraAction } = await import('../../../packages/boundary-gate/host/aura/entry.mjs')
// Missing sparse source is read from the exact current Git checkpoint in memory.
// No library files are materialized, and no structural-codec fallback is accepted.
const recordURL = existsSync(recordFile) ? pathToFileURL(recordFile).href : (() => {
  if (process.env.AUKORA_RECORDS_MODULE) throw Error('Requested actual B records source unavailable')
  execFileSync('git', ['cat-file', '-e', `${base}:plugins/aukora-nostr/lib/records.mjs`], { cwd: root, stdio: 'pipe' })
  return 'aukora-git:///plugins/aukora-nostr/lib/records.mjs'
})()
const records = await import(recordURL)
const identity = await import(new URL('./identity.mjs', recordURL))
const eventTools = await import(new URL('./event.mjs', recordURL))

// Fixed toy/RFC-style test inputs in memory only, never key generation or files.
const privateFromByte = byte => createPrivateKey({ key: Buffer.concat([
  Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.alloc(32, byte)]), format: 'der', type: 'pkcs8' })
const gatePrivate = privateFromByte(1), gatePublic = createPublicKey(gatePrivate)
const controllerPrivate = privateFromByte(2), controllerPublic = createPublicKey(controllerPrivate)
const controllerHex = controllerPublic.export({ type: 'spki', format: 'der' }).subarray(-32).toString('hex')
const scalar = n => n.toString(16).padStart(64, '0')
const authorSecretKeyHex = scalar(3), ownerSecretKeyHex = scalar(4)
const authorPubkeyHex = eventTools.publicKeyOf(authorSecretKeyHex), ownerPubkeyHex = eventTools.publicKeyOf(ownerSecretKeyHex)
const ownerSubject = `aukora:1:${'1'.repeat(64)}`
// Explicit disposable host lifecycle and read grant; these are never production defaults.
const testReadGuards = Object.freeze({ isLive: () => true,
  hasReadGrant: subject => subject === ownerSubject || subject === `aukora:1:${'2'.repeat(64)}` })
const statement = { subject: ownerSubject, npub: identity.npubEncode(authorPubkeyHex), nostrPubkeyHex: authorPubkeyHex,
  handle: 'TEST', createdAt: '2026-01-01T00:00:00Z', safetyVersion: 2 }
const binding = { domain: identity.NOSTR_BINDING_DOMAIN, statement,
  signature: sign(null, identity.bindingPreimage(statement), controllerPrivate).toString('hex'),
  approvalKeyDid: `did:key:${controllerHex}`, label: 'TEST' }
const codec = await createNostrCollectorCodec({ records, authorSecretKeyHex, binding,
  controllerKeyHex: controllerHex, ownerSubject, authorPubkeyHex, ownerPubkeyHex })
const gatePem = gatePublic.export({ type: 'spki', format: 'pem' }).toString()
const testRoot = mkdtempSync(join(tmpdir(), 'aura-collector-check-'))
let db
try {
  const dbPath = join(testRoot, 'source.db')
  db = new DatabaseSync(dbPath)
  db.exec(`PRAGMA journal_mode=WAL; CREATE TABLE ledger(seq INTEGER PRIMARY KEY,at TEXT,event TEXT,proposal TEXT,target TEXT,
    base_sha TEXT,new_sha TEXT,detail TEXT,prev TEXT,hash TEXT,sig TEXT);`)
  const insert = db.prepare('INSERT INTO ledger VALUES(?,?,?,?,?,?,?,?,?,?,?)')
  const entries = []
  function appendSource(event = 'refused', changed = false) {
    const e = { seq: entries.length + 1, at: '2026-01-01T00:00:00Z', event,
      proposal: `00000000-0000-4000-8000-${String(entries.length + 1).padStart(12, '0')}`, target: 'fixture.json', base_sha: null, new_sha: null,
      detail: JSON.stringify({ fixture: true, observed: event, changed }), prev: entries.at(-1)?.hash ?? 'GENESIS' }
    e.hash = gateEntryHash(gateEntryBody(e)); e.sig = sign(null, Buffer.from(e.hash, 'hex'), gatePrivate).toString('base64')
    insert.run(...Object.values(e)); entries.push(e); return e
  }
  const snapshotOptions = { dbPath, sourceId: 'gate-fixture', publicKeyPem: gatePem, expectedKeySha256: gatePublicKeySha256(gatePublic) }
  const storeDir = join(testRoot, 'output'), logPath = join(storeDir, 'gate-observations.nostr.jsonl'), cpPath = join(storeDir, 'checkpoint.json')
  let builds = 0
  const countedCodec = { verify: codec.verify, build: input => { builds++; return codec.build(input) } }
  const run = extra => collectGateOnce({ snapshotOptions, storeDir, codec: countedCodec, now: () => 1767225600, ...extra })
  appendSource('start')
  const sourceBytes = readFileSync(dbPath), walBytes = readFileSync(`${dbPath}-wal`)
  const crashed = await run({ afterAppend: () => { throw Error('synthetic crash after fsync, before checkpoint') } })
  assert.equal(crashed.status, 'incomplete'); assert.equal(builds, 1)
  const firstLine = readFileSync(logPath, 'utf8'); assert.equal(firstLine.trim().split('\n').length, 1)
  assert(!existsSync(cpPath), 'checkpoint must not lead its durable append')
  assert.deepEqual(readFileSync(dbPath), sourceBytes); assert.deepEqual(readFileSync(`${dbPath}-wal`), walBytes)
  const resumed = await run(); assert.equal(resumed.ok, true); assert.equal(builds, 1)
  assert.equal(resumed.deduplicated, 1); assert.equal(readFileSync(logPath, 'utf8'), firstLine)
  console.log('PASS append-before-checkpoint, committed dedupe, source DB/WAL unchanged')

  appendSource('apply'); appendSource('refused')
  const next = await run(); assert.equal(next.ok, true); assert.equal(next.appended, 2); assert.equal(next.grants_authority, false)
  const replay = await run(); assert.equal(replay.ok, true); assert.equal(replay.appended, 0); assert.equal(builds, 3)
  const source = readGateSnapshot(snapshotOptions); assert.equal(source.ok, true)
  const anchors = [{ seq: 3, head: entries[2].hash, gate_fp: snapshotOptions.expectedKeySha256.slice(0, 16),
    entry_at: entries[2].at, anchored_at: '2026-01-01T00:01:00Z' }]
  const cold = await verifyCollectorStore({ storeDir, snapshotOptions, codec, anchors })
  assert.equal(cold.ok, true); assert.equal(cold.coverage.position, 3); assert.equal(cold.anchor_status, 'verified')
  assert(!JSON.stringify(cold).includes('fixture.json')); assert(!JSON.stringify(cold).includes('entry_body'))
  const notAnchored = await verifyCollectorStore({ storeDir, snapshotOptions, codec })
  assert.equal(notAnchored.ok, false); assert.equal(notAnchored.anchor_status, 'unperformed')
  assert.equal((await run({ snapshotOptions: { ...snapshotOptions, expectedKeySha256: '0'.repeat(64) } })).ok, false)
  assert.equal((await run({ snapshotOptions: { ...snapshotOptions, dbPath: join(testRoot, 'missing.db') } })).ok, false)
  assert(!existsSync(join(testRoot, 'missing.db')), 'read-only source open must never create a missing database')
  console.log('PASS approved/refusal fixture observations, replay, real encrypted cold reopen, provided anchor consistency')

  const citationContext = { storeDir, snapshotOptions, codec, anchors }
  const citationDbBytes = readFileSync(dbPath), citationWalBytes = readFileSync(`${dbPath}-wal`)
  const citationLog = readFileSync(logPath), citationCheckpoint = readFileSync(cpPath)
  const citationReader = createCollectorCitationReader(citationContext, testReadGuards)
  const selected = { source: { journal_id: snapshotOptions.sourceId, position: 2, hash: entries[1].hash } }
  const savedEvents = readFileSync(logPath, 'utf8').trimEnd().split('\n').map(JSON.parse)
  const cited = await citationReader.readCitation(ownerSubject, selected)
  assert.equal(cited.ok, true); assert.equal(cited.status, 'verified'); assert.equal(cited.reason, null)
  assert.equal(cited.citation.record_id, savedEvents[1].id)
  assert.deepEqual(cited.citation.source, selected.source)
  assert.equal(cited.citation.key_sha256, snapshotOptions.expectedKeySha256)
  assert.equal(cited.citation.owner_subject, ownerSubject); assert.equal(cited.citation.owner_pubkey_hex, ownerPubkeyHex)
  assert.equal(cited.citation.binding_digest, records.verifyRecord(savedEvents[1], { binding, controllerKeyHex: controllerHex, ownerSubject, authorPubkeyHex, ownerPubkeyHex }).binding_digest)
  assert.equal(cited.grants_authority, false); assert.equal(cited.citation.grants_authority, false)
  assert.deepEqual(Object.keys(cited).sort(), ['ok','status','reason','grants_authority','citation','verification'].sort())
  assert.deepEqual(Object.keys(cited.citation).sort(), ['record_id','source','key_sha256','owner_subject','owner_pubkey_hex','binding_digest','grants_authority'].sort())
  assert(!JSON.stringify(cited).includes('fixture.json')); assert(!JSON.stringify(cited).includes('entry_body'))
  assert(!JSON.stringify(cited).includes(savedEvents[0].id), 'no unrelated record list may escape')
  assert.equal((await citationReader.readCitation(ownerSubject, { ...selected, record_id: savedEvents[1].id })).ok, true)
  const wrongSource = await citationReader.readCitation(ownerSubject, { source: { ...selected.source, hash: 'a'.repeat(64) } })
  assert.equal(wrongSource.reason, 'aura-citation:source-not-found'); assert.equal(wrongSource.citation, null)
  for (const foreign of [{ ...selected.source, position: 1 }, { ...selected.source, journal_id: 'another-gate' }]) {
    const unknown = await citationReader.readCitation(ownerSubject, { source: foreign })
    assert.equal(unknown.reason, 'aura-citation:source-not-found'); assert.equal(unknown.citation, null)
  }
  const wrongId = await citationReader.readCitation(ownerSubject, { ...selected, record_id: savedEvents[0].id })
  assert.equal(wrongId.reason, 'aura-citation:record-id-mismatch'); assert.equal(wrongId.citation, null)
  const noAnchorReader = createCollectorCitationReader({ storeDir, snapshotOptions, codec }, testReadGuards)
  const noAnchorCitation = await noAnchorReader.readCitation(ownerSubject, selected)
  assert.equal(noAnchorCitation.status, 'incomplete'); assert.equal(noAnchorCitation.citation, null)
  assert.equal(noAnchorCitation.verification.anchor_status, 'unperformed')
  const wrongOwner = await citationReader.readCitation(`aukora:1:${'2'.repeat(64)}`, selected)
  assert.equal(wrongOwner.reason, 'aura-citation:owner-mismatch'); assert.equal(wrongOwner.citation, null)
  assert.equal(wrongOwner.verification, null, 'wrong owner must refuse before reading source/store')
  assert.throws(() => createCollectorCitationReader({ ...citationContext, codec: countedCodec }), error => error.code === 'aura-citation:owner-scope-unavailable')
  let codecAccesses = 0
  const capturedReader = createCollectorCitationReader({ storeDir, snapshotOptions, anchors,
    get codec() { codecAccesses++; return codecAccesses === 1 ? codec : countedCodec } }, testReadGuards)
  assert.equal(codecAccesses, 1, 'owner brand and verifier must retain the same captured codec')
  assert.equal((await capturedReader.readCitation(ownerSubject, selected)).ok, true)
  assert.throws(() => createCollectorCitationReader(citationContext),
    error => error.code === 'aura-citation:read-guard-unconfigured')
  let live = true, granted = true, decrypts = 0
  const guardedCodec = await createNostrCollectorCodec({ records: { ...records,
    decryptRecord(...args) { decrypts++; return records.decryptRecord(...args) } },
    authorSecretKeyHex, binding, controllerKeyHex: controllerHex,
    ownerSubject, authorPubkeyHex, ownerPubkeyHex })
  const guardedContext = { storeDir, snapshotOptions, anchors, codec: guardedCodec }
  const retainedGrant = Object.freeze({ fixture: 'original-read-grant' })
  let currentGrant = retainedGrant
  const readGuards = { isLive: () => live,
    hasReadGrant: subject => subject === ownerSubject && granted && currentGrant === retainedGrant }
  const guardedReader = createCollectorCitationReader(guardedContext, readGuards)
  const cachedRead = guardedReader.readCitation
  assert.equal((await cachedRead(ownerSubject, selected)).ok, true)
  let beforeDecrypts = decrypts
  live = false
  const inactiveRead = await cachedRead(ownerSubject, selected)
  if (mutant === 'citation-live') console.log(`MUTANT-OBSERVATION cached inactive read: ok=${inactiveRead.ok}, status=${inactiveRead.status}`)
  assert.equal(inactiveRead.reason, 'aura-citation:owner-inactive')
  assert.equal(decrypts, beforeDecrypts, 'inactive cached handle must refuse before actual B decryption')
  live = true; granted = false
  const revokedRead = await cachedRead(ownerSubject, selected)
  if (mutant === 'citation-grant') console.log(`MUTANT-OBSERVATION cached revoked-grant read: ok=${revokedRead.ok}, status=${revokedRead.status}`)
  assert.equal(revokedRead.reason, 'aura-citation:read-grant-unavailable')
  assert.equal(decrypts, beforeDecrypts, 'revoked read grant must refuse before actual B decryption')
  granted = true; currentGrant = Object.freeze({ fixture: 'replacement-read-grant' })
  assert.equal((await cachedRead(ownerSubject, selected)).reason, 'aura-citation:read-grant-unavailable')
  currentGrant = retainedGrant
  const pendingCitation = cachedRead(ownerSubject, selected)
  guardedReader.dispose()
  const disposedDuringRead = await pendingCitation
  if (mutant === 'citation-final-access') console.log(`MUTANT-OBSERVATION disposed in-flight read: ok=${disposedDuringRead.ok}, status=${disposedDuringRead.status}`)
  assert.equal(disposedDuringRead.reason, 'aura-citation:owner-inactive')
  assert.equal(disposedDuringRead.citation, null); assert.equal(disposedDuringRead.verification, null)
  beforeDecrypts = decrypts
  assert.equal((await cachedRead(ownerSubject, selected)).reason, 'aura-citation:owner-inactive')
  assert.equal(decrypts, beforeDecrypts)
  const revokeReader = createCollectorCitationReader(guardedContext, readGuards)
  const pendingRevocation = revokeReader.readCitation(ownerSubject, selected)
  granted = false
  assert.equal((await pendingRevocation).reason, 'aura-citation:read-grant-unavailable')
  granted = true
  for (const badGuards of [
    { isLive: () => 'true', hasReadGrant: () => true },
    { isLive: () => true, hasReadGrant: () => Promise.resolve(true) },
    { isLive() { throw Error('private fixture diagnostic') }, hasReadGrant: () => true },
  ]) {
    const rejected = await createCollectorCitationReader(guardedContext, badGuards).readCitation(ownerSubject, selected)
    assert.equal(rejected.ok, false); assert.equal(rejected.citation, null); assert.equal(rejected.verification, null)
    assert(!JSON.stringify(rejected).includes('private fixture diagnostic'))
  }
  let unhandledGuardRejection = false
  const observeUnhandledGuard = () => { unhandledGuardRejection = true }
  process.on('unhandledRejection', observeUnhandledGuard)
  try {
    const badAsyncReader = createCollectorCitationReader(guardedContext, {
      isLive: () => true, hasReadGrant: () => Promise.reject(Error('private fixture diagnostic')) })
    const rejected = await badAsyncReader.readCitation(ownerSubject, selected)
    assert.equal(rejected.reason, 'aura-citation:read-grant-unavailable')
    assert.equal(rejected.citation, null); assert.equal(rejected.verification, null)
    await new Promise(resolve => setImmediate(resolve))
    assert.equal(unhandledGuardRejection, false, 'misconfigured async guard must not leak its rejected diagnostic')
  } finally { process.removeListener('unhandledRejection', observeUnhandledGuard) }
  let reentrantReader, reentrantLiveCalls = 0
  reentrantReader = createCollectorCitationReader(guardedContext, {
    isLive() { if (++reentrantLiveCalls === 4) reentrantReader.dispose(); return true },
    hasReadGrant: subject => subject === ownerSubject,
  })
  const beforeReentrantDecrypts = decrypts
  const reentrantCitation = await reentrantReader.readCitation(ownerSubject, selected)
  if (mutant === 'citation-reentrant') console.log(`MUTANT-OBSERVATION reentrant disposed reader: ok=${reentrantCitation.ok}, status=${reentrantCitation.status}`)
  assert.equal(reentrantLiveCalls, 4, 'disposal must occur in the final live callback after cold verification')
  assert(decrypts > beforeReentrantDecrypts, 'reentrancy refusal must discard an actual decrypted cold verification result')
  assert.equal(reentrantCitation.reason, 'aura-citation:owner-inactive')
  assert.equal(reentrantCitation.citation, null); assert.equal(reentrantCitation.verification, null)
  console.log('PASS cached handle disposal, exact retained read grant, in-flight revocation and strict host guard refusals')
  const configuration = { version: 1, kind: 'aukora-aura-context/v1', owner_subject: ownerSubject,
    store_dir: storeDir, python_executable: '/usr/bin/python3', anchors,
    source: { db_path: dbPath, source_id: snapshotOptions.sourceId, public_key_pem: gatePem,
      key_sha256: snapshotOptions.expectedKeySha256, max_rows: 50000, max_bytes: 16 * 1024 * 1024, max_record_bytes: 48 * 1024 },
    nostr: { binding, controller_key_hex: controllerHex, author_pubkey_hex: authorPubkeyHex,
      owner_pubkey_hex: ownerPubkeyHex, author_secret_path: '/fixture-only/existing-author.hex' } }
  const parsedConfiguration = parseAuraConfiguration(JSON.stringify(configuration))
  const loadedContext = await createAuraCollectorContext(parsedConfiguration, { authorSecretKeyHex })
  assert.equal((await runAuraAction('verify', loadedContext)).ok, true)
  assert.equal((await runAuraAction('collect', loadedContext)).appended, 0)
  await assert.rejects(runAuraAction('activate', loadedContext), error => error.code === 'aura-entry:action-invalid')
  for (const change of [
    { ...configuration, first_run: true },
    { ...configuration, python_executable: '/fixture-only/python3' },
    { ...configuration, owner_subject: `aukora:1:${'2'.repeat(64)}` },
    { ...configuration, source: { ...configuration.source, key_sha256: 'a'.repeat(64) } },
    { ...configuration, nostr: { ...configuration.nostr, owner_pubkey_hex: [ownerPubkeyHex] } },
    { ...configuration, source: { ...configuration.source, db_path: '/fixture-only/../source.db' } },
  ]) assert.throws(() => parseAuraConfiguration(JSON.stringify(change)), error => error.code.startsWith('aura-context:'))
  const mismatchedSourcePin = { ...configuration, anchors: [], source: { ...configuration.source, key_sha256: 'a'.repeat(64) } }
  if (mutant === 'context-pin') {
    const accepted = parseAuraConfiguration(JSON.stringify(mismatchedSourcePin))
    console.log(`MUTANT-OBSERVATION mismatched SPKI configuration: accepted=${accepted !== null}`)
  }
  assert.throws(() => parseAuraConfiguration(JSON.stringify(mismatchedSourcePin)),
    error => error.code === 'aura-context:source-invalid')
  assert.throws(() => parseAuraConfiguration('{"version":1,' + JSON.stringify(configuration).slice(1)))
  await assert.rejects(createAuraCollectorContext(configuration, { authorSecretKeyHex }),
    error => error.code === 'aura-context:configuration-unrecognized')
  await assert.rejects(createAuraCollectorContext(parsedConfiguration, { authorSecretKeyHex: ownerSecretKeyHex }),
    error => error.code === 'aura-context:scoped-material-unavailable')
  assert.throws(() => readProtectedAuraData(dbPath), error => error.code === 'aura-context:protected-data-unavailable')
  assert.equal((await runAuraAction('verify', loadedContext)).ok, true)
  // Exercise the actual entry's main block. Dependencies remain cached Git
  // objects in memory, and invalid argv refuses before any protected data read.
  const entryPath = join(root, 'packages/boundary-gate/host/aura/entry.mjs')
  const cliBootstrap = `
    import {registerHooks} from 'node:module';
    import {execFileSync} from 'node:child_process';
    import {relative} from 'node:path';
    import {fileURLToPath,pathToFileURL} from 'node:url';
    const [root,base,entry,...args]=JSON.parse(process.argv[1]);
    registerHooks({
      resolve(specifier,context,next) {
        if(specifier.startsWith('node:'))return next(specifier,context);
        if(context.parentURL?.startsWith('aukora-git:')&&specifier.startsWith('.'))
          return {url:new URL(specifier,context.parentURL).href,shortCircuit:true};
        try{return next(specifier,context)}catch(error){
          if(!context.parentURL||!specifier.startsWith('.'))throw error;
          const rel=relative(root,fileURLToPath(new URL(specifier,context.parentURL)));
          if(!/^(plugins\\/aukora-(nostr|aumlok)\\/|packages\\/contracts\\/src\\/)/u.test(rel))throw error;
          return {url:'aukora-git:///'+rel,shortCircuit:true};
        }
      },
      load(url,context,next) {
        if(!url.startsWith('aukora-git:///'))return next(url,context);
        return {format:'module',shortCircuit:true,source:execFileSync('git',
          ['show',base+':'+url.slice('aukora-git:///'.length)],{cwd:root,encoding:'utf8'})};
      }
    });
    process.argv=[process.execPath,entry,...args];
    await import(pathToFileURL(entry).href);
  `
  for (const args of [['activate'], ['verify', '/candidate-selected/config.json']]) {
    const child = spawnSync(process.execPath, ['--input-type=module', '--eval', cliBootstrap,
      JSON.stringify([root, base, entryPath, ...args])], { encoding: 'utf8', timeout: 15000 })
    assert.equal(child.error, undefined)
    assert.equal(child.status, 2, child.stderr)
    assert.deepEqual(JSON.parse(child.stdout), { ok: false, status: 'incomplete',
      reason: 'aura-entry:action-invalid', grants_authority: false })
  }
  console.log('PASS fixed host configuration, actual binding/source/scoped-key pins and finite collect/verify actions')

  const memoryRecordId = `rem:${'a'.repeat(64)}` // Synthetic association only; never installed provenance.
  let providerLive = true, providerGranted = true, associationsRead = 0
  const providerGuards = { isLive: () => providerLive, hasReadGrant: subject => subject === ownerSubject && providerGranted }
  // Keep generic provider mechanics in explicitly synthetic owner/read guards.
  // Production configured publication below requires a retained proposal scope.
  const fixtureOwnerProvider = (loaded, { referenceForRecord = null, ...guards }) =>
    createAuraRecordsProvider({ ownerSubject, referenceForRecord, ...guards,
      reader: createCollectorCitationReader(loaded.collectorContext, guards) })
  assert.throws(() => createConfiguredAuraRecords(loadedContext, providerGuards),
    error => error.code === 'aura-context:proposal-grant-unconfigured')
  const provider = fixtureOwnerProvider(loadedContext, { ...providerGuards,
    referenceForRecord: id => { associationsRead++; return id === memoryRecordId ? selected : null } })
  const cachedReference = provider.service.referenceForRecord, cachedCitation = provider.service.readCitation
  assert.deepEqual(await cachedReference(memoryRecordId), selected)
  assert.equal((await cachedCitation(selected)).citation.record_id, savedEvents[1].id)
  assert.equal(await cachedReference(`rem:${'b'.repeat(64)}`), null)
  const absentAssociation = fixtureOwnerProvider(loadedContext, providerGuards)
  assert.equal(await absentAssociation.service.referenceForRecord(memoryRecordId), null)
  providerLive = false
  if (mutant === 'provider-live') {
    const accepted = await cachedReference(memoryRecordId)
    console.log(`MUTANT-OBSERVATION inactive association read: returned=${accepted !== null}`)
  }
  await assert.rejects(cachedReference(memoryRecordId), error => error.code === 'aura-citation:owner-inactive')
  assert.equal((await cachedCitation(selected)).reason, 'aura-citation:owner-inactive')
  providerLive = true; providerGranted = false
  if (mutant === 'provider-grant') {
    const accepted = await cachedReference(memoryRecordId)
    console.log(`MUTANT-OBSERVATION revoked-grant association read: returned=${accepted !== null}`)
  }
  await assert.rejects(cachedReference(memoryRecordId), error => error.code === 'aura-citation:read-grant-unavailable')
  providerGranted = true
  let releaseAssociation
  const duringAssociation = fixtureOwnerProvider(loadedContext, { ...providerGuards,
    referenceForRecord: () => new Promise(resolve => { releaseAssociation = resolve }) })
  const pendingAssociation = duringAssociation.service.referenceForRecord(memoryRecordId)
  duringAssociation.dispose(); releaseAssociation(selected)
  await assert.rejects(pendingAssociation, error => error.code === 'aura-citation:owner-inactive')
  let releaseRead
  const duringCitation = createAuraRecordsProvider({ ownerSubject, ...providerGuards, referenceForRecord: null,
    reader: { dispose() {}, readCitation: async (...args) => {
      const actual = await citationReader.readCitation(...args)
      await new Promise(resolve => { releaseRead = resolve })
      return actual
    } } })
  const pendingProviderCitation = duringCitation.service.readCitation(selected)
  while (!releaseRead) await new Promise(resolve => setImmediate(resolve))
  duringCitation.dispose(); releaseRead()
  const lateProviderRead = await pendingProviderCitation
  if (mutant === 'provider-final') console.log(`MUTANT-OBSERVATION disposed provider read: ok=${lateProviderRead.ok}, status=${lateProviderRead.status}`)
  assert.equal(lateProviderRead.reason, 'aura-citation:owner-inactive')
  assert.equal(lateProviderRead.citation, null); assert.equal(lateProviderRead.verification, null)
  let reentrantProvider, providerLiveCalls = 0, verifiedBeforeDisposal = false
  reentrantProvider = createAuraRecordsProvider({ ownerSubject, referenceForRecord: null,
    isLive() { if (++providerLiveCalls === 6) reentrantProvider.dispose(); return true },
    hasReadGrant: subject => subject === ownerSubject,
    reader: { dispose() {}, async readCitation(...args) {
      const result = await citationReader.readCitation(...args)
      verifiedBeforeDisposal = result.ok === true
      return result
    } } })
  const reentrantProviderCitation = await reentrantProvider.service.readCitation(selected)
  if (mutant === 'provider-reentrant') console.log(`MUTANT-OBSERVATION reentrant disposed provider: ok=${reentrantProviderCitation.ok}, status=${reentrantProviderCitation.status}`)
  assert.equal(providerLiveCalls, 6); assert.equal(verifiedBeforeDisposal, true)
  assert.equal(reentrantProviderCitation.reason, 'aura-citation:owner-inactive')
  assert.equal(reentrantProviderCitation.citation, null); assert.equal(reentrantProviderCitation.verification, null)
  const beforeAssociationsRead = associationsRead
  provider.dispose()
  await assert.rejects(cachedReference(memoryRecordId), error => error.code === 'aura-citation:owner-inactive')
  assert.equal((await cachedCitation(selected)).reason, 'aura-citation:owner-inactive')
  assert.equal(associationsRead, beforeAssociationsRead)
  let getterCalls = 0
  const malformedLookup = fixtureOwnerProvider(loadedContext, { ...providerGuards,
    referenceForRecord: () => Object.defineProperty({}, 'source', { enumerable: true, get() { getterCalls++; return selected.source } }) })
  await assert.rejects(malformedLookup.service.referenceForRecord(memoryRecordId),
    error => error.code === 'aura-citation:association-invalid')
  assert.equal(getterCalls, 0)
  assert.equal((await absentAssociation.service.readCitation({ source: { ...selected.source, hash: [selected.source.hash] } })).ok, false)
  console.log('PASS host records provider, synthetic exact association, both cached methods and in-flight disposal refusals')
  // Caller-context mutation cannot redirect a retained owner-bound reader.
  citationContext.storeDir = join(testRoot, 'missing-output'); citationContext.snapshotOptions = {}
  assert.equal((await citationReader.readCitation(ownerSubject, selected)).ok, true)
  assert(!existsSync(citationContext.storeDir), 'citation path must be read-only')
  for (const bad of [{ ...selected, owner_subject: ownerSubject }, { ...selected, storeDir },
    { source: { ...selected.source, hash: [selected.source.hash] } }, { source: { ...selected.source, position: '2' } },
    { ...selected, record_id: [savedEvents[1].id] }, Object.defineProperty({}, 'source', { enumerable: true, get(){ throw Error('must not invoke selector getter') } })]) {
    const rejected = await citationReader.readCitation(ownerSubject, bad)
    assert.equal(rejected.ok, false); assert.equal(rejected.citation, null); assert.equal(rejected.verification, null)
  }
  assert.deepEqual(readFileSync(dbPath), citationDbBytes); assert.deepEqual(readFileSync(`${dbPath}-wal`), citationWalBytes)
  assert.deepEqual(readFileSync(logPath), citationLog); assert.deepEqual(readFileSync(cpPath), citationCheckpoint)
  console.log('PASS actual owner-scoped citations, exact ID/source, cold-only reads and no private/unrelated payload egress')

  // Actual signed SQLite source + actual B collection; only the host action
  // response and eventual note lookup are synthetic. No live capture is claimed.
  const appliedEntry = appendSource('apply', true)
  const appliedReceipt = { v: 2, proposal: appliedEntry.proposal, target: appliedEntry.target,
    base_sha: 'a'.repeat(64), new_sha: 'b'.repeat(64), applied_at: appliedEntry.at }
  const appliedReceiptSig = sign(null, Buffer.from(JSON.stringify(appliedReceipt)), gatePrivate).toString('base64')
  appliedEntry.detail = JSON.stringify({ receipt: appliedReceipt, receipt_sig: appliedReceiptSig })
  appliedEntry.hash = gateEntryHash(gateEntryBody(appliedEntry))
  appliedEntry.sig = sign(null, Buffer.from(appliedEntry.hash, 'hex'), gatePrivate).toString('base64')
  db.prepare('UPDATE ledger SET detail=?,hash=?,sig=? WHERE seq=?').run(
    appliedEntry.detail, appliedEntry.hash, appliedEntry.sig, appliedEntry.seq)
  const laterEntry = appendSource('fixture-later-head')
  const captureConfigurationText = JSON.stringify({ ...configuration, store_dir: join(testRoot, 'capture-output') })
  const captureConfiguration = parseAuraConfiguration(captureConfigurationText)
  const captureContext = await createAuraCollectorContext(captureConfiguration, { authorSecretKeyHex })
  const hashText = text => createHash('sha256').update(text, 'utf8').digest('hex')
  const captureBinding = Object.freeze({ owner_subject: ownerSubject, proposal_id: appliedEntry.proposal,
    source: Object.freeze({ journal_id: snapshotOptions.sourceId, position: appliedEntry.seq, hash: appliedEntry.hash,
      key_sha256: snapshotOptions.expectedKeySha256 }),
    receipt_sha256: hashText(canonicalJson(appliedReceipt)),
    context_sha256: hashText(captureConfigurationText), release_sha: '1'.repeat(40),
    genesis_instance_id: '00000000-0000-4000-8000-000000000001' })
  const fixtureNow = 1767225600000
  const fixtureGrant = { ...captureBinding, version: 1, kind: 'aukora-aura-proposal-read-grant/v1',
    issued_at_ms: fixtureNow - 1000, expires_at_ms: fixtureNow + 299000, grants_authority: false, custody: 'INTERIM' }
  const fixtureLifecycle = { version: 1, kind: 'aukora-aura-read-lifecycle/v1',
    context_sha256: captureBinding.context_sha256, release_sha: captureBinding.release_sha,
    genesis_instance_id: captureBinding.genesis_instance_id }
  // Invented issuer data for disposable source checks only. No root grant is
  // issued, no file custody/installed authorization is inferred from this seam.
  const makeFixtureScope = (overrides = {}) => createRetainedProposalReadScope(captureBinding, {
    readGrant: () => structuredClone(fixtureGrant), readLifecycle: () => structuredClone(fixtureLifecycle),
    isLive: () => providerLive && providerGranted, now: () => fixtureNow, ...overrides })
  const captureScope = makeFixtureScope()
  assert.equal(auraConfigurationSha256(captureConfiguration), hashText(captureConfigurationText))
  assert.throws(() => parseAuraConfiguration('\ufeff' + captureConfigurationText), error => error.code === 'aura-context:configuration-invalid')
  const newlineConfiguration = parseAuraConfiguration(captureConfigurationText + '\n')
  assert.equal(auraConfigurationSha256(newlineConfiguration), hashText(captureConfigurationText + '\n'))
  assert.notEqual(auraConfigurationSha256(newlineConfiguration), auraConfigurationSha256(captureConfiguration),
    'accepted whitespace is part of exact retained protected context bytes')
  assert.equal(validateAuraPublicProposalReadScope(captureConfiguration, captureScope), true,
    'public validator checks actual signed row without loading an author key')
  assert.throws(() => auraConfigurationSha256({ ...captureConfiguration }), error => error.code === 'aura-context:configuration-unrecognized')
  assert.throws(() => createProtectedAuraProposalReadScope(captureConfiguration, captureBinding,
    { isLive: () => true, now: () => fixtureNow }), error => /^aura-(citation|context):/u.test(error.code))
  const captureResolver = createGateCaptureReferenceResolver(captureContext, { proposalScope: captureScope })
  const actionResult = { applied: true, state: 'applied', receipt: appliedReceipt, receipt_sig: appliedReceiptSig,
    ledger_seq: appliedEntry.seq, ledger_hash: appliedEntry.hash, message: 'fixture' }
  let receiptGetterCalls = 0
  const getterReceipt = { ...appliedReceipt }
  Object.defineProperty(getterReceipt, 'proposal', { enumerable: true, get() { receiptGetterCalls++; return appliedEntry.proposal } })
  assert.throws(() => captureResolver.referenceForAppliedAction({ ...actionResult, receipt: getterReceipt }),
    error => error.code === 'aura-context:capture-result-invalid')
  if (mutant === 'capture-getter') console.log(`MUTANT-OBSERVATION nested receipt getter invoked=${receiptGetterCalls}`)
  assert.equal(receiptGetterCalls, 0, 'nested receipt accessor must refuse without invocation')
  const resolvedCapture = captureResolver.referenceForAppliedAction(actionResult)
  assert.deepEqual(resolvedCapture, { source: { journal_id: snapshotOptions.sourceId,
    position: appliedEntry.seq, hash: appliedEntry.hash } })
  assert.notEqual(resolvedCapture.source.position, laterEntry.seq, 'capture must retain its specific action, never latest head')
  const captureDbBytes = readFileSync(dbPath), captureWalBytes = readFileSync(`${dbPath}-wal`)
  assert.equal((await runAuraAction('collect', captureContext)).ok, true)
  const captureProvider = createConfiguredAuraRecords(captureContext, { proposalScope: captureScope,
    referenceForRecord: id => id === memoryRecordId ? resolvedCapture : null })
  const actualAssociation = await captureProvider.service.referenceForRecord(memoryRecordId)
  const actualCaptureCitation = await captureProvider.service.readCitation(actualAssociation)
  assert.equal(actualCaptureCitation.ok, true)
  assert.deepEqual(actualCaptureCitation.citation.source, resolvedCapture.source)
  const captureEvents = readFileSync(join(testRoot, 'capture-output/gate-observations.nostr.jsonl'), 'utf8').trim().split('\n').map(JSON.parse)
  assert.equal(actualCaptureCitation.citation.record_id, captureEvents[appliedEntry.seq - 1].id)
  // A root-retained grant is a production precondition; these tests deliberately
  // cannot provision its fixed files or infer protected custody from callback data.
  assert.throws(() => createRetainedAuraReadScope(captureContext, captureBinding,
    { isLive: () => true, now: () => fixtureNow }), error => /^aura-(citation|context):/u.test(error.code))
  for (const field of ['owner_subject', 'proposal_id', 'receipt_sha256', 'context_sha256', 'release_sha', 'genesis_instance_id']) {
    const changed = structuredClone(fixtureGrant)
    changed[field] = field === 'owner_subject' ? `aukora:1:${'2'.repeat(64)}`
      : field === 'proposal_id' || field === 'genesis_instance_id' ? '00000000-0000-4000-8000-000000000002'
        : field === 'release_sha' ? '2'.repeat(40) : '2'.repeat(64)
    assert.throws(() => makeFixtureScope({ readGrant: () => changed }), error => error.code === 'aura-citation:read-grant-mismatch', field)
  }
  for (const change of [grant => { grant.source.hash = '2'.repeat(64) }, grant => { grant.source.key_sha256 = '2'.repeat(64) },
    grant => { grant.source.position++ }, grant => { grant.source.journal_id = 'another-journal' },
    grant => { grant.expires_at_ms = grant.issued_at_ms + 300001 }, grant => { grant.grants_authority = true },
    grant => { grant.custody = 'ENROLLED' }, grant => { grant.extra = true }]) {
    const changed = structuredClone(fixtureGrant); change(changed)
    assert.throws(() => makeFixtureScope({ readGrant: () => changed }), error => /^aura-citation:/u.test(error.code))
  }
  assert.throws(() => makeFixtureScope({ readGrant: () => null }), error => error.code === 'aura-citation:read-grant-invalid')
  assert.throws(() => makeFixtureScope({ readGrant: () => { throw Error('synthetic missing grant') } }),
    error => error.code === 'aura-citation:read-grant-unavailable')
  assert.throws(() => makeFixtureScope({ readGrant: async () => fixtureGrant }), error => error.code === 'aura-citation:read-grant-invalid')
  let grantGetterCalls = 0
  const getterGrant = { ...fixtureGrant }
  Object.defineProperty(getterGrant, 'source', { enumerable: true, get() { grantGetterCalls++; return fixtureGrant.source } })
  assert.throws(() => makeFixtureScope({ readGrant: () => getterGrant }), error => error.code === 'aura-citation:read-grant-invalid')
  assert.equal(grantGetterCalls, 0, 'protected grant data accessor must not run')
  assert.throws(() => makeFixtureScope({ now: () => fixtureGrant.expires_at_ms }), error => error.code === 'aura-citation:read-grant-expired')
  assert.throws(() => makeFixtureScope({ now: () => fixtureGrant.issued_at_ms - 1 }), error => error.code === 'aura-citation:read-grant-not-yet-valid')
  assert.throws(() => createConfiguredAuraRecords(captureContext, { proposalScope: { ...captureScope } }),
    error => error.code === 'aura-context:proposal-grant-unconfigured')
  for (const alter of [value => { value.proposal_id = '00000000-0000-4000-8000-000000000002' },
    value => { value.receipt_sha256 = '2'.repeat(64) }, value => { value.context_sha256 = '2'.repeat(64) }]) {
    const changedBinding = structuredClone(captureBinding); alter(changedBinding)
    const changedScope = createRetainedProposalReadScope(changedBinding, {
      readGrant: () => ({ ...structuredClone(fixtureGrant), ...changedBinding }),
      readLifecycle: () => ({ ...fixtureLifecycle, context_sha256: changedBinding.context_sha256 }),
      isLive: () => true, now: () => fixtureNow })
    assert.throws(() => createConfiguredAuraRecords(captureContext, { proposalScope: changedScope }),
      error => error.code === 'aura-context:proposal-binding-mismatch')
    assert.throws(() => validateAuraPublicProposalReadScope(captureConfiguration, changedScope),
      error => error.code === 'aura-context:proposal-binding-mismatch')
  }
  console.log('PASS configured scope requires retained grant, exact canonical owner/proposal/source/context/receipt and bounded INTERIM data')

  let scopedRawReads = 0
  const scopedReader = { dispose() {}, async readCitation() { scopedRawReads++; return structuredClone(actualCaptureCitation) } }
  const scopedProvider = createProposalScopedAuraRecordsProvider({ ownerSubject, scope: makeFixtureScope(), reader: scopedReader,
    referenceForRecord: () => ({ source: { ...resolvedCapture.source, hash: '2'.repeat(64) } }) })
  assert.equal(await scopedProvider.service.referenceForRecord(memoryRecordId), null)
  const wrongScopedRead = await scopedProvider.service.readCitation({ source: { ...resolvedCapture.source, hash: '2'.repeat(64) } })
  assert.equal(wrongScopedRead.citation, null); assert.equal(scopedRawReads, 0)
  assert.equal((await scopedProvider.service.readCitation(actualAssociation)).ok, true); assert.equal(scopedRawReads, 1)
  const mutableResult = structuredClone(actualCaptureCitation)
  const mutableProvider = createProposalScopedAuraRecordsProvider({ ownerSubject, scope: makeFixtureScope(), referenceForRecord: null,
    reader: { dispose() {}, async readCitation() { return mutableResult } } })
  const detachedResult = await mutableProvider.service.readCitation(actualAssociation)
  assert.equal(detachedResult.ok, true)
  assert(Object.isFrozen(detachedResult) && Object.isFrozen(detachedResult.citation) && Object.isFrozen(detachedResult.citation.source))
  assert(Object.isFrozen(detachedResult.verification) && Object.isFrozen(detachedResult.verification.source)
    && Object.isFrozen(detachedResult.verification.coverage) && Object.isFrozen(detachedResult.verification.aura_head))
  mutableResult.citation.source.hash = '2'.repeat(64); mutableResult.verification.source.journal_id = 'changed-source'
  mutableResult.verification.coverage.position = 0
  assert.deepEqual(detachedResult, actualCaptureCitation, 'result must retain detached public evidence, not adapter-owned mutable references')
  let verificationGetterCalls = 0
  const getterResult = structuredClone(actualCaptureCitation)
  Object.defineProperty(getterResult.verification, 'source', { enumerable: true,
    get() { verificationGetterCalls++; return actualCaptureCitation.verification.source } })
  const getterProvider = createProposalScopedAuraRecordsProvider({ ownerSubject, scope: makeFixtureScope(), referenceForRecord: null,
    reader: { dispose() {}, async readCitation() { return getterResult } } })
  const getterDenied = await getterProvider.service.readCitation(actualAssociation)
  assert.equal(getterDenied.ok, false); assert.equal(getterDenied.verification, null); assert.equal(verificationGetterCalls, 0)
  const secretSummary = { ...structuredClone(actualCaptureCitation), verification: { ...structuredClone(actualCaptureCitation.verification),
    private_payload: { note: 'synthetic forbidden summary data' } } }
  const secretProvider = createProposalScopedAuraRecordsProvider({ ownerSubject, scope: makeFixtureScope(), referenceForRecord: null,
    reader: { dispose() {}, async readCitation() { return secretSummary } } })
  assert.equal((await secretProvider.service.readCitation(actualAssociation)).verification, null)
  const incompleteGetter = { ok: false, status: 'incomplete', reason: 'aura-citation:source-not-found', grants_authority: false,
    citation: null, verification: getterResult.verification }
  const incompleteProvider = createProposalScopedAuraRecordsProvider({ ownerSubject, scope: makeFixtureScope(), referenceForRecord: null,
    reader: { dispose() {}, async readCitation() { return incompleteGetter } } })
  assert.equal((await incompleteProvider.service.readCitation(actualAssociation)).verification, null); assert.equal(verificationGetterCalls, 0)
  const actualFailedSummary = structuredClone(noAnchorCitation)
  const failedSummaryProvider = createProposalScopedAuraRecordsProvider({ ownerSubject, scope: makeFixtureScope(), referenceForRecord: null,
    reader: { dispose() {}, async readCitation() { return actualFailedSummary } } })
  const detachedFailure = await failedSummaryProvider.service.readCitation(actualAssociation)
  assert.deepEqual(detachedFailure, noAnchorCitation, 'actual incomplete cold evidence remains public and accurate')
  assert(Object.isFrozen(detachedFailure.verification) && Object.isFrozen(detachedFailure.verification.coverage))
  actualFailedSummary.verification.coverage.position = 0
  assert.deepEqual(detachedFailure, noAnchorCitation, 'incomplete summary must also detach from adapter-owned data')
  const detachedScope = makeFixtureScope()
  assert.throws(() => detachedScope.checkOwner(`aukora:1:${'2'.repeat(64)}`), error => error.code === 'aura-citation:owner-mismatch')
  assert.equal(detachedScope.checkOwner(ownerSubject), true, 'a wrong caller cannot revoke another owner grant')
  for (const lifecycleField of ['release_sha', 'genesis_instance_id', 'context_sha256']) {
    const lifecycle = structuredClone(fixtureLifecycle)
    const changingScope = makeFixtureScope({ readLifecycle: () => lifecycle })
    lifecycle[lifecycleField] = lifecycleField === 'genesis_instance_id' ? '00000000-0000-4000-8000-000000000002'
      : lifecycleField === 'release_sha' ? '2'.repeat(40) : '2'.repeat(64)
    assert.throws(() => changingScope.checkOwner(ownerSubject), error => error.code === 'aura-citation:read-lifecycle-mismatch')
    Object.assign(lifecycle, fixtureLifecycle)
    assert.throws(() => changingScope.checkOwner(ownerSubject), error => error.code === 'aura-citation:read-lifecycle-mismatch', 'restore cannot revive revoked instance')
  }
  const changedGrant = structuredClone(fixtureGrant)
  const retainedScope = makeFixtureScope({ readGrant: () => changedGrant })
  changedGrant.expires_at_ms--
  assert.throws(() => retainedScope.checkOwner(ownerSubject), error => error.code === 'aura-citation:read-grant-changed')
  changedGrant.expires_at_ms++
  assert.throws(() => retainedScope.checkOwner(ownerSubject), error => error.code === 'aura-citation:read-grant-changed')
  let scopedClock = fixtureNow
  const rollbackScope = makeFixtureScope({ now: () => scopedClock })
  scopedClock--
  assert.throws(() => rollbackScope.checkOwner(ownerSubject), error => error.code === 'aura-citation:read-clock-rollback')
  scopedClock = fixtureNow
  assert.throws(() => rollbackScope.checkOwner(ownerSubject), error => error.code === 'aura-citation:read-clock-rollback')
  let callbackScope, callbackArmed = false
  callbackScope = makeFixtureScope({ isLive() { if (callbackArmed) callbackScope.dispose(); return true } })
  callbackArmed = true
  assert.throws(() => callbackScope.checkOwner(ownerSubject), error => error.code === 'aura-citation:read-scope-disposed',
    'callback disposal must latch before a synchronous true can authorize')
  let recursiveScope, recursiveArmed = false
  recursiveScope = makeFixtureScope({ readGrant() {
    if (recursiveArmed) recursiveScope.checkOwner(ownerSubject)
    return structuredClone(fixtureGrant)
  } })
  recursiveArmed = true
  assert.throws(() => recursiveScope.checkOwner(ownerSubject), error => error.code === 'aura-citation:read-scope-reentrant')
  recursiveArmed = false
  assert.throws(() => recursiveScope.checkOwner(ownerSubject), error => error.code === 'aura-citation:read-scope-reentrant',
    'reentrant attempt permanently revokes its retained scope')
  console.log('PASS source refusal precedes raw read; grant edits, restart/release/context change and clock rollback permanently revoke')
  console.log('PASS public signed-row validator refuses receipt getters; scoped citation and public cold summary detach/freeze and refuse arbitrary fields')

  for (const adverse of ['expiry', 'restart', 'missing', 'dispose']) {
    let clock = fixtureNow, missing = false, reads = 0, releaseScopedRead
    const epoch = structuredClone(fixtureLifecycle)
    const scope = makeFixtureScope({ now: () => clock,
      readGrant() { if (missing) throw Error('synthetic removed grant'); return structuredClone(fixtureGrant) },
      readLifecycle: () => epoch })
    const inFlight = createProposalScopedAuraRecordsProvider({ ownerSubject, scope, referenceForRecord: null,
      reader: { dispose() {}, async readCitation() {
        reads++; await new Promise(resolve => { releaseScopedRead = resolve }); return structuredClone(actualCaptureCitation)
      } } })
    const pending = inFlight.service.readCitation(actualAssociation)
    while (!releaseScopedRead) await new Promise(resolve => setImmediate(resolve))
    if (adverse === 'expiry') clock = fixtureGrant.expires_at_ms
    if (adverse === 'restart') epoch.genesis_instance_id = '00000000-0000-4000-8000-000000000002'
    if (adverse === 'missing') missing = true
    if (adverse === 'dispose') inFlight.dispose()
    releaseScopedRead()
    const denied = await pending
    assert.equal(denied.ok, false, adverse); assert.equal(denied.citation, null, adverse); assert.equal(denied.verification, null, adverse)
    clock = fixtureNow; missing = false; Object.assign(epoch, fixtureLifecycle)
    assert.equal((await inFlight.service.readCitation(actualAssociation)).ok, false, 'expired/revoked state cannot revive')
    assert.equal(reads, 1, 'no second raw read after revoke'); inFlight.dispose()
  }
  assert.equal((await verifyCollectorStore(captureContext.collectorContext)).ok, true,
    'retained evidence cold verification remains distinct from a revoked live grant')
  console.log('PASS in-flight expiry/restart/missing/disposal discards actual citation; fresh grant required after restart, cold evidence remains intact')

  let probeLiveCalls = 0
  const probeResolver = createGateCaptureReferenceResolver(captureContext, {
    proposalScope: makeFixtureScope({ isLive() { probeLiveCalls++; return true } }) })
  probeLiveCalls = 0; probeResolver.referenceForAppliedAction(actionResult)
  const finalCaptureLiveCall = probeLiveCalls; probeResolver.dispose()
  let reentrantResolver, captureLiveCalls = 0, capturePhase = 'construction'
  reentrantResolver = createGateCaptureReferenceResolver(captureContext, {
    proposalScope: makeFixtureScope({ isLive() {
      if (capturePhase === 'read' && ++captureLiveCalls === finalCaptureLiveCall) reentrantResolver.dispose()
      return true
    } }) })
  capturePhase = 'read'
  let reentrantCapture, reentrantCaptureError
  try { reentrantCapture = reentrantResolver.referenceForAppliedAction(actionResult) }
  catch (error) { reentrantCaptureError = error }
  if (mutant === 'capture-reentrant') console.log(`MUTANT-OBSERVATION reentrant disposed capture: accepted=${!!reentrantCapture}`)
  assert.equal(reentrantCaptureError?.code, 'aura-context:capture-read-unavailable')
  assert.equal(reentrantCapture, undefined)
  assert.equal(captureLiveCalls, finalCaptureLiveCall, 'disposal must happen in the final live callback after exact signed-row and receipt verification')
  const alteredHashResult = { ...actionResult, ledger_hash: 'c'.repeat(64) }
  if (mutant === 'capture-source') console.log(`MUTANT-OBSERVATION altered action hash: accepted=${!!captureResolver.referenceForAppliedAction(alteredHashResult)}`)
  assert.throws(() => captureResolver.referenceForAppliedAction(alteredHashResult), error => error.code === 'aura-context:capture-source-mismatch')
  const alteredReceiptResult = { ...actionResult, receipt: { ...appliedReceipt, new_sha: 'd'.repeat(64) } }
  if (mutant === 'capture-receipt') console.log(`MUTANT-OBSERVATION altered action receipt: accepted=${!!captureResolver.referenceForAppliedAction(alteredReceiptResult)}`)
  assert.throws(() => captureResolver.referenceForAppliedAction(alteredReceiptResult), error => error.code === 'aura-context:capture-receipt-mismatch')
  assert.throws(() => captureResolver.referenceForAppliedAction({ ...actionResult, ledger_seq: laterEntry.seq, ledger_hash: laterEntry.hash }))
  providerGranted = false
  assert.throws(() => captureResolver.referenceForAppliedAction(actionResult), error => error.code === 'aura-context:capture-read-unavailable')
  providerGranted = true; captureResolver.dispose()
  assert.throws(() => captureResolver.referenceForAppliedAction(actionResult), error => error.code === 'aura-context:capture-read-unavailable')
  assert.deepEqual(readFileSync(dbPath), captureDbBytes); assert.deepEqual(readFileSync(`${dbPath}-wal`), captureWalBytes)
  captureProvider.dispose()
  db.prepare('DELETE FROM ledger WHERE seq>?').run(3); entries.splice(3)
  console.log('PASS exact applied-action association, later-head refusal, actual cold citation and receipt/hash tamper refusals')

  const goodLog = readFileSync(logPath, 'utf8'), goodCheckpoint = readFileSync(cpPath, 'utf8')
  const forged = JSON.parse(goodCheckpoint); forged.source_head.position = 999
  writeFileSync(cpPath, JSON.stringify(forged)); const before = builds
  assert.equal((await run()).ok, false); assert.equal(builds, before); assert.equal(readFileSync(logPath, 'utf8'), goodLog)
  writeFileSync(cpPath, goodCheckpoint)
  writeFileSync(logPath, goodLog.slice(0, -1)); assert.equal((await run()).ok, false); writeFileSync(logPath, goodLog)
  const tampered = goodLog.trimEnd().split('\n').map(JSON.parse); tampered[0].sig = '0'.repeat(128)
  writeFileSync(logPath, tampered.map(e => JSON.stringify(e)).join('\n') + '\n'); assert.equal((await run()).ok, false)
  assert.equal((await citationReader.readCitation(ownerSubject, selected)).citation, null)
  const badMac = JSON.parse(goodLog.trimEnd().split('\n')[0])
  const cipher = Buffer.from(badMac.content, 'base64'); cipher[cipher.length - 1] ^= 1
  badMac.content = cipher.toString('base64'); delete badMac.sig; badMac.id = eventTools.eventId(badMac)
  const signedBadMac = records.signRecord(badMac, authorSecretKeyHex)
  records.verifyRecord(signedBadMac, { binding, controllerKeyHex: controllerHex, ownerSubject, authorPubkeyHex, ownerPubkeyHex })
  writeFileSync(logPath, [signedBadMac, ...goodLog.trimEnd().split('\n').slice(1).map(JSON.parse)].map(e => JSON.stringify(e)).join('\n') + '\n')
  assert.equal((await run()).ok, false, 'a genuinely re-signed event with a bad NIP44 MAC must refuse')
  writeFileSync(logPath, '{"id":"' + '0'.repeat(64) + '",' + goodLog.slice(1))
  assert.equal((await run()).ok, false, 'duplicate JSON keys must refuse before append')
  writeFileSync(logPath, goodLog)
  console.log('PASS forged checkpoint, torn/duplicate stream, actual Schnorr signature and NIP44 MAC refusals')

  const badAnchors = anchors.map(a => ({ ...a, head: 'a'.repeat(64) }))
  assert.equal((await verifyCollectorStore({ storeDir, snapshotOptions, codec, anchors: badAnchors })).ok, false)
  const events = goodLog.trimEnd().split('\n').map(JSON.parse)
  const wrongOwnerCodec = await createNostrCollectorCodec({ records, authorSecretKeyHex, binding,
    controllerKeyHex: controllerHex, ownerSubject: `aukora:1:${'2'.repeat(64)}`, authorPubkeyHex, ownerPubkeyHex })
  assert.equal((await verifyCollected({ events, snapshot: source, codec: wrongOwnerCodec, gatePublicKey: gatePem, anchors })).ok, false)
  const misboundReader = createCollectorCitationReader({ storeDir, snapshotOptions, codec: wrongOwnerCodec, anchors }, testReadGuards)
  assert.equal((await misboundReader.readCitation(`aukora:1:${'2'.repeat(64)}`, selected)).citation, null)
  const held = await openCollectorStore(storeDir)
  try { assert.equal((await run()).reason, 'aura-collector:busy') } finally { await held.close() }
  console.log('PASS anchor divergence, real owner-binding mismatch and concurrent writer fence')

  const oldSig = entries[0].sig
  db.prepare('UPDATE ledger SET sig=? WHERE seq=1').run('A'.repeat(86) + '==')
  assert.equal(readGateSnapshot(snapshotOptions).ok, false)
  assert.equal((await citationReader.readCitation(ownerSubject, selected)).citation, null)
  db.prepare('UPDATE ledger SET sig=? WHERE seq=1').run(oldSig)
  db.prepare('DELETE FROM ledger WHERE seq=2').run()
  // A validly signed linked gap isolates the sequence check: hash/signature,
  // prev linkage and selected-head checks must all otherwise remain valid.
  const gapEnd = { ...entries[2], prev: entries[0].hash }
  gapEnd.hash = gateEntryHash(gateEntryBody(gapEnd))
  gapEnd.sig = sign(null, Buffer.from(gapEnd.hash, 'hex'), gatePrivate).toString('base64')
  db.prepare('UPDATE ledger SET prev=?,hash=?,sig=? WHERE seq=3').run(gapEnd.prev, gapEnd.hash, gapEnd.sig)
  assert.equal(readGateSnapshot(snapshotOptions).ok, false)
  const e2 = entries[1]; insert.run(...Object.values(e2))
  db.prepare('UPDATE ledger SET prev=?,hash=?,sig=? WHERE seq=3').run(entries[2].prev, entries[2].hash, entries[2].sig)
  db.prepare('DELETE FROM ledger WHERE seq=3').run()
  assert.equal((await run()).ok, false, 'a shorter valid source must refuse retained coverage')
  assert.equal((await citationReader.readCitation(ownerSubject, selected)).citation, null)
  insert.run(...Object.values(entries[2]))
  // Validly re-sign a same-size alternate source prefix: history comparison must still refuse.
  const alternate = entries.map(e => ({ ...e })); alternate[0].detail = '{"fixture":"altered"}'
  let prev = 'GENESIS'
  for (const e of alternate) {
    e.prev = prev; e.hash = gateEntryHash(gateEntryBody(e)); e.sig = sign(null, Buffer.from(e.hash, 'hex'), gatePrivate).toString('base64')
    db.prepare('UPDATE ledger SET detail=?,prev=?,hash=?,sig=? WHERE seq=?').run(e.detail, e.prev, e.hash, e.sig, e.seq); prev = e.hash
  }
  assert.equal(readGateSnapshot(snapshotOptions).ok, true)
  assert.equal((await run()).ok, false)
  assert.equal((await citationReader.readCitation(ownerSubject, selected)).citation, null)
  for (const e of entries) db.prepare('UPDATE ledger SET detail=?,prev=?,hash=?,sig=? WHERE seq=?').run(e.detail, e.prev, e.hash, e.sig, e.seq)
  console.log('PASS gate signature, gap and validly re-signed historical mutation refusals')

  // Collector output must not follow a leaf symlink into another owned file.
  const unsafeStore = join(testRoot, 'unsafe-output'), untouched = join(testRoot, 'untouched')
  mkdirSync(unsafeStore, { mode: 0o700 }); writeFileSync(untouched, 'untouched', { mode: 0o600 })
  symlinkSync(untouched, join(unsafeStore, 'gate-observations.nostr.jsonl'))
  assert.equal((await run({ storeDir: unsafeStore })).ok, false)
  assert.equal(readFileSync(untouched, 'utf8'), 'untouched')
  assert.equal((await verifyCollectorStore({ storeDir: unsafeStore, snapshotOptions, codec, anchors })).ok, false)
  rmSync(join(unsafeStore, 'gate-observations.nostr.jsonl')); linkSync(untouched, join(unsafeStore, 'gate-observations.nostr.jsonl'))
  await assert.rejects(openCollectorStore(unsafeStore), error => error.code === 'aura-collector:store-unavailable')
  assert.equal(readFileSync(untouched, 'utf8'), 'untouched')
  console.log('PASS missing source, public-key pin, source truncation and output symlink/hardlink refusals')

  while (entries.length < 205) appendSource('fixture-refusal')
  const beyondWindow = await run(); assert.equal(beyondWindow.ok, true); assert.equal(beyondWindow.coverage.position, 205)
  assert.equal((await run()).appended, 0)
  const privateText = 'fixture-refusal'; assert(!readFileSync(logPath, 'utf8').includes(privateText))
  console.log('PASS 205-row selected snapshot coverage exceeds public-log cap; private content encrypted')
  if (mutant) assert(mutationApplied, 'requested actual guard removal must be applied')
  console.log('PASS actual collector/Nostr source checks; synthetic keys/source/anchors, installed acceptance UNPERFORMED')
} finally {
  db?.close()
  rmSync(testRoot, { recursive: true, force: true })
}
