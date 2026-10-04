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
import { execFileSync } from 'node:child_process'
import { registerHooks } from 'node:module'
import { DatabaseSync } from 'node:sqlite'

const root = fileURLToPath(new URL('../../../', import.meta.url))
const base = '7561a97f270e34768dc271f083e091574f7078d2'
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
      if (!context.parentURL || !specifier.startsWith('.')) throw error
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
    if (mutant && url.endsWith(`/scripts/aura/${mutants[mutant][0]}`)) {
      const [file, match, replacement] = mutants[mutant]
      const text = typeof loaded.source === 'string' ? loaded.source : Buffer.from(loaded.source).toString('utf8')
      const altered = text.replace(match, replacement)
      assert.notEqual(altered, text, `focused ${file} guard must exist`)
      loaded = { ...loaded, source: altered }; mutationApplied = true
    }
    return loaded
  },
})

const { collectGateOnce, createNostrCollectorCodec, openCollectorStore } = await import('../collect-gate.mjs')
const { readGateSnapshot, gateEntryBody, gateEntryHash, gatePublicKeySha256 } = await import('../gate-snapshot.mjs')
const { verifyCollectorStore, verifyCollected } = await import('../verify-collected.mjs')
if (!existsSync(recordFile)) throw Error('Actual B records source unavailable; no structural-codec fallback')
const records = await import(pathToFileURL(recordFile).href)
const identity = await import(new URL('./identity.mjs', pathToFileURL(recordFile)))
const eventTools = await import(new URL('./event.mjs', pathToFileURL(recordFile)))

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
      proposal: `fixture-action-${entries.length + 1}`, target: 'fixture.json', base_sha: null, new_sha: null,
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

  const goodLog = readFileSync(logPath, 'utf8'), goodCheckpoint = readFileSync(cpPath, 'utf8')
  const forged = JSON.parse(goodCheckpoint); forged.source_head.position = 999
  writeFileSync(cpPath, JSON.stringify(forged)); const before = builds
  assert.equal((await run()).ok, false); assert.equal(builds, before); assert.equal(readFileSync(logPath, 'utf8'), goodLog)
  writeFileSync(cpPath, goodCheckpoint)
  writeFileSync(logPath, goodLog.slice(0, -1)); assert.equal((await run()).ok, false); writeFileSync(logPath, goodLog)
  const tampered = goodLog.trimEnd().split('\n').map(JSON.parse); tampered[0].sig = '0'.repeat(128)
  writeFileSync(logPath, tampered.map(e => JSON.stringify(e)).join('\n') + '\n'); assert.equal((await run()).ok, false)
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
  const held = await openCollectorStore(storeDir)
  try { assert.equal((await run()).reason, 'aura-collector:busy') } finally { await held.close() }
  console.log('PASS anchor divergence, real owner-binding mismatch and concurrent writer fence')

  const oldSig = entries[0].sig
  db.prepare('UPDATE ledger SET sig=? WHERE seq=1').run('A'.repeat(86) + '==')
  assert.equal(readGateSnapshot(snapshotOptions).ok, false)
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
