// SPDX-License-Identifier: AGPL-3.0-or-later
// Exercise the read-only exporter against retained public rows and its file refusals.
import assert from 'node:assert/strict'
import fs, { existsSync, mkdtempSync, readFileSync, rmSync, statSync, symlinkSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { registerHooks, syncBuiltinESMExports } from 'node:module'
import { spawnSync } from 'node:child_process'
import { DatabaseSync } from 'node:sqlite'
import { generateKeyPairSync } from 'node:crypto'
import { createLedger } from '../../../packages/boundary-gate/src/ledger.mjs'

const mutations = {
  'read-only': ['gate-snapshot.mjs', '{ readOnly: true }', '{ readOnly: false }'],
  signature: ['gate-snapshot.mjs', 'if (!verify(null, Buffer.from(entry.hash, \'hex\'), publicKeyOf(publicKey), signature))', 'if (false)'],
  pin: ['export-ledger.mjs', 'keySha256 ?? gatePublicKeySha256(publicKeyPem)', 'gatePublicKeySha256(publicKeyPem)'],
  empty: ['export-ledger.mjs', 'if (snapshot.records.length === 0)', 'if (false)'],
  overwrite: ['export-ledger.mjs', "flag: 'wx'", "flag: 'w'"],
  permissions: ['export-ledger.mjs', 'mode: 0o600', 'mode: 0o644'],
  bounds: ['export-ledger.mjs', "if (Buffer.byteLength(bytes, 'utf8') > 8 * 1024 * 1024)", 'if (false)'],
}
const mutant = process.argv[2] === '--mutant' ? process.argv[3] : null
assert(!mutant || mutations[mutant], 'known mutant required')
let mutated = false
registerHooks({ load(url, context, next) {
  const loaded = next(url, context)
  if (mutant && url.endsWith(`/scripts/aura/${mutations[mutant][0]}`)) {
    const source = String(loaded.source)
    const altered = source.replace(mutations[mutant][1], mutations[mutant][2])
    assert.notEqual(altered, source, 'actual protected source must be mutated')
    mutated = true
    return { ...loaded, source: altered }
  }
  return loaded
} })
const { exportGateLedger } = await import('../export-ledger.mjs')
const root = fileURLToPath(new URL('../../../', import.meta.url))
const testRoot = mkdtempSync(join(root, '.aura-export-check-'))
const dbPath = join(testRoot, 'gate.db'), publicKeyPath = join(testRoot, 'gate.pub')
const entries = JSON.parse(readFileSync(join(root, 'docs/evidence/l2-demo-2026-10-04/ledger-entries.json'), 'utf8'))
writeFileSync(publicKeyPath, readFileSync(join(root, 'docs/evidence/l2-demo-2026-10-04/gate-ed25519.pub')))
let db
try {
  db = new DatabaseSync(dbPath)
  db.exec(`PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0;
    CREATE TABLE ledger(seq INTEGER PRIMARY KEY, at TEXT, event TEXT, proposal TEXT, target TEXT,
      base_sha TEXT, new_sha TEXT, detail TEXT, prev TEXT, hash TEXT, sig TEXT)`)
  const fields = ['seq', 'at', 'event', 'proposal', 'target', 'base_sha', 'new_sha', 'detail', 'prev', 'hash', 'sig']
  const insert = db.prepare(`INSERT INTO ledger VALUES(${fields.map(() => '?').join(',')})`)
  for (const entry of entries) insert.run(...fields.map(field => entry[field]))
  const sourceBytes = readFileSync(dbPath), walBytes = readFileSync(`${dbPath}-wal`)
  const outPath = join(testRoot, 'export.json'), privatePath = join(testRoot, 'receipt-ed25519.pem')
  writeFileSync(privatePath, 'synthetic private-key sentinel')
  const reads = [], savedRead = fs.readFileSync, oldMask = process.umask(0)
  let result
  try {
    fs.readFileSync = (file, ...args) => { reads.push(file); return savedRead(file, ...args) }
    syncBuiltinESMExports()
    result = exportGateLedger({ dbPath, publicKeyPath, outPath })
  } finally { fs.readFileSync = savedRead; syncBuiltinESMExports(); process.umask(oldMask) }
  assert.equal(result.ok, true)
  assert.deepEqual(reads, [publicKeyPath], 'only the explicit public-key file is read through fs')
  assert.equal(readFileSync(privatePath, 'utf8'), 'synthetic private-key sentinel')
  assert.equal(statSync(outPath).mode & 0o777, 0o600, 'private ledger export mode')
  const bundle = JSON.parse(readFileSync(outPath, 'utf8'))
  assert.deepEqual(bundle.entries, entries)
  assert.equal(bundle.head.seq, entries.at(-1).seq)
  assert.equal(bundle.head.head, entries.at(-1).hash)
  assert.equal(bundle.head.entry_at, entries.at(-1).at)
  assert.equal(bundle.head.gate_fp, bundle.gate_pubkey_sha256.slice(0, 16))
  assert.deepEqual(readFileSync(dbPath), sourceBytes)
  assert.deepEqual(readFileSync(`${dbPath}-wal`), walBytes)
  console.log(`PASS export: ${entries.length} real 10-04 rows and current head; committed WAL included, DB/WAL unchanged, no signing-key read, mode 0600`)

  const verifyPath = join(root, 'scripts/aura/verify-export.mjs')
  const verified = spawnSync(process.execPath, [verifyPath, outPath], { encoding: 'utf8' })
  assert.equal(verified.status, 0, verified.stdout + verified.stderr)
  assert.match(verified.stdout, /^VERIFIED /u)
  const commandOut = join(testRoot, 'cli-export.json')
  const command = spawnSync(process.execPath, [join(root, 'scripts/aura/export-ledger.mjs'), '--db', dbPath,
    '--public-key', publicKeyPath, '--out', commandOut], { encoding: 'utf8' })
  assert.equal(command.status, 0, command.stdout + command.stderr)
  assert.equal(command.stdout.trim(), `EXPORTED aura-export:observed-head entries=${entries.length} seq=${entries.at(-1).seq}`)
  const help = spawnSync(process.execPath, [join(root, 'scripts/aura/export-ledger.mjs'), '--help'], { encoding: 'utf8' })
  assert.equal(help.status, 0)
  assert.match(help.stdout, /local observation, not an independently retained anchor/u)
  console.log('PASS export: admin CLI bundle accepted by the stranger verifier')

  const refusedOut = join(testRoot, 'refused.json')
  const run = overrides => exportGateLedger({ dbPath, publicKeyPath, outPath: refusedOut, ...overrides })
  assert.equal(run({ keySha256: '0'.repeat(64) }).reason, 'gate-source:key-pin-mismatch')
  assert.equal(existsSync(refusedOut), false)
  const sig = entries[0].sig
  db.prepare('UPDATE ledger SET sig=? WHERE seq=1').run('A'.repeat(86) + '==')
  assert.equal(run().reason, 'gate-source:signature-invalid')
  assert.equal(existsSync(refusedOut), false)
  db.prepare('UPDATE ledger SET sig=? WHERE seq=1').run(sig)
  const missing = join(testRoot, 'missing.db')
  assert.equal(run({ dbPath: missing }).reason, 'gate-source:snapshot-unavailable')
  assert.equal(existsSync(missing), false, 'read-only open cannot create the missing database')
  db.exec('DELETE FROM ledger')
  assert.equal(run().reason, 'aura-export:empty-ledger')
  assert.equal(existsSync(refusedOut), false)
  for (const entry of entries) insert.run(...fields.map(field => entry[field]))
  console.log('PASS export: explicit key-pin, invalid signature, missing database and empty ledger refuse without output')

  const sentinel = join(testRoot, 'sentinel'), link = join(testRoot, 'link')
  writeFileSync(sentinel, 'unchanged')
  assert.equal(run({ outPath: sentinel }).reason, 'aura-export:output-unavailable')
  assert.equal(readFileSync(sentinel, 'utf8'), 'unchanged')
  symlinkSync(sentinel, link)
  assert.equal(run({ outPath: link }).reason, 'aura-export:output-unavailable')
  assert.equal(readFileSync(sentinel, 'utf8'), 'unchanged')
  assert.equal(run({ outPath: dbPath }).reason, 'aura-export:output-unavailable')
  console.log('PASS export: exclusive output refuses overwrite, symlink and database destinations')

  const largeKey = generateKeyPairSync('ed25519')
  writeFileSync(publicKeyPath, largeKey.publicKey.export({ type: 'spki', format: 'pem' }))
  db.exec('DELETE FROM ledger; BEGIN')
  const ledger = createLedger(db, { priv: largeKey.privateKey, pub: largeKey.publicKey }, () => '2026-10-04T00:00:00.000Z')
  for (let i = 0; i < 15000; i++) ledger.append('fixture', { detail: { text: 'x'.repeat(190) } })
  db.exec('COMMIT')
  assert.equal(run().reason, 'aura-export:byte-bound-exceeded')
  assert.equal(existsSync(refusedOut), false)
  console.log('PASS export: valid 15000-row snapshot exceeding offline parser byte bound refuses without output')
  if (mutant) assert.equal(mutated, true)
  console.log('PASS export: source checks complete; live Linux node export UNPERFORMED')
} finally { db?.close(); rmSync(testRoot, { recursive: true, force: true }) }
