// SPDX-License-Identifier: AGPL-3.0-or-later
// Exercise independent head readers with signed SQLite and remembered-chain fixtures.
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { generateKeyPairSync, sign } from 'node:crypto'
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { DatabaseSync } from 'node:sqlite'
import { fileURLToPath } from 'node:url'
import * as production from '../ops/node-spawn/browser/aura-head.mjs'
import { gateEntryBody, gateEntryHash, gatePublicKeySha256 } from '../scripts/aura/gate-snapshot.mjs'
import { chainAuraEntries } from '../plugins/aukora-kira/lib/memory-owner.mjs'

const sourceURL = new URL('../ops/node-spawn/browser/aura-head.mjs', import.meta.url)
const source = readFileSync(sourceURL, 'utf8')
const scratch = fileURLToPath(new URL('../.runtime/', import.meta.url))
mkdirSync(scratch, { recursive: true, mode: 0o700 })
const root = mkdtempSync(join(scratch, 'browser-aura-head-'))
let passed = 0, killed = 0

function gateFixture() {
  const directory = mkdtempSync(join(root, 'gate-'))
  const dbPath = join(directory, 'gate.db'), publicKeyPath = join(directory, 'gate.pub')
  const pair = generateKeyPairSync('ed25519')
  writeFileSync(publicKeyPath, pair.publicKey.export({ type: 'spki', format: 'pem' }))
  const db = new DatabaseSync(dbPath)
  db.exec('PRAGMA journal_mode=WAL; CREATE TABLE ledger(seq INTEGER PRIMARY KEY,at TEXT,event TEXT,proposal TEXT,target TEXT,base_sha TEXT,new_sha TEXT,detail TEXT,prev TEXT,hash TEXT,sig TEXT)')
  const rows = []
  for (let seq = 1; seq <= 5; seq++) {
    const row = { seq, at: '2026-10-14T00:00:00.000Z', event: seq === 5 ? 'apply' : 'propose', proposal: null,
      target: null, base_sha: null, new_sha: null, detail: 'synthetic-private-ledger-content', prev: rows.at(-1)?.hash ?? 'GENESIS' }
    row.hash = gateEntryHash(gateEntryBody(row))
    row.sig = sign(null, Buffer.from(row.hash, 'hex'), pair.privateKey).toString('base64')
    db.prepare('INSERT INTO ledger VALUES(?,?,?,?,?,?,?,?,?,?,?)').run(...Object.values(row))
    rows.push(row)
  }
  return { db, dbPath, publicKeyPath, expectedKeySha256: gatePublicKeySha256(pair.publicKey), rows }
}

function gateHead(api) {
  const fixture = gateFixture()
  try {
    const before = [fixture.dbPath, fixture.dbPath + '-wal'].map(file => readFileSync(file))
    const value = api.readBrowserGateHead(fixture)
    assert.deepEqual(value, { head: fixture.rows.at(-1).hash, entries: 5 })
    assert.doesNotMatch(JSON.stringify(value), /synthetic-private-ledger-content|signature|records/u)
    assert.deepEqual([fixture.dbPath, fixture.dbPath + '-wal'].map(file => readFileSync(file)), before)
  } finally { fixture.db.close() }
}

function gateRefusal(api) {
  const fixture = gateFixture()
  try {
    assert.throws(() => api.readBrowserGateHead({ ...fixture, expectedKeySha256: 'f'.repeat(64) }),
      /^Error: BROWSER_AURA_GATE_READ_INVALID$/u)
    fixture.db.prepare('UPDATE ledger SET detail=? WHERE seq=5').run('changed synthetic ledger bytes')
    assert.throws(() => api.readBrowserGateHead(fixture), /^Error: BROWSER_AURA_GATE_READ_INVALID$/u)
  } finally { fixture.db.close() }
}

function kiraHead(api) {
  const stateDir = mkdtempSync(join(root, 'kira-'))
  const file = join(stateDir, 'remembered/aura.jsonl')
  assert.deepEqual(api.readBrowserKiraHead({ stateDir }), { head: null, entries: 0, absence: 'kira-ledger-missing' })
  mkdirSync(join(stateDir, 'remembered'), { mode: 0o700 })
  writeFileSync(file, '', { mode: 0o600 })
  assert.deepEqual(api.readBrowserKiraHead({ stateDir }), { head: null, entries: 0, absence: 'kira-ledger-empty' })
  const [row] = chainAuraEntries(stateDir, [{ op: 'remember', tier: 'remembered', statement: 'synthetic-private-note' }], { file })
  writeFileSync(file, JSON.stringify(row) + '\n', { mode: 0o600 })
  const before = readFileSync(file)
  assert.deepEqual(api.readBrowserKiraHead({ stateDir }), { head: row.hash, entries: 1, absence: null })
  assert.deepEqual(readFileSync(file), before)
}

function kiraRefusal(api) {
  const stateDir = mkdtempSync(join(root, 'kira-broken-'))
  mkdirSync(join(stateDir, 'remembered'), { mode: 0o700 })
  writeFileSync(join(stateDir, 'remembered/aura.jsonl'), '{torn', { mode: 0o600 })
  assert.throws(() => api.readBrowserKiraHead({ stateDir }), /^Error: BROWSER_AURA_KIRA_READ_INVALID$/u)
}

function load(text) {
  const resolved = text.replace(/from '(\.\.\/[^']+)'/gu, (_, value) => `from '${new URL(value, sourceURL).href}'`)
  return import(`data:text/javascript;base64,${Buffer.from(resolved).toString('base64')}`)
}

function cliUsage(text = source) {
  const directory = mkdtempSync(join(root, 'cli-'))
  const file = join(directory, 'aura-head.mjs')
  const resolved = text.replace(/from '(\.\.\/[^']+)'/gu, (_, value) => `from '${new URL(value, sourceURL).href}'`)
    .replace('/home/aukora-host/genesis/state/home/kira-memory', directory)
  writeFileSync(file, resolved)
  const value = spawnSync(process.execPath, [file, 'wrong-kind'], { encoding: 'utf8' })
  assert.equal(value.status, 1)
  assert.equal(value.stdout, '')
  assert.match(value.stderr, /REFUSED BROWSER_AURA_READ_USAGE/u)
}

try {
  for (const run of [gateHead, gateRefusal, kiraHead, kiraRefusal]) { run(production); passed++ }
  cliUsage(); passed++
  if (process.argv.includes('--mutate')) {
    const memoryGuard = source.slice(source.indexOf('  need(value.head === null'), source.indexOf('\n  return value'))
    for (const [name, before, after, run] of [
      ['gate verification required', "need(value.ok === true, 'GATE_READ_INVALID')", 'void value.ok', gateRefusal],
      ['gate records excluded', 'return { head: value.selected_head.hash, entries: value.selected_head.position }',
        'return { head: value.selected_head.hash, entries: value.selected_head.position, records: value.records }', gateHead],
      ['complete memory chain required', memoryGuard, '  void value', kiraRefusal],
    ]) {
      assert.equal(source.split(before).length, 2, name + ': unique mutation anchor')
      const api = await load(source.replace(before, after))
      assert.throws(() => run(api), error => error.code === 'ERR_ASSERTION')
      killed++
      console.log('KILLED ' + name)
    }
    const usage = "need(process.version === 'v24.11.1' &&"
    assert.equal(source.split(usage).length, 2)
    assert.throws(() => cliUsage(source.replace(usage, "need(true || process.version === 'v24.11.1' &&")),
      error => error.code === 'ERR_ASSERTION')
    killed++
    console.log('KILLED reader CLI usage')
  }
  console.log(`browser-node-aura-head: ${passed} passed, 0 failed; ${killed} mutants killed; signed source fixtures only`)
} finally { rmSync(root, { recursive: true, force: true }) }
