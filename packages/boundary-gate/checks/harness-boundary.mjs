// SPDX-License-Identifier: AGPL-3.0-or-later
// Real gate/SQLite/signature/socket checks with synthetic target bytes and a fixture
// P-256 signer. No enrollment, deployed UID, systemd namespace or private-data claim.
import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'
import net from 'node:net'
import { fileURLToPath } from 'node:url'
import { generateKeyPairSync, sign } from 'node:crypto'
import { registerHooks } from 'node:module'
import { spawn, spawnSync } from 'node:child_process'

const variants = {
  restart: ['gate.mjs',
    'const count = db.prepare("SELECT count(*) AS n FROM proposals WHERE state=\'pending\'").get().n',
    'const count = db.prepare("SELECT count(*) AS n FROM proposals WHERE state=\'pending\'").get().n; db.prepare("UPDATE proposals SET state=\'expired\' WHERE state=\'pending\'").run()', 'restart report'],
  close: ['gate.mjs',
    "if (!Object.hasOwn(TARGETS, p.target) || TARGETS[p.target].operatorOnly)\n      throw new Error('refused: only the owner channel may close an operator-only proposal')", '', 'owner-only close'],
  budget: ['gate.mjs', 'chargePropose(); return handler(...args)', 'return handler(...args)', 'durable budget'],
  persistence: ['gate.mjs',
    "row = db.prepare('SELECT window_start_ms,used FROM propose_budget WHERE singleton=1').get()", 'row = null', 'durable budget'],
  owner: ['gate.mjs', 'decide_review: (a, approver) => decideReview(a, approver)',
    'decide_review: (a, approver) => { chargePropose(); return decideReview(a, approver) }', 'durable budget'],
  bytes: ['ledger.mjs', "if (Buffer.byteLength(encoded, 'utf8') > LEDGER_DETAIL_MAX_BYTES) fail()", '', 'new audit bytes'],
  depth: ['ledger.mjs', '|| depth > 16', '', 'new audit bytes'],
  provenance: ['gate.mjs', "return { ok: true, verification: 'caller-reported-unverified' }", 'return { ok: true, verification: \'verified\' }', 'selfcheck claims'],
  latch: ['server.mjs', 'if (handled) return', '', 'one socket request'],
  frame: ['server.mjs', 'if (buf.length + d.length > 1 << 20)', 'if (buf.toString().length + d.toString().length > 1 << 20)', 'UTF-8 frame'],
}
const selected = process.env.AUKORA_HARNESS_BOUNDARY_MUTANT
if (selected) {
  const [file, before, after] = variants[selected] ?? []
  if (!file) throw new Error('unknown test-only mutant')
  registerHooks({ load(url, context, next) {
    const result = next(url, context)
    if (!url.endsWith('/boundary-gate/src/' + file)) return result
    const text = typeof result.source === 'string' ? result.source : Buffer.from(result.source).toString('utf8')
    if (text.split(before).length !== 2) throw new Error('mutant preimage mismatch')
    return { ...result, source: text.replace(before, after) }
  } })
}

const { createGate } = await import('../src/gate.mjs')
const { boundedLedgerJson, entryBody, sha256, LEDGER_DETAIL_MAX_BYTES } = await import('../src/ledger.mjs')
const { lineServer } = await import('../src/server.mjs')
const { accentTarget, accent, tmpHome, memoryStore } = await import('./support/fixture.mjs')
const { ownerAuthorizationSigningBytes } = await import('../../owner-key/src/authorization.mjs')
const ACCENT = 'plugins/synthetic-owner/accent.json'

function fixture(limits = {}) {
  const signer = generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
  const spki = signer.publicKey.export({ type: 'spki', format: 'der' })
  const state = { version: 1, kind: 'aukora-owner-state/v1', owner_subject: 'aukora:1:' + sha256('synthetic-owner'),
    owner_root_spki_base64: spki.toString('base64'), owner_root_id: sha256(spki), owner_epoch: 1,
    registry_sha256: sha256('fixture-registry'), activation_sha256: sha256('fixture-not-enrollment') }
  const home = tmpHome(), clock = { t: Date.UTC(2026, 9, 5, 12) }, store = memoryStore({ [ACCENT]: accent('#FFD700') })
  const targets = { [ACCENT]: { ...accentTarget, operatorOnly: true, ttlMs: 24 * 60 * 60 * 1000 } }
  const open = () => createGate({ home, targets, store, limits, now: () => clock.t, readOwnerState: () => state })
  const gate = open(); gate.startup({ pid: 1 })
  const proposal = gate.ownerOps.raise({ target: ACCENT, content: accent('#00FF00'), why: 'synthetic owner pending intent' })
  const review = gate.ownerOps.review({ id: proposal.id })
  const proof = { algorithm: 'p256-ecdsa-sha256', authorization: review.owner_authorization,
    signature_base64: sign('sha256', ownerAuthorizationSigningBytes(review.owner_authorization), signer.privateKey).toString('base64') }
  const decide = g => g.ownerOps.decide_review({ id: proposal.id, base_sha: review.base_sha, new_sha: review.new_sha,
    review_challenge: review.review_challenge, outcome: 'allowed-once', owner_authorization_proof: proof })
  return { gate, clock, store, open, proposal, review, decide, home }
}
const count = g => g.db.prepare('SELECT count(*) AS n FROM ledger').get().n
const row = (g, id) => g.db.prepare('SELECT * FROM proposals WHERE id=?').get(id)

test('restart report preserves the exact owner pending row and signed review', () => {
  const f = fixture(), before = row(f.gate, f.proposal.id)
  const reviewBefore = f.gate.db.prepare('SELECT * FROM owner_authorization_reviews').get()
  try {
    for (const pid of [1, 7, 500]) assert.deepEqual(f.gate.proposeOps.harness_start({ pid }), { expired: 0, preserved_pending: 1 })
    assert.deepEqual(row(f.gate, f.proposal.id), before)
    assert.deepEqual(f.gate.db.prepare('SELECT * FROM owner_authorization_reviews').get(), reviewBefore)
    assert.equal(f.decide(f.gate).applied, true)
    assert.equal(f.store.writes, 1)
    assert.throws(() => f.decide(f.gate), /live durable review|not pending|single use/)
    assert.equal(f.gate.verify().ok, true)
  } finally { f.gate.close() }
})

test('owner-only close refuses every propose outcome without consuming the owner review', () => {
  const f = fixture(), before = row(f.gate, f.proposal.id)
  try {
    for (const outcome of ['rejected', 'cancelled', 'unavailable', 'expired'])
      assert.throws(() => f.gate.proposeOps.close({ id: f.proposal.id, outcome }), /only the owner channel/)
    assert.deepEqual(row(f.gate, f.proposal.id), before)
    assert.equal(f.decide(f.gate).applied, true)
    assert.equal(f.store.writes, 1)
  } finally { f.gate.close() }
})

test('durable budget charges refused calls across instances/reopen while exact owner proof applies', () => {
  const f = fixture({ proposeMaxPerWindow: 2 }), other = f.open()
  let reopened
  try {
    assert.throws(() => f.gate.proposeOps.propose({ target: ACCENT, session: 'label-1' }), /operator-only/)
    assert.throws(() => other.proposeOps.propose({ target: ACCENT, session: 'label-2' }), /operator-only/)
    const n = count(other)
    f.gate.close(); reopened = f.open()
    for (let i = 0; i < 40; i++) {
      const g = i % 2 ? reopened : other
      assert.throws(() => g.proposeOps.selfcheck({ result: { ok: true, session: 'new-' + i } }), /budget exhausted/)
    }
    assert.equal(count(reopened), n, 'exhaustion must not sign another refusal')
    assert.equal(reopened.db.prepare('SELECT used FROM propose_budget').get().used, 2)
    assert.equal(reopened.ownerOps.status().verify.ok, true)
    let applied
    assert.doesNotThrow(() => { applied = f.decide(reopened) }, 'owner click must survive propose budget exhaustion')
    assert.equal(applied.applied, true)
    assert.equal(f.store.writes, 1)
    assert.equal(reopened.verify().ok, true)
  } finally { f.gate.close(); other.close(); reopened?.close() }
})

test('budget has a bounded new window and a reversed gate clock never resets it', () => {
  const f = fixture({ proposeMaxPerWindow: 1, proposeWindowMs: 1000 })
  try {
    f.gate.proposeOps.selfcheck({ result: null })
    assert.throws(() => f.gate.proposeOps.selfcheck({ result: null }), /budget exhausted/)
    f.clock.t -= 1
    assert.throws(() => f.gate.proposeOps.selfcheck({ result: null }), /invalid retained clock/)
    f.clock.t += 1001
    f.gate.proposeOps.selfcheck({ result: null })
    assert.equal(f.gate.db.prepare('SELECT used FROM propose_budget').get().used, 1)
  } finally { f.gate.close() }
})

test('cross-process durable budget shares one admission row under concurrent refused-call traffic', async () => {
  const f = fixture({ proposeMaxPerWindow: 2 })
  const before = count(f.gate)
  const childCode = `
    import { registerHooks } from 'node:module';
    const mutation = JSON.parse(process.env.AUKORA_FIXTURE_MUTATION);
    if (mutation) registerHooks({load(url,context,next){
      const r=next(url,context); if(!url.endsWith('/boundary-gate/src/'+mutation[0]))return r;
      const s=typeof r.source==='string'?r.source:Buffer.from(r.source).toString('utf8');
      if(s.split(mutation[1]).length!==2)throw Error('mutant preimage mismatch');
      return {...r,source:s.replace(mutation[1],mutation[2])};
    }});
    const { createGate }=await import(process.env.AUKORA_FIXTURE_GATE);
    const gate=createGate({home:process.env.AUKORA_FIXTURE_HOME,store:{read:()=>null},
      limits:{proposeMaxPerWindow:2},now:()=>Number(process.env.AUKORA_FIXTURE_TIME)});
    process.stdout.write('ready\\n');
    process.stdin.once('data',()=>{
      let admitted=0;
      for(let i=0;i<20;i++)try{gate.proposeOps.selfcheck({result:{caller:process.pid,seq:i}});admitted++}catch(e){
        if(!/budget exhausted|database is locked/.test(e.message))throw e;
      }
      gate.close();process.stdout.write(JSON.stringify({admitted})+'\\n');process.stdin.destroy();
    });`
  const env = { ...process.env, AUKORA_FIXTURE_HOME: f.home, AUKORA_FIXTURE_TIME: String(f.clock.t),
    AUKORA_FIXTURE_GATE: new URL('../src/gate.mjs', import.meta.url).href,
    AUKORA_FIXTURE_MUTATION: JSON.stringify(['budget', 'persistence'].includes(selected) ? variants[selected].slice(0, 3) : null) }
  delete env.NODE_OPTIONS; delete env.NODE_PATH
  const children = []
  try {
    for (let i = 0; i < 2; i++) {
      const child = spawn(process.execPath, ['--input-type=module', '-e', childCode], { env, stdio: ['pipe', 'pipe', 'pipe'], timeout: 5000 })
      let out = '', err = ''
      child.stdout.on('data', b => { out += b }); child.stderr.on('data', b => { err += b })
      const ready = new Promise((resolve, reject) => {
        child.on('error', reject)
        child.stdout.on('data', () => { if (out.startsWith('ready\n')) resolve() })
        child.on('close', () => { if (!out.startsWith('ready\n')) reject(new Error('fixture child failed before ready: ' + err)) })
      })
      const done = new Promise((resolve, reject) => {
        child.on('error', reject)
        child.on('close', code => { if (code !== 0) reject(new Error('fixture child failed: ' + err)); else resolve(JSON.parse(out.split('\n')[1])) })
      })
      done.catch(() => {}) // Retain a rejected result until the coordinated join below.
      children.push({ child, ready, done })
      // Startup is sequential; the actual propose handlers below race in two OS processes.
      await ready
    }
    await Promise.all(children.map(c => c.ready))
    for (const c of children) c.child.stdin.write('go\n')
    const results = await Promise.all(children.map(c => c.done))
    assert.ok(results.reduce((n, r) => n + r.admitted, 0) <= 2, 'two OS processes must share the gate budget')
    assert.equal(f.gate.db.prepare('SELECT used FROM propose_budget').get().used, 2)
    assert.ok(count(f.gate) - before <= 2)
    assert.equal(f.gate.verify().ok, true)
  } finally {
    for (const c of children) if (c.child.exitCode === null) c.child.kill('SIGTERM')
    f.gate.close()
  }
})

test('new audit bytes/tree/fields are bounded before signing and retained valid bytes stay exact', () => {
  const f = fixture()
  try {
    const detail = { z: 'literal Unicode 😀', optional: undefined, a: [1.5, undefined, null, true, { note: '\\quoted"' }] }
    const e = f.gate.append('fixture-audit', { detail })
    assert.equal(e.detail, JSON.stringify(detail))
    assert.equal(e.hash, sha256(entryBody(e)))
    const n = count(f.gate)
    assert.throws(() => f.gate.append('too-big', { detail: '\0'.repeat(12000) }), /bounded JSON/)
    assert.throws(() => f.gate.append('too-big', { detail: '😀'.repeat(LEDGER_DETAIL_MAX_BYTES / 4 + 1) }), /bounded JSON/)
    let deep = null
    for (let i = 0; i < 18; i++) deep = { x: deep }
    assert.throws(() => f.gate.append('too-deep', { detail: deep }), /bounded JSON/)
    let invoked = 0
    const getter = Object.defineProperty({}, 'claim', { enumerable: true, get() { invoked++; return true } })
    assert.throws(() => f.gate.append('getter', { detail: getter }), /bounded JSON/)
    assert.throws(() => f.gate.append('hook', { detail: { toJSON() { invoked++; return {} } } }), /bounded JSON/)
    assert.equal(invoked, 0)
    assert.throws(() => f.gate.append('long-target', { target: 'x'.repeat(513) }), /field exceeds bound/)
    assert.equal(count(f.gate), n)
    assert.equal(f.gate.verify().ok, true)
    assert.equal(boundedLedgerJson(detail), JSON.stringify(detail))
  } finally { f.gate.close() }
})

test('selfcheck claims remain caller-reported unverified even with forged verification fields', () => {
  const f = fixture()
  try {
    const result = { ok: true, verification: 'verified', owner_approved: true }
    assert.equal(f.gate.proposeOps.selfcheck({ result }).verification, 'caller-reported-unverified')
    const last = f.gate.db.prepare('SELECT * FROM ledger ORDER BY seq DESC LIMIT 1').get()
    assert.deepEqual(JSON.parse(last.detail), { source: 'propose-socket/harness', verification: 'caller-reported-unverified', result })
    const n = count(f.gate)
    assert.throws(() => f.gate.proposeOps.selfcheck({ result: { text: 'x'.repeat(LEDGER_DETAIL_MAX_BYTES + 1) } }), /bounded JSON/)
    assert.equal(count(f.gate), n)
  } finally { f.gate.close() }
})

async function withSocket(run) {
  const sock = path.join(tmpHome(), 'fixture.sock')
  let calls = 0
  const srv = lineServer({ report: () => ({ call: ++calls }) })
  await new Promise((resolve, reject) => { srv.once('error', reject); srv.listen(sock, resolve) })
  try { await run(sock, () => calls) } finally { await new Promise(r => srv.close(r)) }
}
test('one socket request is dispatched once across a real half-open connection', async () => {
  await withSocket(async (sock, calls) => {
    await new Promise((resolve, reject) => {
      const c = net.createConnection({ path: sock, allowHalfOpen: true })
      c.setTimeout(2000, () => { c.destroy(); reject(new Error('fixture socket timeout')) })
      c.on('error', reject)
      c.on('connect', () => c.write('{"op":"report"}\n'))
      c.once('data', () => { c.write('late second chunk\n'); setTimeout(() => c.end(), 30) })
      c.on('close', resolve)
    })
    assert.equal(calls(), 1, 'a later data event cannot repeat a signed append')
  })
})
test('UTF-8 frame byte bound refuses a multibyte request before any dispatch', async () => {
  await withSocket(async (sock, calls) => {
    const payload = Buffer.from(JSON.stringify({ op: 'report', args: { text: '😀'.repeat(270000) } }) + '\n')
    assert.ok(payload.length > 1 << 20)
    await new Promise((resolve, reject) => {
      const c = net.createConnection(sock)
      c.setTimeout(2000, () => { c.destroy(); reject(new Error('fixture socket timeout')) })
      c.on('error', e => { if (!['EPIPE', 'ECONNRESET'].includes(e.code)) reject(e) })
      c.on('connect', () => c.end(payload))
      c.resume(); c.on('close', resolve)
    })
    assert.equal(calls(), 0, 'byte-overlimit JSON must not dispatch')
  })
})

if (process.argv.includes('--mutations') && !selected) {
  const env = { ...process.env }; delete env.NODE_OPTIONS; delete env.NODE_PATH
  for (const [name, [, , , pattern]] of Object.entries(variants)) {
    const r = spawnSync(process.execPath, ['--test', '--test-name-pattern=' + pattern, fileURLToPath(import.meta.url)],
      { env: { ...env, AUKORA_HARNESS_BOUNDARY_MUTANT: name }, encoding: 'utf8', timeout: 15000, maxBuffer: 1024 * 1024 })
    assert.equal(r.status, 1, `${name} survived or did not produce a test failure:\n${r.stdout}\n${r.stderr}`)
    assert.match(r.stdout, /ERR_ASSERTION/, `${name} failed without the guard assertion:\n${r.stdout}\n${r.stderr}`)
    assert.doesNotMatch(r.stdout + r.stderr, /mutant preimage mismatch|EPERM|ENOENT/)
    console.log('KILLED actual source guard:', name)
  }
}
