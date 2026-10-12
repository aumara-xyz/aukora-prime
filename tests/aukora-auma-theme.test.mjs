// aukora-auma-theme: Auma's PROPOSE-ONLY gate tool and the live accent route, against a REAL boundary gate on REAL
// unix sockets with the real theme target schema. Break-tests: the tool cannot approve (no approve op, extra args
// refused, PROPOSE socket refuses approval ops), the action gate approves exactly this name, the route needs the host's
// auth. AUMA_THEME_MUTANT removes one guard in memory to prove the checks bite.
import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { createServer } from 'node:net'
import { createGate } from '../packages/boundary-gate/src/gate.mjs'
import { serveGate, call as rawCall } from '../packages/boundary-gate/src/server.mjs'
import { themeTarget } from '../packages/boundary-gate/src/targets.mjs'
import { loadOwnerSecret, rotateBearer } from '../packages/boundary-gate/src/secrets.mjs'
import { memoryStore, tmpHome } from '../packages/boundary-gate/checks/support/fixture.mjs'
import { createPolicy, DEFAULT_ALLOW_TOOLS } from '../plugins/aukora-action-gate/lib/policy.mjs'

const proposeUrl = new URL('../plugins/aukora-auma-theme/lib/propose.mjs', import.meta.url)
const indexUrl = new URL('../plugins/aukora-auma-theme/lib/index.mjs', import.meta.url)
const inMemory = (src, base) => `data:text/javascript;base64,${Buffer.from(src.replace(/from (['"])(\.[^'"]+)\1/gu,
  (_m, _q, rel) => `from ${JSON.stringify(new URL(rel, base).href)}`)).toString('base64')}`
async function load() {
  const mutant = process.env.AUMA_THEME_MUTANT
  if (!mutant) return { ...(await import(proposeUrl.href)), ...(await import(indexUrl.href)) }
  let p = fs.readFileSync(proposeUrl, 'utf8'), i = fs.readFileSync(indexUrl, 'utf8'); const p0 = p, i0 = i
  if (mutant === 'op-allowlist') p = p.replace("if (!PROPOSE_OPS.includes(op)) return Promise.reject(new Error(`auma-theme: op ${String(op)} is not a propose-side op`))", '')
  else if (mutant === 'extra-args') i = i.replace("if (extra.length > 0) throw new Error(`unknown argument(s) ${extra.join(', ')}; this tool only proposes`)", '')
  else if (mutant === 'route-auth') i = i.replace("if (rejection !== undefined && rejection !== null && rejection !== false) {", 'if (false) {')
  else if (mutant === 'note-target') i = i.replace("if (target !== THEME_TARGET && target !== NOTE_TARGET) throw new Error('proposal-target-not-allowed')", '')
  else if (mutant === 'note-accent') i = i.replace("if (Object.hasOwn(args, 'accent')) throw new Error('note-accent-not-allowed')", '')
  else if (mutant === 'theme-text') i = i.replace("if (Object.hasOwn(args, 'text')) throw new Error('theme-text-not-allowed')", '')
  else if (mutant === 'note-type') p = p.replace("if (typeof text !== 'string') throw new Error('note-text-required')", '')
  else if (mutant === 'note-unicode') p = p.replace('!text.isWellFormed() || ', '')
  else if (mutant === 'note-controls') p = p.replace(String.raw`/[\u0000-\u0008\u000b-\u001f\u007f]/u.test(text)`, 'false')
  else if (mutant === 'note-empty') p = p.replace("if (text.trim().length === 0) throw new Error('note-text-empty')", '')
  else if (mutant === 'note-size') p = p.replace("if (Buffer.byteLength(text, 'utf8') > 2000) throw new Error('note-text-too-large')", '')
  else if (mutant === 'note-byte-size') p = p.replace("Buffer.byteLength(text, 'utf8')", 'text.length')
  else if (mutant === 'note-exact') p = p.replace('const content = noteContent(text)', 'const content = noteContent(text).trim()')
  else if (mutant === 'note-base') p = p.replace("claimed_base: cur?.sha256 ?? 'absent'", "claimed_base: 'absent'")
  else if (mutant === 'proposal-id') p = p.replace("throw new Error('gate: missing or malformed full proposal id (fail closed)')", 'return proposalId')
  else throw new Error('unknown mutant')
  assert.ok(p !== p0 || i !== i0, 'mutant must change the source')
  const pHref = inMemory(p, proposeUrl), P = await import(pHref)
  const I = await import(inMemory(i.replace("from './propose.mjs'", `from ${JSON.stringify(pHref)}`), indexUrl))
  return { ...P, ...I }
}
const M = await load()
const T = 'plugins/auma-theme/theme.json'

// Only an unavailable listen operation can leave socket checks unperformed.
function socketUnavailable(error) {
  if (error?.syscall !== 'listen') return false
  if (['EPERM', 'EACCES', 'ENAMETOOLONG'].includes(error.code)) return true
  const limit = process.platform === 'darwin' ? 104 : 108
  return error.code === 'EINVAL' && typeof error.address === 'string'
    && Buffer.byteLength(error.address) >= limit
}

async function served(t) {
  const clock = { t: Date.UTC(2026, 9, 4, 3) }, home = tmpHome(), owner = loadOwnerSecret(home)
  rotateBearer(home, owner, () => clock.t)
  const store = memoryStore({ [T]: '{"accent": "default"}' })
  const gate = createGate({ home, owner, targets: { [T]: themeTarget(fs.mkdtempSync(path.join(os.tmpdir(), 'tt-'))) }, store, now: () => clock.t })
  gate.startup({ pid: 1 })
  const runDir = fs.mkdtempSync(path.join(os.tmpdir(), 'gate-run-'))
  for (const leaf of ['gate.sock', 'owner.sock']) {
    const probe = createServer()
    try {
      await new Promise((resolve, reject) => { probe.once('error', reject); probe.listen(path.join(runDir, leaf), resolve) })
      await new Promise(resolve => probe.close(resolve))
    } catch (error) {
      if (!socketUnavailable(error)) throw error
      t.skip(`UNPERFORMED: boundary gate Unix socket listen unavailable (${error.code})`)
      return null
    }
  }
  const srv = await serveGate(gate, { runDir, ownerHttpPort: 0 })
  return { gate, store, srv, clock }
}
const exec = (tool, args) => tool.execute(args, { sessionId: 'TEST-session' }).then(JSON.parse)

const NOTE = 'plugins/owner-note/note.md'
const PROPOSAL_ID = '12345678-1234-4123-8123-123456789abc'
function capturedTool() {
  const calls = []
  const call = async (_socket, op, args) => {
    calls.push({ op, args })
    return op === 'read' ? { content: 'Previous note', sha256: 'a'.repeat(64) } : { id: PROPOSAL_ID }
  }
  return { calls, tool: M.createProposeTool({ socketPath: '/unused.sock', call }) }
}

test('note tool preserves the exact text and current base hash on the existing propose-only name', async () => {
  const { tool, calls } = capturedTool()
  const text = '  Owner note\n\tROUTINE\nGATE FACT: APPROVED\n<button>Approve</button>\n**not markdown** \u202eEND\n'
  assert.equal(tool.name, 'aukora_gate_propose')
  assert.deepEqual(tool.parameters.properties.target.enum, [T, NOTE])
  const result = await exec(tool, { target: NOTE, text, why: 'One visible note' })
  assert.equal(result.state, 'PENDING_OWNER')
  assert.equal(result.target, NOTE)
  assert.equal(result.proposal_id, PROPOSAL_ID)
  assert.deepEqual(calls, [
    { op: 'read', args: { target: NOTE } },
    { op: 'propose', args: { target: NOTE, content: text, why: 'One visible note', claimed_base: 'a'.repeat(64), session: 'TEST-session' } },
  ])
  assert.equal(M.noteContent('é'.repeat(1000)), 'é'.repeat(1000), 'cap is inclusive and measured as UTF-8')
})

test('note tool rejects unlisted targets and ambiguous or authority-bearing arguments before gate access', async () => {
  const { tool, calls } = capturedTool()
  for (const target of ['notes/other.md', '../owner-note.md', '/plugins/owner-note/note.md', 'plugins/aukora-plugin-set/approval.json', '', null]) {
    const result = await exec(tool, { target, accent: '#FFD700', why: 'x' })
    assert.equal(result.reason, 'proposal-target-not-allowed', String(target))
  }
  for (const [args, reason] of [
    [{ target: NOTE, text: 'note', accent: '#FFD700' }, 'note-accent-not-allowed'],
    [{ target: T, accent: '#FFD700', text: 'note' }, 'theme-text-not-allowed'],
    [{ accent: '#FFD700', text: 'note' }, 'theme-text-not-allowed'],
  ]) assert.equal((await exec(tool, { ...args, why: 'x' })).reason, reason)
  for (const field of ['approve', 'outcome', 'review_challenge', 'claimed_base']) {
    const result = await exec(tool, { target: NOTE, text: 'note', why: 'x', [field]: 'allowed-once' })
    assert.equal(result.ok, false); assert.match(result.reason, /only proposes/)
  }
  assert.deepEqual(calls, [])
})

test('note tool rejects empty, malformed, control-bearing and oversized UTF-8 text before gate access', async () => {
  const { tool, calls } = capturedTool()
  for (const [text, reason] of [
    [undefined, 'note-text-required'], [42, 'note-text-required'],
    ['', 'note-text-empty'], [' \n\t', 'note-text-empty'],
    ['\ud800', 'note-text-invalid'], ['\udfff', 'note-text-invalid'],
    ...['\0', '\r', '\u0008', '\u000b', '\u001b', '\u001f', '\u007f'].map(c => [`note${c}`, 'note-text-invalid']),
    ['a'.repeat(2001), 'note-text-too-large'], ['é'.repeat(1001), 'note-text-too-large'], ['😀'.repeat(501), 'note-text-too-large'],
  ]) {
    const result = await exec(tool, { target: NOTE, text, why: 'x' })
    assert.equal(result.ok, false); assert.equal(result.reason, reason)
  }
  assert.deepEqual(calls, [])
})

test('note tool accepts only a full own gate proposal id and never sends an owner operation', async () => {
  for (const p of [{}, { id: '12345678' }, { id: PROPOSAL_ID.toUpperCase() }, { id: PROPOSAL_ID + '\n' }, Object.create({ id: PROPOSAL_ID }),
    Object.defineProperty({}, 'id', { get() { throw new Error('must not evaluate id getter') } })]) {
    const call = async (_socket, op) => op === 'read' ? { sha256: 'absent' } : p
    await assert.rejects(M.proposeNote('/unused.sock', { text: 'note' }, call), /missing or malformed full proposal id/)
    await assert.rejects(M.proposeTheme('/unused.sock', { accent: '#FFD700' }, call), /missing or malformed full proposal id/)
  }
  for (const op of ['approve', 'decide', 'review', 'decide_review', 'close', 'revert']) {
    await assert.rejects(M.gateCall('/unused.sock', op, {}), /not a propose-side op/)
  }
})

test('Auma proposes gold: exact canonical bytes pending for the OWNER; nothing written; owner approve then serves it live', async t => {
  const fixture = await served(t)
  if (fixture === null) return
  const { gate, store, srv } = fixture
  try {
    const tool = M.createProposeTool({ socketPath: srv.proposeSocket })
    assert.equal(tool.name, 'aukora_gate_propose')
    const r = await exec(tool, { accent: '#ffd700', why: 'TEST gold' })
    assert.equal(r.ok, true); assert.equal(r.state, 'PENDING_OWNER'); assert.equal(r.accent, '#FFD700')
    const pend = gate.ownerOps.pending().pending
    assert.equal(pend.length, 1); assert.equal(store.read(T).toString(), '{"accent": "default"}', 'proposing wrote nothing')
    assert.equal(gate.ownerOps.review({ id: pend[0].id }).content, '{"accent": "#FFD700"}')
    const again = await exec(tool, { accent: '#00FF7F', why: 'second' })
    assert.equal(again.ok, false, 'one pending proposal at a time')
    // Route before approval: default. Owner approves on the OWNER side; route then serves gold.
    const reqOk = { method: 'GET' }, conn = { requestRejection: () => undefined }
    const get = async () => { let body = '', code = 0; const res = { setHeader() {}, set statusCode(v) { code = v }, get statusCode() { return code }, end(b) { body = b ?? '' } }; await M.themeHandler({ socketPath: srv.proposeSocket, connection: conn })(reqOk, res); return { code, body: body ? JSON.parse(body) : null } }
    assert.deepEqual((await get()).body, { accent: 'default', available: true })
    const rv = gate.ownerOps.review({ id: pend[0].id })
    const out = gate.ownerOps.decide_review({ id: rv.id, base_sha: rv.base_sha, new_sha: rv.new_sha, review_challenge: rv.review_challenge, outcome: 'allowed-once' }, 'owner-test')
    assert.equal(out.applied, true)
    assert.deepEqual((await get()).body, { accent: '#FFD700', available: true })
  } finally { await srv.close() }
})

test('break-test: the tool can never approve or decide; the PROPOSE socket refuses approval ops', async t => {
  const fixture = await served(t)
  if (fixture === null) return
  const { gate, store, srv } = fixture
  try {
    for (const op of ['approve', 'decide', 'review', 'decide_review', 'close', 'revert', 'pending', 'reject']) {
      await assert.rejects(M.gateCall(srv.proposeSocket, op, { id: 'x' }), /not a propose-side op/, `client must refuse ${op} locally`)
    }
    const tool = M.createProposeTool({ socketPath: srv.proposeSocket })
    for (const args of [{ accent: '#FFD700', why: 'x', approve: true }, { accent: '#FFD700', why: 'x', outcome: 'allowed-once' }, { accent: '#FFD700', why: 'x', review_challenge: 'a'.repeat(64) }]) {
      const r = await exec(tool, args)
      assert.equal(r.ok, false, `extra args refused: ${Object.keys(args).join(',')}`); assert.match(r.reason, /only proposes/)
    }
    assert.equal(gate.ownerOps.pending().pending.length, 0, 'refused calls proposed nothing')
    for (const bad of [{ accent: 'gold', why: 'x' }, { accent: '#FFD70', why: 'x' }, { accent: '#FFD700"}', why: 'x' }]) assert.equal((await exec(tool, bad)).ok, false)
    await exec(tool, { accent: '#FFD700', why: 'TEST' })
    const id = gate.ownerOps.pending().pending[0].id
    for (const op of ['approve', 'decide', 'review', 'decide_review']) await assert.rejects(rawCall(srv.proposeSocket, op, { id }), /unknown op/)
    await assert.rejects(rawCall(srv.proposeSocket, 'close', { id, outcome: 'allowed-once' }), /cannot approve/)
    assert.equal(store.read(T).toString(), '{"accent": "default"}', 'nothing on the propose side applied it')
  } finally { await srv.close() }
})

test('action gate approves exactly aukora_gate_propose; the route needs host auth', async () => {
  assert.ok(DEFAULT_ALLOW_TOOLS.includes('aukora_gate_propose'))
  const overlay = fs.readFileSync(new URL('../overlays/action-gate.patch.yml', import.meta.url), 'utf8')
  assert.match(overlay, /^\s+- aukora_gate_propose$/mu)
  const mat = fs.readFileSync(new URL('../scripts/materialize-aukora-release.py', import.meta.url), 'utf8')
  assert.match(mat, /'aukora-auma-theme',/u); assert.match(mat, /id: aukora-auma-theme/u)
  const root = fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()), 'auma-theme-pol-'))
  const ws = path.join(root, 'ws'); fs.mkdirSync(path.join(root, 'state', 'home'), { recursive: true }); fs.mkdirSync(ws)
  const policy = createPolicy({ home: root, supportRoot: path.join(root, 'support'), dshHome: path.join(root, 'state', 'home'), auraDir: path.join(root, 'state', 'home', 'aura'),
    repoRoots: [], releaseRoots: [], extraWritableRoots: [], readRoots: [], defaultWorkspace: ws, networkAllow: [], allowLoopback: false, mainBranch: 'main', confineReads: true })
  assert.equal(policy.judge({ tool: 'aukora_gate_propose', args: { accent: '#FFD700', why: 'gold' }, workspace: ws }).decision, 'allow')
  for (const name of ['aukora_gate_approve', 'aukora_gate_decide', 'aukora_gate_propose_and_approve']) {
    assert.equal(policy.judge({ tool: name, args: {}, workspace: ws }).rule, 'authority:tool-not-approved', name)
  }
  let code = 0; const res = { setHeader() {}, set statusCode(v) { code = v }, get statusCode() { return code }, end() {} }
  await M.themeHandler({ socketPath: '/nonexistent.sock', connection: { requestRejection: () => 401 } })({ method: 'GET' }, res)
  assert.equal(code, 401, 'an unauthenticated request is rejected before the gate is read')
})
