// THE GATE AS ACCEPTED SIGNER (2026-10-04), end to end on a synthetic installed release:
// operator raise (owner channel) -> pending 24 h, not proposable by an agent -> the popup ceremony (review -> decide_review)
// -> the gate's signed v2 receipt -> the composition gate admits the set ONLY under a pin naming the gate key, and refuses
// every altered field. PSG_MUTANT=<name> removes one guard in memory to prove the checks bite.
import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { createHash, generateKeyPairSync, sign } from 'node:crypto'

const sha = (b) => createHash('sha256').update(b).digest('hex')
async function load(rel, mutant) {
  const url = new URL(rel, import.meta.url)
  let src = fs.readFileSync(url, 'utf8'); const orig = src
  for (const [a, b] of mutant ?? []) src = src.replace(a, b)
  if (mutant) assert.notEqual(src, orig, 'mutant must change the source')
  src = src.replace(/from (['"])(\.[^'"]+)\1/gu, (_m, _q, r) => `from ${JSON.stringify(new URL(r, url).href)}`)
  return import(`data:text/javascript;base64,${Buffer.from(src).toString('base64')}`)
}
const M = process.env.PSG_MUTANT
const MUTANTS = {
  'agent-may-propose': ['../packages/boundary-gate/src/gate.mjs', [["propose: (a) => { refuseOperatorOnly(a?.target, 'propose'); return", 'propose: (a) => { return']]],
  'ttl-for-everyone': ['../packages/boundary-gate/src/gate.mjs', [['&& s.operatorOnly === true ? s.ttlMs', '? s.ttlMs'], ['const ttl = Number.isInteger(s.ttlMs)', 'const ttl = (s.ttlMs ??= 24 * 3600 * 1000) && Number.isInteger(s.ttlMs)']]],
  'no-gate-signature': ['../plugins/aukora-composition-gate/src/plugin-set.mjs', [["if (!ok) throw refuse(SET_REFUSE.SIGNATURE_INVALID, `the gate receipt's", "if (false) throw refuse(SET_REFUSE.SIGNATURE_INVALID, `the gate receipt's"]]],
  'no-set-compare': ['../plugins/aukora-composition-gate/src/plugin-set.mjs', [['if (named.plugin_set !== setDigest || named.operation !== operationDigest) {', 'if (false) {']]],
}
const pick = (rel) => (M && MUTANTS[M]?.[0] === rel ? MUTANTS[M][1] : undefined)
if (M && !MUTANTS[M]) throw new Error('unknown mutant')
const { createGate } = await load('../packages/boundary-gate/src/gate.mjs', pick('../packages/boundary-gate/src/gate.mjs'))
const ps = await load('../plugins/aukora-composition-gate/src/plugin-set.mjs', pick('../plugins/aukora-composition-gate/src/plugin-set.mjs'))
const { allowlist, PLUGIN_SET_TARGET, THEME_TARGET, PLUGIN_SET_TTL_MS, pluginSetApprovalText } = await import('../packages/boundary-gate/src/targets.mjs')
const { loadOwnerSecret, rotateBearer } = await import('../packages/boundary-gate/src/secrets.mjs')
const { OWNER_SOCKET_APPROVER } = await import('../packages/boundary-gate/src/server.mjs')
const { memoryStore } = await import('../packages/boundary-gate/checks/support/fixture.mjs')

function world() {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'psg-')), src = path.join(tmp, 'src')
  fs.mkdirSync(path.join(src, 'plugins/demo/lib'), { recursive: true })
  fs.writeFileSync(path.join(src, 'plugins/demo/lib/index.mjs'), 'export const x = 1\n')
  const record = ps.recordPluginSet({ root: src, rows: [{ id: 'demo', entry: 'plugins/demo/lib/index.mjs' }] })
  const tip = 'f1f7d8d' + 'a'.repeat(33), releasesRoot = path.join(tmp, 'opt'), rel = path.join(releasesRoot, 'release-f1f7d8d', '.dsh-build')
  fs.mkdirSync(rel, { recursive: true })
  fs.writeFileSync(path.join(rel, 'plugin-set.json'), JSON.stringify(record))
  fs.writeFileSync(path.join(rel, 'aukora-release.json'), JSON.stringify({ tipSha: tip }))
  fs.writeFileSync(path.join(rel, 'genesis-artifacts.json'), '{"artifacts":[]}')
  const operation = ps.operationDigestOf(ps.setOperationContent(record))
  const fields = { release: tip, release_dir: 'release-f1f7d8d', plugin_set: record.setDigest, operation, record: sha(fs.readFileSync(path.join(rel, 'genesis-artifacts.json'))) }
  const clock = { t: Date.UTC(2026, 9, 4, 5) }, home = path.join(tmp, 'home'); fs.mkdirSync(home, { mode: 0o700 })
  const owner = loadOwnerSecret(home); rotateBearer(home, owner, () => clock.t)
  const store = memoryStore({ [THEME_TARGET]: '{"accent": "#FFD700"}' })
  const gate = createGate({ home, owner, targets: allowlist(path.join(tmp, 'targets'), { releasesRoot }), store, now: () => clock.t })
  gate.startup({ pid: 1 })
  return { gate, clock, record, fields, content: pluginSetApprovalText(fields), store }
}
const raise = (w, content = w.content) => w.gate.ownerOps.raise({ target: PLUGIN_SET_TARGET, content, why: 'TEST raise' })
function approve(w, id) {
  const r = w.gate.ownerOps.review({ id })
  return { r, out: w.gate.ownerOps.decide_review({ id, base_sha: r.base_sha, new_sha: r.new_sha, review_challenge: r.review_challenge, outcome: 'allowed-once', confirm: r.new_sha.slice(0, 4) }, OWNER_SOCKET_APPROVER) }
}
const pinOf = (w) => ({ kind: ps.GATE_PIN_KIND, gatePubkeyPem: w.gate.pubPem, gatePubkeyFp: w.gate.fp, target: PLUGIN_SET_TARGET, approver: OWNER_SOCKET_APPROVER })

test('an agent cannot propose (or revert to) a plugin-set approval; only the owner channel raises it', () => {
  const w = world()
  assert.throws(() => w.gate.proposeOps.propose({ target: PLUGIN_SET_TARGET, content: w.content, why: 'x', claimed_base: 'absent', session: 's' }), /operator-only/)
  assert.throws(() => w.gate.proposeOps.revert({ target: PLUGIN_SET_TARGET, to_sha: 'previous' }), /operator-only/)
  assert.ok(!Object.hasOwn(w.gate.proposeOps, 'raise'))
  assert.throws(() => w.gate.ownerOps.raise({ target: THEME_TARGET, content: '{"accent": "#000000"}', why: 'x' }), /only for operator-only/)
})

test('raise names the installed release; a wrong tip, set, record or release_dir is refused by the gate', () => {
  const w = world()
  for (const k of ['release', 'plugin_set', 'record']) {
    const bad = { ...w.fields, [k]: w.fields[k].replace(/^./u, c => (c === '0' ? '1' : '0')) }
    if (k === 'release') bad.release_dir = 'release-' + bad.release.slice(0, 7)
    assert.throws(() => raise(w, pluginSetApprovalText(bad)), /schema/)
  }
  const p = raise(w)
  assert.match(p.popup.plain_change, new RegExp(`release ${w.fields.release} \\(release-f1f7d8d\\) \\| plugin set ${w.fields.plugin_set} \\| operation ${w.fields.operation}`))
})

test('the question waits 24 h for an absent owner; the decision window stays 2 min; theme and release do not block each other', () => {
  const w = world()
  const p = raise(w)
  assert.equal(p.expires - p.created, PLUGIN_SET_TTL_MS)
  const t = w.gate.proposeOps.propose({ target: THEME_TARGET, content: '{"accent": "#00BFFF"}', why: 'x', claimed_base: w.gate.proposeOps.read({ target: THEME_TARGET }).sha256, session: 's' })
  assert.equal(t.expires - t.created, 5 * 60 * 1000, 'agent targets keep the 5-minute pending lifetime')
  w.clock.t += 10 * 3600 * 1000
  assert.ok(w.gate.ownerOps.pending().pending.some(r => r.id === p.id), 'still pending after 10 h, nothing applied')
  assert.equal(w.store.read(PLUGIN_SET_TARGET), null)
  const r = w.gate.ownerOps.review({ id: p.id })
  assert.ok(r.review_expires - w.clock.t <= 120000, 'the review challenge is not lengthened')
  w.clock.t += 121000
  assert.throws(() => w.gate.ownerOps.decide_review({ id: p.id, base_sha: r.base_sha, new_sha: r.new_sha, review_challenge: r.review_challenge, outcome: 'allowed-once', confirm: r.new_sha.slice(0, 4) }, OWNER_SOCKET_APPROVER), /expired/)
  w.clock.t += 15 * 3600 * 1000
  assert.ok(!w.gate.ownerOps.pending().pending.some(r2 => r2.id === p.id), 'gone after 24 h, never applied')
  assert.equal(w.store.read(PLUGIN_SET_TARGET), null)
})

test('owner approval -> signed receipt -> admitted only under the gate pin; every alteration refused', () => {
  const w = world()
  const { out } = approve(w, raise(w).id)
  assert.equal(out.applied, true)
  const approval = { kind: ps.GATE_APPROVAL_KIND, content: w.content, receipt: out.receipt, receipt_sig: out.receipt_sig }
  const ok = ps.verifySetApproval({ record: w.record, receipt: approval, pin: pinOf(w) })
  assert.equal(ok.setDigest, w.fields.plugin_set); assert.equal(ok.operationDigest, w.fields.operation); assert.equal(ok.release, w.fields.release)
  const refuses = (mut, code) => { const a = structuredClone(approval), p = pinOf(w); mut(a, p); assert.throws(() => ps.verifySetApproval({ record: w.record, receipt: a, pin: p }), (e) => e.code === code) }
  refuses((a) => { a.receipt_sig = Buffer.alloc(64).toString('base64') }, 'plugin-set-approval-signature-invalid')
  refuses((a) => { a.receipt.applied_at = '2030-01-01T00:00:00.000Z' }, 'plugin-set-approval-signature-invalid')
  refuses((a) => { a.receipt.approver = 'someone else' }, 'plugin-set-approval-for-other-identity')
  refuses((_a, p) => { p.approver = 'someone else' }, 'plugin-set-approver-not-pinned')
  refuses((a) => { a.content = a.content.replace('"v":1', '"v":1 ') }, 'plugin-set-approval-malformed')
  const other = generateKeyPairSync('ed25519')
  refuses((_a, p) => { p.gatePubkeyPem = other.publicKey.export({ type: 'spki', format: 'pem' }) }, 'plugin-set-approver-not-pinned')
  refuses((_a, p) => { const pem = other.publicKey.export({ type: 'spki', format: 'pem' }); p.gatePubkeyPem = pem; p.gatePubkeyFp = sha(other.publicKey.export({ type: 'spki', format: 'der' })).slice(0, 16) }, 'plugin-set-approval-by-unpinned-key')
  // A receipt validly signed by the gate, over content naming ANOTHER set, is refused by the set comparison.
  const otherContent = pluginSetApprovalText({ ...w.fields, plugin_set: 'b'.repeat(64) })
  const forged = { ...out.receipt, new_sha: sha(Buffer.from(otherContent)) }
  const fakeGateKey = w.gate.home && fs.readFileSync(path.join(w.gate.home, 'receipt-ed25519.pem'))
  const sig = sign(null, Buffer.from(JSON.stringify(forged)), fakeGateKey).toString('base64')
  assert.throws(() => ps.verifySetApproval({ record: w.record, receipt: { ...approval, content: otherContent, receipt: forged, receipt_sig: sig }, pin: pinOf(w) }), (e) => e.code === 'plugin-set-approval-for-other-set')
  // Without the gate pin the same gate receipt is NOT an Aumlok receipt: the pin, not the receipt, chooses the signer.
  assert.throws(() => ps.verifySetApproval({ record: w.record, receipt: approval, pin: { approverDid: 'did:key:z6Mk', subject: 's', activeControlDigest: 'c' } }), (e) => e.code === 'plugin-set-approval-malformed')
})

test('the launcher binds the gate approval to the launched release tip and approved record', () => {
  const s = fs.readFileSync(new URL('../scripts/launch-dsh.py', import.meta.url), 'utf8')
  assert.match(s, /_pin\.get\('kind'\) == 'aukora-boundary-gate-owner\/v1'/)
  assert.match(s, /plugin-set-gate-approval-for-other-release/)
  const i = s.indexOf("_pin.get('kind') == 'aukora-boundary-gate-owner/v1'"), j = s.indexOf('if not a.foreground:', i), k = s.indexOf("_named = json.loads(_content)", i)
  assert.ok(i > 0 && j > i && k > j, 'a gate pin is refused outside --foreground (root-protected approval root) before anything is read')
  assert.match(s, /plugin-set-gate-approval-needs-protected-root/)
  assert.match(s, /_named\.get\('record'\) != record_sha or record_sha not in \(a\.approved_record_sha or \[\]\)/)
})

test('the app re-asks an expired (stale-challenge) gate question with a fresh challenge; it never resends a decision', () => {
  const s = fs.readFileSync(new URL('../apps/aukora-desktop/main.mjs', import.meta.url), 'utf8')
  assert.match(s, /else if \(shown\?\.result\?\.state === 'expired' && shown\?\.result\?\.applied === false\) gateSeen\.delete\(question\.pending\.id\)/)
})

test('minimal/verify.py stays byte-identical to its recorded provenance', () => {
  const prov = JSON.parse(fs.readFileSync(new URL('../vendor/aukora-membrane/PROVENANCE.json', import.meta.url), 'utf8'))
  const find = (x) => Array.isArray(x) ? x.map(find).find(Boolean) : x && typeof x === 'object' ? (x.path === 'minimal/verify.py' ? x : Object.values(x).map(find).find(Boolean)) : undefined
  const entry = find(prov)
  assert.equal(sha(fs.readFileSync(new URL('../vendor/aukora-membrane/minimal/verify.py', import.meta.url))), entry.sha256)
})
