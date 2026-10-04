// ROOT TOOLS NEVER RUN CANDIDATE CODE + MONOTONIC RELEASE FLOOR + MAIN = LIVE UNIT (Kimi/GPT review of 524b8f5,
// Peter 2026-10-04 14:52 WITA).
// (1) bin/plugin-set-approval.mjs and bin/release-floor.mjs (root) import only the root-owned gate install; the candidate
//     release is JSON data. The trusted verifier agrees with the composition gate's own verdicts and refusal codes.
// (2) The release floor: an approval applied before the floor is refused at launch; install only moves the floor forward;
//     a rollback is a fresh owner approval and the gate labels that card ROLLBACK.
// (3) The committed aukora-genesis.service is the signed-enforcement unit: --foreground, root approval root, record sha,
//     the floor ExecStartPre, and no waiver flag.
// TV_MUTANT=<name> removes one guard in memory to prove the checks bite.
import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { createHash } from 'node:crypto'
import { spawnSync } from 'node:child_process'

const sha = (b) => createHash('sha256').update(b).digest('hex')
const root = new URL('../', import.meta.url)
const read = (rel) => fs.readFileSync(new URL(rel, root), 'utf8')
const M = process.env.TV_MUTANT ?? ''
async function load(rel, pairs = []) {
  const url = new URL(rel, root)
  let src = fs.readFileSync(url, 'utf8'); const orig = src
  for (const [a, b] of pairs) src = src.replace(a, b)
  if (pairs.length) assert.notEqual(src, orig, 'mutant must change the source')
  src = src.replace(/from (['"])(\.[^'"]+)\1/gu, (_m, _q, r) => `from ${JSON.stringify(new URL(r, url).href)}`)
  return import(`data:text/javascript;base64,${Buffer.from(src).toString('base64')}`)
}
const MUT = {
  'canon-no-signature': ['packages/boundary-gate/src/plugin-set-canon.mjs', [["if (!ok) throw refuse('plugin-set-approval-signature-invalid'", "if (false) throw refuse('plugin-set-approval-signature-invalid'"]]],
  'canon-no-set-compare': ['packages/boundary-gate/src/plugin-set-canon.mjs', [['if (named.plugin_set !== setDigest || named.operation !== operationDigest)', 'if (false)']]],
  'floor-no-check': ['packages/boundary-gate/src/release-floor.mjs', [['if (ms(verified.appliedAt) < ms(floor.applied_at)) {', 'if (false) {']]],
  'floor-moves-back': ['packages/boundary-gate/src/release-floor.mjs', [['if (floor !== null && ms(verified.appliedAt) <= ms(floor.applied_at)) return floor', 'if (false) return floor']]],
}
const pick = (rel) => (MUT[M]?.[0] === rel ? MUT[M][1] : [])
const canon = await load('packages/boundary-gate/src/plugin-set-canon.mjs', pick('packages/boundary-gate/src/plugin-set-canon.mjs'))
const floorMod = await load('packages/boundary-gate/src/release-floor.mjs', pick('packages/boundary-gate/src/release-floor.mjs'))
const ps = await import('../plugins/aukora-composition-gate/src/plugin-set.mjs')
const { createGate } = await import('../packages/boundary-gate/src/gate.mjs')
const { allowlist, PLUGIN_SET_TARGET, THEME_TARGET, pluginSetApprovalText, pluginSetTarget } = await import('../packages/boundary-gate/src/targets.mjs')
const { loadOwnerSecret, rotateBearer } = await import('../packages/boundary-gate/src/secrets.mjs')
const { OWNER_SOCKET_APPROVER } = await import('../packages/boundary-gate/src/server.mjs')
const { memoryStore } = await import('../packages/boundary-gate/checks/support/fixture.mjs')

// A synthetic installed release whose OWN composition-gate verifier is a trap: if root code imported it, the test fails.
function world() {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'tv-')), src = path.join(tmp, 'src')
  fs.mkdirSync(path.join(src, 'plugins/demo/lib'), { recursive: true })
  fs.writeFileSync(path.join(src, 'plugins/demo/lib/index.mjs'), 'export const x = 1\n')
  const record = ps.recordPluginSet({ root: src, rows: [{ id: 'demo', entry: 'plugins/demo/lib/index.mjs' }] })
  const releasesRoot = path.join(tmp, 'opt'), clock = { t: Date.UTC(2026, 9, 4, 7) }
  const home = path.join(tmp, 'home'); fs.mkdirSync(home, { mode: 0o700 })
  const owner = loadOwnerSecret(home); rotateBearer(home, owner, () => clock.t)
  const floorFile = path.join(tmp, 'release-floor.json')
  const targets = { ...allowlist(path.join(tmp, 'targets'), { releasesRoot }), [PLUGIN_SET_TARGET]: pluginSetTarget(path.join(tmp, 'targets'), { releasesRoot, floorFile }) }
  const gate = createGate({ home, owner, targets, store: memoryStore({ [THEME_TARGET]: '{"accent": "#FFD700"}' }), now: () => clock.t })
  gate.startup({ pid: 1 })
  function install(c7) {
    const tip = c7 + 'a'.repeat(33), dir = path.join(releasesRoot, 'release-' + c7), rel = path.join(dir, '.dsh-build')
    fs.mkdirSync(path.join(dir, 'plugins/aukora-composition-gate/src'), { recursive: true }); fs.mkdirSync(rel, { recursive: true })
    fs.writeFileSync(path.join(dir, 'plugins/aukora-composition-gate/src/plugin-set.mjs'), "throw new Error('CANDIDATE CODE EXECUTED')\n")
    fs.writeFileSync(path.join(rel, 'plugin-set.json'), JSON.stringify(record))
    fs.writeFileSync(path.join(rel, 'aukora-release.json'), JSON.stringify({ tipSha: tip }))
    fs.writeFileSync(path.join(rel, 'genesis-artifacts.json'), `{"artifacts":[],"r":"${c7}"}`)
    const fields = { release: tip, release_dir: 'release-' + c7, plugin_set: record.setDigest, operation: canon.operationDigestOf(canon.setOperationContent(record)), record: sha(fs.readFileSync(path.join(rel, 'genesis-artifacts.json'))) }
    return { dir, fields, content: pluginSetApprovalText(fields) }
  }
  function approve(rel) {
    const p = gate.ownerOps.raise({ target: PLUGIN_SET_TARGET, content: rel.content, why: 'TEST raise' })
    const pending = gate.ownerOps.pending().pending.find(x => x.id === p.id)
    const r = gate.ownerOps.review({ id: p.id })
    const out = gate.ownerOps.decide_review({ id: p.id, base_sha: r.base_sha, new_sha: r.new_sha, review_challenge: r.review_challenge, outcome: 'allowed-once' }, OWNER_SOCKET_APPROVER)
    clock.t += 60000
    return { plain: pending.plain, approval: { kind: canon.GATE_APPROVAL_KIND, content: rel.content, receipt: out.receipt, receipt_sig: out.receipt_sig } }
  }
  const pin = { kind: canon.GATE_PIN_KIND, gatePubkeyPem: gate.pubPem, gatePubkeyFp: gate.fp, target: PLUGIN_SET_TARGET, approver: OWNER_SOCKET_APPROVER }
  return { record, install, approve, pin, floorFile }
}

test('root tools import only the root-owned gate install; nothing under a release directory is imported', () => {
  for (const f of ['packages/boundary-gate/bin/plugin-set-approval.mjs', 'packages/boundary-gate/bin/release-floor.mjs', 'packages/boundary-gate/src/plugin-set-canon.mjs', 'packages/boundary-gate/src/release-floor.mjs']) {
    const s = read(f)
    // H b44f35c: the root CLIs execute ONLY hash-checked buffers, as data: URLs, after the pin manifest verified them;
    // no dynamic import names a path. The verifier modules themselves have no dynamic import at all.
    const dyn = s.split('\n').filter(l => /\bimport\s*\(/u.test(l)).map(l => l.trim())
    if (f.includes('/bin/')) {
      assert.equal(dyn.length, 1, `${f}: one dynamic import site`)
      assert.equal(dyn[0], 'const checkedModule = bytes => import(`data:text/javascript;base64,${bytes.toString(\'base64\')}`)', `${f}: dynamic import only of checked bytes`)
    }
    else assert.deepEqual(dyn, [], `${f}: no dynamic import`)
    assert.doesNotMatch(s, /pathToFileURL|createRequire|\brequire\(/u, `${f}: no runtime module loading`)
    for (const m of s.matchAll(/^import .* from '([^']+)'/gmu)) assert.ok(m[1].startsWith('node:') || m[1].startsWith('./') || m[1].startsWith('../src/'), `${f} imports ${m[1]}`)
  }
  assert.equal(read('packages/boundary-gate/src/vendor/plugin-set-content.mjs'), read('plugins/aukora-aumlok/lib/plugin-set-content.mjs'), 'vendored renderer byte-identical')
})

test('trusted verifier = composition gate verdict, on the same approval and every alteration (candidate code never runs)', () => {
  const w = world(), rel = w.install('ea66a0a')
  assert.equal(canon.setOperationContent(w.record), ps.setOperationContent(w.record))
  assert.equal(canon.operationDigestOf('x'), ps.operationDigestOf('x'))
  // the real root CLI, on a release whose own verifier throws if executed
  // H b44f35c: a checkout copy of the root CLI refuses before any local import (only the fixed root-owned install runs);
  // the in-VM run of the real CLI over trap candidates is packages/boundary-gate/src/vendor/check-trusted-verifier.mjs.
  const cli = spawnSync(process.execPath, [new URL('packages/boundary-gate/bin/plugin-set-approval.mjs', root).pathname, 'show', '--release-dir', rel.dir], { encoding: 'utf8' })
  assert.equal(cli.status, 1, cli.stdout); assert.match(cli.stderr, /REFUSED: trusted-entrypoint/u)
  assert.doesNotMatch(cli.stdout + cli.stderr, /CANDIDATE CODE EXECUTED/u)
  const { approval } = w.approve(rel)
  const a = canon.verifyGateSetApproval({ record: w.record, approval, pin: w.pin }), b = ps.verifySetApproval({ record: w.record, receipt: approval, pin: w.pin })
  for (const k of ['setDigest', 'operationDigest', 'approverDid', 'approvalClass', 'release', 'record', 'count']) assert.equal(a[k], b[k], k)
  const alter = [
    (x) => { x.receipt_sig = Buffer.alloc(64).toString('base64') }, (x) => { x.receipt.applied_at = '2030-01-01T00:00:00.000Z' },
    (x) => { x.receipt.approver = 'someone else' }, (x) => { x.content = x.content.replace('"v":1', '"v":1 ') },
    (x) => { x.content = x.content.replace(rel.fields.plugin_set, 'f'.repeat(64)) }, (x) => { x.kind = 'other' },
  ]
  // a VALIDLY SIGNED approval checked against another record (other plugin bytes) -> other-set, in both verifiers
  const t2 = fs.mkdtempSync(path.join(os.tmpdir(), 'tv2-')); fs.mkdirSync(path.join(t2, 'plugins/demo/lib'), { recursive: true })
  fs.writeFileSync(path.join(t2, 'plugins/demo/lib/index.mjs'), 'export const x = 2\n')
  const other = ps.recordPluginSet({ root: t2, rows: [{ id: 'demo', entry: 'plugins/demo/lib/index.mjs' }] })
  assert.throws(() => canon.verifyGateSetApproval({ record: other, approval, pin: w.pin }), (e) => e.code === 'plugin-set-approval-for-other-set')
  assert.throws(() => ps.verifySetApproval({ record: other, receipt: approval, pin: w.pin }), (e) => e.code === 'plugin-set-approval-for-other-set')
  for (const f of alter) {
    const x = structuredClone(approval); f(x)
    let ca = null, pa = null
    try { canon.verifyGateSetApproval({ record: w.record, approval: x, pin: w.pin }) } catch (e) { ca = e.code }
    try { ps.verifySetApproval({ record: w.record, receipt: x, pin: w.pin }) } catch (e) { pa = e.code }
    assert.ok(ca !== null, 'trusted verifier refuses'); assert.equal(ca, pa, 'same refusal code as the composition gate')
  }
})

test('release floor: older approval refused, install only moves forward, rollback = fresh owner card labelled ROLLBACK', () => {
  const w = world(), A = w.install('a3e27d6'), B = w.install('524b8f5')
  const vA = canon.verifyGateSetApproval({ record: w.record, approval: w.approve(A).approval, pin: w.pin })
  let floor = floorMod.advanceFloor(null, vA)
  const vB = canon.verifyGateSetApproval({ record: w.record, approval: w.approve(B).approval, pin: w.pin })
  floor = floorMod.advanceFloor(floor, vB)
  assert.equal(floor.release_dir, 'release-524b8f5'); assert.deepEqual(floor.history, [A.fields.release])
  assert.equal(floorMod.advanceFloor(floor, vA), floor, 'installing the older approval does not lower the floor')
  assert.throws(() => floorMod.checkFloor(floor, vA), /release-below-floor: release-a3e27d6/, 'old approval + old release refused')
  assert.equal(floorMod.checkFloor(floor, vB).ok, true)
  assert.throws(() => floorMod.checkFloor(null, vB), /no release floor/)
  // rollback: a fresh owner approval of A, labelled by the gate, then accepted and the floor moves to it
  floorMod.writeFloor(w.floorFile, floor)
  const again = w.approve(A)
  assert.match(again.plain, /^GATE FACT: ROLLBACK to release-a3e27d6, below the release floor release-524b8f5 \| GATE FACT: plugin set UNCHANGED/)
  const vA2 = canon.verifyGateSetApproval({ record: w.record, approval: again.approval, pin: w.pin })
  assert.equal(floorMod.checkFloor(floor, vA2).ok, true, 'the fresh owner approval passes the floor')
  assert.equal(floorMod.advanceFloor(floor, vA2).release_dir, 'release-a3e27d6')
  assert.ok(again.plain.length <= 600, 'fits the review from_to bound')
})

test('main = live: the committed genesis unit is the signed-enforcement launch with the floor check and no waiver', () => {
  const u = read('packages/boundary-gate/host/systemd/aukora-genesis.service')
  const exec = u.split('\n').filter(l => /^Exec/u.test(l)).join('\n')
  assert.doesNotMatch(exec, /--allow-unapproved|--allow-ungated/u)
  assert.match(exec, /^ExecStart=.*launch-dsh\.py .*--foreground --node \/opt\/aukora-node\/bin\/node --approval-state-root \$\{AUKORA_APPROVAL_ROOT\} --approved-record-sha \$\{AUKORA_RECORD_SHA\}/mu)
  assert.match(exec, /^ExecStartPre=\/opt\/aukora-node\/bin\/node \/opt\/aukora-boundary-gate\/bin\/release-floor\.mjs check --release-dir \$\{AUKORA_RELEASE_DIR\} --approval-state-root \$\{AUKORA_APPROVAL_ROOT\}$/mu)
  assert.match(exec, /^ExecStartPre=.*selfcheck\.mjs/mu)
  assert.match(u, /^EnvironmentFile=\/etc\/aukora-genesis\/release\.env$/mu)
  // and the launcher itself refuses a waiver on a service launch
  assert.match(read('scripts/launch-dsh.py'), /if a\.foreground and \(a\.allow_unapproved or a\.allow_ungated\):\n\s+parser\.error\('foreground-requires-approval/u)
})
