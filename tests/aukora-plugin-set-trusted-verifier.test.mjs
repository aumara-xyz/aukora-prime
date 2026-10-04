// ROOT TOOLS NEVER RUN CANDIDATE CODE + MONOTONIC RELEASE FLOOR + COMMITTED ENFORCEMENT UNIT.
// (1) bin/plugin-set-approval.mjs and bin/release-floor.mjs (root) import only the root-owned gate install; the candidate
//     release is JSON data. The trusted verifier agrees with the composition gate's own verdicts and refusal codes.
// (2) The v2 release floor follows verified signer epoch and signed ledger sequence; boot needs its exact committed
//     approval. A rollback needs fresh owner proof, and the gate labels that card ROLLBACK.
// (3) The committed aukora-genesis.service is the signed-enforcement unit: --foreground, root approval root, record sha,
//     the floor ExecStartPre, and no waiver flag.
// TV_MUTANT=<name> removes one guard in memory to prove the checks bite.
// SOURCE_ONLY: disposable synthetic owner/key/SQLite fixtures and source unit checks; no installed runtime claim.
import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { createHash, createPublicKey } from 'node:crypto'
import { spawnSync } from 'node:child_process'

const sha = (b) => createHash('sha256').update(b).digest('hex')
const root = new URL('../', import.meta.url)
const read = (rel) => fs.readFileSync(new URL(rel, root), 'utf8')
const M = process.env.TV_MUTANT ?? ''
function mutate(src, pairs = []) {
  for (const [a, b] of pairs) {
    assert.ok(src.includes(a), 'mutant must name an existing guard')
    src = src.replace(a, b)
  }
  return src
}
async function load(rel, pairs = []) {
  const url = new URL(rel, root)
  let src = mutate(fs.readFileSync(url, 'utf8'), pairs)
  src = src.replace(/from (['"])(\.[^'"]+)\1/gu, (_m, _q, r) => `from ${JSON.stringify(new URL(r, url).href)}`)
  return import(`data:text/javascript;base64,${Buffer.from(src).toString('base64')}`)
}
const MUT = {
  'canon-no-signature': ['packages/boundary-gate/src/plugin-set-canon.mjs', [["if (!ok) throw refuse('plugin-set-approval-signature-invalid'", "if (false) throw refuse('plugin-set-approval-signature-invalid'"]]],
  'canon-no-set-compare': ['packages/boundary-gate/src/plugin-set-canon.mjs', [['if (named.plugin_set !== setDigest || named.operation !== operationDigest)', 'if (false)']]],
  'canon-no-ledger-signature': ['packages/boundary-gate/src/plugin-set-canon.mjs', [["if (!valid) throw refuse('signed-ledger-entry-signature'", "if (false) throw refuse('signed-ledger-entry-signature'"]]],
  'canon-prefix-epoch': ['packages/boundary-gate/src/plugin-set-canon.mjs', [['row.gate_pubkey_sha256 === signerKeySha256', 'row.gate_pubkey_sha256.slice(0, 16) === signerKeySha256.slice(0, 16)']]],
  'floor-no-check': ['packages/boundary-gate/src/release-floor.mjs', [['if (order < 0)', 'if (false)']]],
  'floor-moves-back': ['packages/boundary-gate/src/release-floor.mjs', [['if (compare(floor, verified) <= 0)', 'if (false)']]],
  'floor-uncommitted-boot': ['packages/boundary-gate/src/release-floor.mjs', [['if (order > 0)', 'if (false)']]],
  'unit-direct-floor': ['packages/boundary-gate/host/systemd/aukora-genesis.service', [['ExecStartPre=/usr/bin/python3 -I -S /usr/local/lib/aukora-boundary/gate-bootstrap floor check', 'ExecStartPre=/opt/aukora-node/bin/node /opt/aukora-boundary-gate/bin/release-floor.mjs check']]],
  'unit-no-package-check': ['packages/boundary-gate/host/systemd/aukora-genesis.service', [['ExecStartPre=/usr/bin/python3 -I -S /usr/local/lib/aukora-boundary/gate-bootstrap check-package\n', '']]],
  'unit-preview-waiver': ['packages/boundary-gate/host/systemd/aukora-genesis.service', [['ExecStart=/usr/bin/python3 scripts/launch-dsh.py', 'ExecStart=/usr/bin/python3 scripts/launch-dsh.py --unsafe-preview-allow-unapproved']]],
  'launcher-service-preview': ['scripts/launch-dsh.py', [["if a.foreground and a.launch_profile != 'production':", 'if False:']]],
  'launcher-production-waiver': ['scripts/launch-dsh.py', [["if a.launch_profile != 'disposable-preview' and (a.unsafe_preview_allow_unapproved or a.unsafe_preview_allow_ungated):", 'if False:']]],
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
function world(t) {
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
  t.after(() => { gate.close(); fs.rmSync(tmp, { recursive: true, force: true }) })
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
    assert.equal(out.applied, true)
    const exported = gate.ownerOps.log({ limit: 200, target: PLUGIN_SET_TARGET })
    assert.equal(exported.verify.ok, true, 'actual synthetic gate ledger verifies')
    const row = exported.entries.find(entry => entry.seq === out.ledger_seq)
    assert.ok(row?.signed_entry, 'owner export supplies the original signed ledger row')
    assert.equal(row.signed_entry.hash, out.ledger_hash)
    assert.deepEqual(row.detail.receipt, out.receipt)
    assert.equal(row.detail.receipt_sig, out.receipt_sig)
    clock.t += 60000
    return { plain: pending.plain, applied: out, approval: { kind: canon.GATE_APPROVAL_KIND, content: rel.content,
      receipt: row.detail.receipt, receipt_sig: row.detail.receipt_sig, ledger_entry: row.signed_entry } }
  }
  const pin = { kind: canon.GATE_PIN_KIND, gatePubkeyPem: gate.pubPem, gatePubkeyFp: gate.fp, target: PLUGIN_SET_TARGET, approver: OWNER_SOCKET_APPROVER }
  const signerKeySha256 = sha(createPublicKey(gate.pubPem).export({ type: 'spki', format: 'der' }))
  const epochs = { version: 1, kind: 'aukora-signer-epochs/v1', epochs: [{ epoch: 1, gate_pubkey_sha256: signerKeySha256 }] }
  return { record, install, approve, pin, epochs, signerKeySha256, floorFile }
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

test('trusted verifier = composition gate verdict, on the same approval and every alteration (candidate code never runs)', t => {
  const w = world(t), rel = w.install('ea66a0a')
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
  t.after(() => fs.rmSync(t2, { recursive: true, force: true }))
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

test('ordered evidence comes from actual signed owner export and the exact full-SPKI signer registry', t => {
  const w = world(t), rel = w.install('ea66a0a'), { approval, applied } = w.approve(rel)
  const input = { record: w.record, approval, pin: w.pin, epochs: w.epochs }
  const verified = canon.verifyOrderedGateApproval(input)
  assert.equal(verified.signerEpoch, 1)
  assert.equal(verified.signerKeySha256, w.signerKeySha256)
  assert.equal(verified.ledgerSeq, applied.ledger_seq)
  assert.equal(verified.ledgerHash, applied.ledger_hash)
  assert.equal(approval.ledger_entry.detail, JSON.stringify({ receipt: approval.receipt, receipt_sig: approval.receipt_sig }))
  assert.throws(() => floorMod.advanceFloor(null, canon.verifyGateSetApproval(input)), { code: 'release-floor-ordering-evidence' })
  const missing = structuredClone(input); delete missing.approval.ledger_entry
  assert.throws(() => canon.verifyOrderedGateApproval(missing), { code: 'signed-ledger-entry-malformed' })
  const seq = structuredClone(input); seq.approval.ledger_entry.seq++
  assert.throws(() => canon.verifyOrderedGateApproval(seq), { code: 'signed-ledger-entry-hash' })
  const sig = structuredClone(input); sig.approval.ledger_entry.sig = Buffer.alloc(64).toString('base64')
  assert.throws(() => canon.verifyOrderedGateApproval(sig), { code: 'signed-ledger-entry-signature' })
  const other = structuredClone(input)
  other.epochs.epochs[0].gate_pubkey_sha256 = w.signerKeySha256.slice(0, -1) + (w.signerKeySha256.endsWith('f') ? 'e' : 'f')
  assert.throws(() => canon.verifyOrderedGateApproval(other), { code: 'signer-epoch-unpinned' })
})

test('release floor: older proof refused, fresh rollback commits before boot and retains the ROLLBACK card/history', t => {
  const w = world(t), A = w.install('a3e27d6'), B = w.install('524b8f5')
  const verify = approval => canon.verifyOrderedGateApproval({ record: w.record, approval, pin: w.pin, epochs: w.epochs })
  const vA = verify(w.approve(A).approval)
  let floor = floorMod.advanceFloor(null, vA)
  const vB = verify(w.approve(B).approval)
  assert.ok(vB.ledgerSeq > vA.ledgerSeq, 'fresh owner decision advances signed sequence')
  assert.throws(() => floorMod.checkFloor(floor, vB), { code: 'release-floor-install-incomplete' })
  floor = floorMod.advanceFloor(floor, vB)
  assert.equal(floor.release_dir, 'release-524b8f5'); assert.deepEqual(floor.history, [A.fields.release])
  assert.equal(floor.kind, 'aukora-release-floor/v2')
  assert.equal(floor.signer_epoch, vB.signerEpoch); assert.equal(floor.ledger_seq, vB.ledgerSeq)
  assert.equal(floor.signer_key_sha256, vB.signerKeySha256); assert.equal(floor.ledger_hash, vB.ledgerHash)
  assert.throws(() => floorMod.advanceFloor(floor, vA), { code: 'release-floor-not-newer' }, 'older install refuses without lowering the floor')
  assert.throws(() => floorMod.advanceFloor(floor, vB), { code: 'release-floor-not-newer' }, 'equal proof cannot be replayed as a new install')
  assert.throws(() => floorMod.checkFloor(floor, vA), /release-below-floor: release-a3e27d6/, 'old approval + old release refused')
  assert.equal(floorMod.checkFloor(floor, vB).ok, true)
  assert.throws(() => floorMod.checkFloor(null, vB), /no release floor/)
  // rollback: a fresh owner approval of A, labelled by the gate, then accepted and the floor moves to it
  // Provision only the disposable card-reading fixture; protected installation/writer behavior is checked separately.
  fs.writeFileSync(w.floorFile, JSON.stringify(floor), { flag: 'wx' })
  assert.deepEqual(floorMod.readFloor(w.floorFile), floor)
  const again = w.approve(A)
  assert.match(again.plain, /^GATE FACT: ROLLBACK to release-a3e27d6, below the release floor release-524b8f5 \| GATE FACT: plugin set UNCHANGED/)
  const vA2 = verify(again.approval)
  assert.ok(vA2.ledgerSeq > vB.ledgerSeq, 'rollback has its own fresh signed owner decision')
  assert.throws(() => floorMod.checkFloor(floor, vA2), { code: 'release-floor-install-incomplete' }, 'fresh rollback waits for its floor commit')
  floor = floorMod.advanceFloor(floor, vA2)
  assert.equal(floor.release_dir, 'release-a3e27d6'); assert.deepEqual(floor.history, [B.fields.release])
  assert.equal(floorMod.checkFloor(floor, vA2).ok, true, 'the exact committed fresh rollback passes the floor')
  assert.throws(() => floorMod.checkFloor(floor, vA), { code: 'release-below-floor' }, 'same release with its original proof still refuses')
  assert.ok(again.plain.length <= 600, 'fits the review from_to bound')
})

test('committed genesis unit checks custody before Node and launches with signed enforcement and no waiver', () => {
  const unitFile = 'packages/boundary-gate/host/systemd/aukora-genesis.service'
  const u = mutate(read(unitFile), pick(unitFile))
  const execLines = u.split('\n').filter(l => /^Exec/u.test(l)), exec = execLines.join('\n')
  assert.doesNotMatch(exec, /--(?:unsafe-preview-)?allow-(?:unapproved|ungated)|--launch-profile(?:=|\s+)disposable-preview/u)
  assert.match(exec, /^ExecStart=.*launch-dsh\.py .*--foreground --node \/opt\/aukora-node\/bin\/node --approval-state-root \$\{AUKORA_APPROVAL_ROOT\} --approved-record-sha \$\{AUKORA_RECORD_SHA\}/mu)
  assert.match(exec, /^ExecStartPre=\/usr\/bin\/python3 -I -S \/usr\/local\/lib\/aukora-boundary\/gate-bootstrap floor check --release-dir \$\{AUKORA_RELEASE_DIR\} --approval-state-root \$\{AUKORA_APPROVAL_ROOT\}$/mu)
  assert.equal(execLines[0], 'ExecStartPre=/usr/bin/python3 -I -S /usr/local/lib/aukora-boundary/gate-bootstrap check-package', 'package custody is checked before the first Node process')
  assert.match(exec, /^ExecStartPre=.*selfcheck\.mjs/mu)
  assert.match(u, /^EnvironmentFile=\/etc\/aukora-genesis\/release\.env$/mu)
  assert.match(u, /^UnsetEnvironment=NODE_OPTIONS NODE_PATH PYTHONPATH PYTHONHOME LD_PRELOAD LD_LIBRARY_PATH LD_AUDIT$/mu)
  // and the launcher itself refuses a waiver on a service launch
  const launcherFile = 'scripts/launch-dsh.py', launcher = mutate(read(launcherFile), pick(launcherFile))
  assert.match(launcher, /if a\.launch_profile != 'disposable-preview' and \(a\.unsafe_preview_allow_unapproved or a\.unsafe_preview_allow_ungated\):\n\s+parser\.error\('unsafe-preview-options-refused/u)
  assert.match(launcher, /if a\.foreground and a\.launch_profile != 'production':\n\s+parser\.error\('foreground-requires-approval/u)
})
