// Software passkey approval must retain owner proof before plugin-set installation.
import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { EventEmitter } from 'node:events'
import { createHash, generateKeyPairSync, sign } from 'node:crypto'
import { spawnSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import { createGate } from '../packages/boundary-gate/src/gate.mjs'
import { createPasskeyOwnerHandler, PASSKEY_PAGE_APPROVER } from '../packages/boundary-gate/src/owner-page.mjs'
import { openDb, keyFingerprint } from '../packages/boundary-gate/src/ledger.mjs'
import { pluginSetTarget, pluginSetApprovalText, PLUGIN_SET_TARGET } from '../packages/boundary-gate/src/targets.mjs'
import { memoryStore } from '../packages/boundary-gate/checks/support/fixture.mjs'
import { createPasskeyEnrollmentCeremony } from '../packages/authority/src/passkey-enrollment.mjs'
import { didKeyFromEd25519PublicKey } from '../packages/authority/upstream/plugins/aukora-aumlok/lib/did-key.mjs'
import { createSoftwareAuthenticator } from '../ops/node-spawn/browser/rehearse-passkey.mjs'

const root = fileURLToPath(new URL('../', import.meta.url)), self = fileURLToPath(import.meta.url)
const hash = value => createHash('sha256').update(value).digest('hex')
const mutant = process.env.PASSKEY_PLUGIN_SET_MUTANT ?? ''
const mutants = new Set(['canon-channel', 'runtime-channel', 'canon-proof', 'runtime-proof'])
assert.ok(!mutant || mutants.has(mutant), 'known passkey plugin-set mutant')

async function load(relative, selected) {
  const url = new URL(relative, import.meta.url)
  let source = fs.readFileSync(url, 'utf8')
  if (mutant === selected + '-channel') source = source.replace(
    'new Set([OWNER_SOCKET_APPROVER, PAGE_APPROVER, PASSKEY_PAGE_APPROVER])',
    'new Set([OWNER_SOCKET_APPROVER, PAGE_APPROVER])')
  if (mutant === selected + '-proof') source = source.replace(
    "|| (!legacy && !retained) || (pin.approver === PASSKEY_PAGE_APPROVER && !retained))",
    '|| (!legacy && !retained))')
  source = source.replace(/from\s+(['"])(\.[^'"]+)\1/gu,
    (_match, _quote, name) => `from ${JSON.stringify(new URL(name, url).href)}`)
  return import(`data:text/javascript;base64,${Buffer.from(source).toString('base64')}`)
}

if (process.argv.includes('--mutations')) {
  for (const name of ['', ...mutants]) {
    const run = spawnSync(process.execPath, ['--test', '--test-reporter=tap', self], { cwd: root, encoding: 'utf8', timeout: 30000,
      env: { ...process.env, PASSKEY_PLUGIN_SET_MUTANT: name }, maxBuffer: 2 * 1024 * 1024 })
    if (!name) {
      assert.equal(run.status, 0, run.stdout + run.stderr)
      console.log('SOURCE-ONLY passkey plugin-set baseline: PASS')
    } else {
      assert.notEqual(run.status, 0, `SURVIVED ${name}`)
      const failure = run.stdout.match(/^not ok .*$/mu)?.[0]
      assert.ok(failure, `mutation ${name} must fail the focused regression`)
      console.log(`KILLED ${name}: ${failure}`)
    }
  }
  console.log(`SOURCE-ONLY passkey plugin-set mutations: ${mutants.size}/${mutants.size} killed`)
} else {
const canon = await load('../packages/boundary-gate/src/plugin-set-canon.mjs', 'canon')
const runtime = await load('../plugins/aukora-composition-gate/src/plugin-set.mjs', 'runtime')
const origin = 'https://owner.example.test', rpId = 'owner.example.test'

async function post(handler, pathname, body) {
  const req = new EventEmitter()
  req.method = 'POST'; req.url = pathname
  req.headers = { host: rpId, origin, 'sec-fetch-site': 'same-origin', 'sec-fetch-mode': 'cors',
    'sec-fetch-dest': 'empty', 'content-type': 'application/json' }
  req.setTimeout = () => {}; req.destroy = () => {}
  const res = { writeHead(status) { this.status = status }, end(value) { this.body = JSON.parse(value) } }
  const pending = handler(req, res)
  req.emit('data', Buffer.from(JSON.stringify(body))); req.emit('end'); await pending
  assert.equal(res.status, 200, JSON.stringify(res.body))
  return res.body.result
}

function fixture(t) {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'passkey-plugin-set-')), home = path.join(tmp, 'gate')
  fs.mkdirSync(home, { mode: 0o700 })
  const pair = generateKeyPairSync('ed25519')
  const key = { priv: pair.privateKey, pub: pair.publicKey,
    pubPem: pair.publicKey.export({ type: 'spki', format: 'pem' }).toString(), fp: keyFingerprint(pair.publicKey) }
  const clock = Date.UTC(2026, 9, 14, 1), bearer = 'synthetic-owner-bearer', claim = 'x'.repeat(43)
  const release = 'abcdef0' + '1'.repeat(33), releasesRoot = path.join(tmp, 'releases')
  const build = path.join(releasesRoot, 'release-abcdef0/.dsh-build')
  fs.mkdirSync(build, { recursive: true })
  const files = { 'plugins/demo/lib/index.mjs': hash('export const demo = 1') }
  const artifact = { id: 'demo', entry: Object.keys(files)[0], files, digest: canon.artifactDigest(files) }
  const record = { kind: canon.PLUGIN_SET_KIND, count: 1, artifacts: { demo: artifact },
    setDigest: canon.pluginSetDigest({ demo: artifact }) }
  fs.writeFileSync(path.join(build, 'aukora-release.json'), JSON.stringify({ tipSha: release }))
  fs.writeFileSync(path.join(build, 'plugin-set.json'), JSON.stringify(record))
  fs.writeFileSync(path.join(build, 'genesis-artifacts.json'), '{"artifacts":[]}')
  const content = pluginSetApprovalText({ release, release_dir: 'release-abcdef0', plugin_set: record.setDigest,
    operation: canon.operationDigestOf(canon.setOperationContent(record)), record: hash('{"artifacts":[]}') })
  const auth = createSoftwareAuthenticator({ origin, rpId })
  const setup = { version: 1, kind: 'aukora-gate-passkey-setup/v1',
    gate: hash(pair.publicKey.export({ type: 'spki', format: 'der' })), node: 'c'.repeat(64), rp_id: rpId, origin,
    claim_sha256: hash(claim), expires_at_ms: clock + 300000,
    binding: { identity: { owner_id: 'software-owner', subject: 'aukora:1:' + 'a'.repeat(64),
      approval_key_did: didKeyFromEd25519PublicKey('b'.repeat(64)), control_digest: 'd'.repeat(64), authorization_epoch: 1 },
    identity_provenance: { kind: 'owner-approved-initial-public-identity/v1', identity_source_sha256: 'e'.repeat(64),
      approval_reference: 'root-selected-test-binding' }, passkey_profile: { profile: 'https', origin, rp_id: rpId },
    user: { id: Buffer.from('software-owner').toString('base64url'), name: 'Owner', display_name: 'Owner' },
    existing_credential_ids: [] } }
  const gate = createGate({ home, key, db: openDb(path.join(home, 'gate.db')),
    owner: { bearer, hmacKey: 'f'.repeat(64), bearer_expires: clock + 300000 },
    readPasskeySetup: () => setup, passkeyEnrollmentCeremony: createPasskeyEnrollmentCeremony,
    targets: { [PLUGIN_SET_TARGET]: pluginSetTarget(path.join(tmp, 'targets'), { releasesRoot, floorFile: path.join(tmp, 'floor.json') }) },
    store: memoryStore(), now: () => clock, limits: { maxPerWindow: 100, rejectCooldownMs: 0 } })
  gate.startup({ pid: 1 })
  t.after(() => { gate.close(); fs.rmSync(tmp, { recursive: true, force: true }) })
  return { gate, pair, bearer, claim, auth, content, record }
}

test('passkey page approval verifies through the installer and runtime; its string without proof is refused', async t => {
  const f = fixture(t), { handler } = createPasskeyOwnerHandler(f.gate, { origin, rpId })
  const started = await post(handler, '/owner/enroll/start', { claim_code: f.claim })
  const registered = await post(handler, '/owner/enroll/register', { enrollment_id: started.enrollment_id,
    registration: f.auth.registration(started.public_key) })
  assert.equal((await post(handler, '/owner/enroll/finish', { enrollment_id: registered.enrollment_id,
    assertion: f.auth.assertion(registered.public_key) })).enrolled, true)
  const proposal = f.gate.ownerOps.raise({ target: PLUGIN_SET_TARGET, content: f.content, why: 'fixture release' })
  const review = await post(handler, '/owner/review', { bearer: f.bearer, id: proposal.id })
  const proof = { version: 2, algorithm: 'webauthn-es256-sha256', authorization: review.owner_authorization,
    assertion: f.auth.assertion(review.public_key) }
  const result = await post(handler, '/owner/approve', { bearer: f.bearer, id: review.id, base_sha: review.base_sha,
    new_sha: review.new_sha, review_challenge: review.review_challenge, owner_authorization_proof: proof })
  assert.equal(result.applied, true)
  assert.equal(result.receipt.v, 3)
  assert.ok(result.receipt.owner_authorization && result.receipt.owner_consumption)
  const exported = f.gate.ownerOps.log({ limit: 200, target: PLUGIN_SET_TARGET })
  const row = exported.entries.find(entry => entry.seq === result.ledger_seq)
  const approval = { kind: canon.GATE_APPROVAL_KIND, content: f.content, receipt: row.detail.receipt,
    receipt_sig: row.detail.receipt_sig, ledger_entry: row.signed_entry }
  const pin = { kind: canon.GATE_PIN_KIND, gatePubkeyPem: f.gate.pubPem, gatePubkeyFp: f.gate.fp,
    target: PLUGIN_SET_TARGET, approver: PASSKEY_PAGE_APPROVER }
  const epochs = { version: 1, kind: 'aukora-signer-epochs/v1', epochs: [{ epoch: 1,
    gate_pubkey_sha256: hash(f.pair.publicKey.export({ type: 'spki', format: 'der' })) }] }
  assert.equal(canon.verifyOrderedGateApproval({ record: f.record, approval, pin, epochs }).release, 'abcdef0' + '1'.repeat(33))
  assert.equal(runtime.verifySetApproval({ record: f.record, receipt: approval, pin }).release, 'abcdef0' + '1'.repeat(33))

  const forgedReceipt = { v: 2, kind: 'change', proposal: result.receipt.proposal, target: result.receipt.target,
    base_sha: result.receipt.base_sha, new_sha: result.receipt.new_sha, applied_at: result.receipt.applied_at,
    approver: PASSKEY_PAGE_APPROVER, approval_evidence_hmac: Buffer.alloc(32).toString('base64'), pubkey_fp: f.gate.fp }
  const forged = { kind: canon.GATE_APPROVAL_KIND, content: f.content, receipt: forgedReceipt,
    receipt_sig: sign(null, Buffer.from(JSON.stringify(forgedReceipt)), f.pair.privateKey).toString('base64') }
  assert.throws(() => canon.verifyGateSetApproval({ record: f.record, approval: forged, pin }), { code: 'plugin-set-approval-malformed' })
  assert.throws(() => runtime.verifySetApproval({ record: f.record, receipt: forged, pin }), { code: 'plugin-set-approval-malformed' })
})
}
