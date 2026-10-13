// Synthetic gate approval binds the typed result to the release receipt and floor; no enrolled-owner fallback.
import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { createHash, generateKeyPairSync, sign } from 'node:crypto'
import { spawnSync } from 'node:child_process'
import { pluginSetTarget, pluginSetApprovalText, PLUGIN_SET_TARGET, THEME_TARGET, themeTarget } from '../packages/boundary-gate/src/targets.mjs'
import { keyFingerprint } from '../packages/boundary-gate/src/ledger.mjs'
import { ownerRootPin } from '../packages/owner-key/src/index.mjs'
import { memoryStore } from '../packages/boundary-gate/checks/support/fixture.mjs'
import { advanceFloor, checkFloor, readFloor } from '../packages/boundary-gate/src/release-floor.mjs'
import * as runtime from '../plugins/aukora-composition-gate/src/plugin-set.mjs'

const root = fileURLToPath(new URL('../', import.meta.url)), self = fileURLToPath(import.meta.url)
const hash = bytes => createHash('sha256').update(bytes).digest('hex')
const PAGE_APPROVER = 'owner via gate approval page (bearer token, typed 2-step confirm)'
const mutations = {
  typed: ['../packages/boundary-gate/src/owner-page.mjs', [['!want || typed !== want', 'false']]],
  bearer: ['../packages/boundary-gate/src/owner-page.mjs', [["if (!bearerOk(owner, f.get('k'), now))", 'if (false)']]],
  nonce: ['../packages/boundary-gate/src/owner-page.mjs', [["if (!c || c.id !== id || c.base !== p.base_sha || c.new !== p.new_sha || now() > c.exp)", 'if (false)']]],
  hashes: ['../packages/boundary-gate/src/owner-page.mjs', [["else if (p.base_sha !== f.get('base') || p.new_sha !== f.get('new'))", 'else if (false)']]],
  claim: ['../packages/boundary-gate/src/card.mjs', [['if (IMPERSONATION.test(nn))', 'if (false)']]],
  enrolled: ['../packages/boundary-gate/src/gate.mjs', [['function ownerAuthorizationRequired() {', 'function ownerAuthorizationRequired() { return false;']]],
  approver: ['../packages/boundary-gate/src/plugin-set-canon.mjs', [["pin.approver !== 'owner via gate approval page (bearer token, typed 2-step confirm)'", 'false']]],
}
const mutant = process.env.BROWSER_OWNER_MUTANT ?? ''
if (mutant && !Object.hasOwn(mutations, mutant)) throw new Error('unknown browser owner mutant')

if (process.argv.includes('--mutations')) {
  for (const name of ['', ...Object.keys(mutations)]) {
    const run = spawnSync(process.execPath, ['--test', '--test-reporter=tap', self], { cwd: root, encoding: 'utf8', timeout: 30000,
      env: { ...process.env, BROWSER_OWNER_MUTANT: name }, maxBuffer: 2 * 1024 * 1024 })
    if (!name) {
      assert.equal(run.status, 0, run.stdout + run.stderr)
      console.log('SOURCE-ONLY browser owner baseline: PASS')
    } else {
      assert.notEqual(run.status, 0, `SURVIVED ${name}`)
      const failure = run.stdout.match(/^not ok .*$/mu)?.[0]
      assert.ok(failure, `mutation ${name} must fail a regression assertion`)
      console.log(`KILLED ${name}: ${failure}`)
    }
  }
  console.log(`SOURCE-ONLY browser owner guard mutations: ${Object.keys(mutations).length}/${Object.keys(mutations).length} killed`)
} else {
async function load(relative) {
  const url = new URL(relative, import.meta.url)
  let source = fs.readFileSync(url, 'utf8')
  if (mutations[mutant]?.[0] === relative) for (const [before, after] of mutations[mutant][1]) {
    assert.ok(source.includes(before), 'mutation must remove the actual named guard')
    source = source.replace(before, after)
  }
  source = source.replace(/from\s+(['"])(\.[^'"]+)\1/gu, (_match, _quote, name) => `from ${JSON.stringify(new URL(name, url).href)}`)
  return import(`data:text/javascript;base64,${Buffer.from(source).toString('base64')}`)
}
const { createGate } = await load('../packages/boundary-gate/src/gate.mjs')
const { createOwnerPage } = await load('../packages/boundary-gate/src/owner-page.mjs')
const canon = await load('../packages/boundary-gate/src/plugin-set-canon.mjs')

function fixture(t, { enrolled = false, theme = false } = {}) {
  const tmp = fs.mkdtempSync(path.join(root, '.browser-owner-')), home = path.join(tmp, 'gate')
  fs.mkdirSync(home, { mode: 0o700 })
  const pair = generateKeyPairSync('ed25519'), pubPem = pair.publicKey.export({ type: 'spki', format: 'pem' }).toString()
  const key = { priv: pair.privateKey, pub: pair.publicKey, pubPem, fp: keyFingerprint(pair.publicKey) }
  const owner = { bearer: 'disposable-fixture-bearer', hmacKey: hash('disposable-fixture-hmac'), bearer_expires: 1791840000000 }
  const clock = { now: 1791792000000 }, releasesRoot = path.join(tmp, 'releases'), floorFile = path.join(tmp, 'floor.json')
  const targetRoot = path.join(tmp, 'targets'), release = 'abcdef0' + '1'.repeat(33), build = path.join(releasesRoot, 'release-abcdef0/.dsh-build')
  fs.mkdirSync(build, { recursive: true })
  const files = { 'plugins/demo/lib/index.mjs': hash('export const demo = 1') }
  const artifact = { id: 'demo', entry: Object.keys(files)[0], files, digest: canon.artifactDigest(files) }
  const record = { kind: canon.PLUGIN_SET_KIND, count: 1, artifacts: { demo: artifact }, setDigest: canon.pluginSetDigest({ demo: artifact }) }
  fs.writeFileSync(path.join(build, 'aukora-release.json'), JSON.stringify({ tipSha: release }))
  fs.writeFileSync(path.join(build, 'plugin-set.json'), JSON.stringify(record))
  fs.writeFileSync(path.join(build, 'genesis-artifacts.json'), '{"artifacts":[]}')
  const content = pluginSetApprovalText({ release, release_dir: 'release-abcdef0', plugin_set: record.setDigest,
    operation: canon.operationDigestOf(canon.setOperationContent(record)), record: hash('{"artifacts":[]}') })
  const store = memoryStore(theme ? { [THEME_TARGET]: '{"accent": "default"}' } : {})
  const targets = theme ? { [THEME_TARGET]: themeTarget(targetRoot) }
    : { [PLUGIN_SET_TARGET]: pluginSetTarget(targetRoot, { releasesRoot, floorFile }) }
  const args = { home, key, owner, targets, store, now: () => clock.now }
  if (enrolled) {
    const ownerPair = generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
    const spki = ownerPair.publicKey.export({ type: 'spki', format: 'der' }).toString('base64')
    args.readOwnerState = () => ({ version: 1, kind: 'aukora-owner-state/v1', owner_subject: 'aukora:1:' + hash('fixture-owner'),
      owner_root_spki_base64: spki, owner_root_id: ownerRootPin(spki).owner_root_id, owner_epoch: 1,
      registry_sha256: hash('fixture-registry'), activation_sha256: hash('fixture-activation') })
  }
  const gate = createGate(args)
  t.after(() => { gate.close(); fs.rmSync(tmp, { recursive: true, force: true }) })
  assert.equal(gate.startup({ pid: 1 }).ok, true)
  const proposal = theme ? gate.proposeOps.propose({ target: THEME_TARGET, content: '{"accent": "#123ABC"}',
    claimed_base: gate.proposeOps.read({ target: THEME_TARGET }).sha256, why: 'fixture theme', session: 'fixture' })
    : gate.ownerOps.raise({ target: PLUGIN_SET_TARGET, content, why: 'fixture release' })
  const page = createOwnerPage(gate)
  const form = (action, extra = {}) => new URLSearchParams({ k: owner.bearer, id: proposal.id,
    base: proposal.base_sha, new: proposal.new_sha, a: action, ...extra })
  const step1 = () => {
    const response = page.act(form('approve-step1'))
    assert.match(response.body, /Nothing has been applied/)
    assert.equal(store.writes, 0)
    return /name=nonce value="([^"]+)"/u.exec(response.body)[1]
  }
  return { tmp, gate, page, proposal, form, step1, clock, owner, store, pair, content, record, floorFile, args }
}

function approved(f) {
  const nonce = f.step1()
  const result = f.page.act(f.form('confirm', { nonce, typed: f.proposal.new_sha }))
  assert.match(result.body, /APPLIED plugins\/aukora-plugin-set\/approval.json/)
  assert.equal(f.store.writes, 1)
  const exported = f.gate.ownerOps.log({ limit: 200, target: PLUGIN_SET_TARGET })
  assert.equal(exported.verify.ok, true)
  const row = exported.entries.find(entry => entry.event === 'apply')
  return { approval: { kind: canon.GATE_APPROVAL_KIND, content: f.content, receipt: row.detail.receipt,
    receipt_sig: row.detail.receipt_sig, ledger_entry: row.signed_entry },
  pin: { kind: canon.GATE_PIN_KIND, gatePubkeyPem: f.gate.pubPem, gatePubkeyFp: f.gate.fp, target: PLUGIN_SET_TARGET, approver: PAGE_APPROVER },
  epochs: { version: 1, kind: 'aukora-signer-epochs/v1', epochs: [{ epoch: 1,
    gate_pubkey_sha256: hash(f.pair.publicKey.export({ type: 'spki', format: 'der' })) }] } }
}

test('first bearer approval signs the exact release and plugin set; only its verified floor permits boot', t => {
  const f = fixture(t), html = f.page.act(f.form('approve-step1')).body
  assert.match(html, new RegExp(`Paste the result SHA-256 <b>${f.proposal.new_sha}</b>`))
  assert.match(html, /first plugin-set approval on this gate/)
  assert.doesNotMatch(html, /type the result colour/)
  assert.equal(readFloor(f.floorFile), null)
  const input = { record: f.record, ...approved(f) }
  assert.equal(input.approval.receipt.approver, PAGE_APPROVER, 'the receipt honestly names bearer page approval')
  const verified = canon.verifyOrderedGateApproval(input)
  assert.throws(() => checkFloor(null, verified), { code: 'release-floor-absent' })
  const floor = advanceFloor(null, verified)
  fs.writeFileSync(f.floorFile, JSON.stringify(floor))
  assert.equal(checkFloor(readFloor(f.floorFile), verified).ok, true)
  assert.throws(() => advanceFloor(floor, verified), { code: 'release-floor-not-newer' })
  assert.doesNotThrow(() => runtime.verifySetApproval({ record: f.record, receipt: input.approval, pin: input.pin }), 'the runtime verifier accepts the same honest page label')
  assert.throws(() => runtime.verifySetApproval({ record: f.record, receipt: input.approval, pin: { ...input.pin, approver: 'owner via some other page' } }), { code: 'plugin-set-approver-not-pinned' })
})

test('release page uses the AUKORA surface and keeps exact approval facts selectable without script', t => {
  const f = fixture(t), html = f.page.pageHtml(''), release = JSON.parse(f.content)
  const heading = `Start release ${release.release.slice(0, 7)} on this node`
  assert.ok(html.indexOf(heading) < html.indexOf('HOST-VERIFIED BY THE BOUNDARY GATE'))
  assert.match(html, /--bg:#0b0d18;--surface:rgba\(38,43,54,\.72\);--border:rgba\(255,255,255,\.1\)/u)
  assert.match(html, /--cyan:#96b4ff;--gold:#e0b76a;--mint:#81d4b4;--violet:#c4aaff;--red:#f2555a;--radius:14px/u)
  assert.match(html, /linear-gradient\(90deg,var\(--mint\),var\(--cyan\),var\(--violet\),var\(--gold\)\)/u)
  assert.match(html, /class=fingerprints tabindex=0 title="Click once to select these exact fingerprints"/u)
  assert.match(html, /\.fingerprints\{[^}]*user-select:all/u)
  for (const value of [f.proposal.base_sha, f.proposal.new_sha, release.release, release.plugin_set, release.operation, release.record]) assert.match(html, new RegExp(value))
  assert.doesNotMatch(html, /<script\b|<(?:img|link)\b[^>]*(?:src|href)=/iu)
  let status, headers, body
  f.page.handler({ method: 'GET', url: '/?k=' + f.owner.bearer }, {
    writeHead: (value, fields) => { status = value; headers = fields }, end: value => { body = value },
  })
  assert.equal(status, 200); assert.equal(body, html)
  assert.equal(headers['x-frame-options'], 'DENY')
  assert.match(headers['content-security-policy'], /default-src 'none'/u)
  assert.match(headers['content-security-policy'], /frame-ancestors 'none'/u)
  const step2 = f.page.act(f.form('approve-step1')).body
  assert.match(step2, /this step expires in 2 minutes/u)
  assert.match(step2, /2-minute limit from the start of step 2/u)
})

test('the actual operator release note is warning-free while a claimed approval still warns', async () => {
  const { cardWarnings } = await load('../packages/boundary-gate/src/card.mjs')
  const source = fs.readFileSync(new URL('../packages/boundary-gate/bin/plugin-set-approval.mjs', import.meta.url), 'utf8')
  const match = /why: '([^']+)' \}\)/u.exec(source)
  assert.ok(match, 'approval raise carries one static operator note')
  assert.deepEqual(cardWarnings({}, '', '', match[1]), [])
  assert.ok(cardWarnings({}, '', '', 'Already approved by the owner.').some(warning => warning.startsWith('NOTE claims prior approval')))
})

test('wrong digest, missing step one, spent nonce, expired nonce and changed displayed hashes perform no write', t => {
  for (const attack of ['typed', 'uppercase', 'missing', 'spent', 'expired', 'base', 'result']) {
    const f = fixture(t), nonce = attack === 'missing' ? 'not-issued' : f.step1()
    if (attack === 'spent') f.page.act(f.form('confirm', { nonce, typed: '' }))
    if (attack === 'expired') f.clock.now += 120001
    const extra = { nonce, typed: attack === 'typed' ? 'f'.repeat(64) : f.proposal.new_sha }
    if (attack === 'uppercase') extra.typed = f.proposal.new_sha.toUpperCase()
    if (attack === 'base') extra.base = 'f'.repeat(64)
    if (attack === 'result') extra.new = 'f'.repeat(64)
    const response = f.page.act(f.form('confirm', extra))
    assert.doesNotMatch(response.body, /APPLIED plugins/)
    assert.equal(f.store.writes, 0, `${attack} cannot apply`)
    assert.equal(f.gate.proposeOps.state({ id: f.proposal.id }).state, 'pending')
  }
})

test('wrong or expired bearer cannot begin or confirm release approval', t => {
  for (const attack of ['wrong', 'expired']) {
    const f = fixture(t), nonce = f.step1()
    if (attack === 'expired') f.clock.now = f.owner.bearer_expires + 1
    const extra = { nonce, typed: f.proposal.new_sha, ...(attack === 'wrong' ? { k: 'wrong' } : {}) }
    assert.equal(f.page.act(f.form('approve-step1', extra)).status, 401)
    assert.equal(f.page.act(f.form('confirm', extra)).status, 401)
    assert.equal(f.store.writes, 0)
  }
})

test('enrolled owner authorization never falls back to bearer and typed confirmation', t => {
  const f = fixture(t, { enrolled: true }), nonce = f.step1()
  const response = f.page.act(f.form('confirm', { nonce, typed: f.proposal.new_sha }))
  assert.match(response.body, /owner proof for allowed-once/)
  assert.equal(f.store.writes, 0)
  assert.equal(f.gate.proposeOps.state({ id: f.proposal.id }).state, 'pending')
})

test('retained enrollment enforcement survives restart without the owner-state reader', t => {
  const f = fixture(t, { enrolled: true })
  f.gate.close()
  const restarted = createGate({ ...f.args, readOwnerState: undefined })
  t.after(() => restarted.close())
  assert.equal(restarted.startup({ pid: 2 }).ok, true)
  assert.equal(restarted.db.prepare('SELECT COUNT(*) n FROM owner_authorization_required').get().n, 1)
  const page = createOwnerPage(restarted), response = page.act(f.form('approve-step1'))
  const nonce = /name=nonce value="([^"]+)"/u.exec(response.body)[1]
  assert.match(page.act(f.form('confirm', { nonce, typed: f.proposal.new_sha })).body, /trusted owner state is unconfigured/)
  assert.equal(f.store.writes, 0)
})

test('theme confirmation retains its existing colour semantics', t => {
  const f = fixture(t, { theme: true }), nonce = f.step1()
  assert.match(f.page.act(f.form('confirm', { nonce, typed: '#123abc' })).body, /APPLIED plugins\/auma-theme\/theme.json/)
  assert.equal(f.store.writes, 1)
})

test('applied release page says what the operator does next', t => {
  const f = fixture(t), nonce = f.step1()
  const result = f.page.act(f.form('confirm', { nonce, typed: f.proposal.new_sha }))
  assert.match(result.body, /Release abcdef0 is approved\. Next, the operator installs this exact approval and starts the node; this page did not start it\./u)
})

test('the trusted verifier refuses other bearer-page approver names even with valid gate signatures', t => {
  const f = fixture(t), input = { record: f.record, ...approved(f) }
  for (const approver of [PAGE_APPROVER + ' altered', 'owner via gate approval page', 'agent via page']) {
    const changed = structuredClone(input)
    changed.pin.approver = approver
    changed.approval.receipt.approver = approver
    changed.approval.receipt_sig = sign(null, Buffer.from(JSON.stringify(changed.approval.receipt)), f.pair.privateKey).toString('base64')
    assert.throws(() => canon.verifyGateSetApproval(changed), { code: 'plugin-set-approver-not-pinned' })
  }
})
}
