// Synthetic signatures test offline evidence bindings and refusal-guard removals.
import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import { createHash, generateKeyPairSync, sign } from 'node:crypto'
import { spawnSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import { resolve } from 'node:path'

const sourceUrl = new URL('../scripts/audit/browser-node-evidence.mjs', import.meta.url)
const self = fileURLToPath(import.meta.url), root = fileURLToPath(new URL('../', import.meta.url))
const original = fs.readFileSync(sourceUrl, 'utf8'), hash = bytes => createHash('sha256').update(bytes).digest('hex')
const sha = label => hash('synthetic:' + label)
const clone = value => structuredClone(value)
const zeroSignature = Buffer.alloc(64).toString('base64')

export function evidenceFixture() {
  const pair = generateKeyPairSync('ed25519'), revision = 'abcdef0' + '1'.repeat(33)
  const fingerprint = hash(pair.publicKey.export({ type: 'spki', format: 'der' }))
  const content = JSON.stringify({ v: 1, kind: 'aukora-plugin-set-approval/v1', release: revision,
    release_dir: 'release-abcdef0', plugin_set: sha('plugin set'), operation: sha('operation'), record: sha('record') })
  const receipt = { v: 2, kind: 'change', proposal: '12345678-1234-1234-1234-123456789abc',
    target: 'plugins/aukora-plugin-set/approval.json', base_sha: 'absent', new_sha: hash(content),
    applied_at: '2026-10-13T10:00:00.000Z', approver: 'owner via gate approval page (bearer token, typed 2-step confirm)',
    approval_evidence_hmac: Buffer.alloc(32, 1).toString('base64'), pubkey_fp: fingerprint.slice(0, 16) }
  const record = { kind: 'aukora-browser-node-evidence/v1', phase: 'after', observed_at: '2026-10-13T10:00:01.000Z',
    release: { revision, record_sha256: sha('record'), plugin_set_sha256: sha('plugin set') },
    signer: { public_key_pem: pair.publicKey.export({ type: 'spki', format: 'pem' }).toString(), sha256: fingerprint },
    approval: { kind: 'aukora-plugin-set-gate-approval/v1', content, receipt, receipt_sig: '', ledger_entry: {
      seq: 5, at: '2026-10-13T10:00:00.001Z', event: 'apply', proposal: receipt.proposal, target: receipt.target,
      base_sha: receipt.base_sha, new_sha: receipt.new_sha, detail: '', prev: sha('prior ledger'), hash: '', sig: '' } },
    floor: { kind: 'aukora-release-floor/v2', release: revision, release_dir: 'release-abcdef0', record: sha('record'),
      signer_epoch: 1, ledger_seq: 5, signer_key_sha256: fingerprint, ledger_hash: '', history: [] },
    installer_inputs: Object.fromEntries(['checkout', 'node', 'dependencies', 'harness'].map(name => [name, sha(name)])),
    checks: ['host_transport', 'root_platform', 'installation_record', 'browser_profile', 'users_modes', 'aura_collector_custody',
      'package_custody', 'node_version', 'package_pins', 'gate_sockets', 'signer_pin', 'loopback_listeners', 'approved_floor',
      'aura_collector', 'harness_service', 'signed_in_ui', 'browser_binding_guard', 'plugin_load', 'claim_service', 'public_origins',
      'anonymous_session', 'claim_exchange', 'claim_cookie', 'public_session', 'claim_replay', 'aura_sources']
      .map(name => ({ name, status: 'PASS' })), record_signature: null }
  function signRow(value = record) {
    const row = value.approval.ledger_entry
    row.hash = hash(JSON.stringify([row.seq, row.at, row.event, row.proposal, row.target, row.base_sha, row.new_sha, row.detail, row.prev]))
    row.sig = sign(null, Buffer.from(row.hash, 'hex'), pair.privateKey).toString('base64')
    value.floor.ledger_hash = row.hash
    return value
  }
  function signReceipt(value = record) {
    const approval = value.approval, receipt = approval.receipt, row = approval.ledger_entry
    approval.receipt_sig = sign(null, Buffer.from(JSON.stringify(receipt)), pair.privateKey).toString('base64')
    Object.assign(row, { proposal: receipt.proposal, target: receipt.target, base_sha: receipt.base_sha,
      new_sha: receipt.new_sha, detail: JSON.stringify({ receipt, receipt_sig: approval.receipt_sig }) })
    return signRow(value)
  }
  signReceipt()
  return { record, pair, signReceipt, signRow }
}

function retainedEvidenceFixture() {
  const f = evidenceFixture(), prior = f.record.approval.receipt
  f.record.approval.receipt = { v: 3, kind: prior.kind, proposal: prior.proposal, target: prior.target,
    base_sha: prior.base_sha, new_sha: prior.new_sha, applied_at: prior.applied_at,
    approver: 'aukora:1:' + 'a'.repeat(64), pubkey_fp: prior.pubkey_fp,
    gate_pubkey_sha256: f.record.signer.sha256,
    owner_authorization: { version: 1, kind: 'aukora-owner-authorization-ref/v1',
      authorization_id: sha('authorization'), proof_sha256: sha('proof') },
    owner_accepted_at_ms: Date.parse(prior.applied_at) - 1,
    owner_consumption: { ledger_seq: 3, ledger_hash: sha('consumption'),
      review_issue: { ledger_seq: 2, ledger_hash: sha('review') } } }
  f.signReceipt()
  return f
}

const attacks = [
  ['record-schema', (r) => { r.private = 'PRIVATE_SENTINEL' }],
  ['record-kind', (r) => { r.phase = 'before' }],
  ['observation-time', (r) => { r.observed_at = '2026-10-13T10:00:01Z' }],
  ['release-schema', (r) => { r.release.address = 'PRIVATE_SENTINEL' }],
  ['signer-schema', (r) => { r.signer.hostname = 'PRIVATE_SENTINEL' }],
  ['signer-key-canonical', (r) => { r.signer.public_key_pem += '\n' }],
  ['signer-fingerprint', (r) => { r.signer.sha256 = r.floor.signer_key_sha256 = sha('other signer') }],
  ['approval-schema', (r) => { r.approval.private = 'PRIVATE_SENTINEL' }],
  ['receipt-schema', (r, f) => { r.approval.receipt.kind = 'revert'; f.signReceipt(r) }],
  ['receipt-public-schema', (r, f) => { r.approval.receipt.approver = 'owner via PRIVATE_SENTINEL'; f.signReceipt(r) }],
  ['receipt-fingerprint', (r, f) => { r.approval.receipt.pubkey_fp = 'f'.repeat(16); f.signReceipt(r) }],
  ['receipt-signature-schema', (r, f) => {
    r.approval.receipt_sig += '\n'; r.approval.ledger_entry.detail = JSON.stringify({ receipt: r.approval.receipt, receipt_sig: r.approval.receipt_sig }); f.signRow(r)
  }],
  ['receipt-signature', (r, f) => {
    r.approval.receipt_sig = zeroSignature; r.approval.ledger_entry.detail = JSON.stringify({ receipt: r.approval.receipt, receipt_sig: r.approval.receipt_sig }); f.signRow(r)
  }],
  ['approval-content-schema', (r, f) => { r.approval.content = '{"private":"PRIVATE_SENTINEL"}'; r.approval.receipt.new_sha = hash(r.approval.content); f.signReceipt(r) }],
  ['approval-content-digest', (r, f) => { r.approval.receipt.new_sha = sha('other approved content'); f.signReceipt(r) }],
  ['approval-release-binding', (r) => { r.release.plugin_set_sha256 = sha('other set') }],
  ['ledger-schema', (r) => { r.approval.ledger_entry.private = 'PRIVATE_SENTINEL' }],
  ['ledger-receipt-binding', (r, f) => { r.approval.ledger_entry.target = 'plugins/other/approval.json'; f.signRow(r) }],
  ['ledger-detail-binding', (r, f) => {
    const detail = JSON.parse(r.approval.ledger_entry.detail); detail.private = 'PRIVATE_SENTINEL'
    r.approval.ledger_entry.detail = JSON.stringify(detail); f.signRow(r)
  }],
  ['ledger-hash', (r) => { r.approval.ledger_entry.seq++; r.floor.ledger_seq++ }],
  ['ledger-signature', (r) => { r.approval.ledger_entry.sig = zeroSignature }],
  ['time-order', (r) => { r.observed_at = '2026-10-13T09:00:00.000Z' }],
  ['floor-schema', (r) => { r.floor.private = 'PRIVATE_SENTINEL' }],
  ['floor-signed-row-binding', (r) => { r.floor.ledger_seq++ }],
  ['installer-schema', (r) => { r.installer_inputs.hostname = 'PRIVATE_SENTINEL' }],
  ['checks-schema', (r) => { r.checks[0].name = 'PRIVATE_SENTINEL' }],
  ['checks-completion', (r) => { r.checks.pop() }],
  ['unsupported-record-signature', (r) => { r.record_signature = zeroSignature }],
]
const guardNames = attacks.map(([name]) => name), specialMutants = ['strict-json', 'detail-json', 'approval-content-grammar',
  'input-complete', 'input-size', 'input-utf8', 'bound-phase-checks', 'legacy-revision-checks'], mutant = process.env.BROWSER_EVIDENCE_MUTANT ?? ''
assert.ok(!mutant || guardNames.includes(mutant) || specialMutants.includes(mutant), 'known production guard mutant')

function removeGuard(source, name) {
  const ending = ", '" + name + "')", end = source.indexOf(ending)
  assert.ok(end >= 0 && source.indexOf(ending, end + 1) === -1, 'one real production guard: ' + name)
  const start = source.lastIndexOf('require(', end)
  return source.slice(0, start) + 'void 0' + source.slice(end + ending.length)
}
function mutatedSource() {
  if (mutant === 'bound-phase-checks') return original.replace("record?.phase === 'bound' ? BOUND_CHECK_NAMES", 'false ? BOUND_CHECK_NAMES')
  if (mutant === 'legacy-revision-checks') return original.replace("LEGACY_AFTER_REVISIONS.has(record?.release?.revision) ? LEGACY_CHECK_NAMES", 'false ? LEGACY_CHECK_NAMES')
  if (mutant === 'strict-json') return original.replace('strictJson(text, MAX_BYTES, 12)', 'JSON.parse(text)')
  if (mutant === 'detail-json') return original.replace('strictJson(row.detail, 4096, 4)', 'JSON.parse(row.detail)')
  if (mutant === 'approval-content-grammar') return original.replace('parseGateApprovalContent(approval.content)', 'JSON.parse(approval.content)')
  if (mutant === 'input-size') return removeGuard(original, 'input-size')
  if (mutant === 'input-utf8') return original.replace("new TextDecoder('utf-8', { fatal: true })", "new TextDecoder('utf-8', { fatal: false })")
  if (mutant === 'input-complete') return original.replace('while (received > 0 && count < bytes.length)', 'while (false)')
  return mutant ? removeGuard(original, mutant) : original
}
async function loadVerifier() {
  let source = mutatedSource()
  source = source.replace(/from\s+(['"])(\.[^'"]+)\1/gu, (_match, _quote, name) => `from ${JSON.stringify(new URL(name, sourceUrl).href)}`)
  return import(`data:text/javascript;base64,${Buffer.from(source).toString('base64')}`)
}

if (process.argv.includes('--mutations')) {
  for (const name of ['', ...guardNames, ...specialMutants]) {
    const run = spawnSync(process.execPath, ['--test', '--test-reporter=tap', self], { cwd: root, encoding: 'utf8', timeout: 30000,
      env: { ...process.env, BROWSER_EVIDENCE_MUTANT: name }, maxBuffer: 2 * 1024 * 1024 })
    if (!name) { assert.equal(run.status, 0, run.stdout + run.stderr); console.log('SOURCE-ONLY browser node evidence baseline: PASS') }
    else {
      assert.notEqual(run.status, 0, `SURVIVED ${name}`)
      assert.match(run.stdout, /^not ok /mu, `mutation ${name} must fail a regression assertion`)
      const failure = name === 'approval-content-grammar'
        ? run.stdout.match(/^not ok .*approval content uses the exact gate grammar.*$/mu)?.[0]
        : run.stdout.match(/^not ok .*$/mu)[0]
      assert.ok(failure, 'the targeted grammar regression must fail when its parser is bypassed')
      console.log(`KILLED ${name}: ${failure}`)
    }
  }
  console.log(`SOURCE-ONLY browser node evidence mutations: ${guardNames.length + specialMutants.length}/${guardNames.length + specialMutants.length} killed; synthetic keys only`)
} else {
const verifier = await loadVerifier()
const refuse = (record, name) => assert.throws(() => verifier.verifyBrowserNodeEvidence(record), { code: 'browser-node-evidence:' + name })

test('offline browser evidence authenticates embedded signed bytes and states its exact limits', () => {
  const f = evidenceFixture(), result = verifier.verifyBrowserNodeEvidence(f.record)
  assert.deepEqual(result, { ok: true, passed: true, checks: 26, ledgerSeq: 5, limitations: verifier.LIMITATIONS })
  assert.match(result.limitations.join('\n'), /public key belongs to a real node/)
  assert.match(result.limitations.join('\n'), /checks really ran/)
  assert.match(result.limitations.join('\n'), /floor has no standalone signature/)
  assert.match(result.limitations.join('\n'), /record is unsigned/)
  const socket = clone(f.record)
  socket.approval.receipt.approver = 'owner via owner.sock (local; 0600 gate user/root only)'; f.signReceipt(socket)
  assert.equal(verifier.verifyBrowserNodeEvidence(socket).passed, true)
  const first = clone(f.record); first.approval.ledger_entry.seq = first.floor.ledger_seq = 1
  first.approval.ledger_entry.prev = 'GENESIS'; f.signRow(first)
  assert.equal(verifier.verifyBrowserNodeEvidence(first).ledgerSeq, 1)
})

test('offline browser evidence accepts a closed retained owner-proof receipt and refuses missing proof fields', () => {
  const f = retainedEvidenceFixture()
  assert.equal(verifier.verifyBrowserNodeEvidence(f.record).passed, true)
  delete f.record.approval.receipt.owner_authorization
  f.signReceipt()
  refuse(f.record, 'receipt-schema')
})

test('bound evidence requires the complete bound checks and keeps after records compatible', () => {
  const f = evidenceFixture()
  f.record.phase = 'bound'
  const names = ['binding_custody', 'binding_overlay', 'kira_active', 'bound_rpc', 'bound_app', 'repeat_prepare',
    'aura_gate_code', 'aura_kira_note', 'composition_active', 'bound_current_invocation']
  const incomplete = clone(f.record)
  refuse(incomplete, 'checks-completion')
  f.record.checks.push(...names.map(name => ({ name, status: 'PASS' })))
  assert.equal(verifier.verifyBrowserNodeEvidence(f.record).passed, true)
  assert.equal(verifier.verifyBrowserNodeEvidence(f.record).checks, 36)
  const container = clone(f.record); container.checks.shift()
  assert.equal(verifier.verifyBrowserNodeEvidence(container, { containerOnly: true }).checks, 35)
  const failed = clone(f.record); failed.checks.pop(); failed.checks.at(-1).status = 'FAIL'
  assert.equal(verifier.verifyBrowserNodeEvidence(failed).passed, false)
  const swapped = clone(f.record)
  ;[swapped.checks[22], swapped.checks[23]] = [swapped.checks[23], swapped.checks[22]]
  refuse(swapped, 'checks-schema')
  const downgraded = clone(f.record); downgraded.phase = 'after'
  refuse(downgraded, 'checks-schema')
})

test('the two committed revisions retain their declared historical check list only', () => {
  for (const name of ['2026-10-13-rehearsal-r1-38004c5.json', '2026-10-14-rehearsal-r1-c18a7e4.json']) {
    const record = JSON.parse(fs.readFileSync(resolve(root, 'evidence/browser-node', name), 'utf8'))
    assert.equal(verifier.verifyBrowserNodeEvidence(record).checks, 22)
  }
  const current = evidenceFixture().record
  current.checks = current.checks.filter(check => verifier.LEGACY_CHECK_NAMES.includes(check.name))
  refuse(current, 'checks-schema')
})

for (const [name, attack] of attacks) test('offline evidence refuses ' + name, () => {
  const f = evidenceFixture(), record = clone(f.record); attack(record, f); refuse(record, name)
})

test('schema rejects every untyped field, noncanonical date, signature and free-text channel', () => {
  for (const [field, values] of Object.entries({
    proposal: ['PRIVATE_SENTINEL', null], target: ['http://PRIVATE_SENTINEL', null], base_sha: ['private', 1],
    new_sha: ['A'.repeat(64), null], applied_at: ['2026-10-13T10:00:00Z', '2026-02-30T10:00:00.000Z'],
    approver: ['owner via gate approval page', 'owner via owner.sock PRIVATE_SENTINEL'],
    approval_evidence_hmac: [Buffer.alloc(32).toString('base64') + '\n', 'PRIVATE_SENTINEL'], pubkey_fp: [1, 'PRIVATE_SENTINEL'],
  })) for (const value of values) {
    const f = evidenceFixture(); f.record.approval.receipt[field] = value; f.signReceipt(); refuse(f.record, 'receipt-public-schema')
  }
  const f = evidenceFixture(), reordered = clone(f.record)
  const { pubkey_fp, ...rest } = reordered.approval.receipt
  reordered.approval.receipt = { pubkey_fp, ...rest }; f.signReceipt(reordered); refuse(reordered, 'receipt-schema')
  for (const attack of [r => { r.floor.history = [r.floor.release] }, r => { r.floor.history = ['1'.repeat(40), '1'.repeat(40)] },
    r => { r.floor.signer_epoch = 0 }, r => { r.floor.kind = 'aukora-release-floor/v1' },
    r => { r.floor.history = Array.from({ length: 65 }, (_, i) => i.toString(16).padStart(40, '0')) }]) {
    const r = clone(f.record); attack(r); refuse(r, 'floor-schema')
  }
  for (const field of ['release', 'release_dir', 'record', 'signer_key_sha256', 'ledger_hash']) {
    const r = clone(f.record); r.floor[field] = field === 'release_dir' ? 'release-aaaaaaa' : 'a'.repeat(field === 'release' ? 40 : 64)
    refuse(r, 'floor-signed-row-binding')
  }
  for (const field of ['revision', 'record_sha256', 'plugin_set_sha256']) {
    const r = clone(f.record); r.release[field] = 'a'.repeat(field === 'revision' ? 40 : 64); refuse(r, 'approval-release-binding')
  }
  for (const field of ['proposal', 'target', 'base_sha', 'new_sha']) {
    const r = clone(f.record); r.approval.ledger_entry[field] = field === 'proposal' ? 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa' : 'a'.repeat(64)
    f.signRow(r); refuse(r, 'ledger-receipt-binding')
  }
  const altered = clone(f.record); altered.approval.receipt.approver = 'owner via owner.sock (local; 0600 gate user/root only)'
  refuse(altered, 'receipt-signature')
  const invalidKey = clone(f.record); invalidKey.signer.public_key_pem = 'PRIVATE_SENTINEL'; refuse(invalidKey, 'signer-key')
})

test('approval content uses the exact gate grammar rather than equivalent reordered JSON', () => {
  const f = evidenceFixture(), fields = JSON.parse(f.record.approval.content)
  f.record.approval.content = JSON.stringify(Object.fromEntries(Object.entries(fields).reverse()))
  f.record.approval.receipt.new_sha = hash(f.record.approval.content); f.signReceipt()
  refuse(f.record, 'approval-content-schema')
})

test('only complete PASS or a prefix ending at its one failed observation is reported', () => {
  const f = evidenceFixture()
  for (const length of [1, 13, 26]) {
    const r = clone(f.record); r.checks = r.checks.slice(0, length); r.checks.at(-1).status = 'FAIL'
    assert.equal(verifier.verifyBrowserNodeEvidence(r).passed, false)
  }
  for (const attack of [r => { r.checks = [] }, r => { r.checks[0].status = 'SKIPPED' },
    r => { r.checks[0].private = 'PRIVATE_SENTINEL' }, r => { [r.checks[0], r.checks[1]] = [r.checks[1], r.checks[0]] }]) {
    const r = clone(f.record); attack(r); refuse(r, 'checks-schema')
  }
  const r = clone(f.record); r.checks[0].status = 'FAIL'; refuse(r, 'checks-completion')
})

test('strict evidence and signed detail JSON reject duplicates and malformed bytes', () => {
  const f = evidenceFixture(), text = JSON.stringify(f.record)
  assert.equal(verifier.parseBrowserNodeEvidence(text).kind, f.record.kind)
  for (const invalid of [text.replace('"phase":"after"', '"phase":"after","phase":"after"'),
    '[[[[[[[[[[[[[0]]]]]]]]]]]]]', '{"value":-0}', '{"value":9007199254740993}', '{"value":"\\ud800"}',
    text.replace('"phase":"after"', '"phase":"after","ph\\u0061se":"after"'), text + ' '.repeat(128 * 1024)]) {
    assert.throws(() => verifier.parseBrowserNodeEvidence(invalid), { code: 'browser-node-evidence:json' })
  }
  const r = clone(f.record)
  r.approval.ledger_entry.detail = r.approval.ledger_entry.detail.replace('"receipt":', '"receipt":null,"receipt":')
  f.signRow(r); refuse(r, 'ledger-detail-json')
})

test('offline CLI gives safe named refusal, PASS/FAIL exits and reads stdin without a node', t => {
  const dir = fs.mkdtempSync(new URL('.browser-evidence-', import.meta.url))
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }))
  const file = resolve(dir, 'record.json'), cli = resolve(dir, 'verifier.mjs'), f = evidenceFixture()
  fs.writeFileSync(cli, mutatedSource())
  const run = (argv, input) => spawnSync(process.execPath, [cli, ...argv], { cwd: root, input,
    encoding: 'utf8', timeout: 10000, maxBuffer: 256 * 1024 })
  fs.writeFileSync(file, JSON.stringify(f.record))
  const pass = run([file]); assert.equal(pass.status, 0, pass.stdout + pass.stderr)
  assert.equal(pass.stdout, 'VERIFIED browser-node-evidence:receipt-signature,approval-bindings,signed-apply-row,floor-core-binding\n'
    + 'OBSERVATIONS PASS checks=26\n' + verifier.LIMITATIONS.join('\n') + '\n')
  assert.equal(run(['--stdin'], JSON.stringify(f.record)).status, 0)
  const container = clone(f.record); container.checks.shift()
  assert.equal(verifier.verifyBrowserNodeEvidence(container, { containerOnly: true }).checks, 25)
  refuse(container, 'checks-schema')
  assert.equal(run(['--stdin-container'], JSON.stringify(container)).status, 0)
  assert.equal(run(['--stdin'], JSON.stringify(container)).status, 1)
  const chunked = parts => spawnSync(process.execPath, ['--input-type=module', '-e', `
    import { spawn } from 'node:child_process'
    const child = spawn(process.execPath, [${JSON.stringify(cli)}, '--stdin'], { stdio: ['pipe', 'pipe', 'pipe'] })
    child.stdout.pipe(process.stdout); child.stderr.pipe(process.stderr)
    const completed = new Promise(resolve => child.on('close', resolve))
    child.stdin.on('error', () => {})
    // A number stands for that many spaces: a 128 KiB literal would exceed Linux's per-argument limit (E2BIG).
    const parts = ${JSON.stringify(parts)}.map(part => typeof part === 'number' ? ' '.repeat(part) : part)
    for (const part of parts) { child.stdin.write(part); await new Promise(resolve => setTimeout(resolve, 20)) }
    child.stdin.end(); process.exitCode = await completed
  `], { encoding: 'utf8', timeout: 10000, maxBuffer: 256 * 1024 })
  const text = JSON.stringify(f.record)
  assert.equal(chunked([text.slice(0, 17), text.slice(17, 51), text.slice(51)]).status, 0, 'valid partial pipe reads reach EOF')
  for (const tail of ['{"private":"PRIVATE_SENTINEL"}', ',"phase":"after"}', 128 * 1024]) {
    const bad = chunked([text, tail]); assert.equal(bad.status, 1, 'later bytes cannot be silently ignored: ' + bad.stdout + bad.stderr)
    assert.match(bad.stdout, /^NOT VERIFIED browser-node-evidence:(?:json|input-size)\n$/)
    assert.doesNotMatch(bad.stdout + bad.stderr, /PRIVATE_SENTINEL/)
  }
  assert.equal(run(['--stdin'], text + ' '.repeat(128 * 1024)).stdout, 'NOT VERIFIED browser-node-evidence:input-size\n')
  const invalidUtf8 = Buffer.concat([Buffer.from(text.slice(0, text.indexOf('aukora-browser-node-evidence'))), Buffer.from([255]),
    Buffer.from(text.slice(text.indexOf('aukora-browser-node-evidence')))])
  assert.equal(run(['--stdin'], invalidUtf8).stdout, 'NOT VERIFIED browser-node-evidence:input-unavailable-or-invalid\n')
  f.record.checks = f.record.checks.slice(0, 11); f.record.checks.at(-1).status = 'FAIL'
  const fail = run(['--stdin'], JSON.stringify(f.record)); assert.equal(fail.status, 2); assert.match(fail.stdout, /OBSERVATIONS FAIL checks=11/)
  for (const [argv, input] of [[[], undefined], [[file + '-PRIVATE_SENTINEL'], undefined], [['--stdin'], 'PRIVATE_SENTINEL'],
    [['--stdin'], Buffer.from([255])], [['--stdin'], '{"private":"PRIVATE_SENTINEL"}'], [['--stdin'], ' '.repeat(128 * 1024 + 1)]]) {
    const bad = run(argv, input); assert.equal(bad.status, 1)
    assert.match(bad.stdout, /^NOT VERIFIED browser-node-evidence:[a-z-]+\n$/)
    assert.doesNotMatch(bad.stdout + bad.stderr, /PRIVATE_SENTINEL|\/Users\/|\.browser-evidence-/)
  }
})
}
