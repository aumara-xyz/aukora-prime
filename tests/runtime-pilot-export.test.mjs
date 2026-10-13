// SPDX-License-Identifier: AGPL-3.0-or-later
// Synthetic signed state exercises public projection, private writes and executable guard mutations.
import assert from 'node:assert/strict'
import { test } from 'node:test'
import { generateKeyPairSync, createHash, sign } from 'node:crypto'
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, symlinkSync, writeFileSync } from 'node:fs'
import { join, dirname, resolve } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { spawnSync } from 'node:child_process'
import { createLedger, openDb } from '../packages/boundary-gate/src/ledger.mjs'
import { pluginSetTarget } from '../packages/boundary-gate/src/targets.mjs'
import { cleanNote, noteMeta } from '../packages/boundary-gate/src/card.mjs'
import { gatePublicKeySha256 } from '../scripts/aura/gate-snapshot.mjs'
import { verifyExport } from '../scripts/aura/verify-export.mjs'
import { pluginSetApprovalText, PLUGIN_SET_TARGET } from '../packages/boundary-gate/src/vendor/operator-data.mjs'
import * as exporter from '../scripts/audit/export-pilot-evidence.mjs'

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const SOURCE = new URL('../scripts/audit/export-pilot-evidence.mjs', import.meta.url)
const date = '2026-10-13T00:00:00.000Z'
const digest = bytes => createHash('sha256').update(bytes).digest('hex')
const secret = 'sk-live-SYNTHETIC_SECRET_DO_NOT_PUBLISH'
const address = 'https://private.invalid:8443/operator'
const paths = ['/branding/aumara-icon-96.png', '/assets/aumara-icon-96.png', '/stock-apps/auma-lingwa.html',
  '/app/auma/auma.js', '/stock-apps/auma-live.html', '/app/aumalive.js', '/stock-apps/zeta-harp/index.html',
  '/stock-apps/zeta-harp/js/zh-fixtures-1.js', '/stock-apps/human-graph/index.html', '/stock-apps/human-graph/graph.css',
  '/stock-apps/dakini-code/index.html', '/stock-apps/dakini-code/assets/index-t74FFCZZ.js',
  '/api/auma-live/status', '/api/aukora/aura-snapshot']
const probe = () => ({ ok: true, code: 'ui-probe:all-served', cookie: secret, url: address,
  checks: paths.map(path => ({ path, status: 200, bytes: 24, contentType: 'application/json', served: true,
    token: secret, address })) })
const refused = (fn, code) => assert.throws(fn, error => error.message === `pilot-evidence:${code}`)

function fixture(root, { unsafe, unsafeReview, badReceipt = false } = {}) {
  const dir = mkdtempSync(join(root, 'fixture-'))
  const { privateKey, publicKey } = generateKeyPairSync('ed25519')
  const publicKeyPem = publicKey.export({ format: 'pem', type: 'spki' }).toString()
  const recordBytes = JSON.stringify({ kind: 'genesis-artifact-record', formatVersion: 1,
    privateRecordContent: { secret, address, path: '/home/private/operator' } }) + '\n'
  const content = pluginSetApprovalText({ release: '1'.repeat(40), release_dir: 'release-1111111',
    plugin_set: '2'.repeat(64), operation: '3'.repeat(64), record: digest(recordBytes) })
  const dbPath = join(dir, 'gate.db'), db = openDb(dbPath)
  const ledger = createLedger(db, { priv: privateKey, pub: publicKey }, () => date)
  const id = '11111111-2222-3333-4444-555555555555'
  const fields = { proposal: id, target: PLUGIN_SET_TARGET, base_sha: 'absent', new_sha: digest(content) }
  if (unsafe) ledger.append('genesis-target', { target: PLUGIN_SET_TARGET, new_sha: digest(content), detail: unsafe })
  ledger.append('gate-start', { detail: { pid: 123, ledger_ok_before_start: true, entries: 0,
    pubkey_fp: gatePublicKeySha256(publicKeyPem).slice(0, 16), owner_bearer: null } })
  const note = 'Admit the AUKORA plugin set of release 1111111 (set 2222222222222222...). Raised by the operator; only the owner approves.'
  ledger.append('propose', { ...fields, detail: { kind: 'change', note: cleanNote(note), note_meta: noteMeta(note),
    session: 'owner-raise', expires: date, displayable: true } })
  const facts = pluginSetTarget(dir, { floorFile: join(dir, 'absent-floor.json') }).reviewFacts('', content)
  const targetReview = { available: true, from_to: facts.from_to, facts_text: JSON.stringify(facts), ...unsafeReview }
  ledger.append('review-issued', { ...fields, detail: { via: 'owner', review_expires: date, target_review: targetReview } })
  const approver = 'owner via owner.sock (local; 0600 gate user/root only)'
  ledger.append('decide', { ...fields, detail: { outcome: 'allowed-once', via: 'owner', approver, spent: true } })
  const receipt = { v: 2, kind: 'change', ...fields, applied_at: date, approver,
    approval_evidence_hmac: Buffer.alloc(32).toString('base64'), pubkey_fp: gatePublicKeySha256(publicKeyPem).slice(0, 16) }
  const receipt_sig = sign(null, Buffer.from(JSON.stringify(receipt)), privateKey).toString('base64')
  const applied = ledger.append('apply', { ...fields, detail: { receipt,
    receipt_sig: badReceipt ? Buffer.alloc(64).toString('base64') : receipt_sig } })
  // A later signed private row is intentionally outside the requested approval prefix.
  ledger.append('selfcheck', { detail: { result: { secret, address } } })
  db.close()
  const options = { dbPath, publicKeyPath: join(dir, 'public.pem'), recordPath: join(dir, 'genesis-artifacts.json'),
    approvalPath: join(dir, 'approval.json'), approvalSeq: applied.seq, launchPath: join(dir, 'launch.json') }
  writeFileSync(options.publicKeyPath, publicKeyPem)
  writeFileSync(options.recordPath, recordBytes)
  writeFileSync(options.approvalPath, content)
  writeFileSync(options.launchPath, JSON.stringify({ url: 'http://127.0.0.1:4567/?token=' + secret, address }))
  return { dir, options, content, recordBytes }
}

async function loadSource(root, changes = [], extra = '') {
  let source = readFileSync(SOURCE, 'utf8')
  for (const [before, after] of changes) {
    assert.ok(source.includes(before), `mutation target exists: ${before}`)
    source = source.replace(before, after)
  }
  source = source.replace(/from '([^']+)'/gu, (whole, specifier) => specifier.startsWith('.')
    ? `from '${new URL(specifier, SOURCE).href}'` : whole)
  source = source.replace("const REPO = resolve(dirname(fileURLToPath(import.meta.url)), '../..')", `const REPO = ${JSON.stringify(REPO)}`)
  const file = join(root, `mutant-${Math.random().toString(16).slice(2)}.mjs`)
  writeFileSync(file, source + '\n' + extra)
  return import(pathToFileURL(file).href)
}

const controls = [
  { name: 'verified signed ledger', changes: [["if (!snapshot.ok) refuse('ledger-unverified')", "if (false) refuse('ledger-unverified')"]],
    exercise(api, root) {
      const f = fixture(root), db = openDb(f.options.dbPath)
      db.exec('DROP TRIGGER ledger_no_update; UPDATE ledger SET sig=' + "'" + Buffer.alloc(64).toString('base64') + "' WHERE seq=1")
      db.close()
      refused(() => api.collectPilotEvidence(f.options, probe), 'ledger-unverified')
    } },
  { name: 'unchanged prefix excludes free text and secret-shaped fields',
    changes: [["if (!publicPrefix(entries)) refuse('ledger-not-public-safe')", "if (false) refuse('ledger-not-public-safe')"]],
    exercise(api, root) {
      for (const unsafe of [{ note: secret }, { session: address }, { unknown: secret }, { note_meta: { hexdump: secret } }]) {
        const f = fixture(root, { unsafe })
        refused(() => api.collectPilotEvidence(f.options, probe), 'ledger-not-public-safe')
      }
    } },
  { name: 'release review facts allow only canonical public facts', changes: [[
    "if (key === 'target_review') return publicTargetReview(item)", "if (key === 'target_review') return true"]],
    exercise(api, root) {
      for (const unsafeReview of [{ from_to: secret }, { facts_text: JSON.stringify({ from_to: address, release_floor: null }) },
        { unknown: secret }, { facts_text: JSON.stringify({ from_to: secret, release_floor: { note: address } }) }]) {
        const f = fixture(root, { unsafeReview })
        refused(() => api.collectPilotEvidence(f.options, probe), 'ledger-not-public-safe')
      }
    } },
  { name: 'approval binds record and target bytes',
    changes: [["refuse('approval-record-binding')", 'void 0']],
    exercise(api, root) {
      const f = fixture(root)
      writeFileSync(f.options.recordPath, JSON.stringify({ kind: 'genesis-artifact-record', formatVersion: 1, changed: true }))
      refused(() => api.collectPilotEvidence(f.options, probe), 'approval-record-binding')
    } },
  { name: 'canonical release approval bytes bind the signed apply digest', changes: [[
    ' || entry.new_sha !== sha(content)', '']], exercise(api, root) {
      const f = fixture(root), approval = JSON.parse(f.content)
      writeFileSync(f.options.approvalPath, pluginSetApprovalText({ ...approval,
        release: '6'.repeat(40), release_dir: 'release-6666666' }))
      refused(() => api.collectPilotEvidence(f.options, probe), 'approval-record-binding')
    } },
  { name: 'nested receipt signature is verified', changes: [["refuse('approval-receipt-binding')", 'void 0']],
    exercise(api, root) {
      const f = fixture(root, { badReceipt: true })
      refused(() => api.collectPilotEvidence(f.options, probe), 'approval-receipt-binding')
    } },
  { name: 'remote launch is refused before probe', changes: [["refuse('launch-not-loopback')", 'void 0'], ["refuse('launch-not-loopback')", 'void 0']],
    exercise(api, root) {
      const f = fixture(root)
      writeFileSync(f.options.launchPath, JSON.stringify({ url: address + '?token=' + secret }))
      refused(() => api.collectPilotEvidence(f.options, probe), 'launch-not-loopback')
    } },
  { name: 'probe fields are projected without arbitrary content', changes: [[
    "return { path: PATHS[index], status: 200, bytes: row.bytes, contentType: row.contentType, served: true }", 'return row']],
    exercise(api, root) {
      const f = fixture(root), files = api.collectPilotEvidence(f.options, probe)
      assert.ok(Object.values(files).every(text => !text.includes(secret) && !text.includes(address)))
    } },
  { name: 'probe must cover every expected screen successfully', changes: [[
    "if (!value || value.ok !== true || value.code !== 'ui-probe:all-served'", "if (false && (!value || value.ok !== true || value.code !== 'ui-probe:all-served'"],
    ["|| !Array.isArray(value.checks) || value.checks.length !== PATHS.length) refuse('ui-probe-not-public-safe')",
    "|| !Array.isArray(value.checks) || value.checks.length !== PATHS.length)) refuse('ui-probe-not-public-safe')"]],
    exercise(api, root) {
      const f = fixture(root), output = probe(); output.checks = []
      refused(() => api.collectPilotEvidence(f.options, () => output), 'ui-probe-not-public-safe')
    } },
  { name: 'unknown probe types are refused', changes: [["|| !TYPES.has(row.contentType)) refuse('ui-probe-not-public-safe')",
    ") refuse('ui-probe-not-public-safe')"]], exercise(api, root) {
      const f = fixture(root), output = probe(); output.checks[0].contentType = secret
      refused(() => api.collectPilotEvidence(f.options, () => output), 'ui-probe-not-public-safe')
    } },
  { name: 'input leaves do not follow symlinks', changes: [[
    'const before = lstatSync(file)', 'const before = lstatSync(realpathSync(file))'],
    ['constants.O_RDONLY | constants.O_NOFOLLOW', 'constants.O_RDONLY']],
    exercise(api, root) {
      const f = fixture(root), link = join(f.dir, 'launch-link.json'); symlinkSync(f.options.launchPath, link)
      refused(() => api.collectPilotEvidence({ ...f.options, launchPath: link }, probe), 'input-file')
    } },
  { name: 'bounded input size', changes: [[' || before.size > limit', ''], [' || opened.size > limit', ''],
    ["if (bytes.length > limit) refuse('input-file')", "if (false) refuse('input-file')"]], exercise(api, root) {
      const f = fixture(root)
      writeFileSync(f.options.launchPath, JSON.stringify({ url: 'http://127.0.0.1:4567/', ignored: 'x'.repeat(17_000) }))
      refused(() => api.collectPilotEvidence(f.options, probe), 'input-file')
    } },
  { name: 'private output directory under umask 002', changes: [['mkdirSync(out, { mode: 0o700 })', 'mkdirSync(out, { mode: 0o777 })']],
    exercise(api, root) {
      const f = fixture(root), out = join(f.dir, 'export')
      api.writePilotEvidence(out, api.collectPilotEvidence(f.options, probe))
      assert.equal(statSync(out).mode & 0o777, 0o700)
    } },
  { name: 'private output files under umask 002', changes: [["{ flag: 'wx', mode: 0o600 }", "{ flag: 'wx', mode: 0o666 }"]],
    exercise(api, root) {
      const f = fixture(root), out = join(f.dir, 'export')
      api.writePilotEvidence(out, api.collectPilotEvidence(f.options, probe))
      for (const file of readdirSync(out)) assert.equal(statSync(join(out, file)).mode & 0o777, 0o600)
    } },
  { name: 'new output does not overwrite existing files', changes: [[
    'mkdirSync(out, { mode: 0o700 })', 'mkdirSync(out, { mode: 0o700, recursive: true })']], exercise(api, root) {
      const f = fixture(root), out = join(f.dir, 'existing'); mkdirSync(out, { mode: 0o700 })
      writeFileSync(join(out, 'sentinel'), secret)
      refused(() => api.writePilotEvidence(out, api.collectPilotEvidence(f.options, probe)), 'output-exists-or-unavailable')
      assert.equal(readFileSync(join(out, 'sentinel'), 'utf8'), secret)
    } },
  { name: 'unsafe output ancestry is refused', changes: [["refuse('output-ancestor')", 'void 0']], exercise(api, root) {
      const f = fixture(root), parent = join(f.dir, 'shared'); mkdirSync(parent); chmodSync(parent, 0o777)
      refused(() => api.writePilotEvidence(join(parent, 'export'), api.collectPilotEvidence(f.options, probe)), 'output-ancestor')
    } },
  { name: 'fixed output names cannot escape', changes: [["refuse('output-shape')", 'void 0']], exercise(api, root) {
      const f = fixture(root), out = join(f.dir, 'export'), files = api.collectPilotEvidence(f.options, probe)
      refused(() => api.writePilotEvidence(out, { ...files, '../escape': secret }), 'output-shape')
    } },
]

test('operator exporter synthetic control and removed-protection mutations', async () => {
  const mask = process.umask(0o002), root = mkdtempSync(join(REPO, '.runtime-pilot-export-'))
  try {
    const f = fixture(root), files = exporter.collectPilotEvidence(f.options, probe), out = join(f.dir, 'public')
    exporter.writePilotEvidence(out, files)
    assert.deepEqual(readdirSync(out).sort(), ['gate-public.pem', 'ledger-export.json', 'release-approval.json',
      'release-digest.json', 'ui-probe.json', 'verification.txt'])
    const bundle = JSON.parse(readFileSync(join(out, 'ledger-export.json'), 'utf8'))
    assert.equal(verifyExport(bundle).entries, f.options.approvalSeq)
    assert.equal(bundle.entries.at(-1).event, 'apply')
    const approvalBytes = readFileSync(join(out, 'release-approval.json'))
    const releaseDigest = JSON.parse(readFileSync(join(out, 'release-digest.json'), 'utf8'))
    assert.equal(digest(approvalBytes), bundle.entries.at(-1).new_sha)
    assert.equal(JSON.parse(approvalBytes.toString('utf8')).release, releaseDigest.release)
    assert.equal(approvalBytes.toString('utf8'), f.content)
    assert.ok(Object.values(files).every(text => !text.includes(secret) && !text.includes(address)
      && !text.includes('/home/private/operator') && !text.includes('PRIVATE KEY')))
    const existingParent = join(f.dir, 'parent-alias'); symlinkSync(f.dir, existingParent)
    exporter.writePilotEvidence(join(existingParent, 'alias-output'), files)
    assert.equal(statSync(join(f.dir, 'alias-output')).mode & 0o777, 0o700)
    for (const control of controls) {
      control.exercise(exporter, root)
      const mutant = await loadSource(root, control.changes)
      assert.throws(() => control.exercise(mutant, root), error => error instanceof assert.AssertionError, control.name)
      console.log(`MUTATION CAUGHT ${control.name}`)
    }
    console.log(`PILOT EXPORT PASS synthetic signed prefix, secret/address exclusions, umask 002; ${controls.length} mutations caught`)
  } finally { rmSync(root, { recursive: true, force: true }); process.umask(mask) }
})

test('probe and whole collection subprocesses carry enforced bounds and checked launch bytes', async () => {
  const root = mkdtempSync(join(REPO, '.runtime-pilot-export-'))
  const base = [['import { spawnSync } from \'node:child_process\'', 'const spawnSync = (...args) => globalThis.__pilotEvidenceSpawn(...args)']]
  try {
    for (const [name, mutation] of [['probe timeout', ['timeout: 5_000,', '']], ['collection timeout', ['timeout: 20_000,', '']]]) {
      const exercise = async changes => {
        const api = await loadSource(root, [...base, ...changes]), f = fixture(root)
        const files = exporter.collectPilotEvidence(f.options, probe)
        globalThis.__pilotEvidenceSpawn = (_node, args, opts) => {
          if (args.includes('--collect-internal')) {
            assert.equal(opts.timeout, 20_000)
            assert.ok(opts.maxBuffer <= 10 * 1024 * 1024)
            return { status: 0, stdout: JSON.stringify(files) }
          }
          assert.equal(opts.timeout, 5_000)
          assert.equal(args.at(-1), '/dev/stdin')
          assert.equal(opts.input.toString(), readFileSync(f.options.launchPath, 'utf8'))
          assert.equal(opts.env.NODE_OPTIONS, undefined)
          return { status: 0, stdout: JSON.stringify(probe()) }
        }
        api.collectPilotEvidence(f.options)
        const logs = [], original = console.log
        console.log = text => logs.push(text)
        try {
          assert.equal(api.main(['--db', f.options.dbPath, '--public-key', f.options.publicKeyPath, '--record', f.options.recordPath,
            '--approval', f.options.approvalPath, '--approval-seq', String(f.options.approvalSeq), '--launch', f.options.launchPath,
            '--out', join(f.dir, 'bounded-output')]), 0)
        } finally { console.log = original }
      }
      await exercise([])
      await assert.rejects(exercise([mutation]), error => error instanceof assert.AssertionError)
      console.log(`MUTATION CAUGHT ${name}`)
    }
  } finally { delete globalThis.__pilotEvidenceSpawn; rmSync(root, { recursive: true, force: true }) }
})

test('operator CLI help and synthetic refusal print no raw secrets and write no files', () => {
  const root = mkdtempSync(join(REPO, '.runtime-pilot-export-'))
  try {
    const f = fixture(root, { unsafe: { note: secret } }), out = join(f.dir, 'refused-output')
    const result = spawnSync('sh', [join(REPO, 'scripts/audit/export-pilot-evidence.sh'), '--db', f.options.dbPath,
      '--public-key', f.options.publicKeyPath, '--record', f.options.recordPath, '--approval', f.options.approvalPath,
      '--approval-seq', String(f.options.approvalSeq), '--launch', f.options.launchPath, '--out', out], { encoding: 'utf8', timeout: 5000 })
    assert.equal(result.status, 1)
    assert.match(result.stdout, /^NOT EXPORTED pilot-evidence:ledger-not-public-safe\n$/u)
    assert.ok(!(result.stdout + result.stderr).includes(secret))
    assert.ok(!(result.stdout + result.stderr).includes(address))
    assert.ok(!readdirSync(f.dir).includes('refused-output'))
    const help = spawnSync('sh', [join(REPO, 'scripts/audit/export-pilot-evidence.sh'), '--help'], { encoding: 'utf8', timeout: 5000 })
    assert.equal(help.status, 0)
    assert.match(help.stdout, /Operator-only: run ON the node/u)
    assert.match(help.stdout, /does not prove process identity, owner attendance, latestness or anchor custody/u)
  } finally { rmSync(root, { recursive: true, force: true }) }
})

test('operator CLI writes verified synthetic evidence with only UI transport replaced', async () => {
  const mask = process.umask(0o002), root = mkdtempSync(join(REPO, '.runtime-pilot-export-'))
  try {
    const api = await loadSource(root, [[
      'function runUiProbe(_launchPath, launchBytes) {',
      `function runUiProbe(_launchPath, launchBytes) { return ${JSON.stringify(probe())};`]],
    'export const fixtureSourceFile = fileURLToPath(import.meta.url)')
    const f = fixture(root), out = join(f.dir, 'cli-output')
    const run = spawnSync(process.execPath, [api.fixtureSourceFile, '--db', f.options.dbPath,
      '--public-key', f.options.publicKeyPath, '--record', f.options.recordPath, '--approval', f.options.approvalPath,
      '--approval-seq', String(f.options.approvalSeq), '--launch', f.options.launchPath, '--out', out],
    { encoding: 'utf8', timeout: 5000 })
    assert.equal(run.status, 0, run.stdout + run.stderr)
    assert.match(run.stdout, /^EXPORTED pilot-evidence:public-prefix-and-probe;/u)
    assert.equal(statSync(out).mode & 0o777, 0o700)
    for (const name of readdirSync(out)) {
      assert.equal(statSync(join(out, name)).mode & 0o777, 0o600)
      const content = readFileSync(join(out, name), 'utf8')
      assert.ok(!content.includes(secret) && !content.includes(address))
    }
    const offline = spawnSync(process.execPath, [join(REPO, 'scripts/aura/verify-export.mjs'), join(out, 'ledger-export.json'),
      '--public-key', join(out, 'gate-public.pem')], { encoding: 'utf8', timeout: 5000 })
    assert.equal(offline.status, 0, offline.stdout + offline.stderr)
    assert.match(offline.stdout, /^VERIFIED gate-chain-only entries=5 anchored_through=0 unanchored_entries=5/mu)
    console.log('PILOT CLI PASS synthetic transport; offline verifier accepted prefix with separately supplied public key')
  } finally { rmSync(root, { recursive: true, force: true }); process.umask(mask) }
})

test('operator shell excludes inherited Node preload code before it can print or write', () => {
  const root = mkdtempSync(join(REPO, '.runtime-pilot-export-'))
  try {
    const preload = join(root, 'preload.cjs')
    writeFileSync(preload, `process.stdout.write(${JSON.stringify(secret)})`)
    const env = { ...process.env, NODE_OPTIONS: '--require=' + preload, NODE_PATH: secret }
    const exercise = shell => {
      const result = spawnSync('sh', [shell, '--help'], { encoding: 'utf8', env, timeout: 5000 })
      assert.equal(result.status, 0)
      assert.ok(!result.stdout.includes(secret))
    }
    const shell = join(REPO, 'scripts/audit/export-pilot-evidence.sh')
    exercise(shell)
    const mutant = join(root, 'mutant.sh')
    const source = readFileSync(shell, 'utf8').replace('unset NODE_OPTIONS NODE_PATH', '')
      .replace('exec node "$SCRIPT_DIR/export-pilot-evidence.mjs" "$@"',
        `exec node '${fileURLToPath(SOURCE)}' "$@"`)
    writeFileSync(mutant, source)
    assert.throws(() => exercise(mutant), error => error instanceof assert.AssertionError)
    console.log('MUTATION CAUGHT inherited Node preload exclusion')
  } finally { rmSync(root, { recursive: true, force: true }) }
})
