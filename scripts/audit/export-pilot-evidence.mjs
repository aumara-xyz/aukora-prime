#!/usr/bin/env node
// SPDX-License-Identifier: AGPL-3.0-or-later
// Verify a public-safe signed prefix, bind its approval to record bytes, and publish private files.
import { spawnSync } from 'node:child_process'
import { createHash, verify, createPublicKey } from 'node:crypto'
import { constants, openSync, closeSync, fstatSync, readFileSync, lstatSync, realpathSync, mkdirSync, writeFileSync, rmSync } from 'node:fs'
import { basename, dirname, join, resolve } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { parseArgs } from 'node:util'
import { gatePublicKeySha256, readGateSnapshot } from '../aura/gate-snapshot.mjs'
import { verifyExport } from '../aura/verify-export.mjs'
import { parseUniqueJson } from '../aura/verify-collected.mjs'
import { parsePluginSetApproval, PLUGIN_SET_TARGET } from '../../packages/boundary-gate/src/vendor/operator-data.mjs'

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), '../..')
const HEX = /^[0-9a-f]{64}$/u
const DATE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u
const UUID = /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/u
const SIGNATURE = /^[A-Za-z0-9+/]{86}==$/u
const TARGETS = new Set([PLUGIN_SET_TARGET, 'plugins/auma-theme/theme.json', 'plugins/owner-note/note.md'])
const EVENTS = new Set(['genesis-target', 'gate-start', 'owner-bearer-rotated', 'harness-start', 'selfcheck',
  'propose', 'review-issued', 'decide', 'apply', 'revert-applied', 'expire'])
const WORDS = new Set(['', 'change', 'revert', 'owner', 'owner-review', 'owner.sock', 'allowed-once', 'rejected',
  'owner-raise', 'owner via owner.sock (local; 0600 gate user/root only)',
  'owner via gate approval page (bearer token, typed 2-step confirm)', 'owner via gate passkey page', 'owner via gate approval page (bearer token)',
  'current bytes adopted at gate start', 'ttl elapsed', 'propose-socket/harness', 'caller-reported-unverified'])
const NUMBERS = new Set(['v', 'version', 'pid', 'entries', 'nonascii', 'expired_pending', 'preserved_pending'])
const BOOLEANS = new Set(['displayable', 'spent', 'ledger_ok_before_start', 'rotated'])
const DIGESTS = new Set(['base_sha', 'new_sha', 'pubkey_fp', 'fp8'])
const TEXT = new Set(['kind', 'note', 'session', 'via', 'outcome', 'reason', 'source', 'verification', 'approver', 'result'])
const OBJECTS = new Set(['receipt', 'note_meta', 'owner_bearer'])
const PUBLIC_RELEASE_FACTS = /^(?:GATE FACT: ROLLBACK to release-[0-9a-f]{7}, below the release floor release-[0-9a-f]{7} \| )?GATE FACT: (?:first plugin-set approval on this gate|plugin set CHANGED since your approval of release-[0-9a-f]{7}|plugin set UNCHANGED since your approval of release-[0-9a-f]{7} \([0-9a-f]{12}\), operation (?:unchanged|CHANGED)) \| ADMIT AUKORA PLUGIN SET \| release [0-9a-f]{40} \(release-[0-9a-f]{7}\) \| plugin set [0-9a-f]{64} \| operation [0-9a-f]{64} \(rechecked at launch\) \| release record [0-9a-f]{64}$/u
const PATHS = ['/branding/aumara-icon-96.png', '/assets/aumara-icon-96.png', '/stock-apps/auma-lingwa.html',
  '/app/auma/auma.js', '/stock-apps/auma-live.html', '/app/aumalive.js', '/stock-apps/zeta-harp/index.html',
  '/stock-apps/zeta-harp/js/zh-fixtures-1.js', '/stock-apps/human-graph/index.html', '/stock-apps/human-graph/graph.css',
  '/stock-apps/dakini-code/index.html', '/stock-apps/dakini-code/assets/index-t74FFCZZ.js',
  '/api/auma-live/status', '/api/aukora/aura-snapshot']
const TYPES = new Set(['image/png', 'text/html', 'text/javascript', 'application/javascript', 'text/css', 'application/json'])
const refuse = name => { throw new Error(`pilot-evidence:${name}`) }
const sha = bytes => createHash('sha256').update(bytes).digest('hex')
const json = text => parseUniqueJson(text, { maxBytes: 8 * 1024 * 1024 })

function publicFloor(value) {
  if (value === null) return true
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false
  const identity = typeof value.release === 'string' && /^[0-9a-f]{40}$/u.test(value.release)
    && value.release_dir === 'release-' + value.release.slice(0, 7) && HEX.test(value.record)
    && Array.isArray(value.history) && value.history.length <= 64
    && value.history.every(release => typeof release === 'string' && /^[0-9a-f]{40}$/u.test(release))
  if (value.kind === 'aukora-release-floor/v1') return identity && DATE.test(value.applied_at)
    && Object.keys(value).sort().join(',') === 'applied_at,history,kind,record,release,release_dir'
  return identity && value.kind === 'aukora-release-floor/v2'
    && Object.keys(value).sort().join(',') === 'history,kind,ledger_hash,ledger_seq,record,release,release_dir,signer_epoch,signer_key_sha256'
    && HEX.test(value.ledger_hash) && HEX.test(value.signer_key_sha256)
    && Number.isSafeInteger(value.ledger_seq) && value.ledger_seq > 0
    && Number.isSafeInteger(value.signer_epoch) && value.signer_epoch > 0
}

function publicTargetReview(value) {
  if (!value || Object.keys(value).sort().join(',') !== 'available,facts_text,from_to') return false
  if (value.available === false) return value.from_to === null && value.facts_text === null
  if (value.available !== true || typeof value.from_to !== 'string' || !PUBLIC_RELEASE_FACTS.test(value.from_to)
    || typeof value.facts_text !== 'string') return false
  let facts
  try { facts = json(value.facts_text) } catch { return false }
  return facts && Object.keys(facts).sort().join(',') === 'from_to,release_floor'
    && facts.from_to === value.from_to && publicFloor(facts.release_floor)
}

function boundedRead(file, limit) {
  const before = lstatSync(file)
  if (!before.isFile() || before.isSymbolicLink() || before.size > limit) refuse('input-file')
  const fd = openSync(file, constants.O_RDONLY | constants.O_NOFOLLOW)
  try {
    const opened = fstatSync(fd)
    if (!opened.isFile() || opened.dev !== before.dev || opened.ino !== before.ino || opened.size > limit) refuse('input-file')
    const bytes = readFileSync(fd)
    if (bytes.length > limit) refuse('input-file')
    return bytes
  } finally { closeSync(fd) }
}

// Free text, unknown keys and encoded note dumps are refused rather than redacted from signed bytes.
function publicDetail(value, depth = 0) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || depth > 4) return false
  return Object.entries(value).every(([key, item]) => {
    if (key === 'target_review') return publicTargetReview(item)
    if (item === null) return OBJECTS.has(key) || TEXT.has(key)
    if (NUMBERS.has(key)) return Number.isSafeInteger(item) && item >= 0
    if (BOOLEANS.has(key)) return typeof item === 'boolean'
    if (DIGESTS.has(key)) return typeof item === 'string' && (HEX.test(item)
      || (key === 'pubkey_fp' && /^[0-9a-f]{16}$/u.test(item)) || (key === 'fp8' && /^[0-9a-f]{8}$/u.test(item)) || item === 'absent')
    if (['expires', 'review_expires', 'applied_at'].includes(key)) return (typeof item === 'string' && DATE.test(item))
      || (key === 'expires' && Number.isSafeInteger(item) && item >= 0)
    if (key === 'proposal') return typeof item === 'string' && UUID.test(item)
    if (key === 'target') return TARGETS.has(item)
    if (key === 'receipt_sig') return typeof item === 'string' && SIGNATURE.test(item)
    if (key === 'approval_evidence_hmac') return typeof item === 'string' && /^[A-Za-z0-9+/]{43}=$/u.test(item)
    if (key === 'note' && typeof item === 'string' && /^Admit the AUKORA plugin set of release [0-9a-f]{7} \(set [0-9a-f]{16}\.\.\.\)\. Raised by the operator; only the owner (?:approves\.|appr\.\.\.)$/u.test(item)) return true
    if (TEXT.has(key)) return WORDS.has(item)
    if (OBJECTS.has(key)) return publicDetail(item, depth + 1)
    return false
  })
}

function publicPrefix(entries) {
  return entries.every(entry => {
    let detail
    try { detail = entry.detail === null ? null : json(entry.detail) } catch { return false }
    return DATE.test(entry.at) && EVENTS.has(entry.event)
      && (entry.proposal === null || UUID.test(entry.proposal)) && (entry.target === null || TARGETS.has(entry.target))
      && [entry.base_sha, entry.new_sha].every(value => value === null || value === 'absent' || HEX.test(value))
      && (entry.detail === null || publicDetail(detail))
  })
}

export function publicUiProbe(value) {
  if (!value || value.ok !== true || value.code !== 'ui-probe:all-served'
    || !Array.isArray(value.checks) || value.checks.length !== PATHS.length) refuse('ui-probe-not-public-safe')
  const checks = value.checks.map((row, index) => {
    if (!row || row.path !== PATHS[index] || row.status !== 200 || row.served !== true
      || !Number.isSafeInteger(row.bytes) || row.bytes <= 0 || row.bytes > 64 * 1024 * 1024
      || !TYPES.has(row.contentType)) refuse('ui-probe-not-public-safe')
    return { path: PATHS[index], status: 200, bytes: row.bytes, contentType: row.contentType, served: true }
  })
  return { ok: true, code: 'ui-probe:all-served', checks }
}

function runUiProbe(_launchPath, launchBytes) {
  const result = spawnSync(process.execPath, [join(REPO, 'ops/pilot/ui-probe.mjs'), '--json', '/dev/stdin'],
    { input: launchBytes, encoding: 'utf8', timeout: 5_000, maxBuffer: 1024 * 1024,
      env: { PATH: dirname(process.execPath), NODE_NO_WARNINGS: '1' } })
  if (result.status !== 0 || result.error) refuse('ui-probe-unperformed-or-failed')
  try { return json(result.stdout) } catch { refuse('ui-probe-output-invalid') }
}

export function collectPilotEvidence(options, probe = runUiProbe) {
  const publicKeyPem = boundedRead(options.publicKeyPath, 4096).toString('utf8')
  const keySha256 = gatePublicKeySha256(publicKeyPem)
  const snapshot = readGateSnapshot({ dbPath: options.dbPath, publicKeyPem, expectedKeySha256: keySha256,
    sourceId: 'gate-ledger', maxRows: 10_000, maxBytes: 8 * 1024 * 1024 })
  if (!snapshot.ok) refuse('ledger-unverified')
  const seq = options.approvalSeq
  if (!Number.isSafeInteger(seq) || seq < 1 || seq > snapshot.records.length) refuse('approval-sequence')
  const entries = snapshot.records.slice(0, seq).map(row => row.entry)
  if (!publicPrefix(entries)) refuse('ledger-not-public-safe')
  const entry = entries.at(-1)
  const content = boundedRead(options.approvalPath, 512)
  const approval = parsePluginSetApproval(content.toString('utf8'))
  const recordBytes = boundedRead(options.recordPath, 8 * 1024 * 1024)
  const record = json(recordBytes.toString('utf8'))
  if (!approval || approval.release_dir !== 'release-' + approval.release.slice(0, 7)
    || record.kind !== 'genesis-artifact-record' || record.formatVersion !== 1 || sha(recordBytes) !== approval.record
    || entry.event !== 'apply' || entry.target !== PLUGIN_SET_TARGET || entry.new_sha !== sha(content)) refuse('approval-record-binding')
  const detail = json(entry.detail), receipt = detail.receipt
  if (!receipt || receipt.proposal !== entry.proposal || receipt.target !== entry.target
    || receipt.base_sha !== entry.base_sha || receipt.new_sha !== entry.new_sha
    || !verify(null, Buffer.from(JSON.stringify(receipt)), createPublicKey(publicKeyPem), Buffer.from(detail.receipt_sig, 'base64')))
    refuse('approval-receipt-binding')
  const launchBytes = boundedRead(options.launchPath, 16 * 1024)
  const launch = json(launchBytes.toString('utf8'))
  let url
  try { url = new URL(launch.url) } catch { refuse('launch-not-loopback') }
  if (!['http:', 'https:'].includes(url.protocol) || !['127.0.0.1', '[::1]'].includes(url.hostname)
    || url.username || url.password) refuse('launch-not-loopback')
  const probeResult = publicUiProbe(probe(options.launchPath, launchBytes))
  const head = { seq, head: entry.hash, gate_fp: keySha256.slice(0, 16), entry_at: entry.at, anchored_at: new Date().toISOString() }
  const bundle = { kind: 'aukora-gate-export/v1', public_key_pem: publicKeyPem, gate_pubkey_sha256: keySha256, entries, head }
  const verified = verifyExport(bundle)
  return {
    'ledger-export.json': JSON.stringify(bundle) + '\n',
    'gate-public.pem': publicKeyPem,
    'release-approval.json': content.toString('utf8'),
    'release-digest.json': JSON.stringify({ kind: 'aukora-pilot-release-evidence/v1', release: approval.release,
      record_sha256: approval.record, approval_content_sha256: entry.new_sha, approval_seq: seq,
      approval_entry_hash: entry.hash, gate_key_sha256: keySha256 }) + '\n',
    'ui-probe.json': JSON.stringify(probeResult) + '\n',
    'verification.txt': `VERIFIED ${verified.reason} entries=${verified.entries} anchored_through=0 unanchored_entries=${verified.entries}\n`
      + 'SCOPE signed supplied prefix only; no independent anchor, owner attendance, process identity or latestness proof\n',
  }
}

export function writePilotEvidence(outPath, files) {
  const names = ['ledger-export.json', 'gate-public.pem', 'release-approval.json', 'release-digest.json', 'ui-probe.json', 'verification.txt']
  if (!files || Object.keys(files).sort().join(',') !== names.sort().join(',')
    || !Object.values(files).every(value => typeof value === 'string' && Buffer.byteLength(value) <= 8 * 1024 * 1024)) refuse('output-shape')
  const requested = resolve(outPath)
  const out = join(realpathSync(dirname(requested)), basename(requested))
  // A shared sticky temporary parent is allowed; the export directory itself is always new and private.
  for (let parent = dirname(out);; parent = dirname(parent)) {
    const stat = lstatSync(parent)
    if (!stat.isDirectory() || stat.isSymbolicLink() || (stat.uid !== 0 && stat.uid !== process.getuid())
      || ((stat.mode & 0o022) !== 0 && !(stat.uid === 0 && (stat.mode & 0o1000)))) refuse('output-ancestor')
    if (parent === dirname(parent)) break
  }
  try { mkdirSync(out, { mode: 0o700 }) } catch { refuse('output-exists-or-unavailable') }
  try {
    for (const [name, text] of Object.entries(files)) writeFileSync(join(out, name), text, { flag: 'wx', mode: 0o600 })
  } catch { rmSync(out, { recursive: true, force: true }); refuse('output-unavailable') }
}

function help() {
  console.log('Operator-only: run ON the node, using the record of the separately identified running release.')
  console.log('Usage: scripts/audit/export-pilot-evidence.sh --db FILE --public-key PUBLIC.pem --record genesis-artifacts.json --approval approval.json --approval-seq N --launch launch-url.json --out NEW_DIRECTORY')
  console.log('Writes ledger-export.json (unchanged signed prefix through approval), gate-public.pem, release-approval.json (exact canonical approved bytes), release-digest.json, ui-probe.json and verification.txt.')
  console.log('No signing keys, configuration, record contents, credentials, addresses or raw probe errors are copied; only numeric loopback is probed.')
  console.log('Existing outputs and unsafe ancestor directories are refused; directories are 0700 and files 0600 under any umask.')
  console.log('Unknown or free-text signed fields refuse the entire export before writing. Redacting them would invalidate signatures.')
  console.log('An unsafe historical prefix stays REPORTED. This command does not prove process identity, owner attendance, latestness or anchor custody.')
  console.log('Whole collection is bounded to 20 seconds; the UI probe is bounded to 5 seconds. No harness archive or build is needed.')
  console.log('Review and commit these public files under evidence/ separately; independently retain the gate public key and an anchor.')
  console.log('Verify offline: node scripts/aura/verify-export.mjs evidence/<bundle>/ledger-export.json --public-key evidence/<bundle>/gate-public.pem [--anchor INDEPENDENT_HEAD.json]')
}

export function main(argv = process.argv.slice(2)) {
  try {
    if (argv.length === 1 && argv[0] === '--help') { help(); return 0 }
    const { values } = parseArgs({ args: argv, strict: true, options: Object.fromEntries(
      ['db', 'public-key', 'record', 'approval', 'approval-seq', 'launch', 'out'].map(name => [name, { type: 'string' }])) })
    if (Object.keys(values).length !== 7 || !Object.values(values).every(value => value.length > 0)
      || !/^[1-9][0-9]{0,4}$/u.test(values['approval-seq'])) refuse('usage')
    const options = { dbPath: values.db, publicKeyPath: values['public-key'], recordPath: values.record,
      approvalPath: values.approval, approvalSeq: Number(values['approval-seq']), launchPath: values.launch }
    const child = spawnSync(process.execPath, [fileURLToPath(import.meta.url), '--collect-internal'],
      { input: JSON.stringify(options), encoding: 'utf8', timeout: 20_000, maxBuffer: 10 * 1024 * 1024,
        env: { PATH: dirname(process.execPath), NODE_NO_WARNINGS: '1' } })
    if (child.error) refuse('collection-unperformed')
    if (child.status !== 0) {
      const code = /^NOT EXPORTED (pilot-evidence:[a-z-]+)\n$/u.exec(child.stdout)?.[1]
      throw new Error(code ?? 'pilot-evidence:collection-failed')
    }
    writePilotEvidence(values.out, json(child.stdout))
    console.log('EXPORTED pilot-evidence:public-prefix-and-probe; private files require operator review before publication')
    return 0
  } catch (error) {
    const code = /^pilot-evidence:[a-z-]+$/u.test(error?.message) ? error.message : 'pilot-evidence:input-unavailable-or-invalid'
    console.log(`NOT EXPORTED ${code}`)
    return 1
  }
}

if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  if (process.argv.length === 3 && process.argv[2] === '--collect-internal') {
    try { console.log(JSON.stringify(collectPilotEvidence(json(readFileSync(0, 'utf8'))))) }
    catch (error) {
      const code = /^pilot-evidence:[a-z-]+$/u.test(error?.message) ? error.message : 'pilot-evidence:input-unavailable-or-invalid'
      console.log(`NOT EXPORTED ${code}`); process.exitCode = 1
    }
  } else process.exitCode = main()
}
