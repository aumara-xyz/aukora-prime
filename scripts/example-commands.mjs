#!/usr/bin/env node
// Example actions use the running gates and verify their retained receipts and ledgers.
import fs from 'node:fs'
import path from 'node:path'
import { spawnSync } from 'node:child_process'
import { DatabaseSync } from 'node:sqlite'
import { createHash } from 'node:crypto'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { parseArgs } from 'node:util'
import { examplePath, writePrivate, authenticateLaunch, assertActionRefusal, checkAdmission } from './fresh-clone-runtime.mjs'

const refuse = code => Object.assign(new Error(code), { code })
const readJson = file => JSON.parse(fs.readFileSync(file, 'utf8'))
const themeContent = '{"accent": "#FFD700"}'
const passed = (name, ok) => {
  console.log((ok ? 'PASS | ' : 'FAIL | ') + name)
  if (!ok) throw refuse('example-verification-failed')
}

export function parseExampleArgs(argv) {
  const { values, positionals } = parseArgs({ args: argv, allowPositionals: true, options: { root: { type: 'string' } } })
  if (positionals.length !== 1 || !['approve', 'refuse', 'verify'].includes(positionals[0]) || !values.root)
    throw refuse('example-arguments-invalid')
  return { command: positionals[0], root: values.root }
}

export function readExample(root) {
  examplePath(root, root)
  const file = path.join(root, 'example-ready.json')
  examplePath(root, file, { privateRoot: true })
  const ready = readJson(file)
  if (ready.version !== 1 || ready.kind !== 'aukora-prime-example/v1' || ready.root !== root)
    throw refuse('example-readiness-invalid')
  for (const name of ['checkout', 'release', 'launchFile']) examplePath(root, ready[name])
  if (ready.launchFile !== path.join(root, 'support/state/launch-url.json')) throw refuse('example-launch-path-invalid')
  const url = new URL(ready.origin)
  if (url.protocol !== 'http:' || url.hostname !== '127.0.0.1' || url.origin !== ready.origin)
    throw refuse('example-origin-not-loopback')
  return ready
}

async function modules(checkout) {
  const load = relative => import(pathToFileURL(path.join(checkout, relative)).href)
  const [server, targets, receipts, ledger] = await Promise.all([
    load('packages/boundary-gate/src/server.mjs'), load('packages/boundary-gate/src/targets.mjs'),
    load('packages/boundary-gate/src/receipts.mjs'), load('packages/boundary-gate/src/ledger.mjs'),
  ])
  return { server, targets, receipts, ledger }
}

export function assertApplied(applied, entry, content) {
  if (applied?.applied !== true || entry?.event !== 'apply' || entry.proposal !== applied.receipt?.proposal
    || entry.detail?.receipt_sig !== applied.receipt_sig || JSON.stringify(entry.detail?.receipt) !== JSON.stringify(applied.receipt)
    || content !== themeContent) throw refuse('example-approved-bytes-mismatch')
}

export function assertRefusalEntry(entry, previousSequence) {
  if (!entry || entry.sequence <= previousSequence || entry.op !== 'tool.decision' || entry.tool !== 'fresh_clone_unapproved_action'
    || entry.callId !== 'fresh-clone-denial' || entry.decision !== 'deny' || entry.rule !== 'authority:tool-not-approved')
    throw refuse('example-refusal-entry-missing')
}

function actionEntries(root) {
  const file = path.join(root, 'support/state/home/aura-actions/aura.jsonl')
  if (!fs.existsSync(file)) return []
  examplePath(root, file, { privateRoot: true })
  const text = fs.readFileSync(file, 'utf8')
  if (!text.endsWith('\n')) throw refuse('example-action-ledger-torn')
  return text.trimEnd().split('\n').filter(Boolean).map(line => JSON.parse(line))
}

async function approve(ready, api) {
  const { root, checkout } = ready, socket = path.join(root, 'gate-run/gate.sock'), ownerSocket = path.join(root, 'gate-run/owner.sock')
  const target = api.targets.THEME_TARGET, content = themeContent
  const current = await api.server.call(socket, 'read', { target })
  if (current.content === content) throw refuse('example-theme-already-approved')
  const proposal = await api.server.call(socket, 'propose', { target, content, claimed_base: current.sha256,
    why: 'Example: change the app theme accent to gold.', session: 'prime-example' })
  const pending = await api.server.call(ownerSocket, 'pending')
  const card = pending.pending.find(row => row.id === proposal.id)
  if (!card || card.new_sha !== proposal.new_sha) throw refuse('example-pending-card-mismatch')
  console.log('PENDING CARD | ' + JSON.stringify(card))
  const result = spawnSync(process.execPath, [path.join(checkout, 'packages/boundary-gate/bin/owner-cli.mjs'),
    '--socket', ownerSocket, 'approve', card.id, card.new_sha], { env: { PATH: process.env.PATH }, encoding: 'utf8', timeout: 15000 })
  if (result.status !== 0) throw refuse('example-owner-command-refused')
  const summary = JSON.parse(result.stdout.trim()), log = await api.server.call(ownerSocket, 'log', { target, limit: 200 })
  const entry = log.entries.find(row => row.event === 'apply' && row.proposal === proposal.id)
  const applied = { applied: summary.applied, receipt: entry?.detail?.receipt, receipt_sig: entry?.detail?.receipt_sig }
  const observed = await api.server.call(socket, 'read', { target })
  assertApplied(applied, entry, observed.content)
  passed('example owner command and exact theme bytes', log.verify?.ok === true)
  writePrivate(root, path.join(root, 'example-approval.json'), { proposal: card.id, target: card.target,
    base_sha: card.base_sha, new_sha: card.new_sha }, examplePath)
  writePrivate(root, path.join(root, 'example-receipt.json'), { receipt: applied.receipt, receipt_sig: applied.receipt_sig }, examplePath)
  console.log('SIGNED RECEIPT | ' + JSON.stringify({ receipt: applied.receipt, receipt_sig: applied.receipt_sig }))
  passed('example approve', true)
}

async function refuseAction(ready) {
  const previousSequence = actionEntries(ready.root).at(-1)?.sequence ?? 0
  const { url, headers } = await authenticateLaunch({ ...ready, stayUp: true })
  const response = await fetch(url.origin + '/api/fresh-clone-probe', { headers, signal: AbortSignal.timeout(10000) })
  if (response.status !== 200) throw refuse('example-refusal-route-unavailable')
  const result = await response.json()
  assertActionRefusal(result)
  const entry = actionEntries(ready.root).at(-1)
  assertRefusalEntry(entry, previousSequence)
  console.log('REFUSAL | ' + JSON.stringify(result.result))
  console.log('REFUSAL ENTRY | ' + JSON.stringify(entry))
  writePrivate(ready.root, path.join(ready.root, 'example-refusal.json'), { sequence: entry.sequence, hash: entry.hash }, examplePath)
  passed('example refuse', true)
}

export function verifySignedEvidence(db, evidence, publicKey, api, expected) {
  passed('example receipt names exact theme change', evidence.receipt?.target === api.targets.THEME_TARGET
    && evidence.receipt.new_sha === createHash('sha256').update(themeContent).digest('hex')
    && evidence.receipt.proposal === expected?.proposal && evidence.receipt.base_sha === expected.base_sha
    && evidence.receipt.new_sha === expected.new_sha && evidence.receipt.target === expected.target)
  passed('example receipt signature', api.receipts.verifyReceiptSignature(evidence.receipt, evidence.receipt_sig, publicKey).ok)
  passed('example signed ledger', api.ledger.verifyLedger(db, publicKey).ok)
  passed('example receipt in signed ledger', api.receipts.verifyReceipt(db, evidence.receipt, evidence.receipt_sig, publicKey).ok)
}

async function verify(ready, api) {
  const { root, checkout } = ready, file = path.join(root, 'example-receipt.json')
  examplePath(root, file, { privateRoot: true })
  const expectedFile = path.join(root, 'example-approval.json')
  examplePath(root, expectedFile, { privateRoot: true })
  const expected = readJson(expectedFile), evidence = readJson(file), keyFile = path.join(root, 'gate-run/receipt-ed25519.pub'), dbFile = path.join(root, 'gate-home/gate.db')
  examplePath(root, keyFile); examplePath(root, dbFile, { privateRoot: true })
  const publicKey = fs.readFileSync(keyFile, 'utf8'), db = new DatabaseSync(dbFile, { readOnly: true })
  try {
    verifySignedEvidence(db, evidence, publicKey, api, expected)
  } finally { db.close() }
  try { await checkAdmission({ ...ready, stayUp: true }); passed('example release floor', true) }
  catch { passed('example release floor', false) }
  const logFile = path.join(root, 'support/state/home/aura-actions/aura.jsonl')
  const proofFile = path.join(root, 'example-refusal.json')
  examplePath(root, proofFile, { privateRoot: true })
  const proof = readJson(proofFile), entry = actionEntries(root).find(row => row.sequence === proof.sequence && row.hash === proof.hash)
  assertRefusalEntry(entry, 0)
  const result = spawnSync(process.execPath, [path.join(checkout, 'scripts/aura/verify-append-only.mjs'), 'retain', logFile],
    { env: { PATH: process.env.PATH }, encoding: 'utf8', timeout: 10000 })
  passed('example action ledger chain', result.status === 0)
  console.log('LIMIT | local keys and heads do not prove owner custody containment or an external ledger anchor')
  passed('example verify', true)
}

export async function runExample({ command, root }) {
  const ready = readExample(root), api = await modules(ready.checkout)
  if (command === 'approve') await approve(ready, api)
  else if (command === 'refuse') await refuseAction(ready)
  else if (command === 'verify') await verify(ready, api)
  else throw refuse('example-command-invalid')
}

if (import.meta.url.startsWith('file:') && process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1])) {
  try { await runExample(parseExampleArgs(process.argv.slice(2))) }
  catch (error) {
    const unavailable = ['EPERM', 'EACCES'].includes(error.code)
    console.error((unavailable ? 'UNPERFORMED: ' : 'FAIL | ') + (error.code ?? 'example-command-failed'))
    process.exitCode = unavailable ? 2 : 1
  }
}
