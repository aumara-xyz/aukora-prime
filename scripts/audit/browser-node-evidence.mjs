#!/usr/bin/env node
// SPDX-License-Identifier: AGPL-3.0-or-later
// Verify public receipt, signed apply-row and floor bindings without contacting a node.
import fs from 'node:fs'
import { createHash, createPublicKey, verify } from 'node:crypto'
import { resolve } from 'node:path'
import { pathToFileURL } from 'node:url'

export const LEGACY_CHECK_NAMES = Object.freeze(['host_transport', 'root_platform', 'installation_record', 'browser_profile', 'users_modes',
  'package_custody', 'node_version', 'package_pins', 'gate_sockets', 'signer_pin', 'loopback_listeners',
  'approved_floor', 'harness_service', 'signed_in_ui', 'plugin_load', 'claim_service', 'public_origins',
  'anonymous_session', 'claim_exchange', 'claim_cookie', 'public_session', 'claim_replay'])
const LEGACY_AFTER_REVISIONS = new Set([
  '38004c5159500b23ffaefb5df8c98e3ee4150e9f',
  'c18a7e4bfe2fa3ee2afdd2b91f7b9d82ffa1279a',
])
export const CHECK_NAMES = Object.freeze(['host_transport', 'root_platform', 'installation_record', 'browser_profile', 'users_modes',
  'aura_collector_custody', 'package_custody', 'node_version', 'package_pins', 'gate_sockets', 'signer_pin', 'loopback_listeners',
  'approved_floor', 'aura_collector', 'harness_service', 'signed_in_ui', 'browser_binding_guard', 'plugin_load', 'claim_service',
  'public_origins', 'anonymous_session', 'claim_exchange', 'claim_cookie', 'public_session', 'claim_replay', 'aura_sources'])
export const BOUND_CHECK_NAMES = Object.freeze([...CHECK_NAMES, 'binding_custody', 'binding_overlay', 'kira_active',
  'bound_rpc', 'bound_app', 'repeat_prepare', 'aura_gate_code', 'aura_kira_note', 'composition_active', 'bound_current_invocation'])
export const LIMITATIONS = Object.freeze([
  'CANNOT VERIFY public key belongs to a real node, owner identity or attendance, approval-channel custody, or retained owner-proof history.',
  'CANNOT VERIFY checks really ran, their results, observation time, installer bytes or process-loaded release; record is unsigned.',
  'CANNOT VERIFY floor history, signer epoch, protected custody, monotonic enforcement, complete ledger chain or latest ledger head; floor has no standalone signature.',
  'CANNOT VERIFY release or plugin bytes, operation digest derivation, HTTPS/browser rendering, enrollment, containment or a model reply.',
])
const MAX_BYTES = 128 * 1024
const LEGACY_RECEIPT_FIELDS = ['v', 'kind', 'proposal', 'target', 'base_sha', 'new_sha', 'applied_at', 'approver', 'approval_evidence_hmac', 'pubkey_fp']
const OWNER_RECEIPT_FIELDS = ['v', 'kind', 'proposal', 'target', 'base_sha', 'new_sha', 'applied_at', 'approver', 'pubkey_fp',
  'gate_pubkey_sha256', 'owner_authorization', 'owner_accepted_at_ms', 'owner_consumption']
const ROW_FIELDS = ['seq', 'at', 'event', 'proposal', 'target', 'base_sha', 'new_sha', 'detail', 'prev', 'hash', 'sig']
const TARGET = 'plugins/aukora-plugin-set/approval.json'
const APPROVERS = new Set(['owner via owner.sock (local; 0600 gate user/root only)',
  'owner via gate approval page (bearer token, typed 2-step confirm)'])
const SHA64 = /^[0-9a-f]{64}$/u, SHA40 = /^[0-9a-f]{40}$/u
const UUID = /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/u
const refuse = name => { throw Object.assign(new Error(`browser-node-evidence:${name}`), { code: `browser-node-evidence:${name}` }) }
const require = (condition, name) => { if (!condition) refuse(name) }
const hex = (value, pattern = SHA64) => typeof value === 'string' && pattern.test(value)
const positive = value => Number.isSafeInteger(value) && value > 0
const sha = bytes => createHash('sha256').update(bytes).digest('hex')
const closed = (value, fields, ordered = false) => value !== null && typeof value === 'object' && !Array.isArray(value)
  && [Object.prototype, null].includes(Object.getPrototypeOf(value))
  && Reflect.ownKeys(value).length === fields.length && fields.every((field, index) => {
    const descriptor = Object.getOwnPropertyDescriptor(value, field)
    return descriptor?.enumerable === true && Object.hasOwn(descriptor, 'value')
      && (!ordered || Object.keys(value)[index] === field)
  })
const utc = value => typeof value === 'string' && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u.test(value)
  && Number.isFinite(Date.parse(value)) && new Date(value).toISOString() === value
const base64 = (value, length) => typeof value === 'string' && Buffer.from(value, 'base64').length === length
  && Buffer.from(value, 'base64').toString('base64') === value
function retainedProof(receipt, keyHash) {
  const reference = receipt.owner_authorization, consumption = receipt.owner_consumption, issue = consumption?.review_issue
  return /^aukora:1:[0-9a-f]{64}$/u.test(receipt.approver) && receipt.gate_pubkey_sha256 === keyHash
    && closed(reference, ['version', 'kind', 'authorization_id', 'proof_sha256'], true)
    && reference.version === 1 && reference.kind === 'aukora-owner-authorization-ref/v1'
    && hex(reference.authorization_id) && hex(reference.proof_sha256)
    && Number.isSafeInteger(receipt.owner_accepted_at_ms) && receipt.owner_accepted_at_ms >= 0
    && closed(consumption, ['ledger_seq', 'ledger_hash', 'review_issue'], true)
    && positive(consumption.ledger_seq) && hex(consumption.ledger_hash)
    && closed(issue, ['ledger_seq', 'ledger_hash'], true) && positive(issue.ledger_seq)
    && issue.ledger_seq < consumption.ledger_seq && hex(issue.ledger_hash)
}
function signed(bytes, key, signature) {
  try { return verify(null, bytes, key, Buffer.from(signature, 'base64')) } catch { return false }
}

// The gate accepts exactly these approval bytes; the record contains no plugin manifest to derive operation.
const GATE_CONTENT = /^\{"v":1,"kind":"aukora-plugin-set-approval\/v1","release":"([0-9a-f]{40})","release_dir":"(release-[0-9a-f]{7})","plugin_set":"([0-9a-f]{64})","operation":"([0-9a-f]{64})","record":"([0-9a-f]{64})"\}$/u
function parseGateApprovalContent(content) {
  const match = GATE_CONTENT.exec(content)
  return match ? { release: match[1], release_dir: match[2], plugin_set: match[3], operation: match[4], record: match[5] } : null
}

// Refuse duplicate decoded keys, unsafe numbers, excess nesting and nonpublic JSON encodings.
function strictJson(text, maxBytes, maxDepth) {
  if (typeof text !== 'string' || Buffer.byteLength(text) > maxBytes) refuse('json')
  let at = 0
  const space = () => { while (/[\t\n\r ]/u.test(text[at] ?? '') && at < text.length) at++ }
  function string() {
    const begin = at++
    while (at < text.length && text[at] !== '"') { if (text[at] === '\\') at++; at++ }
    if (at >= text.length) refuse('json')
    const value = JSON.parse(text.slice(begin, ++at))
    if (/[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/u.test(value)) refuse('json')
    return value
  }
  function value(depth) {
    space(); if (depth > maxDepth) refuse('json')
    if (text[at] === '"') { string(); return }
    const open = text[at], object = open === '{'
    if (object || open === '[') {
      at++; space(); const close = object ? '}' : ']', keys = new Set()
      if (text[at] !== close) for (;;) {
        if (object) {
          if (text[at] !== '"') refuse('json')
          const key = string(); if (keys.has(key)) refuse('json'); keys.add(key)
          space(); if (text[at++] !== ':') refuse('json')
        }
        value(depth + 1); space()
        if (text[at] !== ',') break
        at++; space()
      }
      if (text[at++] !== close) refuse('json')
      return
    }
    const token = /^(?:true|false|null|-?(?:0|[1-9][0-9]*))/u.exec(text.slice(at))?.[0]
    if (!token || (/-?[0-9]/u.test(token) && (!Number.isSafeInteger(Number(token)) || token === '-0'))) refuse('json')
    at += token.length
  }
  value(0); space(); if (at !== text.length) refuse('json')
  return JSON.parse(text)
}

export function parseBrowserNodeEvidence(text) {
  try { return strictJson(text, MAX_BYTES, 12) }
  catch { refuse('json') }
}

export function verifyBrowserNodeEvidence(record, { containerOnly = false } = {}) {
  const phaseNames = record?.phase === 'bound' ? BOUND_CHECK_NAMES
    : LEGACY_AFTER_REVISIONS.has(record?.release?.revision) ? LEGACY_CHECK_NAMES : CHECK_NAMES
  const checkNames = containerOnly ? phaseNames.slice(1) : phaseNames
  require(closed(record, ['kind', 'phase', 'observed_at', 'release', 'signer', 'approval', 'floor', 'installer_inputs', 'checks', 'record_signature']), 'record-schema')
  require(record.kind === 'aukora-browser-node-evidence/v1' && ['after', 'bound'].includes(record.phase), 'record-kind')
  require(utc(record.observed_at), 'observation-time')
  const release = record.release, signer = record.signer, approval = record.approval, floor = record.floor
  require(closed(release, ['revision', 'record_sha256', 'plugin_set_sha256']) && hex(release.revision, SHA40)
    && hex(release.record_sha256) && hex(release.plugin_set_sha256), 'release-schema')
  require(closed(signer, ['public_key_pem', 'sha256']) && typeof signer.public_key_pem === 'string'
    && signer.public_key_pem.length <= 4096 && hex(signer.sha256), 'signer-schema')
  let key
  try { key = createPublicKey(signer.public_key_pem) } catch { refuse('signer-key') }
  require(key.asymmetricKeyType === 'ed25519' && key.export({ type: 'spki', format: 'pem' }).toString() === signer.public_key_pem, 'signer-key-canonical')
  const keyHash = sha(key.export({ type: 'spki', format: 'der' }))
  require(signer.sha256 === keyHash, 'signer-fingerprint')
  require(closed(approval, ['kind', 'content', 'receipt', 'receipt_sig', 'ledger_entry'])
    && approval.kind === 'aukora-plugin-set-gate-approval/v1' && typeof approval.content === 'string'
    && approval.content.length <= 1024, 'approval-schema')
  const receipt = approval.receipt, legacy = closed(receipt, LEGACY_RECEIPT_FIELDS, true) && receipt.v === 2
  const retained = closed(receipt, OWNER_RECEIPT_FIELDS, true) && receipt.v === 3
  require((legacy || retained) && receipt.kind === 'change', 'receipt-schema')
  require(typeof receipt.proposal === 'string' && UUID.test(receipt.proposal) && receipt.target === TARGET
    && (receipt.base_sha === 'absent' || hex(receipt.base_sha)) && hex(receipt.new_sha)
    && receipt.base_sha !== receipt.new_sha && utc(receipt.applied_at) && hex(receipt.pubkey_fp, /^[0-9a-f]{16}$/u)
    && (legacy ? APPROVERS.has(receipt.approver) && base64(receipt.approval_evidence_hmac, 32)
      : retainedProof(receipt, keyHash)), 'receipt-public-schema')
  require(receipt.pubkey_fp === keyHash.slice(0, 16), 'receipt-fingerprint')
  require(base64(approval.receipt_sig, 64), 'receipt-signature-schema')
  require(signed(Buffer.from(JSON.stringify(receipt)), key, approval.receipt_sig), 'receipt-signature')
  const named = parseGateApprovalContent(approval.content)
  require(named !== null, 'approval-content-schema')
  require(sha(Buffer.from(approval.content)) === receipt.new_sha, 'approval-content-digest')
  require(named.release === release.revision && named.release_dir === 'release-' + release.revision.slice(0, 7)
    && named.record === release.record_sha256 && named.plugin_set === release.plugin_set_sha256, 'approval-release-binding')
  const row = approval.ledger_entry
  require(closed(row, ROW_FIELDS) && positive(row.seq) && utc(row.at) && row.event === 'apply'
    && typeof row.detail === 'string' && row.detail.length <= 4096 && hex(row.hash) && base64(row.sig, 64)
    && (row.seq === 1 ? row.prev === 'GENESIS' : hex(row.prev)), 'ledger-schema')
  require(row.proposal === receipt.proposal && row.target === receipt.target && row.base_sha === receipt.base_sha
    && row.new_sha === receipt.new_sha, 'ledger-receipt-binding')
  let detail
  try { detail = strictJson(row.detail, 4096, 4) } catch { refuse('ledger-detail-json') }
  require(closed(detail, ['receipt', 'receipt_sig']) && JSON.stringify(detail.receipt) === JSON.stringify(receipt)
    && detail.receipt_sig === approval.receipt_sig, 'ledger-detail-binding')
  const body = JSON.stringify([row.seq, row.at, row.event, row.proposal, row.target, row.base_sha, row.new_sha, row.detail, row.prev])
  require(sha(Buffer.from(body)) === row.hash, 'ledger-hash')
  require(signed(Buffer.from(row.hash, 'hex'), key, row.sig), 'ledger-signature')
  require(Date.parse(receipt.applied_at) <= Date.parse(row.at) && Date.parse(row.at) <= Date.parse(record.observed_at), 'time-order')
  require(closed(floor, ['kind', 'release', 'release_dir', 'record', 'signer_epoch', 'ledger_seq', 'signer_key_sha256', 'ledger_hash', 'history'])
    && floor.kind === 'aukora-release-floor/v2' && positive(floor.signer_epoch) && positive(floor.ledger_seq)
    && hex(floor.release, SHA40) && typeof floor.release_dir === 'string' && /^release-[0-9a-f]{7}$/u.test(floor.release_dir)
    && hex(floor.record) && hex(floor.signer_key_sha256) && hex(floor.ledger_hash)
    && Array.isArray(floor.history) && floor.history.length <= 64
    && floor.history.every(previous => hex(previous, SHA40) && previous !== floor.release)
    && new Set(floor.history).size === floor.history.length, 'floor-schema')
  require(floor.release === named.release && floor.release_dir === named.release_dir && floor.record === named.record
    && floor.signer_key_sha256 === signer.sha256 && floor.ledger_seq === row.seq && floor.ledger_hash === row.hash, 'floor-signed-row-binding')
  require(closed(record.installer_inputs, ['checkout', 'node', 'dependencies', 'harness'])
    && Object.values(record.installer_inputs).every(value => hex(value)), 'installer-schema')
  require(Array.isArray(record.checks) && record.checks.length >= 1 && record.checks.length <= checkNames.length
    && record.checks.every((check, index) => closed(check, ['name', 'status']) && check.name === checkNames[index]
      && ['PASS', 'FAIL'].includes(check.status)), 'checks-schema')
  require(record.checks.slice(0, -1).every(check => check.status === 'PASS')
    && (record.checks.at(-1).status === 'FAIL' || record.checks.length === checkNames.length), 'checks-completion')
  require(record.record_signature === null, 'unsupported-record-signature')
  return { ok: true, passed: record.checks.every(check => check.status === 'PASS'), checks: record.checks.length,
    ledgerSeq: row.seq, limitations: [...LIMITATIONS] }
}

export function main(argv = process.argv.slice(2)) {
  try {
    require(argv.length === 1 && argv[0].length > 0, 'usage')
    const fd = ['--stdin', '--stdin-container'].includes(argv[0]) ? 0 : fs.openSync(argv[0], 'r')
    let text
    try {
      const bytes = Buffer.alloc(MAX_BYTES + 1)
      let count = 0, received
      do {
        received = fs.readSync(fd, bytes, count, bytes.length - count, null)
        count += received
      } while (received > 0 && count < bytes.length)
      require(count <= MAX_BYTES, 'input-size')
      text = new TextDecoder('utf-8', { fatal: true }).decode(bytes.subarray(0, count))
    } finally { if (fd !== 0) fs.closeSync(fd) }
    const result = verifyBrowserNodeEvidence(parseBrowserNodeEvidence(text), { containerOnly: argv[0] === '--stdin-container' })
    console.log('VERIFIED browser-node-evidence:receipt-signature,approval-bindings,signed-apply-row,floor-core-binding')
    console.log(`OBSERVATIONS ${result.passed ? 'PASS' : 'FAIL'} checks=${result.checks}`)
    for (const line of result.limitations) console.log(line)
    return result.passed ? 0 : 2
  } catch (error) {
    const code = /^browser-node-evidence:[a-z-]+$/u.test(error?.code) ? error.code : 'browser-node-evidence:input-unavailable-or-invalid'
    console.log(`NOT VERIFIED ${code}`)
    return 1
  }
}
if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) process.exitCode = main()
