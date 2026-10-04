// TRUSTED PLUGIN-SET VERIFIER FOR THE ROOT OPERATOR TOOLS (Kimi/GPT review of 524b8f5, Peter 2026-10-04 14:52 WITA).
//
// bin/plugin-set-approval.mjs and bin/release-floor.mjs run as root. They used to dynamic-import the CANDIDATE release's
// plugins/aukora-composition-gate/src/plugin-set.mjs, so code the owner had not yet approved ran as root before approval.
// This module is the canonical verifier inside the root-owned gate install (/opt/aukora-boundary-gate, root:root,
// go-w, checked by the gate self-check). A candidate release is read strictly as DATA: its .dsh-build JSON records.
// Nothing under a release directory is ever imported or executed by root.
//
// Parity: these functions must agree byte-for-byte with the composition gate's own (plugins/aukora-composition-gate/src/
// plugin-set.mjs, which the runtime runs at import). tests/aukora-plugin-set-trusted-verifier.test.mjs pins that, and
// vendor/plugin-set-content.mjs is pinned byte-identical to plugins/aukora-aumlok/lib/plugin-set-content.mjs.
import { createHash, createPublicKey, verify as cryptoVerify } from 'node:crypto'
import { setOperationContent as renderSetOperationContent } from './vendor/plugin-set-content.mjs'

const OPERATION_CONTENT_DOMAIN = 'aukora:operation-content:v1'
export const PLUGIN_SET_KIND = 'aukora-plugin-set/v1'
export const GATE_PIN_KIND = 'aukora-boundary-gate-owner/v1'
export const GATE_APPROVAL_KIND = 'aukora-plugin-set-gate-approval/v1'
export const GATE_PLUGIN_SET_TARGET = 'plugins/aukora-plugin-set/approval.json'
const GATE_CONTENT = /^\{"v":1,"kind":"aukora-plugin-set-approval\/v1","release":"([0-9a-f]{40})","release_dir":"(release-[0-9a-f]{7})","plugin_set":"([0-9a-f]{64})","operation":"([0-9a-f]{64})","record":"([0-9a-f]{64})"\}$/u
const GATE_RECEIPT_KEYS = ['v', 'kind', 'proposal', 'target', 'base_sha', 'new_sha', 'applied_at', 'approver', 'approval_evidence_hmac', 'pubkey_fp']

const refuse = (code, detail) => Object.assign(new Error(`${code}: ${detail}`), { code, reason: detail })
export const digestOf = (bytes) => createHash('sha256').update(bytes).digest('hex')

/** `sha256(domain ‖ 0x00 ‖ content)`, the operation digest the owner approves. */
export function operationDigestOf(content) {
  return createHash('sha256').update(OPERATION_CONTENT_DOMAIN, 'utf8').update('\0', 'utf8').update(Buffer.from(content, 'utf8')).digest('hex')
}
export function artifactDigest(files) {
  return digestOf(Buffer.from(Object.keys(files).sort().map(key => `${key}\n${files[key]}\n`).join(''), 'utf8'))
}
export function pluginSetDigest(artifacts) {
  const digests = Object.values(artifacts).map(artifact => artifact.digest)
  return digestOf(Buffer.from([...digests].sort().map(digest => `${digest}\n`).join(''), 'utf8'))
}

/** Every artifact digest and the set digest RECOMPUTED from the per-file digests; a disagreeing record is refused. */
export function checkPluginSetRecord(record) {
  if (record === null || typeof record !== 'object' || record.kind !== PLUGIN_SET_KIND || record.artifacts === null || typeof record.artifacts !== 'object') {
    throw refuse('plugin-set-record-malformed', `the plugin set record is not a ${PLUGIN_SET_KIND} record`)
  }
  const artifacts = {}
  for (const [id, artifact] of Object.entries(record.artifacts)) {
    const files = artifact?.files
    if (artifact?.id !== id || typeof artifact.entry !== 'string' || files === null || typeof files !== 'object'
      || Object.keys(files).length === 0 || !Object.values(files).every((d) => /^[0-9a-f]{64}$/u.test(d)) || !Object.hasOwn(files, artifact.entry)) {
      throw refuse('plugin-set-record-malformed', `the record for ${id} does not carry its entry and per-file digests`)
    }
    const digest = artifactDigest(files)
    if (digest !== artifact.digest) throw refuse('plugin-set-record-malformed', `${id}: the stored digest is not the digest of its own files`)
    artifacts[id] = { id, entry: artifact.entry, files, digest }
  }
  const setDigest = pluginSetDigest(artifacts)
  if (setDigest !== record.setDigest || Object.keys(artifacts).length !== record.count) {
    throw refuse('plugin-set-record-malformed', 'the stored set digest or count is not the one its artifacts derive')
  }
  return { artifacts, setDigest, count: Object.keys(artifacts).length }
}

/** The exact operation text the owner approves, rendered from the (data) record. */
export function setOperationContent(record) {
  checkPluginSetRecord(record)
  return renderSetOperationContent(record)
}

export function parseGateApprovalContent(content) {
  const m = GATE_CONTENT.exec(typeof content === 'string' ? content : '')
  return m ? { release: m[1], release_dir: m[2], plugin_set: m[3], operation: m[4], record: m[5] } : null
}

/** The gate-signed approval checked against the root pin and the (data) record: the same verdict the composition gate reaches. */
export function verifyGateSetApproval({ record, approval, pin }) {
  const content = setOperationContent(record)
  const operationDigest = operationDigestOf(content)
  const { setDigest, count } = checkPluginSetRecord(record)
  if (pin === null || typeof pin !== 'object' || pin.kind !== GATE_PIN_KIND || typeof pin.gatePubkeyPem !== 'string' || !/^[0-9a-f]{16}$/u.test(String(pin.gatePubkeyFp))
    || pin.target !== GATE_PLUGIN_SET_TARGET || typeof pin.approver !== 'string' || !pin.approver.startsWith('owner via owner.sock')) {
    throw refuse('plugin-set-approver-not-pinned', 'the gate pin does not name a gate key, the plugin-set target and the owner-channel approver')
  }
  const receipt = approval?.receipt
  if (approval === null || typeof approval !== 'object' || approval.kind !== GATE_APPROVAL_KIND || typeof approval.content !== 'string'
    || typeof approval.receipt_sig !== 'string' || receipt === null || typeof receipt !== 'object'
    || Object.keys(receipt).join(',') !== GATE_RECEIPT_KEYS.join(',') || receipt.v !== 2 || receipt.kind !== 'change') {
    throw refuse('plugin-set-approval-malformed', `the approval is not a complete ${GATE_APPROVAL_KIND} record with a v2 gate receipt`)
  }
  let key
  try { key = createPublicKey(pin.gatePubkeyPem) } catch { throw refuse('plugin-set-approver-not-pinned', 'the pinned gate key is not a public key') }
  const fp = digestOf(key.export({ type: 'spki', format: 'der' })).slice(0, 16)
  if (key.asymmetricKeyType !== 'ed25519' || fp !== pin.gatePubkeyFp) throw refuse('plugin-set-approver-not-pinned', 'the pinned gate key is not the pinned Ed25519 key')
  if (receipt.pubkey_fp !== fp) throw refuse('plugin-set-approval-by-unpinned-key', `the receipt names gate key ${String(receipt.pubkey_fp)}, the pin ${fp}`)
  if (receipt.target !== pin.target || receipt.approver !== pin.approver) throw refuse('plugin-set-approval-for-other-identity', 'another target or approver than the pinned owner channel')
  let ok = false
  try { ok = cryptoVerify(null, Buffer.from(JSON.stringify(receipt), 'utf8'), key, Buffer.from(approval.receipt_sig, 'base64')) } catch { ok = false }
  if (!ok) throw refuse('plugin-set-approval-signature-invalid', `the gate receipt's signature does not verify under gate key ${fp}`)
  if (digestOf(Buffer.from(approval.content, 'utf8')) !== receipt.new_sha) throw refuse('plugin-set-approval-malformed', 'the approval content is not the bytes the receipt signed')
  const named = parseGateApprovalContent(approval.content)
  if (named === null) throw refuse('plugin-set-approval-malformed', 'the approved content is not the canonical plugin-set approval')
  if (named.plugin_set !== setDigest || named.operation !== operationDigest) throw refuse('plugin-set-approval-for-other-set', 'the approval names another set or operation than this record derives')
  return { setDigest, operationDigest, approverDid: `gate:${fp}`, approvalClass: 'gate-owner-review', keyClass: 'gate-ed25519',
    issuedAt: Date.parse(receipt.applied_at), appliedAt: receipt.applied_at, count, release: named.release, release_dir: named.release_dir, record: named.record }
}
