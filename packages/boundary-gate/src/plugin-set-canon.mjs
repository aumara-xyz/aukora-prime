// TRUSTED PLUGIN-SET VERIFIER FOR THE ROOT OPERATOR TOOLS (Kimi/GPT review of 524b8f5, Peter 2026-10-04 14:52 WITA).
//
// bin/plugin-set-approval.mjs and bin/release-floor.mjs run as root. They used to dynamic-import the CANDIDATE release's
// plugins/aukora-composition-gate/src/plugin-set.mjs, so code the owner had not yet approved ran as root before approval.
// This module is the canonical verifier inside the root-owned gate install (/opt/aukora-boundary-gate, root:root,
// go-w; verifier bytes checked before execution by the operator bootstrap). A candidate release is read strictly as DATA: its .dsh-build JSON records.
// Nothing under a release directory is ever imported or executed by root.
//
// Parity: these functions must agree byte-for-byte with the composition gate's own (plugins/aukora-composition-gate/src/
// plugin-set.mjs, which the runtime runs at import). tests/aukora-plugin-set-trusted-verifier.test.mjs pins that, and
// vendor/plugin-set-content.mjs is pinned byte-identical to plugins/aukora-aumlok/lib/plugin-set-content.mjs.
import { createHash, createPublicKey, verify as cryptoVerify } from 'node:crypto'
// Exact renderer retained inline to make the verified buffer builtin-only.
// Source: src/vendor/plugin-set-content.mjs SHA256 65b83b44366700a63f97d63fc0e9369bdfc918f7c51fdaad52ccdf84ef56d485
// Only its export/function name changes here; rendered bytes and refusal behavior remain pinned.
// Shared approval text for the gate, become and packaged desktop resolver.
// The gate additionally recomputes artifact/set digests and verifies the approval signature.
const malformed = detail => Object.assign(new Error(`plugin-set-record-malformed: ${detail}`),
  { code: 'plugin-set-record-malformed', reason: detail })

function renderSetOperationContent(record) {
  const { artifacts, setDigest, count } = record ?? {}
  const hex = value => typeof value === 'string' && /^[0-9a-f]{64}$/u.test(value)
  if (record?.kind !== 'aukora-plugin-set/v1' || !hex(setDigest)
    || !artifacts || typeof artifacts !== 'object' || Array.isArray(artifacts)
    || count !== Object.keys(artifacts).length || Object.entries(artifacts).some(([id, artifact]) =>
      artifact?.id !== id || !hex(artifact.digest) || !artifact.files || typeof artifact.files !== 'object'
      || Array.isArray(artifact.files) || !Object.hasOwn(artifact.files, artifact.entry)
      || !Object.values(artifact.files).every(hex))) throw malformed('malformed plugin set')
  const files = new Set(Object.values(artifacts).flatMap((artifact) => Object.keys(artifact.files)))
  const ids = Object.keys(artifacts).sort()
  // Keep existing plugin-only receipts valid during the release-binding migration.
  if (record.release === undefined) {
    const width = Math.max(...ids.map(id => id.length))
    return [
      'AUKORA: ADMIT THESE PLUGINS',
      'Approve lets exactly these plugin bytes load. A changed, added or',
      'unrecorded file in them is refused when Node loads it.',
      `set ${setDigest}`,
      `${String(count)} plugins, ${String(files.size)} files, sha256 each:`,
      ...ids.map(id => `${id.padEnd(width)} ${String(Object.keys(artifacts[id].files).length).padStart(4)} ${artifacts[id].digest.slice(0, 16)}`),
      'Not covered: node_modules, the gate bootstrap, workers.',
      '',
    ].join('\n')
  }
  // Release binding (scripts/aukora/release-digest.mjs): cutover coverage, with the exclusions stated below.
  const release = record.release
  if (release !== undefined && (release === null || typeof release !== 'object' || !/^[0-9a-f]{40}$/u.test(release.commit)
    || !/^[0-9a-f]{64}$/u.test(release.tree) || !/^[0-9a-f]{64}$/u.test(release.shell) || !Number.isSafeInteger(release.files) || release.files < 0)) {
    throw malformed('the plugin set record carries a malformed release binding')
  }
  return [
    release ? 'AUKORA: LOAD THIS RELEASE' : 'AUKORA: ADMIT THESE PLUGINS',
    ...(release ? [
      `commit ${release.commit}`,
      `release ${release.tree} (${String(release.files)} files)`,
      `shell ${release.shell}`,
      'Release and shell covered at cutover; not rechecked each boot or later read.',
      'Excluded: .dsh-build/plugin-set.json (self-reference), non-executable Finder .DS_Store files; external state/tools; external symlink targets.',
    ] : []),
    'Plugin bytes checked at gate install and imports through its hook.',
    'Gate bootstrap/workers recorded; not import-gated in their own loaders.',
    `set ${setDigest}`,
    `${String(count)} plugins, ${String(files.size)} files, sha256 each:`,
    ...ids.map((id) => `${id} ${String(Object.keys(artifacts[id].files).length)} ${artifacts[id].digest.slice(0, 16)}`),
    ...(release ? [] : ['Outside plugin set: bare dependencies, apps/cli, shell (unless release-bound).']),
    '',
  ].join('\n')
}


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

// Ordered admission preserves the original receipt grammar. Its sequence is independently signed by the ledger,
// and the root-protected public map binds the actual Ed25519 SPKI to a non-reusable signer epoch.
export function verifyOrderedGateApproval({ record, approval, pin, epochs }) {
  const verified = verifyGateSetApproval({ record, approval, pin })
  if (epochs?.version !== 1 || epochs.kind !== 'aukora-signer-epochs/v1'
    || Object.keys(epochs).sort().join(',') !== 'epochs,kind,version'
    || !Array.isArray(epochs.epochs) || epochs.epochs.length < 1 || epochs.epochs.length > 64) throw refuse('signer-epochs-malformed', 'no protected signer registry')
  const keys = new Set(); let previous = 0
  for (const row of epochs.epochs) {
    if (row === null || typeof row !== 'object' || Object.keys(row).sort().join(',') !== 'epoch,gate_pubkey_sha256'
      || !Number.isSafeInteger(row.epoch) || row.epoch !== previous + 1 || !/^[0-9a-f]{64}$/u.test(row.gate_pubkey_sha256)
      || keys.has(row.gate_pubkey_sha256)) throw refuse('signer-epochs-malformed', 'epochs and keys must each be unique')
    previous = row.epoch; keys.add(row.gate_pubkey_sha256)
  }
  const key = createPublicKey(pin.gatePubkeyPem), signerKeySha256 = digestOf(key.export({ type: 'spki', format: 'der' }))
  const signerEpoch = epochs.epochs.find(row => row.gate_pubkey_sha256 === signerKeySha256)?.epoch
  if (signerEpoch === undefined) throw refuse('signer-epoch-unpinned', 'the signed key has no operator-pinned epoch')
  const e = approval.ledger_entry
  const columns = ['seq', 'at', 'event', 'proposal', 'target', 'base_sha', 'new_sha', 'detail', 'prev', 'hash', 'sig']
  if (e === null || typeof e !== 'object' || Object.keys(e).sort().join(',') !== [...columns].sort().join(',')
    || !Number.isSafeInteger(e.seq) || e.seq < 1 || e.event !== 'apply' || typeof e.detail !== 'string' || e.detail.length > 65536
    || !/^[0-9a-f]{64}$/u.test(e.hash) || typeof e.sig !== 'string'
    || (e.seq === 1 ? e.prev !== 'GENESIS' : !/^[0-9a-f]{64}$/u.test(e.prev))) throw refuse('signed-ledger-entry-malformed', 'no closed applied ledger entry')
  const r = approval.receipt
  if (e.proposal !== r.proposal || e.target !== r.target || e.base_sha !== r.base_sha || e.new_sha !== r.new_sha
    || typeof e.at !== 'string' || e.at.length > 64) throw refuse('signed-ledger-entry-binding', 'ledger row is not the approved effect')
  const detail = JSON.parse(e.detail)
  if (detail === null || typeof detail !== 'object' || Object.keys(detail).sort().join(',') !== 'receipt,receipt_sig'
    || JSON.stringify(detail.receipt) !== JSON.stringify(r) || detail.receipt_sig !== approval.receipt_sig) throw refuse('signed-ledger-entry-binding', 'signed detail differs from the installed receipt')
  const body = JSON.stringify([e.seq, e.at, e.event, e.proposal, e.target, e.base_sha, e.new_sha, e.detail, e.prev])
  if (digestOf(Buffer.from(body, 'utf8')) !== e.hash) throw refuse('signed-ledger-entry-hash', 'sequence or signed row bytes changed')
  let valid = false
  try { valid = cryptoVerify(null, Buffer.from(e.hash, 'hex'), key, Buffer.from(e.sig, 'base64')) } catch {}
  if (!valid) throw refuse('signed-ledger-entry-signature', 'row was not signed by the pinned gate key')
  return { ...verified, signerEpoch, signerKeySha256, ledgerSeq: e.seq, ledgerHash: e.hash }
}
