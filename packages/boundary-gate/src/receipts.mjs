// Gate signatures, intact ledger inclusion and retained owner-proof references authenticate receipts.
import { createHmac, createPublicKey, verify, timingSafeEqual } from 'node:crypto'
import { keyFingerprint, verifyLedger, sha256, SHA } from './ledger.mjs'

const FIELDS = ['v', 'kind', 'proposal', 'target', 'base_sha', 'new_sha', 'applied_at', 'approver', 'approval_evidence_hmac', 'pubkey_fp']
const OWNER_FIELDS = ['v', 'kind', 'proposal', 'target', 'base_sha', 'new_sha', 'applied_at', 'approver', 'pubkey_fp',
  'gate_pubkey_sha256', 'owner_authorization', 'owner_accepted_at_ms', 'owner_consumption']
const hex = value => typeof value === 'string' && value.length === 64 && SHA.test(value)
const integer = value => Number.isSafeInteger(value) && !Object.is(value, -0) && value >= 0
const fail = code => { throw Object.assign(new Error('receipt:' + code), { code: 'receipt:' + code }) }
function closed(value, fields) {
  if (!value || typeof value !== 'object' || ![Object.prototype, null].includes(Object.getPrototypeOf(value))) fail('shape')
  const descriptors = Object.getOwnPropertyDescriptors(value), keys = Reflect.ownKeys(descriptors)
  if (keys.length !== fields.length || keys.some((key, i) => key !== fields[i])) fail('shape')
  const out = Object.create(null)
  for (const field of fields) {
    const d = descriptors[field]
    if (!d?.enumerable || !Object.hasOwn(d, 'value')) fail('shape')
    out[field] = d.value
  }
  return out
}
function ownerReceipt(supplied, pub) {
  const receipt = closed(supplied, OWNER_FIELDS)
  const reference = closed(receipt.owner_authorization, ['version', 'kind', 'authorization_id', 'proof_sha256'])
  const consumption = closed(receipt.owner_consumption, ['ledger_seq', 'ledger_hash', 'review_issue'])
  const issue = closed(consumption.review_issue, ['ledger_seq', 'ledger_hash'])
  const applied = Date.parse(receipt.applied_at)
  if (receipt.v !== 3 || !['change', 'revert'].includes(receipt.kind)
    || typeof receipt.proposal !== 'string' || typeof receipt.target !== 'string'
    || !(receipt.base_sha === 'absent' || hex(receipt.base_sha)) || !hex(receipt.new_sha)
    || receipt.base_sha === receipt.new_sha || !integer(applied) || new Date(applied).toISOString() !== receipt.applied_at
    || typeof receipt.approver !== 'string' || !/^aukora:1:[0-9a-f]{64}$/u.test(receipt.approver)
    || receipt.gate_pubkey_sha256 !== sha256(pub.export({ type: 'spki', format: 'der' }))
    || receipt.pubkey_fp !== keyFingerprint(pub) || !integer(receipt.owner_accepted_at_ms)
    || receipt.owner_accepted_at_ms > applied || reference.version !== 1 || reference.kind !== 'aukora-owner-authorization-ref/v1'
    || !hex(reference.authorization_id) || !hex(reference.proof_sha256)
    || !integer(issue.ledger_seq) || issue.ledger_seq < 1 || !hex(issue.ledger_hash)
    || !integer(consumption.ledger_seq) || consumption.ledger_seq <= issue.ledger_seq || !hex(consumption.ledger_hash)) fail('owner-layout')
  consumption.review_issue = issue
  receipt.owner_consumption = consumption
  receipt.owner_authorization = reference
  return receipt
}

export function verifyReceiptSignature(receipt, sigB64, pubPem) {
  const pub = typeof pubPem === 'string' ? createPublicKey(pubPem) : pubPem
  const errors = []
  if (!receipt || typeof receipt !== 'object' || Array.isArray(receipt)) return { ok: false, errors: ['receipt is not an object'] }
  if (Object.getOwnPropertyDescriptor(receipt, 'v')?.value === 3) {
    try {
      receipt = ownerReceipt(receipt, pub)
      const signature = typeof sigB64 === 'string' ? Buffer.from(sigB64, 'base64') : Buffer.alloc(0)
      if (signature.length !== 64 || signature.toString('base64') !== sigB64
        || !verify(null, Buffer.from(JSON.stringify(receipt)), pub, signature)) fail('signature')
    } catch (error) { errors.push(error.code ?? 'receipt:invalid') }
    return { ok: errors.length === 0, errors }
  }
  const keys = Object.keys(receipt)
  if (keys.length !== FIELDS.length || FIELDS.some((f, i) => keys[i] !== f)) errors.push('receipt fields differ from the v2 layout')
  if (receipt.v !== 2) errors.push('unsupported receipt version')
  if (!['change', 'revert'].includes(receipt.kind)) errors.push('unknown receipt kind')
  if (!SHA.test(String(receipt.new_sha)) || !(SHA.test(String(receipt.base_sha)) || receipt.base_sha === 'absent')) errors.push('bad sha fields')
  if (receipt.pubkey_fp !== keyFingerprint(pub)) errors.push('pubkey fingerprint mismatch')
  let good = false; try { good = verify(null, Buffer.from(JSON.stringify(receipt)), pub, Buffer.from(String(sigB64), 'base64')) } catch {}
  if (!good) errors.push('bad receipt signature')
  return { ok: errors.length === 0, errors }
}

// Signed history binds the retained proof bytes to issuance, consumption and apply.
// This authenticates the gate's acceptance; independent owner-proof verification remains separate.
function verifyRetainedOwnerReceipt(db, receipt, apply) {
  const ref = receipt.owner_authorization, pointer = receipt.owner_consumption
  const retained = db.prepare('SELECT * FROM owner_authorization_consumptions WHERE authorization_id=?').get(ref.authorization_id)
  const consume = db.prepare('SELECT * FROM ledger WHERE seq=? AND hash=?').get(pointer.ledger_seq, pointer.ledger_hash)
  const issue = db.prepare('SELECT * FROM ledger WHERE seq=? AND hash=?').get(pointer.review_issue.ledger_seq, pointer.review_issue.ledger_hash)
  if (!retained || !consume || !issue || consume.event !== 'owner-authorization-consumed' || issue.event !== 'review-issued'
    || pointer.ledger_seq >= apply.seq || [consume, issue].some(row => row.proposal !== receipt.proposal
      || row.target !== receipt.target || row.base_sha !== receipt.base_sha || row.new_sha !== receipt.new_sha)) fail('owner-history')
  const accepted = JSON.parse(consume.detail), issued = JSON.parse(issue.detail), proof = JSON.parse(retained.proof_text)
  const authorization = JSON.parse(issued.authorization_text)
  if (retained.proposal_id !== receipt.proposal || retained.gate !== receipt.gate_pubkey_sha256
    || retained.proof_sha256 !== ref.proof_sha256 || retained.accepted_at_ms !== receipt.owner_accepted_at_ms
    || retained.consume_seq !== consume.seq || retained.consume_hash !== consume.hash
    || retained.issue_seq !== issue.seq || retained.issue_hash !== issue.hash
    || retained.owner_state_text !== JSON.stringify(issued.owner_state)
    || retained.owner_state_text !== JSON.stringify(accepted.owner_state)
    || accepted.proof_text !== retained.proof_text || JSON.stringify(accepted.owner_authorization) !== JSON.stringify(ref)
    || accepted.accepted_at_ms !== receipt.owner_accepted_at_ms || accepted.spent !== true
    || accepted.outcome !== 'allowed-once' || accepted.approver !== receipt.approver
    || accepted.operation !== receipt.kind || JSON.stringify(accepted.review_issue) !== JSON.stringify(pointer.review_issue)
    || issued.authorization_id !== ref.authorization_id || issued.gate_pubkey_sha256 !== receipt.gate_pubkey_sha256
    || issued.issued_at_ms !== authorization.issued_at_ms || issued.expires_at_ms !== authorization.expires_at_ms
    || !integer(receipt.owner_accepted_at_ms) || authorization.issued_at_ms > receipt.owner_accepted_at_ms
    || receipt.owner_accepted_at_ms >= authorization.expires_at_ms
    || authorization.proposal_id !== receipt.proposal || authorization.target !== receipt.target
    || authorization.operation !== receipt.kind || authorization.before_sha256 !== receipt.base_sha
    || authorization.after_sha256 !== receipt.new_sha || authorization.gate !== receipt.gate_pubkey_sha256
    || authorization.owner_subject !== receipt.approver || authorization.challenge !== retained.challenge
    || JSON.stringify(proof.authorization) !== issued.authorization_text
    || sha256(Buffer.from((proof.version === 2 ? 'aukora:owner-authorization-proof:v2\0' : 'aukora:owner-authorization-proof:v1\0')
      + retained.proof_text, 'utf8')) !== ref.proof_sha256
    || sha256(Buffer.from((authorization.version === 2 ? 'aukora:owner-authorization:v2\0' : 'aukora:owner-authorization:v1\0')
      + issued.authorization_text, 'utf8')) !== ref.authorization_id) fail('owner-proof-reference')
}

export function verifyApprovalEvidence(receipt, hmacKeyHex) {
  const want = createHmac('sha256', Buffer.from(hmacKeyHex, 'hex')).update(`${receipt.proposal}\n${receipt.base_sha}\n${receipt.new_sha}\n${receipt.approver}`).digest()
  let got; try { got = Buffer.from(String(receipt.approval_evidence_hmac), 'base64') } catch { return false }
  return got.length === want.length && timingSafeEqual(got, want)
}

// Full check against the ledger database (read-only handle is enough).
export function verifyReceipt(db, receipt, sigB64, pubPem) {
  const pub = typeof pubPem === 'string' ? createPublicKey(pubPem) : pubPem
  const sig = verifyReceiptSignature(receipt, sigB64, pub)
  const chain = verifyLedger(db, pub)
  const errors = [...sig.errors]
  if (!chain.ok) errors.push('ledger chain or signatures broken')
  const row = db.prepare("SELECT seq, event, proposal, target, base_sha, new_sha, detail FROM ledger WHERE proposal=? AND event IN ('apply','revert-applied') ORDER BY seq").all(String(receipt?.proposal ?? ''))
  const match = row.find(r => { try { const d = JSON.parse(r.detail); return JSON.stringify(d.receipt) === JSON.stringify(receipt) && d.receipt_sig === sigB64 } catch { return false } })
  if (!match) errors.push('receipt not found in an apply entry of the ledger')
  else if (match.base_sha !== receipt.base_sha || match.new_sha !== receipt.new_sha) errors.push('ledger entry hashes differ from the receipt')
  if (sig.ok && chain.ok && match && receipt.v === 3) {
    try {
      if (match.target !== receipt.target || match.event !== (receipt.kind === 'revert' ? 'revert-applied' : 'apply')) fail('apply-mismatch')
      verifyRetainedOwnerReceipt(db, ownerReceipt(receipt, pub), match)
    } catch (error) { errors.push(error.code ?? 'receipt:owner-history-unavailable') }
  }
  return { ok: errors.length === 0, errors, ledger_seq: match?.seq ?? null, ledger_entries: chain.entries }
}
