// Verification of the gate's signed receipts. A receipt is valid only if (1) its Ed25519 signature verifies
// under the gate's public key, (2) its key fingerprint matches that key, and (3) the same receipt and signature
// appear in an apply/revert-applied entry of an intact ledger. The HMAC approval evidence can additionally be
// recomputed by whoever holds the owner secret (the gate user).
import { createHmac, createPublicKey, verify, timingSafeEqual } from 'node:crypto'
import { keyFingerprint, verifyLedger, SHA } from './ledger.mjs'

const FIELDS = ['v', 'kind', 'proposal', 'target', 'base_sha', 'new_sha', 'applied_at', 'approver', 'approval_evidence_hmac', 'pubkey_fp']

export function verifyReceiptSignature(receipt, sigB64, pubPem) {
  const pub = typeof pubPem === 'string' ? createPublicKey(pubPem) : pubPem
  const errors = []
  if (!receipt || typeof receipt !== 'object' || Array.isArray(receipt)) return { ok: false, errors: ['receipt is not an object'] }
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
  const row = db.prepare("SELECT seq, event, proposal, base_sha, new_sha, detail FROM ledger WHERE proposal=? AND event IN ('apply','revert-applied') ORDER BY seq").all(String(receipt?.proposal ?? ''))
  const match = row.find(r => { try { const d = JSON.parse(r.detail); return JSON.stringify(d.receipt) === JSON.stringify(receipt) && d.receipt_sig === sigB64 } catch { return false } })
  if (!match) errors.push('receipt not found in an apply entry of the ledger')
  else if (match.base_sha !== receipt.base_sha || match.new_sha !== receipt.new_sha) errors.push('ledger entry hashes differ from the receipt')
  return { ok: errors.length === 0, errors, ledger_seq: match?.seq ?? null, ledger_entries: chain.entries }
}
