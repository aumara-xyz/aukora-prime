#!/usr/bin/env node
// Owner CLI over the gate's OWNER socket (0600, gate user only), e.g. via `sudo -n -u aukora-gate`.
//   owner-cli.mjs --socket PATH pending | approve <id8+> <result-sha256-prefix(>=12)> | reject <id8+>
// Approval is bound to an id prefix AND the expected result sha256 prefix, so the operator approves exactly
// the change that was read out to the owner. The operator is trusted by construction (it can become the gate
// user); this path keeps the HARNESS out of approvals, it does not constrain the operator.
import { call } from '../src/server.mjs'

const argv = process.argv.slice(2)
const si = argv.indexOf('--socket'); if (si < 0 || !argv[si + 1]) { console.error('--socket PATH is required'); process.exit(2) }
const sock = argv[si + 1]; argv.splice(si, 2)
const [op, pre, sha] = argv
const { pending } = await call(sock, 'pending', {})
if (op === 'pending') {
  for (const p of pending) {
    console.log(`${p.id.slice(0, 8)}  ${p.kind}  ${p.target}  ${p.base_sha.slice(0, 12)} -> ${p.new_sha.slice(0, 12)}  expires ${new Date(p.expires).toISOString()}`)
    if (p.plain) console.log(`    ${p.plain}\n    ${p.after_apply}\n    ${p.swatch ?? ''}`)
    console.log(`    note: ${p.note_display ?? p.why ?? ''}`)
    for (const w of p.warnings ?? []) console.log(`    ! WARNING: ${w}`)
  }
  if (!pending.length) console.log('no pending proposals')
  process.exit(0)
}
if (!['approve', 'reject'].includes(op) || !pre || pre.length < 8) { console.error('usage: owner-cli.mjs --socket PATH pending | approve <id8+> <result-sha256-prefix(>=12)> | reject <id8+>'); process.exit(2) }
const m = pending.filter(p => p.id.startsWith(pre)); if (m.length !== 1) { console.error(`refused: ${m.length} pending proposals match ${pre}`); process.exit(3) }
const p = m[0]
if (op === 'approve' && (!sha || sha.length < 12 || !p.new_sha.startsWith(sha))) { console.error(`refused: expected result sha256 prefix (>=12 hex) must match the pending proposal (${p.new_sha.slice(0, 12)}…)`); process.exit(4) }
const r = await call(sock, op, { id: p.id })
console.log(JSON.stringify({ proposal: p.id.slice(0, 8), result: r.state, applied: r.applied, message: r.message, ledger_seq: r.ledger_seq ?? null, approver: r.receipt?.approver ?? null, evidence_hmac: r.receipt?.approval_evidence_hmac ? r.receipt.approval_evidence_hmac.slice(0, 16) + '…' : null }))
