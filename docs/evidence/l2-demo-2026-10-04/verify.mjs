#!/usr/bin/env node
// Stranger's verifier for AUKORA boundary-gate evidence. No dependencies, no network: Node 18+ only.
//   node verify.mjs            (run inside this folder)
// Checks, against the PUBLISHED gate public key (gate-ed25519.pub):
//   1. the apply receipt's Ed25519 signature over its exact JSON bytes (receipt.json + receipt.sig);
//   2. every exported ledger entry: hash = sha256(entry body), Ed25519 signature over that hash, and the hash chain
//      (#1 starts the chain; every next entry's prev = the previous entry's hash, with NO missing seq) — this
//      covers the REFUSAL entries too, and a removed or reordered entry fails;
//   3. the receipt names the same proposal/new_sha as the signed ledger apply entry.
//   node verify.mjs --anchor gate-ledger.jsonl [--whole]
//   4. against the head anchors published OUTSIDE the pilot (branch `ledger-anchor`, anchors/gate-ledger.jsonl):
//      every anchor must name this key, seqs must increase, and every anchor inside the export must equal the
//      exported entry's hash (a rewritten entry fails). An anchor PAST the export's last entry means the gate's
//      ledger is longer than this export: reported, and with --whole (claim: this is the whole ledger) it FAILS,
//      so dropping entries off the end is detectable.
import { createHash, createPublicKey, verify } from 'node:crypto'
import { readFileSync } from 'node:fs'
const here = new URL('./', import.meta.url)
const read = f => readFileSync(new URL(f, here), 'utf8')
const pub = createPublicKey(read('gate-ed25519.pub'))
const fp = createHash('sha256').update(pub.export({ type: 'spki', format: 'der' })).digest('hex').slice(0, 16)
let bad = 0; const ok = (cond, msg) => { console.log(`${cond ? 'OK  ' : 'FAIL'} ${msg}`); if (!cond) bad++ }
console.log(`gate key fingerprint ${fp}`)
const receiptBytes = read('receipt.json').replace(/\n$/u, '')
const receipt = JSON.parse(receiptBytes)
ok(JSON.stringify(receipt) === receiptBytes, 'receipt.json is the exact signed byte form')
ok(verify(null, Buffer.from(receiptBytes), pub, Buffer.from(read('receipt.sig').trim(), 'base64')), `apply receipt signature (proposal ${receipt.proposal.slice(0, 8)}, ${receipt.target} -> ${receipt.new_sha.slice(0, 12)})`)
ok(receipt.pubkey_fp === fp, 'receipt names this key')
const body = e => JSON.stringify([e.seq, e.at, e.event, e.proposal ?? null, e.target ?? null, e.base_sha ?? null, e.new_sha ?? null, e.detail ?? null, e.prev])
const entries = JSON.parse(read('ledger-entries.json'))
let last = null
for (const e of entries) {
  const h = createHash('sha256').update(body(e)).digest('hex')
  ok(h === e.hash && verify(null, Buffer.from(e.hash, 'hex'), pub, Buffer.from(e.sig, 'base64')),
    `ledger #${e.seq} ${e.event} ${String(e.proposal ?? '').slice(0, 8)} ${e.event === 'decide' ? '(' + (JSON.parse(e.detail || '{}').outcome ?? '') + ')' : ''} signed`)
  if (last === null) ok(e.seq === 1 && e.prev === 'GENESIS', `chain starts at #1 (seq ${e.seq})`)
  else ok(e.seq === last.seq + 1 && e.prev === last.hash, `chain #${last.seq} -> #${e.seq}`)
  last = e
}
const argv = process.argv.slice(2), ai = argv.indexOf('--anchor')
if (ai >= 0) {
  const anchorFile = argv[ai + 1]
  if (!anchorFile) { console.log('FAIL --anchor needs a file'); process.exit(1) }
  const anchors = readFileSync(anchorFile, 'utf8').split('\n').filter(l => l.trim()).map(l => JSON.parse(l))
  const bySeq = new Map(entries.map(e => [e.seq, e]))
  ok(anchors.length > 0, `anchor file has ${anchors.length} anchor(s)`)
  let prevSeq = 0
  for (const a of anchors) {
    ok(Number.isInteger(a.seq) && a.seq > prevSeq && /^[0-9a-f]{64}$/u.test(a.head ?? ''), `anchor #${a.seq} well-formed and increasing`)
    ok(a.gate_fp === fp, `anchor #${a.seq} names this key`)
    prevSeq = Number.isInteger(a.seq) ? a.seq : prevSeq
    if (last && a.seq <= last.seq) ok(bySeq.get(a.seq)?.hash === a.head, `anchor #${a.seq} (${String(a.head).slice(0, 12)}, anchored ${a.anchored_at}) = exported entry hash`)
  }
  const top = anchors.at(-1)
  if (top && last && top.seq > last.seq) {
    if (argv.includes('--whole')) ok(false, `whole ledger claimed, but the gate ledger was anchored at #${top.seq} and this export ends at #${last.seq} (truncated)`)
    else console.log(`NOTE this export ends at #${last.seq}; the published anchor shows the gate ledger reached #${top.seq} — the export is a prefix`)
  } else if (top && last && top.seq < last.seq) console.log(`NOTE entries after #${top.seq} are not anchored yet (export ends at #${last.seq})`)
  else if (top && last) ok(true, `export tail #${last.seq} is the latest anchored head`)
}
const apply = entries.find(e => e.event === 'apply' && e.proposal === receipt.proposal)
ok(!!apply && apply.new_sha === receipt.new_sha, 'signed ledger apply entry matches the receipt')
console.log(bad === 0 ? 'VERIFIED' : `NOT VERIFIED (${bad} failure(s))`)
process.exit(bad === 0 ? 0 : 1)
