#!/usr/bin/env node
// Stranger's verifier for AUKORA boundary-gate evidence. No dependencies, no network: Node 18+ only.
//   node verify.mjs            (run inside this folder)
// Checks, against the PUBLISHED gate public key (gate-ed25519.pub):
//   1. the apply receipt's Ed25519 signature over its exact JSON bytes (receipt.json + receipt.sig);
//   2. every exported ledger entry: hash = sha256(entry body), Ed25519 signature over that hash, and the hash chain
//      (#1 starts the chain; every next entry's prev = the previous entry's hash, with NO missing seq) — this
//      covers the REFUSAL entries too, and a removed or reordered entry fails;
//   3. the receipt names the same proposal/new_sha as the signed ledger apply entry.
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
const apply = entries.find(e => e.event === 'apply' && e.proposal === receipt.proposal)
ok(!!apply && apply.new_sha === receipt.new_sha, 'signed ledger apply entry matches the receipt')
console.log(bad === 0 ? 'VERIFIED' : `NOT VERIFIED (${bad} failure(s))`)
process.exit(bad === 0 ? 0 : 1)
