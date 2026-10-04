#!/usr/bin/env node
// Ledger tail anchoring: the published head (branch `ledger-anchor`, anchors/gate-ledger.jsonl) and the two readers of it.
//   node tests/gate-ledger-anchor.test.mjs
// Part A runs the stranger's verifier (docs/evidence/l2-demo-2026-10-04/verify.mjs) on disposable copies of the real
// signed export with crafted anchor files: a matching anchor verifies; a rewritten entry, a foreign key, a non-increasing
// anchor file, and a truncated export under --whole all fail. Part B runs the publisher's pure decision
// (packages/boundary-gate/anchor/publish-anchor.py --plan) against the same entries: it publishes a moved head, stays
// quiet on an unchanged one, and refuses truncation, rewrite, a key change, an unverified chain and a bad remote file.
// Offline; no network, no gate, no GitHub.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { cpSync, mkdtempSync, readFileSync, writeFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = join(dirname(fileURLToPath(import.meta.url)), '..')
const evid = join(root, 'docs/evidence/l2-demo-2026-10-04')
const publisher = join(root, 'packages/boundary-gate/anchor/publish-anchor.py')
const entries = JSON.parse(readFileSync(join(evid, 'ledger-entries.json'), 'utf8'))
const FP = '6cdce2bbeb7b725c'
const last = entries.at(-1)
const anchor = (e, extra = {}) => ({ seq: e.seq, head: e.hash, gate_fp: FP, entry_at: e.at, anchored_at: '2026-10-04T04:00:00Z', ...extra })
const jsonl = (xs) => xs.map(x => JSON.stringify(x)).join('\n') + '\n'

function runVerify(anchors, { whole = false, dropLast = false } = {}) {
  const d = mkdtempSync(join(tmpdir(), 'anchor-')); cpSync(evid, d, { recursive: true })
  if (dropLast) writeFileSync(join(d, 'ledger-entries.json'), JSON.stringify(entries.slice(0, -1)))
  writeFileSync(join(d, 'a.jsonl'), jsonl(anchors))
  const r = spawnSync(process.execPath, [join(d, 'verify.mjs'), '--anchor', join(d, 'a.jsonl'), ...(whole ? ['--whole'] : [])], { encoding: 'utf8' })
  rmSync(d, { recursive: true, force: true }); return r
}

test('A1 anchor at the export tail verifies, also with --whole', () => {
  const r = runVerify([anchor(entries[9]), anchor(last)], { whole: true })
  assert.equal(r.status, 0, r.stdout); assert.match(r.stdout, /VERIFIED/); assert.match(r.stdout, /anchor #24 .* = exported entry hash/)
})
test('A2 rewritten entry: anchor hash differs from the exported entry -> NOT VERIFIED', () => {
  const r = runVerify([anchor(last, { head: 'ab'.repeat(32) })]); assert.equal(r.status, 1); assert.match(r.stdout, /FAIL anchor #24/)
})
const later = { seq: 30, head: 'aa'.repeat(32), gate_fp: FP, entry_at: 'x', anchored_at: '2026-10-04T05:00:00Z' }
test('A3 truncation: gate ledger anchored at #30, export ends at #24, --whole -> NOT VERIFIED, and only for that', () => {
  const r = runVerify([anchor(last), later], { whole: true }); assert.equal(r.status, 1)
  assert.match(r.stdout, /FAIL whole ledger claimed.*#30.*#24 \(truncated\)/); assert.match(r.stdout, /NOT VERIFIED \(1 failure/)
  const d = runVerify([anchor(last)], { whole: true, dropLast: true }); assert.equal(d.status, 1); assert.match(d.stdout, /truncated/)
})
test('A4 same export without --whole is reported as a prefix, not hidden', () => {
  const r = runVerify([anchor(last), later]); assert.equal(r.status, 0, r.stdout); assert.match(r.stdout, /reached #30 — the export is a prefix/)
})
test('A5 anchor naming another key fails', () => {
  const r = runVerify([anchor(last, { gate_fp: '0123456789abcdef' })]); assert.equal(r.status, 1); assert.match(r.stdout, /FAIL anchor #24 names this key/)
})
test('A6 non-increasing anchor file fails', () => {
  const r = runVerify([anchor(last), anchor(entries[9])]); assert.equal(r.status, 1); assert.match(r.stdout, /FAIL anchor #10 well-formed and increasing/)
})
test('A7 without --anchor the verifier behaves as before', () => {
  const r = spawnSync(process.execPath, [join(evid, 'verify.mjs')], { encoding: 'utf8' }); assert.equal(r.status, 0); assert.doesNotMatch(r.stdout, /anchor/)
})

const gateReply = (es, { ok = true, fp = FP } = {}) => ({ verify: { ok, entries: es.at(-1).seq, head: es.at(-1).hash, errors: ok ? [] : ['seq 3: bad signature'] },
  pubkey_fp: fp, entries: es.slice().reverse().map(({ seq, at, event, hash }) => ({ seq, at, event, hash })) })
function plan(remote, gate) {
  const r = spawnSync('python3', [publisher, '--plan'], { input: JSON.stringify({ remote, gate, now: '2026-10-04T04:00:00Z' }), encoding: 'utf8' })
  return { status: r.status, out: JSON.parse(r.stdout || '{}'), err: r.stderr }
}
test('B1 first anchor publishes the verified head', () => {
  const p = plan('', gateReply(entries)); assert.equal(p.status, 0, p.err); assert.deepEqual(p.out.publish, anchor(last))
})
test('B2 unchanged head publishes nothing', () => {
  const p = plan(jsonl([anchor(last)]), gateReply(entries)); assert.equal(p.status, 0); assert.equal(p.out.publish, null)
})
test('B3 moved head publishes after checking the old anchor still holds', () => {
  const p = plan(jsonl([anchor(entries[19])]), gateReply(entries)); assert.equal(p.status, 0); assert.equal(p.out.publish.seq, 24)
})
test('B4 gate shorter than the last anchor -> TRUNCATION refusal', () => {
  const p = plan(jsonl([anchor(last)]), gateReply(entries.slice(0, -2))); assert.equal(p.status, 3); assert.match(p.out.refuse, /TRUNCATION/)
})
test('B5 same seq, different hash -> REWRITE refusal', () => {
  const p = plan(jsonl([anchor(last, { head: 'cd'.repeat(32) })]), gateReply(entries)); assert.equal(p.status, 3); assert.match(p.out.refuse, /REWRITE/)
})
test('B6 older anchored entry changed under a new head -> REWRITE refusal', () => {
  const p = plan(jsonl([anchor(entries[19], { head: 'ef'.repeat(32) })]), gateReply(entries)); assert.equal(p.status, 3); assert.match(p.out.refuse, /REWRITE: entry #20/)
})
test('B7 unverified chain, changed key, malformed remote: all refused', () => {
  assert.match(plan('', gateReply(entries, { ok: false })).out.refuse, /does not verify/)
  assert.match(plan(jsonl([anchor(entries[19])]), gateReply(entries, { fp: '0123456789abcdef' })).out.refuse, /key changed/)
  assert.match(plan('{"seq":"x"}\n', gateReply(entries)).out.refuse, /malformed/)
  assert.match(plan(jsonl([anchor(last), anchor(entries[19])]), gateReply(entries)).out.refuse, /not increasing/)
})
test('B8 gate log top entry that disagrees with its verified head is refused', () => {
  const g = gateReply(entries); g.entries[0] = { ...g.entries[0], hash: '00'.repeat(32) }
  assert.match(plan('', g).out.refuse, /does not match its verified head/)
})
