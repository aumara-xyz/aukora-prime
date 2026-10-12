#!/usr/bin/env node
// Runs the co-presence receipt checkers over every vector and fixture beside them and compares each outcome with the
// one written here. The checkers and their data are copied unchanged from aumara-xyz/aukora-contact
// (copresence-portal-v0); see README.md. Exit 0 only if every row matches.
//
// What a pass means: these two files still refuse and accept what they refused and accepted where they were written.
// A valid receipt is evidence that two keys signed the same moment; it is not proof that a person was present, and
// it grants nothing.
import { spawnSync } from 'node:child_process'
import { readFileSync, readdirSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const here = path.dirname(fileURLToPath(import.meta.url))
const VECTORS = {
  'genuine.json': 'valid',
  'spacetime_genuine.json': 'valid',
  'audio_genuine.json': 'valid',
  'sig_b_tampered.json': 'invalid sig_B_invalid',
  'sig_a_garbage.json': 'invalid sig_A_invalid',
  'pk_b_swapped.json': 'invalid sig_A_invalid',
  'window_11s.json': 'invalid ceremony_window_exceeded',
  'spacetime_contradiction.json': 'invalid suspicious_spacetime_contradiction',
  'spacetime_spoofed_acc0.json': 'invalid suspicious_spoofed_accuracy',
  'audio_nonce_mismatch.json': 'invalid suspicious_audio_nonce_mismatch',
  'audio_relay_delayed.json': 'invalid suspicious_audio_relay_detected',
}
const FIXTURES = {
  'good.json': '{"valid":true,',
  'fail-wrong-text.json': 'invalid intent_mismatch',
  'fail-missing-ack.json': 'invalid no_owner_signature',
  'fail-bad-ack-signature.json': 'invalid bad_owner_signature',
}
const run = (script, ...args) => {
  const p = spawnSync(process.execPath, [path.join(here, script), ...args], { encoding: 'utf8' })
  return { code: p.status, out: (p.stdout ?? '').trim() }
}
let failed = 0
const row = (name, expected, got) => {
  const wantOk = expected === 'valid' || expected.startsWith('{')
  const ok = got.out.startsWith(expected) && got.code === (wantOk ? 0 : 1)
  if (!ok) failed++
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}: ${got.out.slice(0, 70)} (exit ${got.code})`)
}
// Every data file must have an expectation and every expectation a file: a vector nobody checks is not a check.
const same = (dir, table) => {
  const files = readdirSync(path.join(here, dir)).filter(f => f.endsWith('.json')).sort()
  const ok = JSON.stringify(files) === JSON.stringify(Object.keys(table).sort())
  if (!ok) { failed++; console.log(`FAIL  ${dir}: files and expectations differ`) }
}
same('vectors', VECTORS); same('fixtures', FIXTURES)
for (const [file, expected] of Object.entries(VECTORS)) row(`vectors/${file}`, expected, run('verify.mjs', path.join(here, 'vectors', file)))
const text = readFileSync(path.join(here, 'fixtures', 'TEXT.txt'), 'utf8').replace(/\n$/u, '')
for (const [file, expected] of Object.entries(FIXTURES)) row(`fixtures/${file}`, expected, run('verify-intent.mjs', path.join(here, 'fixtures', file), '--text', text))
console.log(failed === 0 ? `copresence check: PASS (${Object.keys(VECTORS).length + Object.keys(FIXTURES).length} rows)` : `copresence check: FAIL (${failed})`)
process.exit(failed === 0 ? 0 : 1)
