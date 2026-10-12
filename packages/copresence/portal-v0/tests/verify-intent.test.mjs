// verify-intent.mjs must agree with the page's own core, and with the Python gate's refusals.
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadCore } from './load-core.mjs';

const P = loadCore();
const ROOT = path.dirname(path.dirname(path.dirname(fileURLToPath(import.meta.url))));
const dir = mkdtempSync(path.join(tmpdir(), 'vi-'));
const TEXT = 'buzz-grant:' + 'ab'.repeat(32) + ':' + 'cd'.repeat(32);
const T = Math.floor(Date.now() / 1000);

async function mint(text, mode) {
  const m = await P.generateKeyPair(), o = await P.generateKeyPair();
  const digest = await P.intentDigest(text), salt = '5a'.repeat(16), nonce = await P.intentNonce(digest, salt);
  const signs = mode === 'unsigned' ? null : { digest: mode === 'other' ? await P.intentDigest(text + '!') : digest, asker: m.pk };
  const M = P.createDevice({ privateKey: m.privateKey, pk: m.pk, now: () => T, geo: () => null, nonce: () => nonce });
  const O = P.createDevice({ privateKey: o.privateKey, pk: o.pk, now: () => T, geo: () => null, ack: () => signs });
  let sig = null;
  for (let i = 0; i < 8 && !(M.receipt && O.receipt); i++) { const fm = await M.frame(), fo = await O.frame(); if (fo.F.ack) sig = fo.F.ack; await M.process(fo); await O.process(fm); }
  const side = M.receipt.minted_by;
  const r = P.finalizeReceipt(M.receipt, { intent: { text, digest, salt, side, ack: sig ? { sig, by: side === 'A' ? 'B' : 'A' } : undefined } });
  return { r, owner: o.pk, machine: m.pk };
}
let n = 0;
function run(r, ...args) {
  const f = path.join(dir, 'r' + (n++) + '.json'); writeFileSync(f, JSON.stringify(r));
  const p = spawnSync(process.execPath, [path.join(ROOT, 'verify-intent.mjs'), f, ...args], { encoding: 'utf8' });
  return { code: p.status, out: p.stdout.trim() };
}

test('a signed approval for the exact text passes and reports core, keys and digest', async () => {
  const { r, owner, machine } = await mint(TEXT);
  const v = run(r, '--text', TEXT, '--approver', owner, '--max-age', '300');
  assert.equal(v.code, 0, v.out);
  const j = JSON.parse(v.out);
  assert.equal(j.core, r.core); assert.equal(j.approver_key, owner); assert.equal(j.asker_key, machine);
  assert.equal(j.text_digest, await P.intentDigest(TEXT));
});

test('every way it should refuse', async () => {
  const { r, owner, machine } = await mint(TEXT);
  const refuse = (v, why) => { assert.equal(v.code, 1, v.out); assert.ok(v.out.startsWith('invalid ' + why), v.out); };
  refuse(run(r, '--text', TEXT + ' '), 'intent_mismatch');
  refuse(run(r, '--text', TEXT, '--approver', machine), 'wrong_approver');
  refuse(run(Object.assign({}, r, { t_B: r.t_B })), 'usage');
  refuse(run(r, '--text', TEXT, '--max-age', '0'), 'stale_receipt');
  refuse(run((await mint(TEXT, 'unsigned')).r, '--text', TEXT), 'no_owner_signature');
  refuse(run((await mint(TEXT, 'other')).r, '--text', TEXT), 'bad_owner_signature');
  const lifted = JSON.parse(JSON.stringify((await mint(TEXT)).r)); lifted.intent.ack = r.intent.ack;
  refuse(run(lifted, '--text', TEXT), 'bad_owner_signature');
  const salted = JSON.parse(JSON.stringify(r)); salted.intent.salt = '00'.repeat(16);
  refuse(run(salted, '--text', TEXT), 'intent_not_committed');
  const broken = JSON.parse(JSON.stringify(r)); broken.sig_B = broken.sig_B.slice(0, -2) + (broken.sig_B.endsWith('00') ? '01' : '00');
  refuse(run(broken, '--text', TEXT), 'receipt');
  const plain = JSON.parse(JSON.stringify(r)); delete plain.intent;
  refuse(run(plain, '--text', TEXT), 'no_intent');
});
