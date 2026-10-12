// Gate 1d: approval — the asked text travels in frame pieces, and the approver's own key signs it for one session.
import test from 'node:test';
import assert from 'node:assert/strict';
import { loadCore } from './load-core.mjs';

const P = loadCore();
const T = 1791700000;
const SENSES = () => ({ cap: 7, snd: 'a1b2c3d4', mov: 9 });
const GEO = () => ({ lat: 37.123456, lon: -122.123456, acc: 12 });

// An asking machine M and an approving phone O. `approve` is what the phone's person has tapped (or null).
async function scene(text, approve) {
  const m = await P.generateKeyPair(), o = await P.generateKeyPair();
  const digest = await P.intentDigest(text), salt = '5a'.repeat(16), nonce = await P.intentNonce(digest, salt);
  const pieces = P.askChunks(text, digest);
  const M = P.createDevice({ privateKey: m.privateKey, pk: m.pk, now: () => T, geo: GEO, senses: SENSES, nonce: () => nonce, ask: () => pieces });
  const O = P.createDevice({ privateKey: o.privateKey, pk: o.pk, now: () => T, geo: GEO, senses: SENSES, ack: () => (approve ? approve(m.pk) : null) });
  return { M, O, m, o, digest, salt, pieces };
}

test('the text survives the pieces, in any order, for one to sixteen pieces', async () => {
  for (const text of ['ok', 'refine 0193: tighten the review prompt (3 edits) #' + 'ab'.repeat(32), 'né — 日本語 ✓ '.repeat(20).trim(), 'x'.repeat(1024)]) {
    const digest = await P.intentDigest(text), pieces = P.askChunks(text, digest);
    assert.ok(pieces.length >= 1 && pieces.length <= 16);
    const reader = P.createAskReader();
    let got = null;
    for (const piece of pieces.slice().reverse()) got = (await reader.push(piece)) || got;
    assert.deepEqual(got, { text, digest });
  }
  assert.equal(P.askChunks('x'.repeat(1025), await P.intentDigest('x')), null, 'a text that does not fit is refused, not cut');
});

test('the reader refuses text that would not read the way it hashes', async () => {
  for (const text of ['pay ‮ecila', 'two\nlines', ' padded', 'zero​width', 'bell\u0007']) {
    const digest = await P.intentDigest(text), reader = P.createAskReader();
    let got = null;
    for (const piece of P.askChunks(text, digest)) got = (await reader.push(piece)) || got;
    assert.equal(got, null, JSON.stringify(text));
  }
  // pieces that name one digest but carry another text
  const reader = P.createAskReader();
  const lie = P.askChunks('send everything', await P.intentDigest('send nothing'));
  assert.equal(await reader.push(lie[0]), null);
});

test('ask and ack are signed frame fields, survive the wire, and every frame still fits QR v9', async () => {
  const text = 'refine 0193: tighten the review prompt (3 edits) #' + 'cd'.repeat(32);
  const s = await scene(text, null);
  const approved = await scene(text, null); // sizes for the approver's frames
  void approved;
  const { M, O, m, digest } = s;
  let longest = 0;
  const fm = await M.frame(), wire = P.encodeFrame(fm);
  longest = Math.max(longest, wire.length);
  const back = P.decodeFrame(wire, { pk: O.pk });
  assert.equal(back.ok, true);
  assert.equal(P.canonicalJson(back.packet.F), P.canonicalJson(fm.F));
  assert.equal(back.packet.F.ask, s.pieces[fm.F.i % s.pieces.length]);
  assert.equal((await O.inspect(back.packet)).ok, true, 'the piece is covered by the frame signature');
  const forged = JSON.parse(JSON.stringify(back.packet)); forged.F.ask = forged.F.ask.slice(0, -2) + (forged.F.ask.endsWith('00') ? '01' : '00');
  assert.equal((await O.inspect(forged)).code, 'BAD_SIG_F');

  const o2 = await P.generateKeyPair();
  const O2 = P.createDevice({ privateKey: o2.privateKey, pk: o2.pk, now: () => T, geo: GEO, senses: SENSES, ack: () => ({ digest, asker: m.pk }) });
  const face = await O2.frame();
  assert.equal(await P.verifyAck(o2.pk, digest, m.pk, O2.sessionNonce, face.F.ack), true);
  await O2.process(fm);
  const seen = await O2.frame();
  assert.equal(seen.F.type, 'SEENYOU');
  for (const pk of [face, seen]) {
    const w = P.encodeFrame(pk), d = P.decodeFrame(w, { pk: m.pk });
    longest = Math.max(longest, w.length);
    assert.equal(d.ok, true, pk.F.type);
    assert.equal(d.packet.F.ack, pk.F.ack);
    assert.equal(P.canonicalJson(d.packet.F), P.canonicalJson(pk.F));
  }
  assert.ok(longest <= 335, 'longest approval frame is ' + longest + ' chars');
  console.log('# longest approval frame: ' + longest + ' chars');
});

test('a malformed piece cannot be put on the wire', async () => {
  const { M, O } = await scene('ok', null);
  const fm = await M.frame();
  const good = P.decodeFrame(P.encodeFrame(fm), { pk: O.pk });
  assert.equal(good.ok, true);
  const F = Object.assign({}, fm.F, { ask: 'zz' });
  assert.throws(() => P.encodeFrame({ F, sig_F: fm.sig_F }));
});

test('the signature is for one text, one asker and one session', async () => {
  const text = 'enroll this phone as the owner of this computer’s agent';
  const { M, O, m, o, digest } = await scene(text, (asker) => ({ digest: null, asker }));
  void M;
  const other = await P.generateKeyPair();
  const sig = await P.signAck(o.privateKey, digest, m.pk, O.sessionNonce);
  assert.equal(await P.verifyAck(o.pk, digest, m.pk, O.sessionNonce, sig), true);
  assert.equal(await P.verifyAck(o.pk, await P.intentDigest(text + '!'), m.pk, O.sessionNonce, sig), false, 'different words');
  assert.equal(await P.verifyAck(o.pk, digest, other.pk, O.sessionNonce, sig), false, 'different asker');
  assert.equal(await P.verifyAck(o.pk, digest, m.pk, '00'.repeat(8), sig), false, 'different session');
  assert.equal(await P.verifyAck(other.pk, digest, m.pk, O.sessionNonce, sig), false, 'different approver');
  assert.equal((await O.frame()).F.ack, undefined, 'no signature without a full digest');
});

test('a device that has not approved carries no signature; one that has completes the ceremony with it', async () => {
  const text = 'refine 0193: tighten the review prompt (3 edits)';
  let tapped = false;
  const s = await scene(text, null);
  const o = await P.generateKeyPair();
  const O = P.createDevice({ privateKey: o.privateKey, pk: o.pk, now: () => T, geo: GEO, senses: SENSES, ack: () => (tapped ? { digest: s.digest, asker: s.m.pk } : null) });
  const M = s.M;
  assert.equal((await O.frame()).F.ack, undefined);
  tapped = true;
  let ack = null, ackNonce = null;
  for (let i = 0; i < 8 && !(M.receipt && O.receipt); i++) {
    const fo = await O.frame(), fm = await M.frame();
    if (fo.F.ack) { ack = fo.F.ack; ackNonce = fo.F.nonce || fo.F.my_nonce; }
    await M.process(fo); await O.process(fm);
  }
  assert.ok(M.receipt && O.receipt);
  const side = M.receipt.minted_by, peer = side === 'A' ? 'B' : 'A';
  assert.equal(M.receipt['nonce_' + peer], ackNonce, 'the signature was made for the nonce that is in the receipt');
  assert.equal(await P.verifyAck(M.receipt['pk_' + peer], s.digest, M.receipt['pk_' + side], M.receipt['nonce_' + peer], ack), true);
  const r = P.finalizeReceipt(M.receipt, { intent: { text, digest: s.digest, salt: s.salt, side, ack: { sig: ack, by: peer } } });
  assert.equal((await P.verifyReceipt(r)).valid, true);
  assert.ok(!('intent' in P.receiptForPublish(r, 'coarse')), 'asked text never goes into a published copy');
  const pub = P.receiptForPublish(P.finalizeReceipt(O.receipt, { approved: { text, digest: s.digest, asker: s.m.pk } }), 'coarse');
  assert.ok(!('approved' in pub) && !('intent' in pub), 'what was approved never goes into a published copy');
});

test('a handshake or bloom frame never carries the signature (they must stay small)', async () => {
  const s = await scene('ok', null);
  const o = await P.generateKeyPair();
  const O = P.createDevice({ privateKey: o.privateKey, pk: o.pk, now: () => T, geo: GEO, senses: SENSES, ack: () => ({ digest: s.digest, asker: s.m.pk }) });
  const types = {};
  for (let i = 0; i < 8 && !(s.M.receipt && O.receipt); i++) {
    const fo = await O.frame(), fm = await s.M.frame();
    types[fo.F.type] = types[fo.F.type] || !!fo.F.ack;
    assert.equal(fm.F.ask !== undefined, fm.F.type === 'FACE');
    await s.M.process(fo); await O.process(fm);
  }
  const last = await O.frame(); types[last.F.type] = types[last.F.type] || !!last.F.ack;
  for (const t of Object.keys(types)) assert.equal(types[t], t === 'FACE' || t === 'SEENYOU', t);
});
