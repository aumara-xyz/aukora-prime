// Gate 1c: the sense layer — signed sense fields on the wire, the blind sound-code decoder, inspect().
import test from 'node:test';
import assert from 'node:assert/strict';
import { loadCore } from './load-core.mjs';

const P = loadCore();
function rng(seed) { let a = seed >>> 0; return () => { a |= 0; a = (a + 0x6d2b79f5) | 0; let t = Math.imul(a ^ (a >>> 15), 1 | a); t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t; return ((t ^ (t >>> 14)) >>> 0) / 4294967296; }; }
async function pair(sensesA, sensesB) {
  const a = await P.generateKeyPair(), b = await P.generateKeyPair();
  const t = 1791700000;
  const mk = (k, sn) => P.createDevice({ privateKey: k.privateKey, pk: k.pk, now: () => t, geo: () => null, senses: sn });
  return { A: mk(a, sensesA), B: mk(b, sensesB) };
}

test('frames without a senses provider are unchanged (no cap / snd / mov)', async () => {
  const { A } = await pair(undefined, undefined);
  const F = (await A.frame()).F;
  assert.ok(!('cap' in F) && !('snd' in F) && !('mov' in F));
});

test('sense fields are signed, survive the wire for every frame type, and every type still fits QR v9 or smaller', async () => {
  const sn = () => ({ cap: 7, snd: 'a1b2c3d4', mov: 9 });
  const { A, B } = await pair(sn, sn);
  const seen = {};
  for (let i = 0; i < 8 && !(A.receipt && B.receipt); i++) {
    for (const [from, to] of [[A, B], [B, A]]) {
      const pk = await from.frame(), text = P.encodeFrame(pk);
      seen[pk.F.type] = Math.max(seen[pk.F.type] || 0, text.length);
      const d = P.decodeFrame(text, { pk: to.pk });
      assert.equal(d.ok, true, pk.F.type);
      assert.equal(P.canonicalJson(d.packet.F), P.canonicalJson(pk.F));
      assert.deepEqual([d.packet.F.cap, d.packet.F.snd, d.packet.F.mov], [7, 'a1b2c3d4', 9]);
      await to.process(d.packet);
    }
  }
  assert.ok(A.receipt && B.receipt, 'ceremony completes with sense fields present');
  assert.deepEqual(Object.keys(seen).sort(), ['BLOOM', 'FACE', 'HANDSHAKE', 'SEENYOU']);
  for (const [type, len] of Object.entries(seen)) assert.ok(len <= 335, type + ' is ' + len + ' chars');
  console.log('# frame text lengths with senses: ' + JSON.stringify(seen));
});

test('a sense field changed in transit breaks the frame signature', async () => {
  const { A, B } = await pair(() => ({ cap: 3, snd: '00000001' }), undefined);
  const pk = await A.frame();
  const forged = { F: Object.assign({}, pk.F, { snd: 'ffffffff' }), sig_F: pk.sig_F };
  assert.equal((await B.process(forged)).code, 'BAD_SIG_F');
  assert.equal((await B.inspect(forged)).code, 'BAD_SIG_F');
  assert.equal((await B.process({ F: Object.assign({}, pk.F, { mov: 99 }), sig_F: pk.sig_F })).code, 'MALFORMED');
});

test('inspect() verifies a frame and never advances the state machine', async () => {
  const { A, B } = await pair(undefined, undefined);
  const fa = await A.frame();
  assert.deepEqual([(await B.inspect(fa)).ok, B.state, B.targetPk], [true, 'FACE', null]);
  await B.process(fa);
  assert.equal(B.state, 'SEENYOU');
  const again = await A.frame();
  for (let i = 0; i < 3; i++) assert.equal((await B.inspect(again)).ok, true);
  assert.equal(B.state, 'SEENYOU');
  const c = await P.generateKeyPair();
  const C = P.createDevice({ privateKey: c.privateKey, pk: c.pk, now: () => 1791700000, geo: () => null });
  assert.equal((await B.inspect(await C.frame())).code, 'BYSTANDER');
  assert.equal((await B.inspect(await B.frame())).code, 'SELF');
});

test('sound code: 19 symbols; the detector reads an unknown code blind, at both sample rates, inside noise', () => {
  const r = rng(7);
  for (const sr of [44100, 48000]) {
    for (let trial = 0; trial < 6; trial++) {
      const code = new Uint8Array([r() * 256, r() * 256, r() * 256, r() * 256]);
      const sym = P.soundSymbols(code);
      assert.equal(sym.length, 19);
      const burst = P.audioSynth(sym, sr, 0.07 * (trial % 2 ? 0.1 : 1));
      const total = new Float32Array(Math.round(sr * 3.5));
      for (let i = 0; i < total.length; i++) total[i] = (r() - 0.5) * 0.0006;
      const off = Math.floor(r() * sr * 1.5) + 2000;
      for (let i = 0; i < burst.length; i++) total[off + i] += burst[i];
      const det = P.createAudioDetector(sr);
      for (let i = 0; i < total.length; i += 1024) det.push(total.subarray(i, i + 1024));
      const d = det.decode();
      assert.ok(d, 'decoded at ' + sr + ' trial ' + trial);
      assert.equal(d.hex, P.bytesToHex(code));
    }
  }
});

test('sound code: silence, noise, a steady tone and a cut-off burst decode to nothing; a corrupted symbol is rejected', () => {
  const sr = 48000, r = rng(11);
  const feed = (buf) => { const det = P.createAudioDetector(sr); for (let i = 0; i < buf.length; i += 1024) det.push(buf.subarray(i, i + 1024)); return det.decode(); };
  assert.equal(feed(new Float32Array(sr * 3)), null);
  const noise = new Float32Array(sr * 3); for (let i = 0; i < noise.length; i++) noise[i] = (r() - 0.5) * 0.05;
  assert.equal(feed(noise), null);
  const tone = new Float32Array(sr * 3); for (let i = 0; i < tone.length; i++) tone[i] = 0.05 * Math.sin((2 * Math.PI * 19200 * i) / sr);
  assert.equal(feed(tone), null);
  const code = new Uint8Array([1, 2, 3, 4]), sym = P.soundSymbols(code);
  const pad = (b) => { const o = new Float32Array(sr * 2); o.set(b, 9000); return o; };
  assert.equal(feed(pad(P.audioSynth(sym.slice(0, 15), sr, 0.07))), null);
  const bad = sym.slice(); bad[9] = (bad[9] + 3) % 8;
  assert.equal(feed(pad(P.audioSynth(bad, sr, 0.07))), null);
  assert.equal(feed(pad(P.audioSynth(sym, sr, 0.07))).hex, '01020304');
});

test('finalizeReceipt records the echo and motion evidence and only then says ECHO_CONFIRMED', async () => {
  const { A, B } = await pair(undefined, undefined);
  for (let i = 0; i < 8 && !(A.receipt && B.receipt); i++) { const fa = await A.frame(), fb = await B.frame(); await A.process(fb); await B.process(fa); }
  const base = A.receipt || B.receipt;
  assert.equal(P.finalizeReceipt(base, {}).acoustic_channel, 'NOT_PERFORMED');
  const r = P.finalizeReceipt(base, { acoustic_channel: 'ECHO_CONFIRMED', sound_echo: { sent_code: 'a1b2c3d4', peer_returned_it: true }, motion: { result: 'SEEN_AND_CLAIMED' } });
  assert.equal(r.acoustic_channel, 'ECHO_CONFIRMED');
  assert.equal(r.sound_echo.peer_returned_it, true);
  assert.equal(P.finalizeReceipt(base, { acoustic_channel: 'VERIFIED_LOCAL' }).acoustic_channel, 'NOT_PERFORMED', 'a caller cannot assert the timed label');
  assert.equal((await P.verifyReceipt(r)).reason, 'valid');
});

test('sound code in the lower fallback band decodes and reports its band; the two bands do not cross-talk', () => {
  const sr = 48000, code = new Uint8Array([9, 8, 7, 6]), sym = P.soundSymbols(code);
  const feed = (buf) => { const det = P.createAudioDetector(sr); for (let i = 0; i < buf.length; i += 1024) det.push(buf.subarray(i, i + 1024)); return det; };
  const pad = (b) => { const o = new Float32Array(sr * 2); o.set(b, 7000); return o; };
  const lo = feed(pad(P.audioSynth(sym, sr, 0.09, 1))), hi = feed(pad(P.audioSynth(sym, sr, 0.09, 0)));
  assert.deepEqual([lo.decode().hex, lo.decode().band], ['09080706', 1]);
  assert.deepEqual([hi.decode().hex, hi.decode().band], ['09080706', 0]);
  assert.ok(hi.peak()[0] > hi.peak()[1] + 20 && lo.peak()[1] > lo.peak()[0] + 20, 'the probe points at the band that was played');
  const cross = feed(pad(P.audioSynth(sym, sr, 0.09, 1)));
  assert.equal(cross.decode().band, 1, 'a low-band burst is never read as a high-band one');
});

test('decode can look past this device\'s own code, and clear() forgets earlier sound', () => {
  const sr = 48000;
  const mine = new Uint8Array([1, 1, 1, 1]), peer = new Uint8Array([2, 2, 2, 2]);
  const buf = new Float32Array(sr * 4);
  buf.set(P.audioSynth(P.soundSymbols(peer), sr, 0.3, 0), 6000);            // the peer speaks first
  buf.set(P.audioSynth(P.soundSymbols(mine), sr, 0.3, 1), sr * 2);          // then someone replays my own code, in the other band
  const det = P.createAudioDetector(sr);
  for (let i = 0; i < buf.length; i += 1024) det.push(buf.subarray(i, i + 1024));
  assert.equal(det.decode().hex, '01010101', 'the newest burst is my own code');
  assert.equal(det.decode('01010101').hex, '02020202', 'told to skip it, the peer\'s code is still found');
  det.clear();
  assert.equal(det.decode(), null);
});
