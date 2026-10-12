// Gate 1b: the parts Gate 1 does not reach — the publish path, location privacy at publish,
// the network guard's shape, and the CSP stamp. Written by the page author; Gate 1 is the independent one.
import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { loadCore, readPortalHtml, extractScript } from './load-core.mjs';
import { schnorr } from '../../../../plugins/aukora-nostr/lib/vendor/noble-curves/curves/secp256k1.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const P = loadCore();
const html = readPortalHtml();
const app = extractScript(html, 'portal-app'), core = extractScript(html, 'portal-core'), guard = extractScript(html, 'portal-guard');

async function ceremony(geoA, geoB) {
  const a = await P.generateKeyPair(), b = await P.generateKeyPair();
  const t = 1791600000;
  const mk = (k, g) => P.createDevice({ privateKey: k.privateKey, pk: k.pk, now: () => t, geo: () => g });
  const A = mk(a, geoA), B = mk(b, geoB);
  for (let i = 0; i < 8 && !(A.receipt && B.receipt); i++) { const fa = await A.frame(), fb = await B.frame(); await A.process(fb); await B.process(fa); }
  assert.ok(A.receipt && B.receipt, 'both devices minted');
  return A.receipt;
}
const HOME = { lat: 37.774929, lon: -122.419416, acc: 8 }, NEAR = { lat: 37.774951, lon: -122.419437, acc: 14 };

test('a signed publish event is a valid NIP-01 event under an independent BIP-340 verifier', async () => {
  assert.equal(P.hasSigner, true);
  const r = await ceremony(HOME, NEAR);
  const sk = crypto.getRandomValues(new Uint8Array(32));
  const ev = await P.signNostrEvent(P.buildNostrEvent(r, 'coarse', '', 1791600100), sk);
  assert.match(ev.id, /^[0-9a-f]{64}$/); assert.match(ev.sig, /^[0-9a-f]{128}$/); assert.match(ev.pubkey, /^[0-9a-f]{64}$/);
  assert.equal(ev.id, await P.nostrEventId(ev));
  assert.equal(ev.kind, 30078);
  assert.equal(schnorr.verify(Buffer.from(ev.sig, 'hex'), Buffer.from(ev.id, 'hex'), Buffer.from(ev.pubkey, 'hex')), true, 'independent Noble verifier accepts the signature');
  const tampered = Object.assign({}, ev, { content: ev.content + ' ' });
  assert.notEqual(await P.nostrEventId(tampered), ev.id);
});

test('the published copy never carries more location than the chosen class; coarse is the default', async () => {
  const r = await ceremony(HOME, NEAR); // which device is A depends on the key order, so both sides are checked
  const before = JSON.stringify(r);
  const exactDigits = ['774929', '419416', '774951', '419437'];
  for (const cls of [undefined, 'coarse', 'nonsense']) {
    const ev = P.buildNostrEvent(r, cls, 'f'.repeat(64), 1791600100);
    const flat = JSON.stringify(ev);
    for (const d of exactDigits) assert.ok(!flat.includes(d), 'coarse output leaks an exact coordinate digit run ' + d);
    const c = JSON.parse(ev.content);
    assert.equal(c.geo_privacy, 'coarse_100m');
    for (const g of [c.geo_A, c.geo_B]) assert.deepEqual([g.lat, g.lon], [37.775, -122.419]);
    assert.ok(c.geo_A.acc >= 100 && c.geo_B.acc >= 100, 'coarse copy does not claim fine accuracy');
    assert.equal((await P.verifyReceipt(c)).reason, 'valid');
  }
  const red = P.buildNostrEvent(r, 'redacted', 'f'.repeat(64), 1791600100);
  assert.ok(!/37\.7|122\.4/.test(JSON.stringify(red)), 'redacted output carries no coordinates');
  assert.equal(JSON.parse(red.content).geo_privacy, 'redacted');
  const ex = P.buildNostrEvent(r, 'exact', 'f'.repeat(64), 1791600100);
  assert.deepEqual([JSON.parse(ex.content).geo_A.lat, JSON.parse(ex.content).geo_B.lat].sort(), [37.774929, 37.774951]);
  assert.ok(ex.tags.some((t) => t[0] === 'geo_privacy' && t[1] === 'exact_explicit_opt_in'));
  assert.equal(JSON.stringify(r), before, 'building a publish copy does not alter the stored receipt');
});

test('a spoofed-accuracy receipt stays flagged in the coarse copy', async () => {
  const r = await ceremony({ lat: 37.774929, lon: -122.419416, acc: 0.5 }, NEAR);
  assert.equal(r.sentinel_verdict, 'SUSPICIOUS');
  const c = P.receiptForPublish(r, 'coarse');
  assert.equal(c.sentinel_verdict, 'SUSPICIOUS');
  assert.equal(Math.min(c.geo_A.acc, c.geo_B.acc), 0.5, 'coarsening must not launder a sub-metre accuracy claim');
  assert.match((await P.verifyReceipt(c)).reason, /^suspicious_spoofed_accuracy/);
});

test('network: page code reaches the network only through the guard, and only after arm()', () => {
  for (const [name, src] of [['portal-core', core], ['portal-app', app]]) {
    assert.ok(!/\bfetch\s*\(/.test(src), name + ' calls fetch directly');
    assert.ok(!/new\s+WebSocket\b/.test(src), name + ' constructs a WebSocket directly');
    assert.ok(!/XMLHttpRequest|sendBeacon|EventSource|RTCPeerConnection|importScripts/.test(src), name + ' names another network API');
  }
  assert.equal((app.match(/NET\.openSocket\(/g) || []).length, 1, 'one socket call site');
  assert.equal((app.match(/NET\.arm\(/g) || []).length, 1, 'one arming call site');
  assert.ok(app.indexOf('NET.arm(e)') < app.indexOf('NET.openSocket('), 'arming precedes the socket');
  assert.match(app, /action\('publish', async \(e\) => \{\s*if \(!NET\.arm\(e\)\) return;/, 'arming is the first statement of the publish tap handler');
  assert.match(guard, /if \(!armed \|\| !\/\^wss:/, 'openSocket refuses when disarmed');
  assert.equal((guard.match(/nativeFetch\(/g) || []).length, 1, 'the guard uses the real fetch exactly once (the pinned vendor file)');
  assert.match(guard, /nativeFetch\(VENDOR, \{ integrity: VENDOR_SRI/);
});

test('keys: non-extractable generation and no export path anywhere in the page', () => {
  assert.match(core, /generateKey\(ECDSA, false, \['sign', 'verify'\]\)/);
  const exports = (core + app).match(/exportKey\([^)]*\)/g) || [];
  assert.deepEqual(exports, ["exportKey('raw', kp.publicKey)"], 'the only export is the public key');
  assert.ok(!/wrapKey|pkcs8|'jwk'/.test(core + app));
});

test('the details view renders the does-not-prove list from the core constant, in full', () => {
  assert.match(app, /P\.DOES_NOT_PROVE_LEAD/);
  assert.match(app, /for \(const line of P\.DOES_NOT_PROVE\) ol\.appendChild/);
  assert.ok(!/innerHTML|outerHTML|insertAdjacentHTML|document\.write/.test(app), 'no HTML string sinks in the app');
});

test('the CSP in the page matches its inline blocks (stamp is current)', () => {
  const r = spawnSync('node', [path.join(here, 'stamp-csp.mjs'), '--check'], { encoding: 'utf8' });
  assert.equal(r.status, 0, r.stdout);
});

test('the peer\'s signed echo frame (which carries the peer\'s exact position) is published only with the exact class', async () => {
  const r = await ceremony(HOME, NEAR);
  const peerFrame = { F: { v: 1, type: 'SEENYOU', my_pk: r.pk_B, target_pk: r.pk_A, my_nonce: r.nonce_B, peer_nonce: r.nonce_A, t: r.t_B, i: 3, geo: { lat: 37.774951, lon: -122.419437, acc: 14 }, cap: 3, snd: 'a1b2c3d4' }, sig_F: 'ab'.repeat(64) };
  const withEcho = P.finalizeReceipt(r, { acoustic_channel: 'ECHO_CONFIRMED', sound_echo: { sent_code: 'a1b2c3d4', peer_returned_it: true, peer_frame: peerFrame } });
  for (const cls of ['coarse', 'redacted']) {
    const ev = P.buildNostrEvent(withEcho, cls, 'f'.repeat(64), 1791600100), flat = JSON.stringify(ev);
    for (const d of ['774929', '419416', '774951', '419437']) assert.ok(!flat.includes(d), cls + ' leaks ' + d);
    assert.equal(JSON.parse(ev.content).sound_echo.peer_frame, undefined, cls + ' copy must not carry the peer frame');
    assert.ok(flat.includes('ECHO_CONFIRMED'), 'the claim itself still travels');
  }
  assert.ok(JSON.parse(P.buildNostrEvent(withEcho, 'exact', 'f'.repeat(64), 1791600100).content).sound_echo.peer_frame);
  assert.ok(withEcho.sound_echo.peer_frame, 'the stored receipt keeps its evidence');
});
