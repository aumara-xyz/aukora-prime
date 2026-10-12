// Gate 1: independent conformance suite for the portal's pure logic core.
//
//   node --test copresence-portal-v0/tests/gate1-core.test.mjs
//
// Written from the frozen references only (toy/sim.py, verify.mjs, SPEC-v1.md,
// vectors/, runtime/spacetime_sentinel.py) and the PortalCore contract, never
// from an implementation. The suite evaluates the exact bytes of the
// <script id="portal-core"> block that ships in portal/index.html (through
// tests/load-core.mjs), so it gates the shipped text, not a copy of it.
//
// Oracles used, all independent of the code under test:
//   - python3 importing toy/sim.py (canonical_json, compute_receipt_core)
//   - `node verify.mjs <file>` as a subprocess (receipts)
//   - node:crypto (ECDSA P-256 verify exactly as verify.mjs does, SHA-256,
//     point compression)
//   - RFC 9285 test vectors and a 15-line reference Base45
//   - the two pinned vendor QR libraries (encode with one, decode with the other)
//
// Readings chosen where the contract left room (each is also named in the
// failure message of the test it affects):
//   R1  canonicalJson: byte-identical to sim.py on U+0000..U+007E. sim.py
//       escapes everything from U+007F up as \uXXXX (json.dumps default) while
//       the contract says "scalars via JSON.stringify", which emits those
//       characters raw. Either form is accepted for non-ASCII, but as a whole:
//       escaping some of those characters and not others matches neither.
//       Structure, key order and every other byte must still equal sim.py.
//   R2  Corrupted frame text: the wire layout is private, so "bit-flipped ->
//       ok:false" is enforced as "never throws and never yields a different
//       packet whose sig_F verifies". ok:false is demanded outright only for
//       text that cannot be a frame under any layout (not Base45, or too short
//       to hold a 64-byte signature).
//   R3  receipt.clocks has no fixed schema, so the clamp is located as a
//       boolean under a key matching /clamp/i and the raw clock as a numeric
//       leaf equal to the responder's injected now().
//   R4  The 3 s clock-skew verdict is asserted on the responder's receipt (the
//       device that clamps). The initiator's verdict is reported, not asserted.
//   R5  The audio detector may keep a sliding window, so match() is polled
//       while audio is pushed in chunks; one matched:true poll is a match.
//       240 ms after a chirp has ended, match() must rest on all 43 symbols
//       (total === 43), so a right-prefix / wrong-remainder chirp is not a match.
//
// Tests that hold the page to more than the letter of the contract, so that a
// failure there is adjudicated rather than assumed to be a page bug:
//   06g  the frame index must survive the wire past 16 bits (18 h of FACE)
//   08j  a third key's SEENYOU must not derail a locked ceremony (sim.py does
//        not guard this; a faithful port stalls until the timeout)
//   13d  the detector must still match a chirp 20 dB below synthesis level
//   14f  the CSP must allow-list the inline blocks it ships with
//
// If portal/index.html or its portal-core block is missing, all tests fail
// with one message that starts "portal-core not found".
import test, { after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { loadCore, loadQr, VERIFY_MJS, VECTORS_DIR, PORTAL_HTML } from './load-core.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.join(here, '..');
const TOY_DIR = path.join(here, 'data', 'toy');
const SPEC_MD = path.join(ROOT, 'SPEC-v1.md');
const PENTORA_VECTORS = path.join(here, 'pentora-vectors.json');
const PORTAL_DIR = path.dirname(PORTAL_HTML);

// ---------------------------------------------------------------------------
// Loading. Nothing below may crash when the page does not exist yet: every
// test fails with the same one-line message instead.
// ---------------------------------------------------------------------------
let CORE = null;
let CORE_ERROR = null;
let HTML = null;
try {
  HTML = fs.readFileSync(PORTAL_HTML, 'utf8');
} catch {
  HTML = null;
}
try {
  CORE = loadCore();
} catch (err) {
  const message = String((err && err.message) || err);
  if (HTML === null) {
    CORE_ERROR = 'portal-core not found: portal/index.html does not exist yet';
  } else if (/not found in portal\/index\.html/.test(message)) {
    CORE_ERROR = 'portal-core not found: portal/index.html has no <script id="portal-core"> block';
  } else {
    CORE_ERROR = `portal-core failed to load: ${message}`;
  }
}

function gate(name, fn) {
  test(name, async (t) => {
    if (!CORE) assert.fail(CORE_ERROR);
    await fn(t, CORE);
  });
}

// ---------------------------------------------------------------------------
// Small independent helpers
// ---------------------------------------------------------------------------
const hex = (u8) => Buffer.from(u8).toString('hex');
const unhex = (h) => new Uint8Array(Buffer.from(h, 'hex'));
const enc = (s) => new Uint8Array(Buffer.from(s, 'utf8'));

function fmt(v) {
  try {
    const s = JSON.stringify(v, (k, x) => (x instanceof Uint8Array ? `u8:${hex(x)}` : x));
    if (s === undefined) return String(v);
    return s.length > 480 ? `${s.slice(0, 480)}...` : s;
  } catch {
    return String(v);
  }
}

async function settle(fn) {
  try {
    return { ok: true, value: await fn() };
  } catch (error) {
    return { ok: false, error };
  }
}

// Deterministic PRNG (mulberry32). No Math.random anywhere in this file.
function mulberry32(seed) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function detBytes(n, seed) {
  const rnd = mulberry32(seed);
  const out = new Uint8Array(n);
  for (let i = 0; i < n; i += 1) out[i] = Math.floor(rnd() * 256);
  return out;
}

// Reference canonical JSON: keys sorted by UTF-16 code unit, no whitespace.
function refCanon(v) {
  if (Array.isArray(v)) return `[${v.map(refCanon).join(',')}]`;
  if (v && typeof v === 'object') {
    return `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${refCanon(v[k])}`).join(',')}}`;
  }
  return JSON.stringify(v);
}

// Reference Base45 (RFC 9285).
const B45 = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:';
const B45_RE = /^[0-9A-Z $%*+\-./:]*$/;
function refB45Encode(u8) {
  let s = '';
  for (let i = 0; i + 1 < u8.length; i += 2) {
    const v = u8[i] * 256 + u8[i + 1];
    s += B45[v % 45] + B45[Math.floor(v / 45) % 45] + B45[Math.floor(v / 2025)];
  }
  if (u8.length % 2) {
    const v = u8[u8.length - 1];
    s += B45[v % 45] + B45[Math.floor(v / 45)];
  }
  return s;
}
function refB45Decode(s) {
  const out = [];
  for (let i = 0; i < s.length; i += 3) {
    const c = [...s.slice(i, i + 3)].map((ch) => B45.indexOf(ch));
    if (c.length === 3) {
      const v = c[0] + c[1] * 45 + c[2] * 2025;
      out.push(v >> 8, v & 255);
    } else {
      out.push(c[0] + c[1] * 45);
    }
  }
  return Uint8Array.from(out);
}

// node:crypto side, the same primitives verify.mjs uses.
const SPKI_PREFIX_P256 = Buffer.from('3059301306072a8648ce3d020106082a8648ce3d030107034200', 'hex');
const PK_RE = /^04[0-9a-f]{128}$/;
const SIG_RE = /^[0-9a-f]{128}$/;
const NONCE_RE = /^[0-9a-f]{16}$/;

function nodePublicKey(pkHex) {
  return crypto.createPublicKey({ key: Buffer.concat([SPKI_PREFIX_P256, Buffer.from(pkHex, 'hex')]), format: 'der', type: 'spki' });
}
function nodeVerify(pkHex, bytes, sigHex) {
  try {
    if (typeof pkHex !== 'string' || !/^04[0-9a-fA-F]{128}$/.test(pkHex)) return false;
    if (typeof sigHex !== 'string' || !/^[0-9a-fA-F]{128}$/.test(sigHex)) return false;
    return crypto.verify('sha256', bytes, { key: nodePublicKey(pkHex), dsaEncoding: 'ieee-p1363' }, Buffer.from(sigHex, 'hex'));
  } catch {
    return false;
  }
}
function nodeCore(pkA, pkB, nonceA, nonceB, tB) {
  const be = Buffer.alloc(8);
  be.writeBigUInt64BE(BigInt(tB));
  const payload = Buffer.concat([
    Buffer.from('copresence.v0', 'utf8'), Buffer.from([0]),
    Buffer.from(pkA, 'hex'), Buffer.from(pkB, 'hex'),
    Buffer.from(nonceA, 'hex'), Buffer.from(nonceB, 'hex'), be,
  ]);
  return new Uint8Array(crypto.createHash('sha256').update(payload).digest());
}
// Deterministic P-256 identity that lives entirely in node:crypto: a signer the
// page code has never seen, used for forged, stale and interop frames.
const NODE_KEYS = new Map();
function nodeKey(label) {
  if (NODE_KEYS.has(label)) return NODE_KEYS.get(label);
  const d = crypto.createHash('sha256').update(`gate1/key/${label}`).digest();
  const ecdh = crypto.createECDH('prime256v1');
  ecdh.setPrivateKey(d);
  const pub = ecdh.getPublicKey();
  const jwk = {
    kty: 'EC', crv: 'P-256', d: d.toString('base64url'),
    x: pub.subarray(1, 33).toString('base64url'), y: pub.subarray(33).toString('base64url'),
  };
  const key = crypto.createPrivateKey({ key: jwk, format: 'jwk' });
  const out = {
    pk: pub.toString('hex'),
    compressed: ecdh.getPublicKey('hex', 'compressed'),
    sign: (bytes) => crypto.sign('sha256', bytes, { key, dsaEncoding: 'ieee-p1363' }).toString('hex'),
  };
  NODE_KEYS.set(label, out);
  return out;
}
// Signs with a device's own non-extractable key without going through PortalCore.
async function subtleSign(privateKey, bytes) {
  return hex(new Uint8Array(await globalThis.crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, privateKey, bytes)));
}
function flipHex(s, pos = s.length - 1) {
  return s.slice(0, pos) + (parseInt(s[pos], 16) ^ 1).toString(16) + s.slice(pos + 1);
}

function readVector(name) {
  return JSON.parse(fs.readFileSync(path.join(VECTORS_DIR, name), 'utf8'));
}

// `node verify.mjs <file>` as the receipt oracle.
let TMP = null;
let tmpSeq = 0;
after(() => {
  if (TMP) fs.rmSync(TMP, { recursive: true, force: true });
});
function runVerifyFile(file) {
  const r = spawnSync(process.execPath, [VERIFY_MJS, file], { encoding: 'utf8', timeout: 30000 });
  const stdout = (r.stdout || '').trim();
  let code = `unparseable(${stdout.slice(0, 60)}|${(r.stderr || '').trim().split('\n')[0].slice(0, 60)})`;
  if (stdout === 'valid') code = 'valid';
  else if (stdout.startsWith('invalid ')) code = stdout.slice(8).trim().split(/\s+/)[0].split(':')[0];
  return { status: r.status, stdout, valid: r.status === 0 && stdout === 'valid', code };
}
function runVerify(receipt, label = 'receipt') {
  if (!TMP) TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'gate1-core-'));
  tmpSeq += 1;
  const file = path.join(TMP, `${String(tmpSeq).padStart(3, '0')}-${label.replace(/[^a-z0-9_-]+/gi, '_').slice(0, 60)}.json`);
  fs.writeFileSync(file, JSON.stringify(receipt, null, 2));
  return runVerifyFile(file);
}
const reasonCode = (reason) => String(reason).trim().split(/\s+/)[0].split(':')[0];

// Runs the CLI oracle and the in-page port on one receipt and requires both to
// give `expected` ('valid' or the code verify.mjs prints after "invalid ").
async function expectVerify(P, receipt, label, expected) {
  const cli = runVerify(receipt, label);
  assert.equal(cli.code, expected, `${label}: node verify.mjs printed "${cli.stdout}" (exit ${cli.status}), expected ${expected}`);
  assert.equal(cli.valid, expected === 'valid', `${label}: node verify.mjs exit ${cli.status}, stdout "${cli.stdout}"`);
  const page = await settle(() => P.verifyReceipt(receipt));
  assert.ok(page.ok, `${label}: verifyReceipt threw ${page.error && page.error.message}`);
  assert.equal(page.value && page.value.valid, cli.valid, `${label}: verifyReceipt said ${fmt(page.value)}, verify.mjs said "${cli.stdout}"`);
  assert.equal(reasonCode(page.value.reason), cli.code, `${label}: verifyReceipt reason ${fmt(page.value.reason)}, verify.mjs said "${cli.stdout}"`);
  return cli;
}

// python3 + toy/sim.py, spawned once for the whole file.
const PY_SRC = `
import json, sys
payload = json.loads(sys.stdin.buffer.read().decode("utf-8"))
sys.path.insert(0, payload["toy"])
import sim
out = {
    "canon": [sim.canonical_json(x) for x in payload["canon"]],
    "cores": [sim.compute_receipt_core(a, b, na, nb, tb).hex() for (a, b, na, nb, tb) in payload["cores"]],
}
sys.stdout.write(json.dumps(out))
`;
let PY = null;
function python() {
  if (PY) return PY;
  const payload = { toy: TOY_DIR, canon: [...canonAscii(), ...CANON_UNICODE], cores: coreCases() };
  const r = spawnSync('python3', ['-B', '-c', PY_SRC], { input: JSON.stringify(payload), encoding: 'utf8', timeout: 60000 });
  if (r.error || r.status !== 0) {
    const why = r.error ? r.error.message : (r.stderr || '').trim().split('\n').slice(-3).join(' | ');
    PY = { error: `python3 differential against toy/sim.py could not run: ${why}` };
  } else {
    PY = { data: JSON.parse(r.stdout) };
  }
  return PY;
}
function pythonData() {
  const py = python();
  if (py.error) assert.fail(py.error);
  return py.data;
}

function deepKeys(v, out = [], prefix = '') {
  if (Array.isArray(v)) {
    v.forEach((x, i) => deepKeys(x, out, `${prefix}[${i}]`));
  } else if (v && typeof v === 'object') {
    for (const k of Object.keys(v)) {
      const p = prefix ? `${prefix}.${k}` : k;
      out.push({ key: k, path: p });
      deepKeys(v[k], out, p);
    }
  }
  return out;
}
function leaves(v, out = [], prefix = '') {
  if (Array.isArray(v)) {
    v.forEach((x, i) => leaves(x, out, `${prefix}[${i}]`));
  } else if (v && typeof v === 'object') {
    for (const k of Object.keys(v)) leaves(v[k], out, prefix ? `${prefix}.${k}` : k);
  } else {
    out.push({ path: prefix, value: v });
  }
  return out;
}

// ---------------------------------------------------------------------------
// Fixed corpora
// ---------------------------------------------------------------------------
const EPOCH = 1791538000; // the epoch sim.py's scenarios start from
const GEO_A = Object.freeze({ lat: 37.774929, lon: -122.419416, acc: 8.0 });
const GEO_B = Object.freeze({ lat: 37.774931, lon: -122.419418, acc: 6.0 });
const GEO_C = Object.freeze({ lat: 37.774935, lon: -122.41942, acc: 10.0 });

function canonAscii() {
  const a = nodeKey('canon-a').pk;
  const b = nodeKey('canon-b').pk;
  return [
    null, true, false, 0, 1, -1, 7, 42, 255, 65536, EPOCH, 4294967296, 9007199254740991, -9007199254740991,
    '', 'a', 'FACE', 'hello world', 'quote " and backslash \\', 'slash / stays', 'tab\tnewline\ncr\rbs\bff\f',
    '\u0000\u0001\u001f', '~ tilde {braces} [brackets]', '<script>&amp;</script>', '0', 'null', 'true',
    [], {}, [[]], [{}], { '': 0 }, [null, true, false, 0, '', [], {}],
    [3, 1, 2], ['b', 'a', ['d', 'c', { z: 1, a: 2 }]],
    { b: 1, a: 2 },
    { b: 1, a: 2, C: 3, _: 4, 10: 5, 9: 6, '': 7, A: 8, aa: 9, ab: 10, aB: 11, 'a b': 12, 'a.b': 13, 'a-b': 14 },
    { 2: 'two', 10: 'ten', 1: 'one', '01': 'zero-one', '-1': 'neg', 100: 'hundred' },
    { 'k"q': 1, 'k\\b': 2, 'k\nn': 3, 'k\tt': 4, 'k/s': 5 },
    { nested: { z: [1, { y: null, x: [true, false] }], a: { c: 'd', b: {} } }, list: [{ b: 2, a: 1 }, { d: 4, c: 3 }] },
    { v: 1, type: 'FACE', pk: a, nonce: '4ac9b0aec239b94e', t: EPOCH, i: 1 },
    { v: 1, type: 'FACE', pk: a, nonce: '4ac9b0aec239b94e', t: EPOCH, i: 1, geo: { lat: 37, lon: -122, acc: 8 } },
    { v: 1, type: 'SEENYOU', my_pk: a, target_pk: b, my_nonce: '4ac9b0aec239b94e', peer_nonce: '59f14fdff0698c6d', t: EPOCH + 1, i: 2 },
    {
      v: 1, type: 'HANDSHAKE', pk_A: a, pk_B: b, nonce_A: '4ac9b0aec239b94e', nonce_B: '59f14fdff0698c6d',
      t_A: EPOCH, t_B: EPOCH + 2, sig_B: 'ab'.repeat(64), t: EPOCH + 2, i: 3, geo: { lat: -33, lon: 151, acc: 12 },
    },
    { v: 1, type: 'BLOOM', pk: a, sig_A: 'cd'.repeat(64), t: EPOCH + 3, i: 4 },
  ];
}
// BMP, non-surrogate keys only: there code-unit order (contract) and code-point
// order (Python's sorted) are the same order.
const CANON_UNICODE = [
  '\u007f', '\u0080', 'é', 'é', 'ÿ', 'Ā', 'café naïve', '日本語',
  '  ', '﻿', '￿', '\u{1F600}', 'a\u{1F600}b\u{10FFFF}', 'mixed é "q" \\ \n \u{1F512}',
  ['é', ['日'], { 'é': 'é' }],
  { 'é': 1, z: 2, a: 3, Z: 4, '日': 5, 'ä': 6, 'é': 7, '\u007f': 8, '~': 9 },
  { 'д': { 'б': 1, 'а': 2 }, 'α': [{ 'γ': 1, 'β': 2 }] },
];
// What Python's json.dumps(ensure_ascii=True) does to everything outside U+0020..U+007E
// that JSON.stringify leaves raw.
const asciiEscape = (s) => s.replace(/[\u007f-￿]/g, (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`);

function coreCases() {
  const g = readVector('genuine.json');
  const k = (i) => nodeKey(`core-${i}`).pk;
  return [
    [g.pk_A, g.pk_B, g.nonce_A, g.nonce_B, g.t_B],
    [k(0), k(1), '0000000000000000', '0000000000000000', 0],
    [k(1), k(0), 'ffffffffffffffff', 'ffffffffffffffff', 1],
    [k(2), k(3), '0123456789abcdef', 'fedcba9876543210', EPOCH],
    [k(3), k(2), '0123456789abcdef', 'fedcba9876543210', EPOCH], // roles swapped: C must change
    [k(4), k(5), '1122334455667788', '8877665544332211', 2147483648], // 2^31
    [k(4), k(5), '1122334455667788', '8877665544332211', 4294967295], // 2^32 - 1
    [k(4), k(5), '1122334455667788', '8877665544332211', 4294967296], // 2^32
    [k(5), k(4), 'cafebabe12345678', '00000000000000ff', 1099511627775], // 2^40 - 1
    [k(0), k(2), 'a1b2c3d4e5f60718', '18f6e5d4c3b2a1f0', 9007199254740991], // 2^53 - 1
  ];
}

const API_FUNCTIONS = [
  'hexToBytes', 'bytesToHex', 'utf8', 'concat', 'sha256', 'canonicalJson', 'b45encode', 'b45decode',
  'generateKeyPair', 'signBytes', 'verifyBytes', 'compressPk', 'decompressPk', 'computeCore',
  'encodeFrame', 'decodeFrame', 'createDevice', 'verifyReceipt', 'sentinel', 'finalizeReceipt',
  'pentoraDigits', 'pentoraDigest', 'shortDigest', 'faceHead',
  'audioNonce', 'audioSymbols', 'audioSynth', 'createAudioDetector',
];
const ACCEPT_CODES = ['LOCKED', 'TIEBREAK_INITIATOR', 'HANDSHAKE_SIGNED', 'BLOOM_MINTED', 'BLOOM_CONFIRMED'];
const REFUSE_CODES = ['MALFORMED', 'SELF', 'BAD_SIG_F', 'STALE', 'BYSTANDER', 'NOT_ADDRESSED', 'BAD_SIG_B', 'BAD_SIG_A', 'WINDOW', 'IGNORED'];
const VERDICTS = ['CONSISTENT_CLAIMED', 'SUSPICIOUS'];
const ACOUSTIC = ['NOT_PERFORMED', 'VERIFIED_LOCAL', 'SUSPICIOUS'];
const FROZEN = ['v', 'pk_A', 'pk_B', 'nonce_A', 'nonce_B', 't_A', 't_B', 'sig_A', 'sig_B'];
const BOUND_BY_C = ['pk_A', 'pk_B', 'nonce_A', 'nonce_B', 't_B'];
const NOT_BOUND_BY_C = ['t_A', 'geo_A', 'geo_B', 'sentinel_verdict', 'position_source', 'anomalies', 'acoustic_channel', 'audio', 'clocks', 'does_not_prove', 'schema', 'alg'];
const FORBIDDEN_KEY = /confiden|percent|pct|score/i;

// ---------------------------------------------------------------------------
// Device harness
// ---------------------------------------------------------------------------
async function spawnDevice(P, { keyPair = null, geo = null, skew = 0, events = true } = {}) {
  const kp = keyPair || (await P.generateKeyPair());
  const clock = { t: EPOCH + skew };
  const seen = [];
  const opts = {
    privateKey: kp.privateKey,
    pk: kp.pk,
    now: () => clock.t,
    geo: typeof geo === 'function' ? geo : () => (geo ? { ...geo } : null),
  };
  if (events) opts.onEvent = (code, detail) => { seen.push({ code, detail }); };
  const dev = await P.createDevice(opts);
  assert.ok(dev && typeof dev === 'object', `createDevice must return a device object, got ${fmt(dev)}`);
  return { dev, kp, pk: kp.pk, clock, skew, geo, events: seen };
}
// Two fresh key pairs, lower pk first (sim.py scenarios 1, 5, 6 do the same swap).
async function orderedKeyPairs(P) {
  const a = await P.generateKeyPair();
  const b = await P.generateKeyPair();
  return a.pk < b.pk ? [a, b] : [b, a];
}
function snapshot(dev) {
  return {
    state: dev.state,
    role: dev.role ?? null,
    targetPk: dev.targetPk ?? null,
    peerNonce: dev.peerNonce ?? null,
    sessionNonce: dev.sessionNonce,
    lockedAt: dev.lockedAt ?? null,
    core: dev.core ? hex(dev.core) : null,
    receipt: dev.receipt ? refCanon(dev.receipt) : null,
  };
}
function assertResultShape(res, what) {
  assert.ok(res && typeof res === 'object', `${what}: process() must resolve to { accepted, code }, got ${fmt(res)}`);
  assert.equal(typeof res.accepted, 'boolean', `${what}: accepted must be a boolean, got ${fmt(res)}`);
  assert.equal(typeof res.code, 'string', `${what}: code must be a string, got ${fmt(res)}`);
  const allowed = res.accepted ? ACCEPT_CODES : REFUSE_CODES;
  assert.ok(allowed.includes(res.code), `${what}: ${res.accepted ? 'accepted' : 'refusal'} code ${res.code} is not in the contract (${allowed.join(', ')})`);
}
function assertAccepted(res, code, what) {
  assertResultShape(res, what);
  assert.ok(res.accepted === true && res.code === code, `${what}: expected accepted ${code}, got ${fmt(res)}`);
}
function assertRefused(res, codes, what) {
  assertResultShape(res, what);
  assert.ok(res.accepted === false && codes.includes(res.code), `${what}: expected refusal ${codes.join(' or ')}, got ${fmt(res)}`);
}

// The sim.py scenario loop: 0.5 s steps, epoch = int(start + t), both devices
// rotate a frame every step, then cameras see what the schedule allows.
async function drive(A, B, { aSeesBFrom, bSeesAFrom, bystander = null, maxT = 8.0 }) {
  const log = { A: [], B: [], packets: { A: [], B: [], C: [] } };
  for (let step = 0; step * 0.5 <= maxT; step += 1) {
    const t = step * 0.5;
    const base = Math.floor(EPOCH + t);
    for (const d of [A, B, bystander]) if (d) d.clock.t = base + d.skew;
    const pa = await A.dev.frame();
    const pb = await B.dev.frame();
    const pc = bystander ? await bystander.dev.frame() : null;
    log.packets.A.push(pa);
    log.packets.B.push(pb);
    if (pc) {
      log.packets.C.push(pc);
      log.A.push({ t, from: 'C', type: pc.F.type, before: A.dev.state, res: await A.dev.process(pc) });
      log.B.push({ t, from: 'C', type: pc.F.type, before: B.dev.state, res: await B.dev.process(pc) });
    }
    if (t >= aSeesBFrom) log.A.push({ t, from: 'B', type: pb.F.type, before: A.dev.state, res: await A.dev.process(pb) });
    if (t >= bSeesAFrom) log.B.push({ t, from: 'A', type: pa.F.type, before: B.dev.state, res: await B.dev.process(pa) });
    if (A.dev.state === 'BLOOM' && B.dev.state === 'BLOOM') break;
  }
  return log;
}
const acceptedFrom = (entries, from) => entries.filter((e) => e.from === from && e.res && e.res.accepted).map((e) => e.res.code);
const describeLog = (name, entries) => entries
  .map((e) => `  t=${e.t.toFixed(1)} ${name}(${e.before}) saw ${e.from}:${e.type} -> ${fmt(e.res)}`).join('\n');

// A lower-pk device A and a higher-pk device B exchange frames at one clock
// second until B has signed (HANDSHAKE) and A is the waiting initiator.
async function toHandshake(P, { geoA = GEO_A, geoB = GEO_B, skewA = 0, skewB = 0 } = {}) {
  const [ka, kb] = await orderedKeyPairs(P);
  const A = await spawnDevice(P, { keyPair: ka, geo: geoA, skew: skewA });
  const B = await spawnDevice(P, { keyPair: kb, geo: geoB, skew: skewB });
  const fa = await A.dev.frame();
  const fb = await B.dev.frame();
  assertAccepted(await A.dev.process(fb), 'LOCKED', 'A (lower pk) sees B FACE');
  assertAccepted(await B.dev.process(fa), 'LOCKED', 'B (higher pk) sees A FACE');
  const sa = await A.dev.frame();
  const sb = await B.dev.frame();
  assertAccepted(await A.dev.process(sb), 'TIEBREAK_INITIATOR', 'A (lower pk) sees B SEENYOU');
  assertAccepted(await B.dev.process(sa), 'HANDSHAKE_SIGNED', 'B (higher pk) sees A SEENYOU');
  return { A, B, frames: { fa, fb, sa, sb } };
}
async function toBloom(P, opts = {}) {
  const s = await toHandshake(P, opts);
  const hs = await s.B.dev.frame();
  assertAccepted(await s.A.dev.process(hs), 'BLOOM_MINTED', 'A (initiator) sees B HANDSHAKE');
  const bl = await s.A.dev.frame();
  assertAccepted(await s.B.dev.process(bl), 'BLOOM_CONFIRMED', 'B (responder) sees A BLOOM');
  return { ...s, frames: { ...s.frames, hs, bl } };
}
async function tickReset(d, what) {
  const res = await d.dev.tick();
  assert.ok(res && typeof res.reset === 'boolean', `${what}: tick() must return { reset: boolean }, got ${fmt(res)}`);
  return res.reset;
}
// Free-running exchange: every round both devices rotate and see each other.
async function pump(A, B, rounds = 6) {
  for (let r = 0; r < rounds; r += 1) {
    const pa = await A.dev.frame();
    const pb = await B.dev.frame();
    await A.dev.process(pb);
    await B.dev.process(pa);
    if (A.dev.state === 'BLOOM' && B.dev.state === 'BLOOM') return true;
  }
  return false;
}

// Independent frame builders: field names and order as sim.py rotate_frame,
// signature by node:crypto over utf8(refCanon(F)).
const withGeo = (F, geo) => (geo ? { ...F, geo: { ...geo } } : F);
const faceF = (pk, { nonce, t, i = 1, geo = null }) => withGeo({ v: 1, type: 'FACE', pk, nonce, t, i }, geo);
const seenYouF = (myPk, targetPk, { myNonce, peerNonce, t, i = 2, geo = null }) => withGeo(
  { v: 1, type: 'SEENYOU', my_pk: myPk, target_pk: targetPk, my_nonce: myNonce, peer_nonce: peerNonce, t, i }, geo);
const handshakeF = (pkA, pkB, { nonceA, nonceB, tA, tB, sigB, t, i = 3, geo = null }) => withGeo(
  { v: 1, type: 'HANDSHAKE', pk_A: pkA, pk_B: pkB, nonce_A: nonceA, nonce_B: nonceB, t_A: tA, t_B: tB, sig_B: sigB, t, i }, geo);
const bloomF = (pk, { sigA, t, i = 4 }) => ({ v: 1, type: 'BLOOM', pk, sig_A: sigA, t, i });
const signedBy = (key, F) => ({ F, sig_F: key.sign(enc(refCanon(F))) });
const resignAs = async (device, F) => ({ F, sig_F: await subtleSign(device.kp.privateKey, enc(refCanon(F))) });
const senderOf = (F) => F && (F.pk || F.my_pk || F.pk_B);

const FRAME_KEYS = {
  FACE: ['i', 'nonce', 'pk', 't', 'type', 'v'],
  SEENYOU: ['i', 'my_nonce', 'my_pk', 'peer_nonce', 't', 'target_pk', 'type', 'v'],
  HANDSHAKE: ['i', 'nonce_A', 'nonce_B', 'pk_A', 'pk_B', 'sig_B', 't', 't_A', 't_B', 'type', 'v'],
  BLOOM: ['i', 'pk', 'sig_A', 't', 'type', 'v'],
};
function assertFrameShape(packet, type, hasGeo, what) {
  assert.ok(packet && typeof packet === 'object', `${what}: frame() must resolve to a packet, got ${fmt(packet)}`);
  assert.deepEqual(Object.keys(packet).sort(), ['F', 'sig_F'], `${what}: a packet is exactly { F, sig_F }`);
  const { F, sig_F: sigF } = packet;
  assert.equal(F.type, type, `${what}: frame type`);
  assert.equal(F.v, 1, `${what}: frame version`);
  const expected = [...FRAME_KEYS[type], ...(hasGeo && type !== 'BLOOM' ? ['geo'] : [])].sort();
  assert.deepEqual(Object.keys(F).sort(), expected, `${what}: F must carry exactly the sim.py fields${hasGeo ? '' : ' and no geo key'}`);
  assert.ok(Number.isSafeInteger(F.t) && Number.isSafeInteger(F.i), `${what}: t and i must be integers`);
  assert.match(sigF, SIG_RE, `${what}: sig_F must be 128 lowercase hex`);
  assert.ok(nodeVerify(senderOf(F), enc(refCanon(F)), sigF), `${what}: sig_F must verify (node:crypto) under the sender pk over utf8(canonicalJson(F))`);
  if ('geo' in F) {
    assert.deepEqual(Object.keys(F.geo).sort(), ['acc', 'lat', 'lon'], `${what}: geo is { lat, lon, acc }`);
  }
}

function assertReceiptShape(P, r, label) {
  assert.ok(r && typeof r === 'object' && !Array.isArray(r), `${label}: receipt must be an object, got ${fmt(r)}`);
  assert.deepEqual(JSON.parse(JSON.stringify(r)), r, `${label}: receipt must be plain JSON data (no undefined values, no typed arrays)`);
  assert.equal(r.v, 0, `${label}: v`);
  assert.equal(r.schema, 'aukora.copresence.receipt.v1', `${label}: schema`);
  assert.match(r.pk_A, PK_RE, `${label}: pk_A`);
  assert.match(r.pk_B, PK_RE, `${label}: pk_B`);
  assert.match(r.nonce_A, NONCE_RE, `${label}: nonce_A`);
  assert.match(r.nonce_B, NONCE_RE, `${label}: nonce_B`);
  assert.match(r.sig_A, SIG_RE, `${label}: sig_A`);
  assert.match(r.sig_B, SIG_RE, `${label}: sig_B`);
  assert.ok(Number.isSafeInteger(r.t_A) && Number.isSafeInteger(r.t_B), `${label}: t_A and t_B must be integers`);
  assert.ok(r.t_B - r.t_A >= 0 && r.t_B - r.t_A <= 10, `${label}: window 0 <= t_B - t_A <= 10, got ${r.t_B - r.t_A}`);
  assert.ok(typeof r.alg === 'string' && r.alg.length > 0, `${label}: alg must be a non-empty string`);
  assert.ok(VERDICTS.includes(r.sentinel_verdict), `${label}: sentinel_verdict must be CONSISTENT_CLAIMED or SUSPICIOUS, got ${fmt(r.sentinel_verdict)}`);
  assert.equal(r.position_source, 'SELF_REPORTED_UNVERIFIABLE', `${label}: position_source`);
  assert.ok(Array.isArray(r.anomalies) && r.anomalies.every((a) => typeof a === 'string'), `${label}: anomalies must be an array of strings`);
  assert.equal(r.sentinel_verdict === 'SUSPICIOUS', r.anomalies.length > 0,
    `${label}: SUSPICIOUS if and only if anomalies is non-empty (verdict ${r.sentinel_verdict}, anomalies ${fmt(r.anomalies)})`);
  assert.ok(ACOUSTIC.includes(r.acoustic_channel), `${label}: acoustic_channel ${fmt(r.acoustic_channel)} not in ${ACOUSTIC.join(' | ')}`);
  assert.ok(Array.isArray(r.signed_fields) && r.signed_fields.every((f) => typeof f === 'string'), `${label}: signed_fields must be an array of strings`);
  for (const f of BOUND_BY_C) assert.ok(r.signed_fields.includes(f), `${label}: signed_fields must name ${f} (it is inside C)`);
  for (const f of NOT_BOUND_BY_C) assert.ok(!r.signed_fields.includes(f), `${label}: signed_fields must not claim ${f} (C does not bind it)`);
  assert.deepEqual(r.does_not_prove, P.DOES_NOT_PROVE, `${label}: does_not_prove must deep-equal DOES_NOT_PROVE`);
  assert.ok(r.clocks && typeof r.clocks === 'object' && !Array.isArray(r.clocks), `${label}: clocks must be an object`);
  const bad = deepKeys(r).filter((k) => FORBIDDEN_KEY.test(k.key)).map((k) => k.path);
  assert.deepEqual(bad, [], `${label}: receipts never carry a confidence / percentage / score key`);
  for (const g of ['geo_A', 'geo_B']) {
    if (g in r) {
      assert.ok(r[g] && typeof r[g] === 'object', `${label}: ${g} present but not an object (omit the key when the position is unknown)`);
      assert.deepEqual(Object.keys(r[g]).sort(), ['acc', 'lat', 'lon'], `${label}: ${g} is { lat, lon, acc }`);
      assert.ok(['lat', 'lon', 'acc'].every((k) => typeof r[g][k] === 'number' && Number.isFinite(r[g][k])), `${label}: ${g} numbers`);
    }
  }
}
const clampFlags = (r) => leaves(r.clocks).filter((l) => /clamp/i.test(l.path) && typeof l.value === 'boolean');

// Full post-conditions for a finished ceremony between `init` (lower pk) and `resp`.
async function assertCeremony(P, init, resp, label, { verdict = 'CONSISTENT_CLAIMED', verify = 'valid' } = {}) {
  assert.equal(init.dev.state, 'BLOOM', `${label}: initiator state`);
  assert.equal(resp.dev.state, 'BLOOM', `${label}: responder state`);
  assert.ok(init.pk < resp.pk, `${label}: harness error, initiator must hold the lower pk`);
  assert.equal(init.dev.role, 'INITIATOR_A', `${label}: the lower pk is INITIATOR_A`);
  assert.equal(resp.dev.role, 'RESPONDER_B', `${label}: the higher pk is RESPONDER_B`);
  const rI = init.dev.receipt;
  const rR = resp.dev.receipt;
  assert.ok(rI, `${label}: initiator has no receipt`);
  assert.ok(rR, `${label}: responder has no receipt`);
  for (const f of FROZEN) assert.deepEqual(rI[f], rR[f], `${label}: the two receipts disagree on frozen field ${f}`);
  assert.equal(rI.pk_A, init.pk, `${label}: pk_A is the lower pk`);
  assert.equal(rI.pk_B, resp.pk, `${label}: pk_B is the higher pk`);
  assert.equal(rI.nonce_A, init.dev.sessionNonce, `${label}: nonce_A is the initiator session nonce`);
  assert.equal(rI.nonce_B, resp.dev.sessionNonce, `${label}: nonce_B is the responder session nonce`);
  const C = nodeCore(rI.pk_A, rI.pk_B, rI.nonce_A, rI.nonce_B, rI.t_B);
  for (const [who, d] of [['initiator', init], ['responder', resp]]) {
    assert.ok(d.dev.core instanceof Uint8Array && d.dev.core.length === 32, `${label}: ${who} core must be a Uint8Array(32)`);
    assert.equal(hex(d.dev.core), hex(C), `${label}: ${who} core must equal C recomputed from the receipt`);
  }
  assert.ok(nodeVerify(rI.pk_A, C, rI.sig_A), `${label}: sig_A must verify over C (node:crypto)`);
  assert.ok(nodeVerify(rI.pk_B, C, rI.sig_B), `${label}: sig_B must verify over C (node:crypto)`);
  for (const [who, r] of [['initiator', rI], ['responder', rR]]) {
    assertReceiptShape(P, r, `${label} ${who} receipt`);
    if (verdict) assert.equal(r.sentinel_verdict, verdict, `${label} ${who} receipt: sentinel_verdict (anomalies ${fmt(r.anomalies)})`);
    if (verify) await expectVerify(P, r, `${label}-${who}`, verify);
  }
  return { rI, rR, C };
}

// ===========================================================================
// 0. Surface and primitives
// ===========================================================================
gate('00a PortalCore exposes the whole contract surface', (t, P) => {
  const missing = API_FUNCTIONS.filter((n) => typeof P[n] !== 'function');
  assert.deepEqual(missing, [], `PortalCore is missing functions: ${missing.join(', ')}`);
  assert.ok(Array.isArray(P.DOES_NOT_PROVE), 'PortalCore.DOES_NOT_PROVE must be an array');
});

gate('00b encoding primitives: hexToBytes, bytesToHex, utf8, concat, sha256', async (t, P) => {
  assert.equal(P.bytesToHex(new Uint8Array([0, 1, 0xab, 0xff])), '0001abff', 'bytesToHex is lowercase');
  const back = P.hexToBytes('0001abff');
  assert.ok(back instanceof Uint8Array, 'hexToBytes returns a Uint8Array');
  assert.equal(hex(back), '0001abff');
  assert.equal(hex(P.hexToBytes('')), '');
  const text = 'hé 日 \u{1F600}';
  assert.equal(hex(P.utf8(text)), Buffer.from(text, 'utf8').toString('hex'), 'utf8 is UTF-8');
  assert.equal(hex(P.concat(new Uint8Array([1, 2]), new Uint8Array(0), new Uint8Array([3]))), '010203');
  assert.equal(hex(P.concat()), '');
  const abc = await P.sha256(enc('abc'));
  assert.ok(abc instanceof Uint8Array && abc.length === 32, 'sha256 resolves to a Uint8Array(32)');
  assert.equal(hex(abc), 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
  assert.equal(hex(await P.sha256(new Uint8Array(0))), 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
  for (const n of [1, 55, 56, 64, 65, 1000]) {
    const data = detBytes(n, 7000 + n);
    assert.equal(hex(await P.sha256(data)), crypto.createHash('sha256').update(data).digest('hex'), `sha256 of ${n} bytes`);
  }
});

// ===========================================================================
// 1. Canonical JSON
// ===========================================================================
gate('01a canonicalJson is byte-identical to sim.py canonical_json (python3 differential, ASCII corpus)', (t, P) => {
  const corpus = canonAscii();
  const expected = pythonData().canon.slice(0, corpus.length);
  const problems = [];
  corpus.forEach((value, n) => {
    assert.match(JSON.stringify(value), /^[\u0000-~]*$/, `suite self-check: ASCII corpus item ${n}`);
    let out;
    try {
      out = P.canonicalJson(value);
    } catch (err) {
      problems.push(`#${n} ${fmt(value)}: threw ${err.message}`);
      return;
    }
    if (out !== expected[n]) problems.push(`#${n} ${fmt(value)}\n      page  : ${out}\n      sim.py: ${expected[n]}`);
    else if (out !== refCanon(value)) problems.push(`#${n}: suite self-check, reference canon disagrees with sim.py`);
  });
  assert.deepEqual(problems, [], `canonicalJson differs from sim.py canonical_json on ${problems.length} of ${corpus.length} items:\n    ${problems.join('\n    ')}`);
  t.diagnostic(`${corpus.length} ASCII corpus items byte-identical to sim.py`);
});

gate('01b canonicalJson on non-ASCII text equals sim.py, in one consistent escape form (reading R1)', (t, P) => {
  const offset = canonAscii().length;
  const expected = pythonData().canon.slice(offset, offset + CANON_UNICODE.length);
  const problems = [];
  const form = { sim: [], raw: [], mixed: [] };
  const rawUnits = new Set();
  CANON_UNICODE.forEach((value, n) => {
    const simForm = expected[n];
    const rawForm = refCanon(value);
    assert.ok(rawForm !== simForm && asciiEscape(rawForm) === simForm, `suite self-check: unicode corpus item ${n}`);
    let out;
    try {
      out = P.canonicalJson(value);
    } catch (err) {
      problems.push(`#${n} ${fmt(value)}: threw ${err.message}`);
      return;
    }
    if (typeof out !== 'string' || asciiEscape(out) !== simForm) {
      problems.push(`#${n} differs from sim.py beyond escape form\n      page (escaped for comparison): ${typeof out === 'string' ? asciiEscape(out) : fmt(out)}\n      sim.py                       : ${simForm}`);
      return;
    }
    for (const ch of out.match(/[\u007f-￿]/g) || []) rawUnits.add(`U+${ch.charCodeAt(0).toString(16).toUpperCase().padStart(4, '0')}`);
    if (out === simForm) form.sim.push(n);
    else if (out === rawForm) form.raw.push(n);
    else form.mixed.push(n);
  });
  assert.deepEqual(problems, [], `canonicalJson differs from sim.py canonical_json on non-ASCII input:\n    ${problems.join('\n    ')}`);
  t.diagnostic(`non-ASCII items: ${form.sim.length} in sim.py \\uXXXX form, ${form.raw.length} in raw JSON.stringify form, ${form.mixed.length} mixed`);
  // R1: sim.py (json.dumps) writes every character outside U+0020..U+007E as \uXXXX; JSON.stringify writes
  // U+007F and above raw. The contract names both, so either is accepted, but only as a whole: output that
  // escapes some of those characters and not others is identical to neither.
  const consistent = form.mixed.length === 0 && (form.sim.length === 0 || form.raw.length === 0);
  assert.ok(consistent,
    `canonicalJson is neither sim.py form nor JSON.stringify form: ${form.sim.length} items match sim.py byte for byte, `
    + `${form.raw.length} are raw JSON.stringify, ${form.mixed.length} mix the two. Left raw: ${[...rawUnits].sort().slice(0, 12).join(', ')}. `
    + 'sim.py escapes every code unit from U+007F up (U+007F DEL included).');
});

// ===========================================================================
// 2. Receipt core and signatures
// ===========================================================================
gate('02a computeCore is byte-identical to sim.py compute_receipt_core and to the verify.mjs formula (10 fixed cases)', async (t, P) => {
  const cases = coreCases();
  const py = pythonData().cores;
  assert.equal(py.length, cases.length, 'suite self-check: python returned one core per case');
  const seen = new Set();
  for (const [n, c] of cases.entries()) {
    const node = hex(nodeCore(...c));
    assert.equal(py[n], node, `suite self-check: sim.py and the verify.mjs formula disagree on case ${n}`);
    const got = await P.computeCore(...c);
    assert.ok(got instanceof Uint8Array && got.length === 32, `case ${n}: computeCore must resolve to a Uint8Array(32), got ${fmt(got)}`);
    assert.equal(hex(got), py[n], `case ${n} (t_B=${c[4]}): computeCore differs from sim.py compute_receipt_core`);
    seen.add(hex(got));
  }
  assert.equal(seen.size, cases.length, 'every case must give a distinct core');
});

gate('02b signBytes over C verifies in node:crypto exactly as verify.mjs does', async (t, P) => {
  const kp = await P.generateKeyPair();
  const peer = nodeKey('sig-peer');
  const C = await P.computeCore(kp.pk, peer.pk, '1122334455667788', '8877665544332211', EPOCH + 2);
  const sig = await P.signBytes(kp.privateKey, C);
  assert.match(sig, SIG_RE, 'signBytes must resolve to 128 lowercase hex (raw IEEE P1363 r||s)');
  const key = nodePublicKey(kp.pk);
  assert.equal(crypto.verify('sha256', C, { key, dsaEncoding: 'ieee-p1363' }, Buffer.from(sig, 'hex')), true, 'sig over C must verify the verify.mjs way');
  const other = await P.computeCore(kp.pk, peer.pk, '1122334455667788', '8877665544332211', EPOCH + 3);
  assert.equal(crypto.verify('sha256', other, { key, dsaEncoding: 'ieee-p1363' }, Buffer.from(sig, 'hex')), false, 'sig must not verify over a different core');
  assert.equal(crypto.verify('sha256', C, { key: nodePublicKey(peer.pk), dsaEncoding: 'ieee-p1363' }, Buffer.from(sig, 'hex')), false, 'sig must not verify under another key');
  // A hand-assembled v0 receipt signed with signBytes on one side and node:crypto on the other passes the CLI verifier.
  const [pkA, pkB, signA, signB] = kp.pk < peer.pk
    ? [kp.pk, peer.pk, (c) => P.signBytes(kp.privateKey, c), async (c) => peer.sign(c)]
    : [peer.pk, kp.pk, async (c) => peer.sign(c), (c) => P.signBytes(kp.privateKey, c)];
  const core = await P.computeCore(pkA, pkB, 'a1b2c3d4e5f60718', '18f6e5d4c3b2a1f0', EPOCH + 4);
  const receipt = {
    v: 0, pk_A: pkA, pk_B: pkB, nonce_A: 'a1b2c3d4e5f60718', nonce_B: '18f6e5d4c3b2a1f0',
    t_A: EPOCH + 1, t_B: EPOCH + 4, sig_A: await signA(core), sig_B: await signB(core),
  };
  const cli = runVerify(receipt, 'signBytes-receipt');
  assert.ok(cli.valid, `a receipt signed with signBytes must pass node verify.mjs, got "${cli.stdout}" (exit ${cli.status})`);
});

gate('02c verifyBytes accepts node:crypto and frozen-vector signatures; returns false, never throws, on malformed input', async (t, P) => {
  const k = nodeKey('verify-bytes');
  const msg = enc('point and bloom');
  const sig = k.sign(msg);
  assert.equal(await P.verifyBytes(k.pk, msg, sig), true, 'a node:crypto P1363 signature must verify');
  assert.equal(await P.verifyBytes(k.pk, enc('point and bloom!'), sig), false, 'wrong message');
  assert.equal(await P.verifyBytes(nodeKey('someone-else').pk, msg, sig), false, 'wrong key');
  assert.equal(await P.verifyBytes(k.pk, msg, flipHex(sig, 5)), false, 'flipped r');
  assert.equal(await P.verifyBytes(k.pk, msg, flipHex(sig, 100)), false, 'flipped s');
  const g = readVector('genuine.json');
  const C = nodeCore(g.pk_A, g.pk_B, g.nonce_A, g.nonce_B, g.t_B);
  assert.equal(await P.verifyBytes(g.pk_A, C, g.sig_A), true, 'vectors/genuine.json sig_A over C');
  assert.equal(await P.verifyBytes(g.pk_B, C, g.sig_B), true, 'vectors/genuine.json sig_B over C');
  assert.equal(await P.verifyBytes(g.pk_B, C, readVector('sig_b_tampered.json').sig_B), false, 'vectors/sig_b_tampered.json sig_B');
  assert.equal(await P.verifyBytes(g.pk_A, C, readVector('sig_a_garbage.json').sig_A), false, 'vectors/sig_a_garbage.json sig_A');
  const offCurve = `04${'00'.repeat(31)}01${'00'.repeat(31)}01`;
  const badPks = ['', '04', 'zz'.repeat(65), `03${k.pk.slice(2)}`, k.pk.slice(0, 128), `${k.pk}00`, offCurve, null, undefined, 42, {}];
  const badSigs = ['', '00', 'zz'.repeat(64), sig.slice(0, 126), `${sig}00`, '00'.repeat(64), 'ff'.repeat(64), null, undefined, 42, {}];
  for (const pk of badPks) {
    const r = await settle(() => P.verifyBytes(pk, msg, sig));
    assert.ok(r.ok, `verifyBytes threw on malformed pk ${fmt(pk)}: ${r.error && r.error.message}`);
    assert.equal(r.value, false, `verifyBytes must return false for malformed pk ${fmt(pk)}`);
  }
  for (const s of badSigs) {
    const r = await settle(() => P.verifyBytes(k.pk, msg, s));
    assert.ok(r.ok, `verifyBytes threw on malformed signature ${fmt(s)}: ${r.error && r.error.message}`);
    assert.equal(r.value, false, `verifyBytes must return false for malformed signature ${fmt(s)}`);
  }
});

// ===========================================================================
// 3. Keys
// ===========================================================================
gate('03 generateKeyPair: pk is 04||X||Y lowercase hex and the private key is a non-extractable CryptoKey', async (t, P) => {
  const kp = await P.generateKeyPair();
  assert.match(kp.pk, PK_RE, 'pk must be 130 lowercase hex chars starting 04');
  assert.doesNotThrow(() => nodePublicKey(kp.pk), 'pk must be a point on P-256');
  const key = kp.privateKey;
  assert.ok(key instanceof CryptoKey, 'privateKey must be a CryptoKey');
  assert.equal(key.type, 'private');
  assert.equal(key.extractable, false, 'privateKey.extractable must be false');
  assert.equal(key.algorithm.name, 'ECDSA');
  assert.equal(key.algorithm.namedCurve, 'P-256');
  assert.ok(key.usages.includes('sign'), 'privateKey must be usable for sign');
  await assert.rejects(globalThis.crypto.subtle.exportKey('jwk', key), 'exportKey(jwk) must reject');
  await assert.rejects(globalThis.crypto.subtle.exportKey('pkcs8', key), 'exportKey(pkcs8) must reject');
  await assert.rejects(globalThis.crypto.subtle.exportKey('raw', key), 'exportKey(raw) must reject');
  assert.ok(!Object.keys(kp).some((k) => /^(d|priv|secret|jwk|pkcs8)/i.test(k) && typeof kp[k] === 'string'), 'the key pair must not carry private material as a string');
  const second = await P.generateKeyPair();
  assert.notEqual(second.pk, kp.pk, 'two generated keys must differ');
  // The pk really belongs to the private key.
  const msg = enc('ownership');
  assert.ok(nodeVerify(kp.pk, msg, await subtleSign(key, msg)), 'pk must be the public half of privateKey');
});

// ===========================================================================
// 4. Point compression
// ===========================================================================
gate('04a compressPk / decompressPk round-trip for 50 keys (node:crypto as the oracle)', async (t, P) => {
  const parity = { '02': 0, '03': 0 };
  for (let n = 0; n < 50; n += 1) {
    const k = nodeKey(`compress-${n}`);
    const c = await P.compressPk(k.pk);
    assert.ok(c instanceof Uint8Array && c.length === 33, `key ${n}: compressPk must return a Uint8Array(33)`);
    assert.equal(hex(c), k.compressed, `key ${n}: compressed form differs from node:crypto`);
    assert.equal(await P.decompressPk(unhex(k.compressed)), k.pk, `key ${n}: decompressPk must return the original lowercase pk`);
    parity[k.compressed.slice(0, 2)] += 1;
  }
  assert.ok(parity['02'] > 0 && parity['03'] > 0, 'suite self-check: both y parities are exercised');
  const kp = await P.generateKeyPair();
  assert.equal(await P.decompressPk(await P.compressPk(kp.pk)), kp.pk, 'a generated key round-trips');
});

gate('04b decompressPk rejects an x that is not on the curve', async (t, P) => {
  const p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn;
  const b = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604bn;
  const modpow = (base, e, m) => {
    let r = 1n;
    let a = base % m;
    let k = e;
    while (k > 0n) {
      if (k & 1n) r = (r * a) % m;
      a = (a * a) % m;
      k >>= 1n;
    }
    return r;
  };
  const onCurve = (x) => {
    const rhs = (((x * x * x - 3n * x + b) % p) + p) % p;
    return rhs === 0n || modpow(rhs, (p - 1n) / 2n, p) === 1n;
  };
  const candidates = [];
  for (let x = 1n; candidates.length < 3; x += 1n) if (!onCurve(x)) candidates.push(x);
  const realX = BigInt(`0x${nodeKey('compress-0').pk.slice(2, 66)}`);
  for (let x = realX + 1n; candidates.length < 6; x += 1n) if (!onCurve(x)) candidates.push(x);
  for (const x of candidates) {
    for (const prefix of ['02', '03']) {
      const point = `${prefix}${x.toString(16).padStart(64, '0')}`;
      assert.throws(() => crypto.ECDH.convertKey(Buffer.from(point, 'hex'), 'prime256v1', undefined, undefined, 'uncompressed'), `suite self-check: ${point} is off-curve for node:crypto too`);
      const r = await settle(() => P.decompressPk(unhex(point)));
      assert.ok(!r.ok, `decompressPk must throw for off-curve ${point}, returned ${fmt(r.value)}`);
    }
  }
});

// ===========================================================================
// 5. Base45
// ===========================================================================
gate('05a Base45 round-trip for lengths 0..300, QR alphanumeric charset only', (t, P) => {
  for (let n = 0; n <= 300; n += 1) {
    const data = detBytes(n, 4500 + n);
    const text = P.b45encode(data);
    assert.equal(typeof text, 'string', `length ${n}: b45encode must return a string`);
    assert.match(text, B45_RE, `length ${n}: output must use only the QR alphanumeric charset`);
    assert.equal(text.length, Math.floor(n / 2) * 3 + (n % 2) * 2, `length ${n}: RFC 9285 output length`);
    assert.equal(text, refB45Encode(data), `length ${n}: encoding differs from RFC 9285`);
    const back = P.b45decode(text);
    assert.ok(back instanceof Uint8Array, `length ${n}: b45decode must return a Uint8Array`);
    assert.equal(hex(back), hex(data), `length ${n}: round-trip`);
  }
  for (const data of [new Uint8Array(64).fill(0), new Uint8Array(65).fill(255), Uint8Array.from({ length: 256 }, (_, i) => i)]) {
    assert.equal(hex(P.b45decode(P.b45encode(data))), hex(data), 'edge byte patterns round-trip');
  }
});

gate('05b Base45 matches the RFC 9285 vectors and b45decode throws on invalid input', (t, P) => {
  const vectors = [['AB', 'BB8'], ['Hello!!', '%69 VD92EX0'], ['base-45', 'UJCLQE7W581'], ['ietf!', 'QED8WEX0']];
  for (const [plain, encoded] of vectors) {
    assert.equal(P.b45encode(enc(plain)), encoded, `RFC 9285 encode "${plain}"`);
    assert.equal(Buffer.from(P.b45decode(encoded)).toString('utf8'), plain, `RFC 9285 decode "${encoded}"`);
  }
  assert.equal(P.b45encode(new Uint8Array([255, 255])), 'FGW', '0xFFFF is the largest triplet');
  const invalid = [
    ['a single character (length 1 mod 3)', 'A'],
    ['four characters (length 1 mod 3)', 'BB8A'],
    ['lowercase', 'bb8'],
    ['a character outside the alphabet', 'BB#'],
    ['a triplet above 65535', 'GGW'],
    ['the largest triplet ":::"', ':::'],
    ['a trailing pair above 255', '::'],
    ['non-ASCII', 'BÉB'],
  ];
  for (const [what, text] of invalid) {
    assert.throws(() => P.b45decode(text), `b45decode must throw on ${what}: ${JSON.stringify(text)}`);
  }
});

// ===========================================================================
// 6. Frames and the QR wire codec
// ===========================================================================
// Eight real packets, straight from devices: every type, with and without geo.
// `self` is the pk of the device each one is addressed to.
async function capturePackets(P) {
  const out = [];
  for (const hasGeo of [true, false]) {
    const s = await toBloom(P, hasGeo ? {} : { geoA: null, geoB: null });
    const tag = hasGeo ? 'geo' : 'no geo';
    out.push({ name: `FACE (${tag})`, type: 'FACE', hasGeo, packet: s.frames.fa, self: s.B.pk, sender: s.A.pk });
    out.push({ name: `SEENYOU (${tag})`, type: 'SEENYOU', hasGeo, packet: s.frames.sa, self: s.B.pk, sender: s.A.pk });
    out.push({ name: `HANDSHAKE (${tag})`, type: 'HANDSHAKE', hasGeo, packet: s.frames.hs, self: s.A.pk, sender: s.B.pk });
    out.push({ name: `BLOOM (${tag})`, type: 'BLOOM', hasGeo, packet: s.frames.bl, self: s.B.pk, sender: s.A.pk });
  }
  return out;
}

const QR_CAP_L_ALNUM = [[6, 195], [7, 224], [8, 279], [9, 335], [10, 395]];
function qrTableVersion(len) {
  for (const [v, cap] of QR_CAP_L_ALNUM) if (len <= cap) return v;
  return Infinity;
}
// Encodes with the pinned qrcode-generator, rasterises, decodes with the pinned jsQR.
function qrRoundTrip(qrcode, jsQR, text) {
  const qr = qrcode(0, 'L');
  qr.addData(text, 'Alphanumeric');
  qr.make();
  const modules = qr.getModuleCount();
  const scale = 4;
  const quiet = 4;
  const size = (modules + quiet * 2) * scale;
  const rgba = new Uint8ClampedArray(size * size * 4).fill(255);
  for (let r = 0; r < modules; r += 1) {
    for (let c = 0; c < modules; c += 1) {
      if (!qr.isDark(r, c)) continue;
      for (let dy = 0; dy < scale; dy += 1) {
        for (let dx = 0; dx < scale; dx += 1) {
          const o = (((r + quiet) * scale + dy) * size + ((c + quiet) * scale + dx)) * 4;
          rgba[o] = 0;
          rgba[o + 1] = 0;
          rgba[o + 2] = 0;
        }
      }
    }
  }
  const seen = jsQR(rgba, size, size);
  return { version: (modules - 17) / 4, decoded: seen ? seen.data : null };
}

async function decodeOk(P, text, selfPk, original, what) {
  const r = await settle(() => P.decodeFrame(text, { pk: selfPk }));
  assert.ok(r.ok, `${what}: decodeFrame threw ${r.error && r.error.message}`);
  const res = r.value;
  assert.ok(res && res.ok === true && res.packet, `${what}: expected { ok:true, packet }, got ${fmt(res)}`);
  assert.equal(refCanon(res.packet.F), refCanon(original.F), `${what}: canonicalJson(decoded.F) must equal canonicalJson(original.F)`);
  assert.equal(P.canonicalJson(res.packet.F), P.canonicalJson(original.F), `${what}: canonicalJson(decoded.F) must equal canonicalJson(original.F) (page canonicalJson)`);
  assert.equal(res.packet.sig_F, original.sig_F, `${what}: sig_F must survive the wire unchanged`);
  return res.packet;
}

gate('06a frames carry exactly the sim.py fields, a valid sig_F, a +1 frame index, and no geo key without a position', async (t, P) => {
  for (const hasGeo of [true, false]) {
    const s = await toBloom(P, hasGeo ? {} : { geoA: null, geoB: null });
    const { A, B, frames } = s;
    const tag = hasGeo ? 'with geo' : 'without geo';
    assertFrameShape(frames.fa, 'FACE', hasGeo, `initiator FACE ${tag}`);
    assertFrameShape(frames.fb, 'FACE', hasGeo, `responder FACE ${tag}`);
    assertFrameShape(frames.sa, 'SEENYOU', hasGeo, `initiator SEENYOU ${tag}`);
    assertFrameShape(frames.sb, 'SEENYOU', hasGeo, `responder SEENYOU ${tag}`);
    assertFrameShape(frames.hs, 'HANDSHAKE', hasGeo, `HANDSHAKE ${tag}`);
    assertFrameShape(frames.bl, 'BLOOM', hasGeo, `BLOOM ${tag}`);
    assert.equal(frames.fa.F.pk, A.pk);
    assert.equal(frames.fa.F.nonce, A.dev.sessionNonce, 'FACE.nonce is the session nonce');
    assert.match(A.dev.sessionNonce, NONCE_RE, 'sessionNonce is 16 lowercase hex');
    assert.equal(frames.fa.F.t, EPOCH, 'frames are stamped t = now()');
    assert.deepEqual([frames.fa.F.i, frames.sa.F.i, frames.bl.F.i], [1, 2, 3], 'the frame index starts at 1 and increments by one per frame()');
    assert.deepEqual([frames.fb.F.i, frames.sb.F.i, frames.hs.F.i], [1, 2, 3], 'the frame index starts at 1 and increments by one per frame()');
    assert.equal(frames.sa.F.my_pk, A.pk);
    assert.equal(frames.sa.F.target_pk, B.pk, 'SEENYOU names the locked peer');
    assert.equal(frames.sa.F.my_nonce, A.dev.sessionNonce);
    assert.equal(frames.sa.F.peer_nonce, B.dev.sessionNonce, 'SEENYOU echoes the peer nonce');
    assert.equal(frames.hs.F.pk_A, A.pk, 'HANDSHAKE.pk_A is the initiator (lower pk)');
    assert.equal(frames.hs.F.pk_B, B.pk, 'HANDSHAKE.pk_B is the responder (higher pk)');
    assert.equal(frames.hs.F.nonce_A, A.dev.sessionNonce);
    assert.equal(frames.hs.F.nonce_B, B.dev.sessionNonce);
    assert.equal(frames.hs.F.t_A, frames.sa.F.t, 't_A is the t of the initiator SEENYOU frame the responder acted on');
    const C = nodeCore(A.pk, B.pk, A.dev.sessionNonce, B.dev.sessionNonce, frames.hs.F.t_B);
    assert.ok(nodeVerify(B.pk, C, frames.hs.F.sig_B), 'HANDSHAKE.sig_B must verify over C (node:crypto)');
    assert.equal(frames.bl.F.pk, A.pk);
    assert.ok(nodeVerify(A.pk, C, frames.bl.F.sig_A), 'BLOOM.sig_A must verify over C (node:crypto)');
    if (hasGeo) {
      assert.deepEqual(frames.fa.F.geo, { ...GEO_A }, 'FACE.geo is the device position');
      assert.deepEqual(frames.hs.F.geo, { ...GEO_B }, 'HANDSHAKE.geo is the responder position');
    }
  }
});

gate('06b geo in frames is quantised: lat/lon to 1e-6, acc to 0.1 and clamped to [0, 6553.5]', async (t, P) => {
  const decimals = (x) => {
    const s = JSON.stringify(x);
    assert.match(s, /^-?\d+(\.\d+)?$/, `geo number ${s} must print as a plain decimal`);
    return s.includes('.') ? s.split('.')[1].length : 0;
  };
  const raw = { lat: 37.7749294321, lon: -122.4194164999, acc: 8.04 };
  const d = await spawnDevice(P, { geo: raw });
  const { F } = await d.dev.frame();
  assert.ok('geo' in F, 'a device with a position puts geo in its FACE frame');
  assert.ok(Math.abs(F.geo.lat - raw.lat) <= 1e-6 && decimals(F.geo.lat) <= 6, `lat ${F.geo.lat} must be ${raw.lat} quantised to 1e-6`);
  assert.ok(Math.abs(F.geo.lon - raw.lon) <= 1e-6 && decimals(F.geo.lon) <= 6, `lon ${F.geo.lon} must be ${raw.lon} quantised to 1e-6`);
  assert.ok(Math.abs(F.geo.acc - raw.acc) <= 0.1 && decimals(F.geo.acc) <= 1, `acc ${F.geo.acc} must be ${raw.acc} quantised to 0.1`);
  const huge = await spawnDevice(P, { geo: { lat: 1.5, lon: 2.5, acc: 99999 } });
  assert.equal((await huge.dev.frame()).F.geo.acc, 6553.5, 'acc is clamped to 6553.5');
  const negative = await spawnDevice(P, { geo: { lat: 1.5, lon: 2.5, acc: -5 } });
  assert.equal((await negative.dev.frame()).F.geo.acc, 0, 'acc is clamped to 0');
  const exact = await spawnDevice(P, { geo: GEO_A });
  assert.deepEqual((await exact.dev.frame()).F.geo, { ...GEO_A }, 'already-quantised values pass through unchanged');
});

gate('06c frame codec round-trip for every frame type with and without geo; each fits a version <= 10 QR (ECC L, alphanumeric)', async (t, P) => {
  let libs;
  try {
    libs = loadQr();
  } catch (err) {
    assert.fail(`the pinned vendor QR libraries could not be loaded: ${err.message}`);
  }
  for (const c of await capturePackets(P)) {
    const text = await P.encodeFrame(c.packet);
    assert.equal(typeof text, 'string', `${c.name}: encodeFrame must return a string`);
    assert.match(text, B45_RE, `${c.name}: wire text must use only the QR alphanumeric charset`);
    const decoded = await decodeOk(P, text, c.self, c.packet, c.name);
    assert.ok(nodeVerify(c.sender, enc(refCanon(decoded.F)), decoded.sig_F), `${c.name}: the decoded packet must still verify under the sender pk`);
    assert.ok(text.length <= 395, `${c.name}: ${text.length} chars does not fit a version 10 QR at ECC L alphanumeric (395 chars)`);
    const qr = qrRoundTrip(libs.qrcode, libs.jsQR, text);
    assert.ok(qr.version <= 10, `${c.name}: qrcode-generator needed version ${qr.version} for ${text.length} chars`);
    assert.ok(qr.version <= qrTableVersion(text.length), `${c.name}: suite self-check, capacity table vs qrcode-generator (${qr.version})`);
    assert.equal(qr.decoded, text, `${c.name}: jsQR must read back the exact wire text from the rendered QR`);
    await decodeOk(P, qr.decoded, c.self, c.packet, `${c.name} after QR + jsQR`);
    if (c.type === 'FACE' || c.type === 'BLOOM') {
      await decodeOk(P, text, nodeKey('codec-onlooker').pk, c.packet, `${c.name} read by a third device`);
    }
    t.diagnostic(`${c.name}: ${text.length} chars -> QR version ${qr.version} (ECC L, alphanumeric)`);
  }
});

gate('06d a SEENYOU / HANDSHAKE frame not addressed to self decodes to NOT_ADDRESSED', async (t, P) => {
  const outsider = nodeKey('codec-outsider').pk;
  for (const c of (await capturePackets(P)).filter((x) => x.type === 'SEENYOU' || x.type === 'HANDSHAKE')) {
    const text = await P.encodeFrame(c.packet);
    for (const [who, pk] of [['an outsider', outsider], ['the sender itself', c.sender]]) {
      const r = await settle(() => P.decodeFrame(text, { pk }));
      assert.ok(r.ok, `${c.name} read by ${who}: decodeFrame threw ${r.error && r.error.message}`);
      assert.ok(r.value && r.value.ok === false && r.value.code === 'NOT_ADDRESSED', `${c.name} read by ${who}: expected { ok:false, code:'NOT_ADDRESSED' }, got ${fmt(r.value)}`);
    }
  }
});

gate('06e truncated / bit-flipped / random frame text never throws and never yields an acceptable frame (reading R2)', async (t, P) => {
  const cases = await capturePackets(P);
  const tally = { refused: 0, same: 0, unverifiable: 0 };
  const codes = {};
  const problems = [];
  const check = async (what, text, selfPk, original, mustBeMalformed) => {
    const r = await settle(() => P.decodeFrame(text, { pk: selfPk }));
    if (!r.ok) {
      problems.push(`${what}: decodeFrame threw ${r.error && r.error.message}`);
      return;
    }
    const res = r.value;
    if (res && res.ok === false && typeof res.code === 'string') {
      if (mustBeMalformed && res.code !== 'MALFORMED') problems.push(`${what}: expected code MALFORMED, got ${res.code}`);
      tally.refused += 1;
      codes[res.code] = (codes[res.code] || 0) + 1;
      return;
    }
    if (!res || res.ok !== true || !res.packet || typeof res.packet !== 'object') {
      problems.push(`${what}: decodeFrame must return { ok:true, packet } or { ok:false, code }, got ${fmt(res)}`);
      return;
    }
    if (mustBeMalformed) {
      problems.push(`${what}: text that cannot hold a frame decoded ok:true ${fmt(res.packet.F)}`);
      return;
    }
    let same = false;
    let verifies = false;
    try {
      same = !!original && refCanon(res.packet.F) === refCanon(original.F) && res.packet.sig_F === original.sig_F;
      verifies = nodeVerify(senderOf(res.packet.F), enc(refCanon(res.packet.F)), res.packet.sig_F);
    } catch {
      verifies = false;
    }
    if (same) tally.same += 1;
    else if (verifies) problems.push(`${what}: corrupted text decoded to a DIFFERENT packet whose sig_F verifies: ${fmt(res.packet.F)}`);
    else tally.unverifiable += 1;
  };

  const anySelf = cases[0].self;
  // (a) Text that is not a frame under any layout: must be { ok:false, code:'MALFORMED' }.
  const garbage = ['', ' ', 'A', 'AB', 'hello world', 'not base45 at all', '{"F":{},"sig_F":""}', '\u0000', '\u{1F600}', 'A'.repeat(5000), '%%%', ':::', '$'.repeat(95)];
  for (const g of garbage) await check(`garbage ${JSON.stringify(g).slice(0, 32)}`, g, anySelf, null, true);
  const rnd = mulberry32(0x6a7e1);
  for (let n = 0; n < 40; n += 1) {
    const text = refB45Encode(detBytes(Math.floor(rnd() * 63), 9100 + n)); // < 64 bytes: no room for a signature
    await check(`random short Base45 #${n} (${text.length} chars)`, text, anySelf, null, true);
  }
  for (const c of cases) {
    const text = await P.encodeFrame(c.packet);
    for (const len of [1, 2, 3, 48, 95]) await check(`${c.name} truncated to ${len} chars`, text.slice(0, len), c.self, c.packet, true);
    // (b) Plausible-length damage: refused, or harmless.
    for (const cut of [1, 2, 3, 4, 30, 31, 32]) await check(`${c.name} truncated by ${cut} chars`, text.slice(0, text.length - cut), c.self, c.packet, false);
    await check(`${c.name} truncated to half`, text.slice(0, Math.floor(text.length / 2)), c.self, c.packet, false);
    await check(`${c.name} with 3 chars appended`, `${text}BB8`, c.self, c.packet, false);
    for (let pos = 0; pos < text.length; pos += 1) {
      const swapped = B45[(B45.indexOf(text[pos]) + 1 + (pos % 44)) % 45];
      await check(`${c.name} char ${pos} ${JSON.stringify(text[pos])}->${JSON.stringify(swapped)}`, text.slice(0, pos) + swapped + text.slice(pos + 1), c.self, c.packet, false);
    }
    const bytes = refB45Decode(text);
    for (let j = 0; j < bytes.length; j += 3) {
      const flipped = Uint8Array.from(bytes);
      flipped[j] ^= 1 << (j % 8);
      await check(`${c.name} bit ${j % 8} of byte ${j} flipped`, refB45Encode(flipped), c.self, c.packet, false);
    }
  }
  for (let n = 0; n < 60; n += 1) {
    const text = refB45Encode(detBytes(100 + Math.floor(rnd() * 160), 9300 + n));
    await check(`random Base45 #${n} (${text.length} chars)`, text, anySelf, null, false);
  }
  assert.deepEqual(problems.slice(0, 12), [], `${problems.length} corrupted inputs were mishandled (first 12 shown)`);
  t.diagnostic(`corrupted inputs: ${tally.refused} refused ${fmt(codes)}, ${tally.unverifiable} decoded but unverifiable (process() would answer BAD_SIG_F), ${tally.same} decoded to the identical packet (don't-care bits)`);
});

gate('06f independently built frames (node:crypto signer, extreme geo values) round-trip through the codec', async (t, P) => {
  const kA = nodeKey('codec-A');
  const kB = nodeKey('codec-B');
  const now = EPOCH + 5;
  const nA = '0011223344556677';
  const nB = 'ffeeddccbbaa9988';
  const C = nodeCore(kA.pk, kB.pk, nA, nB, now - 1);
  const geos = [
    null, GEO_A, GEO_C,
    { lat: -89.999999, lon: 179.999999, acc: 6553.5 },
    { lat: 90, lon: -180, acc: 0 },
    { lat: 0, lon: 0, acc: 0.1 },
    { lat: 0.000001, lon: -0.000001, acc: 1 },
    { lat: -33.868819, lon: 151.209296, acc: 1234.5 },
  ];
  for (const [n, geo] of geos.entries()) {
    const tag = geo ? `geo ${fmt(geo)}` : 'no geo';
    const face = signedBy(kA, faceF(kA.pk, { nonce: nA, t: now, i: 7 + n, geo }));
    await decodeOk(P, await P.encodeFrame(face), kB.pk, face, `hand-built FACE, ${tag}`);
    const seen = signedBy(kA, seenYouF(kA.pk, kB.pk, { myNonce: nA, peerNonce: nB, t: now, i: 8 + n, geo }));
    await decodeOk(P, await P.encodeFrame(seen), kB.pk, seen, `hand-built SEENYOU, ${tag}`);
    const hs = signedBy(kB, handshakeF(kA.pk, kB.pk, { nonceA: nA, nonceB: nB, tA: now - 2, tB: now - 1, sigB: kB.sign(C), t: now, i: 9 + n, geo }));
    await decodeOk(P, await P.encodeFrame(hs), kA.pk, hs, `hand-built HANDSHAKE, ${tag}`);
  }
  const bloom = signedBy(kA, bloomF(kA.pk, { sigA: kA.sign(C), t: now, i: 12 }));
  await decodeOk(P, await P.encodeFrame(bloom), kB.pk, bloom, 'hand-built BLOOM');
  // The longest HANDSHAKE the protocol allows before the 10 s timeout still fits the QR budget.
  // The oldest HANDSHAKE a live responder can still be showing: signed 5 s after t_A, shown until the 10 s timeout.
  const late = signedBy(kB, handshakeF(kA.pk, kB.pk, { nonceA: nA, nonceB: nB, tA: now - 15, tB: now - 10, sigB: kB.sign(nodeCore(kA.pk, kB.pk, nA, nB, now - 10)), t: now, i: 4000, geo: { lat: -89.999999, lon: -179.999999, acc: 6553.5 } }));
  const lateText = await P.encodeFrame(late);
  await decodeOk(P, lateText, kA.pk, late, 'hand-built HANDSHAKE just before the timeout');
  assert.ok(lateText.length <= 395, `worst-case HANDSHAKE is ${lateText.length} chars, over the version 10 budget of 395`);
  // A responder whose clock runs 3 s behind stamps the frame earlier than the clamped t_B it carries.
  const behind = signedBy(kB, handshakeF(kA.pk, kB.pk, { nonceA: nA, nonceB: nB, tA: now, tB: now, sigB: kB.sign(nodeCore(kA.pk, kB.pk, nA, nB, now)), t: now - 3, i: 5, geo: GEO_B }));
  await decodeOk(P, await P.encodeFrame(behind), kA.pk, behind, 'hand-built HANDSHAKE from a responder whose clock is 3 s behind');
});

gate('06g the frame index survives the wire beyond 8 and 16 bits (a page left open for a day emits more than 65535 frames)', async (t, P) => {
  const k = nodeKey('codec-index');
  const reader = nodeKey('codec-index-reader').pk;
  for (const i of [255, 256, 65535, 65536, 100000, 1000000]) {
    const face = signedBy(k, faceF(k.pk, { nonce: '0f1e2d3c4b5a6978', t: EPOCH + 86400, i, geo: GEO_B }));
    const enc1 = await settle(() => P.encodeFrame(face));
    assert.ok(enc1.ok, `encodeFrame threw for frame index i=${i}: ${enc1.error && enc1.error.message}`);
    await decodeOk(P, enc1.value, reader, face, `FACE with i=${i}`);
  }
});

// ===========================================================================
// 7. sim.py scenarios 1, 3, 6 through createDevice
// ===========================================================================
const TRACE_INITIATOR = ['LOCKED', 'TIEBREAK_INITIATOR', 'BLOOM_MINTED'];
const TRACE_RESPONDER = ['LOCKED', 'HANDSHAKE_SIGNED', 'BLOOM_CONFIRMED'];

gate('07a sim.py scenario 1: genuine ceremony, A sees B from 2.0 s, B sees A from 2.5 s', async (t, P) => {
  const [ka, kb] = await orderedKeyPairs(P);
  const A = await spawnDevice(P, { keyPair: ka, geo: GEO_A });
  const B = await spawnDevice(P, { keyPair: kb, geo: GEO_B });
  for (const d of [A, B]) {
    assert.equal(d.dev.state, 'FACE', 'a new device starts in FACE');
    assert.ok(d.dev.role == null && d.dev.targetPk == null && d.dev.peerNonce == null, 'a new device has no role, target or peer nonce');
    assert.ok(d.dev.core == null && d.dev.receipt == null && d.dev.lockedAt == null, 'a new device has no core, receipt or lock time');
    assert.equal(d.dev.pk, d.pk, 'device.pk');
    assert.match(d.dev.sessionNonce, NONCE_RE, 'device.sessionNonce');
  }
  const log = await drive(A, B, { aSeesBFrom: 2.0, bSeesAFrom: 2.5 });
  const trace = `\n${describeLog('A', log.A)}\n${describeLog('B', log.B)}`;
  for (const e of [...log.A, ...log.B]) assertResultShape(e.res, `process() at t=${e.t}`);
  assert.deepEqual(acceptedFrom(log.A, 'B'), TRACE_INITIATOR, `initiator accepted codes${trace}`);
  assert.deepEqual(acceptedFrom(log.B, 'A'), TRACE_RESPONDER, `responder accepted codes${trace}`);
  const { rI } = await assertCeremony(P, A, B, 'scenario-1');
  assert.equal(A.dev.targetPk, B.pk);
  assert.equal(B.dev.targetPk, A.pk);
  assert.equal(rI.t_A, EPOCH + 3, 't_A is the t of the initiator SEENYOU frame the responder acted on (sim.py: epoch + 3)');
  assert.equal(rI.t_B, EPOCH + 3, 't_B is the responder clock when it signed (sim.py: epoch + 3)');
  assert.deepEqual(rI.geo_A, { ...GEO_A }, 'geo_A');
  assert.deepEqual(rI.geo_B, { ...GEO_B }, 'geo_B');
  assert.deepEqual(B.dev.receipt.geo_A, { ...GEO_A }, 'responder receipt geo_A');
  assert.deepEqual(B.dev.receipt.geo_B, { ...GEO_B }, 'responder receipt geo_B');
  assert.equal(rI.acoustic_channel, 'NOT_PERFORMED', 'no audio was performed (fail-open law, SPEC 6.2)');
  assert.deepEqual(rI.anomalies, []);
  for (const f of clampFlags(rI).concat(clampFlags(B.dev.receipt))) assert.equal(f.value, false, `no clamp happened, but clocks.${f.path} is true`);
});

for (const [name, lowerIsA] of [['A holds the lower pk', true], ['A holds the higher pk', false]]) {
  gate(`07b sim.py scenario 3: symmetric start, both see each other from 1.0 s (${name})`, async (t, P) => {
    const [lo, hi] = await orderedKeyPairs(P);
    const A = await spawnDevice(P, { keyPair: lowerIsA ? lo : hi, geo: GEO_A, events: lowerIsA });
    const B = await spawnDevice(P, { keyPair: lowerIsA ? hi : lo, geo: GEO_B });
    const log = await drive(A, B, { aSeesBFrom: 1.0, bSeesAFrom: 1.0 });
    const trace = `\n${describeLog('A', log.A)}\n${describeLog('B', log.B)}`;
    const [init, resp] = lowerIsA ? [A, B] : [B, A];
    assert.deepEqual(acceptedFrom(lowerIsA ? log.A : log.B, lowerIsA ? 'B' : 'A'), TRACE_INITIATOR, `lower-pk device accepted codes${trace}`);
    assert.deepEqual(acceptedFrom(lowerIsA ? log.B : log.A, lowerIsA ? 'A' : 'B'), TRACE_RESPONDER, `higher-pk device accepted codes${trace}`);
    const { rI } = await assertCeremony(P, init, resp, `scenario-3-${lowerIsA ? 'a-low' : 'a-high'}`);
    assert.equal(rI.t_A, EPOCH + 1);
    assert.equal(rI.t_B, EPOCH + 1);
    assert.deepEqual(rI[lowerIsA ? 'geo_A' : 'geo_B'], { ...GEO_A }, 'each geo is filed under the role its device took');
    assert.deepEqual(rI[lowerIsA ? 'geo_B' : 'geo_A'], { ...GEO_B }, 'each geo is filed under the role its device took');
    assert.ok(log.packets.A.length <= 6, `the collision must resolve within 2.0 s of first sight (SPEC Q2), took ${log.packets.A.length} half-second steps`);
  });
}

gate('07c sim.py scenario 6: a bystander device C (SEENYOU -> D) is ignored and A and B still bloom', async (t, P) => {
  const [ka, kb] = await orderedKeyPairs(P);
  const A = await spawnDevice(P, { keyPair: ka, geo: GEO_A });
  const B = await spawnDevice(P, { keyPair: kb, geo: GEO_B });
  const C = await spawnDevice(P, { geo: GEO_C });
  const D = nodeKey('scenario-6-D');
  // sim.py forces C into SEENYOU(target D); here C gets there by seeing D's FACE.
  assertAccepted(await C.dev.process(signedBy(D, faceF(D.pk, { nonce: '1234567812345678', t: EPOCH }))), 'LOCKED', 'bystander C locks on D');
  assert.equal(C.dev.targetPk, D.pk);
  const log = await drive(A, B, { aSeesBFrom: 1.0, bSeesAFrom: 1.0, bystander: C });
  const trace = `\n${describeLog('A', log.A)}\n${describeLog('B', log.B)}`;
  for (const pc of log.packets.C) {
    assert.equal(pc.F.type, 'SEENYOU', 'suite self-check: C keeps emitting SEENYOU');
    assert.equal(pc.F.target_pk, D.pk, 'suite self-check: C targets D');
  }
  for (const [name, entries] of [['A', log.A], ['B', log.B]]) {
    for (const e of entries.filter((x) => x.from === 'C')) {
      const allowed = e.before === 'FACE' ? ['NOT_ADDRESSED', 'IGNORED', 'BYSTANDER'] : ['BYSTANDER', 'NOT_ADDRESSED'];
      assertRefused(e.res, allowed, `${name} in ${e.before} sees bystander C at t=${e.t}`);
    }
  }
  assert.deepEqual(acceptedFrom(log.A, 'B'), TRACE_INITIATOR, `initiator accepted codes${trace}`);
  assert.deepEqual(acceptedFrom(log.B, 'A'), TRACE_RESPONDER, `responder accepted codes${trace}`);
  const { rI } = await assertCeremony(P, A, B, 'scenario-6');
  assert.equal(A.dev.targetPk, B.pk, 'A stayed bound to B');
  assert.equal(B.dev.targetPk, A.pk, 'B stayed bound to A');
  assert.ok(![rI.pk_A, rI.pk_B].includes(C.pk) && ![rI.pk_A, rI.pk_B].includes(D.pk), 'the receipt names only A and B');
  assert.equal(C.dev.state, 'SEENYOU', 'the bystander was not pulled into the ceremony');
  assert.equal(C.dev.receipt ?? null, null);
});

// ===========================================================================
// 8. Negative scenarios
// ===========================================================================
gate('08a stale frame (8 s old) is refused with STALE and the device stays in FACE; the 5 s boundary is inclusive', async (t, P) => {
  const peer = nodeKey('stale-peer');
  const B = await spawnDevice(P, { geo: GEO_B });
  const stale = signedBy(peer, faceF(peer.pk, { nonce: '1234567812345678', t: EPOCH - 8 }));
  assertRefused(await B.dev.process(stale), ['STALE'], 'FACE frame 8 s old (sim.py scenario 4)');
  assert.equal(B.dev.state, 'FACE');
  assert.ok(B.dev.targetPk == null, 'a stale frame must not bind a target');
  for (const delta of [-6, 6, -3600, 3600]) {
    assertRefused(await B.dev.process(signedBy(peer, faceF(peer.pk, { nonce: '1234567812345678', t: EPOCH + delta }))), ['STALE'], `FACE frame stamped ${delta} s from now`);
    assert.equal(B.dev.state, 'FACE');
  }
  for (const delta of [-5, 5, 0]) {
    const fresh = await spawnDevice(P, { geo: GEO_B });
    assertAccepted(await fresh.dev.process(signedBy(peer, faceF(peer.pk, { nonce: '1234567812345678', t: EPOCH + delta }))), 'LOCKED', `FACE frame stamped ${delta} s from now is fresh (|now - t| <= 5)`);
    assert.equal(fresh.dev.state, 'SEENYOU');
    assert.equal(fresh.dev.targetPk, peer.pk);
    assert.equal(fresh.dev.peerNonce, '1234567812345678');
    assert.equal(fresh.dev.lockedAt, EPOCH, 'lockedAt is the local clock at lock');
  }
});

gate('08b a flipped sig_F, or a changed F under the old sig_F, is refused with BAD_SIG_F (sim.py scenario 7)', async (t, P) => {
  const A = await spawnDevice(P, { geo: GEO_A });
  const B = await spawnDevice(P, { geo: GEO_B });
  const packet = await A.dev.frame();
  const last = packet.sig_F[packet.sig_F.length - 1];
  const tampered = { F: packet.F, sig_F: packet.sig_F.slice(0, -1) + (last !== '0' ? '0' : '1') };
  assertRefused(await B.dev.process(tampered), ['BAD_SIG_F'], 'FACE with the last sig_F hex digit changed');
  assert.equal(B.dev.state, 'FACE');
  assertRefused(await B.dev.process({ F: packet.F, sig_F: flipHex(packet.sig_F, 3) }), ['BAD_SIG_F'], 'FACE with r flipped');
  assertRefused(await B.dev.process({ F: { ...packet.F, nonce: 'deadbeefdeadbeef' }, sig_F: packet.sig_F }), ['BAD_SIG_F'], 'FACE with a swapped nonce');
  assertRefused(await B.dev.process({ F: { ...packet.F, i: packet.F.i + 1 }, sig_F: packet.sig_F }), ['BAD_SIG_F'], 'FACE with a bumped frame index');
  const thief = nodeKey('pk-thief');
  assertRefused(await B.dev.process({ F: { ...packet.F, pk: thief.pk }, sig_F: packet.sig_F }), ['BAD_SIG_F'], 'FACE re-attributed to another pk');
  // BAD_SIG_F is checked before STALE.
  const old = faceF(thief.pk, { nonce: '1234567812345678', t: EPOCH - 60 });
  assertRefused(await B.dev.process({ F: old, sig_F: flipHex(thief.sign(enc(refCanon(old))), 9) }), ['BAD_SIG_F'], 'stale frame with a bad signature (check order: BAD_SIG_F before STALE)');
  assert.equal(B.dev.state, 'FACE');
  assert.ok(B.dev.targetPk == null);
  assertAccepted(await B.dev.process(packet), 'LOCKED', 'the untampered frame');
});

gate('08c structurally broken packets are refused with MALFORMED and never throw', async (t, P) => {
  const B = await spawnDevice(P, { geo: GEO_B });
  const k = nodeKey('malformed-peer');
  const good = signedBy(k, faceF(k.pk, { nonce: '1234567812345678', t: EPOCH }));
  // No packet, no F, or no signer to check against: MALFORMED. Where a signer is
  // named but the rest is unusable, sim.py calls it a bad frame signature, so
  // BAD_SIG_F is accepted there too.
  const M = ['MALFORMED'];
  const MS = ['MALFORMED', 'BAD_SIG_F'];
  const broken = [
    ['null', null, M], ['undefined', undefined, M], ['a string', 'FACE', M], ['a number', 7, M], ['an array', [], M], ['{}', {}, M],
    ['F: null', { F: null, sig_F: good.sig_F }, M], ['F: {}', { F: {}, sig_F: good.sig_F }, M],
    ['no sender pk', { F: { v: 1, type: 'FACE', nonce: '1234567812345678', t: EPOCH, i: 1 }, sig_F: good.sig_F }, M],
    ['no sig_F', { F: good.F }, MS], ['sig_F not a string', { F: good.F, sig_F: 12 }, MS],
    ['pk not hex', { F: { ...good.F, pk: 'zz'.repeat(65) }, sig_F: good.sig_F }, MS],
    ['no type', { F: { v: 1, pk: k.pk, nonce: '1234567812345678', t: EPOCH, i: 1 }, sig_F: good.sig_F }, MS],
  ];
  for (const [what, packet, allowed] of broken) {
    const r = await settle(() => B.dev.process(packet));
    assert.ok(r.ok, `process(${what}) threw ${r.error && r.error.message}`);
    assertRefused(r.value, allowed, `process(${what})`);
    assert.equal(B.dev.state, 'FACE');
    assert.ok(B.dev.targetPk == null, `process(${what}) must not bind a target`);
  }
  assertAccepted(await B.dev.process(good), 'LOCKED', 'the well-formed frame from the same signer');
});

gate('08d a forged SEENYOU from a third key binds the victim to the forger, never to the real peer (sim.py scenario 2)', async (t, P) => {
  const A = await spawnDevice(P, { geo: GEO_A });
  const B = await spawnDevice(P, { geo: GEO_B });
  const forger = nodeKey('relay-forger');
  const packetA = await A.dev.frame();
  const forged = signedBy(forger, {
    v: 1, type: 'SEENYOU', my_pk: forger.pk, target_pk: B.pk, my_nonce: 'cafebabe12345678', peer_nonce: packetA.F.nonce, t: EPOCH, i: 1,
  });
  assertAccepted(await B.dev.process(forged), 'LOCKED', 'B sees the forged SEENYOU');
  assert.equal(B.dev.targetPk, forger.pk, 'B is bound to the key that signed the frame');
  assert.notEqual(B.dev.targetPk, A.pk, 'B is not bound to A');
  assert.equal(B.dev.peerNonce, 'cafebabe12345678');
  assert.ok(A.dev.targetPk == null, 'A is untouched');
  const sb = await B.dev.frame();
  assert.equal(sb.F.type, 'SEENYOU');
  assert.equal(sb.F.target_pk, forger.pk, "B's SEENYOU names the forger");
  // A and B now look at each other for 3 s: no knot between A and B can form.
  for (let step = 1; step <= 6; step += 1) {
    const now = Math.floor(EPOCH + step * 0.5);
    A.clock.t = now;
    B.clock.t = now;
    const pa = await A.dev.frame();
    const pb = await B.dev.frame();
    assertRefused(await B.dev.process(pa), ['BYSTANDER', 'NOT_ADDRESSED'], `B (locked on the forger) sees A's ${pa.F.type}`);
    assertRefused(await A.dev.process(pb), ['NOT_ADDRESSED', 'IGNORED', 'BYSTANDER'], `A sees B's ${pb.F.type} naming the forger`);
    assert.equal(B.dev.targetPk, forger.pk, 'B never rebinds to A');
    assert.equal(A.dev.state, 'FACE');
  }
  assert.ok(A.dev.receipt == null && B.dev.receipt == null, 'no receipt between A and B');
  // The forger holds no key of A: a signature by the forger cannot stand in for A's.
  assertRefused(await B.dev.process({ F: { ...packetA.F, t: B.clock.t }, sig_F: forger.sign(enc(refCanon({ ...packetA.F, t: B.clock.t }))) }), ['BAD_SIG_F'], "A's FACE re-signed by the forger");
});

gate('08e a HANDSHAKE with a tampered sig_B is refused with BAD_SIG_B and no receipt is minted', async (t, P) => {
  const { A, B } = await toHandshake(P);
  const hs = await B.dev.frame();
  assert.equal(hs.F.type, 'HANDSHAKE');
  const before = snapshot(A.dev);
  // The frame signature is re-made with B's own key, so only sig_B is wrong.
  const tampered = await resignAs(B, { ...hs.F, sig_B: flipHex(hs.F.sig_B, 20) });
  assertRefused(await A.dev.process(tampered), ['BAD_SIG_B'], 'HANDSHAKE with one sig_B digit flipped');
  assert.deepEqual(snapshot(A.dev), before, 'the initiator must not change state');
  // A real signature by B, but over the core of a different ceremony.
  const otherCore = nodeCore(hs.F.pk_A, hs.F.pk_B, hs.F.nonce_B, hs.F.nonce_A, hs.F.t_B);
  const transplanted = await resignAs(B, { ...hs.F, sig_B: await subtleSign(B.kp.privateKey, otherCore) });
  assertRefused(await A.dev.process(transplanted), ['BAD_SIG_B'], 'HANDSHAKE whose sig_B signs a different core');
  // sig_B made by a key that is not pk_B.
  const stranger = nodeKey('handshake-stranger');
  const impostor = await resignAs(B, { ...hs.F, sig_B: stranger.sign(nodeCore(hs.F.pk_A, hs.F.pk_B, hs.F.nonce_A, hs.F.nonce_B, hs.F.t_B)) });
  assertRefused(await A.dev.process(impostor), ['BAD_SIG_B'], 'HANDSHAKE whose sig_B was made by another key');
  assert.equal(A.dev.state, 'SEENYOU');
  assert.ok(A.dev.receipt == null, 'no receipt after a bad sig_B');
  assertAccepted(await A.dev.process(hs), 'BLOOM_MINTED', 'the untampered HANDSHAKE');
});

gate('08f a BLOOM with a tampered sig_A is refused with BAD_SIG_A and no receipt is minted', async (t, P) => {
  const { A, B } = await toHandshake(P);
  const hs = await B.dev.frame();
  assertAccepted(await A.dev.process(hs), 'BLOOM_MINTED', 'A sees HANDSHAKE');
  const bl = await A.dev.frame();
  assert.equal(bl.F.type, 'BLOOM');
  const before = snapshot(B.dev);
  const tampered = await resignAs(A, { ...bl.F, sig_A: flipHex(bl.F.sig_A, 20) });
  assertRefused(await B.dev.process(tampered), ['BAD_SIG_A'], 'BLOOM with one sig_A digit flipped');
  assert.deepEqual(snapshot(B.dev), before, 'the responder must not change state');
  const otherCore = nodeCore(hs.F.pk_A, hs.F.pk_B, hs.F.nonce_A, hs.F.nonce_B, hs.F.t_B + 1);
  const transplanted = await resignAs(A, { ...bl.F, sig_A: await subtleSign(A.kp.privateKey, otherCore) });
  assertRefused(await B.dev.process(transplanted), ['BAD_SIG_A'], 'BLOOM whose sig_A signs a different core (other t_B)');
  assert.equal(B.dev.state, 'HANDSHAKE');
  assert.ok(B.dev.receipt == null, 'no receipt after a bad sig_A');
  assertAccepted(await B.dev.process(bl), 'BLOOM_CONFIRMED', 'the untampered BLOOM');
});

gate('08g a frame carrying the device\'s own pk is refused with SELF', async (t, P) => {
  const B = await spawnDevice(P, { geo: GEO_B });
  const own = await B.dev.frame();
  assertRefused(await B.dev.process(own), ['SELF'], 'own FACE frame (a mirror)');
  assert.equal(B.dev.state, 'FACE');
  assert.ok(B.dev.targetPk == null);
  // SELF is checked before BAD_SIG_F.
  assertRefused(await B.dev.process({ F: faceF(B.pk, { nonce: '1234567812345678', t: EPOCH }), sig_F: '00'.repeat(64) }), ['SELF'], 'own pk with a garbage signature (check order: SELF before BAD_SIG_F)');
  const peer = nodeKey('self-test-peer');
  assertAccepted(await B.dev.process(signedBy(peer, faceF(peer.pk, { nonce: '1234567812345678', t: EPOCH }))), 'LOCKED', 'peer FACE');
  const ownSeenYou = await B.dev.frame();
  assert.equal(ownSeenYou.F.type, 'SEENYOU');
  const before = snapshot(B.dev);
  assertRefused(await B.dev.process(ownSeenYou), ['SELF'], 'own SEENYOU frame');
  assert.deepEqual(snapshot(B.dev), before);
});

gate('08h bystander frames while locked are refused with BYSTANDER or NOT_ADDRESSED and change nothing', async (t, P) => {
  const C = await spawnDevice(P, { geo: GEO_C });
  const D = nodeKey('bystander-D');
  const X = nodeKey('bystander-X');
  const faceC = await C.dev.frame();
  assertAccepted(await C.dev.process(signedBy(D, faceF(D.pk, { nonce: '1234567812345678', t: EPOCH }))), 'LOCKED', 'C locks on D');
  const seenYouC = await C.dev.frame();
  const strayHandshake = signedBy(X, handshakeF(D.pk, X.pk, {
    nonceA: '1234567812345678', nonceB: '8765432187654321', tA: EPOCH, tB: EPOCH,
    sigB: X.sign(nodeCore(D.pk, X.pk, '1234567812345678', '8765432187654321', EPOCH)), t: EPOCH,
  }));
  const strayBloom = signedBy(X, bloomF(X.pk, { sigA: X.sign(enc('not a core')), t: EPOCH }));
  const strays = [['FACE from C', faceC], ['SEENYOU C -> D', seenYouC], ['HANDSHAKE X -> D', strayHandshake], ['BLOOM from X', strayBloom]];

  const hsState = await toHandshake(P);
  const bloomState = await toBloom(P);
  const lockedOnly = await spawnDevice(P, { geo: GEO_A });
  const target = nodeKey('bystander-target');
  assertAccepted(await lockedOnly.dev.process(signedBy(target, faceF(target.pk, { nonce: 'aaaaaaaaaaaaaaaa', t: EPOCH }))), 'LOCKED', 'device locks on its target');
  const subjects = [
    ['SEENYOU (locked via FACE)', lockedOnly, ['BYSTANDER', 'NOT_ADDRESSED']],
    ['SEENYOU (initiator awaiting HANDSHAKE)', hsState.A, ['BYSTANDER', 'NOT_ADDRESSED']],
    ['HANDSHAKE (responder awaiting BLOOM)', hsState.B, ['BYSTANDER', 'NOT_ADDRESSED']],
    ['BLOOM (initiator)', bloomState.A, ['BYSTANDER', 'NOT_ADDRESSED', 'IGNORED']],
    ['BLOOM (responder)', bloomState.B, ['BYSTANDER', 'NOT_ADDRESSED', 'IGNORED']],
  ];
  for (const [state, subject, allowed] of subjects) {
    const before = snapshot(subject.dev);
    for (const [what, packet] of strays) {
      assertRefused(await subject.dev.process(packet), allowed, `${state} sees ${what}`);
      assert.deepEqual(snapshot(subject.dev), before, `${state} must not change after ${what}`);
    }
  }
  // The locked devices are still live: the ceremony in progress completes.
  const hs = await hsState.B.dev.frame();
  assertAccepted(await hsState.A.dev.process(hs), 'BLOOM_MINTED', 'the real HANDSHAKE after the bystander traffic');
});

gate('08i a HANDSHAKE replayed into a later session of the same initiator is refused (session nonce binding)', async (t, P) => {
  const { A, B } = await toHandshake(P);
  for (const d of [A, B]) d.clock.t = EPOCH + 11;
  assert.equal(await tickReset(A, 'A at +11 s'), true, 'A times out of SEENYOU');
  assert.equal(A.dev.state, 'FACE');
  // A locks on B again (a FACE signed with B's key), now under a new session nonce.
  const face = await resignAs(B, faceF(B.pk, { nonce: B.dev.sessionNonce, t: EPOCH + 11 }));
  assertAccepted(await A.dev.process(face), 'LOCKED', 'A (new session) sees a FACE from B');
  // B never ticked: it still shows the HANDSHAKE it signed for A's OLD nonce, freshly stamped.
  const old = await B.dev.frame();
  assert.equal(old.F.type, 'HANDSHAKE');
  assert.notEqual(old.F.nonce_A, A.dev.sessionNonce, 'suite self-check: the HANDSHAKE names the old nonce');
  assertRefused(await A.dev.process(old), ['BAD_SIG_B', 'NOT_ADDRESSED', 'IGNORED', 'WINDOW'], 'HANDSHAKE signed for a previous session nonce');
  assert.equal(A.dev.state, 'SEENYOU');
  assert.ok(A.dev.receipt == null, 'a replayed HANDSHAKE must not mint a receipt');
});

gate('08j a SEENYOU from a third key, addressed to a device already locked on its peer, cannot derail that ceremony', async (t, P) => {
  // sim.py rule 3 lets such a frame through (it is addressed to us) and its SEENYOU branch then tiebreaks
  // against the THIRD key: a higher-pk victim signs a HANDSHAKE for the outsider while still targeting its
  // real peer, and the real ceremony stalls until the timeout. Whatever the device answers, it must not sign
  // for a key it is not locked on, and the ceremony in progress must still complete.
  const third = Array.from({ length: 16 }, (_, n) => nodeKey(`hijack-${n}`)).sort((x, y) => (x.pk < y.pk ? -1 : 1))[0];
  for (const victimName of ['B', 'A']) {
    let ka;
    let kb;
    do {
      [ka, kb] = await orderedKeyPairs(P);
    } while (!(ka.pk > third.pk)); // both device keys sit above the outsider's: the "higher pk signs" branch
    const A = await spawnDevice(P, { keyPair: ka, geo: GEO_A });
    const B = await spawnDevice(P, { keyPair: kb, geo: GEO_B });
    const fa = await A.dev.frame();
    const fb = await B.dev.frame();
    assertAccepted(await A.dev.process(fb), 'LOCKED', 'A sees B FACE');
    assertAccepted(await B.dev.process(fa), 'LOCKED', 'B sees A FACE');
    const [victim, peer] = victimName === 'B' ? [B, A] : [A, B];
    const forged = signedBy(third, seenYouF(third.pk, victim.pk, { myNonce: 'c0c0c0c0c0c0c0c0', peerNonce: victim.dev.sessionNonce, t: EPOCH, i: 1 }));
    const res = await victim.dev.process(forged);
    assertResultShape(res, `${victimName} (locked on its peer) sees a third key's SEENYOU`);
    assert.ok(!(res.accepted && res.code === 'HANDSHAKE_SIGNED'), `${victimName}, locked on its peer, signed a HANDSHAKE for a third key: ${fmt(res)}`);
    assert.equal(victim.dev.targetPk, peer.pk, `${victimName} must stay bound to its peer`);
    if (victim.dev.state === 'HANDSHAKE') {
      const { F } = await victim.dev.frame();
      assert.equal(F.pk_A, peer.pk, `${victimName}: HANDSHAKE.pk_A must be the locked peer`);
      assert.ok(nodeVerify(F.pk_B, nodeCore(F.pk_A, F.pk_B, F.nonce_A, F.nonce_B, F.t_B), F.sig_B), `${victimName}: the HANDSHAKE it shows carries a sig_B that does not sign the core the frame names`);
    }
    assert.ok(await pump(A, B), `after a third key's SEENYOU to ${victimName} the real ceremony no longer completes (states ${A.dev.state} / ${B.dev.state}, last answer ${fmt(res)})`);
    const { rI } = await assertCeremony(P, A, B, `third-key-seenyou-to-${victimName}`);
    assert.ok(![rI.pk_A, rI.pk_B].includes(third.pk), 'the receipt names only A and B');
  }
});

// ===========================================================================
// 9. Owner-decided differences from sim.py
// ===========================================================================
gate('09a responder clock 3 s behind the initiator: t_B is clamped up to t_A, the clamp is recorded, the verdict is SUSPICIOUS (R3, R4)', async (t, P) => {
  const { A, B, frames } = await toBloom(P, { skewB: -3 });
  const { rI, rR } = await assertCeremony(P, A, B, 'skew-3s', { verdict: null });
  assert.equal(rR.t_A, EPOCH, "t_A is the initiator's frame time");
  assert.ok(rR.t_B >= rR.t_A, `t_B (${rR.t_B}) must not be earlier than t_A (${rR.t_A})`);
  assert.equal(rR.t_B, EPOCH, 't_B = max(now(), t_A) = t_A when the responder clock is behind');
  assert.equal(frames.hs.F.t_B, EPOCH, 'the HANDSHAKE frame carries the clamped t_B');
  assert.equal(frames.hs.F.t, EPOCH - 3, 'the frame itself is still stamped with the raw local clock');
  const flags = clampFlags(rR);
  assert.ok(flags.some((f) => f.value === true), `responder receipt.clocks must record the clamp as a true boolean under a key matching /clamp/i, got ${fmt(rR.clocks)}`);
  assert.ok(leaves(rR.clocks).some((l) => l.value === EPOCH - 3), `responder receipt.clocks must record its raw local clock (${EPOCH - 3}), got ${fmt(rR.clocks)}`);
  assert.equal(rR.sentinel_verdict, 'SUSPICIOUS', `raw skew of 3 s exceeds 2 s: the responder receipt must be SUSPICIOUS (anomalies ${fmt(rR.anomalies)})`);
  t.diagnostic(`initiator receipt under 3 s responder skew: ${rI.sentinel_verdict}, clocks ${fmt(rI.clocks)}`);
});

gate('09b ordinary clock skew (responder 1 s behind, or 2 s ahead) still yields a valid receipt with t_B >= t_A', async (t, P) => {
  const behind = await toBloom(P, { skewB: -1 });
  const b = await assertCeremony(P, behind.A, behind.B, 'skew-1s-behind', { verdict: null });
  assert.equal(b.rR.t_A, EPOCH);
  assert.equal(b.rR.t_B, EPOCH, 'clamped to t_A');
  assert.ok(clampFlags(b.rR).some((f) => f.value === true), `the 1 s clamp must be recorded, got ${fmt(b.rR.clocks)}`);
  assert.ok(leaves(b.rR.clocks).some((l) => l.value === EPOCH - 1), `the raw local clock (${EPOCH - 1}) must be recorded, got ${fmt(b.rR.clocks)}`);
  assert.equal(b.rR.sentinel_verdict, 'CONSISTENT_CLAIMED', `a raw skew of 1 s does not exceed 2 s and must not be SUSPICIOUS (anomalies ${fmt(b.rR.anomalies)})`);
  const ahead = await toBloom(P, { skewB: 2 });
  const a = await assertCeremony(P, ahead.A, ahead.B, 'skew-2s-ahead', { verdict: null });
  assert.equal(a.rR.t_A, EPOCH);
  assert.equal(a.rR.t_B, EPOCH + 2, 'a responder clock ahead of t_A is used as is');
  for (const f of clampFlags(a.rR)) assert.equal(f.value, false, `nothing was clamped, but clocks.${f.path} is true`);
});

gate('09c tick() resets a device stuck in SEENYOU or HANDSHAKE after 10 s with a new sessionNonce, and not before', async (t, P) => {
  const { A, B } = await toHandshake(P);
  assert.equal(A.dev.state, 'SEENYOU');
  assert.equal(B.dev.state, 'HANDSHAKE');
  assert.equal(A.dev.lockedAt, EPOCH, 'lockedAt is the epoch second of the lock');
  assert.equal(B.dev.lockedAt, EPOCH, 'lockedAt is the epoch second of the lock');
  const nonces = { A: A.dev.sessionNonce, B: B.dev.sessionNonce };
  for (const dt of [0, 1, 9, 10]) {
    for (const [name, d] of [['A', A], ['B', B]]) {
      d.clock.t = EPOCH + dt;
      const before = snapshot(d.dev);
      assert.equal(await tickReset(d, name), false, `${name}: tick() at +${dt} s must not reset (now - lockedAt > 10 is false)`);
      assert.deepEqual(snapshot(d.dev), before, `${name}: tick() at +${dt} s must change nothing`);
    }
  }
  for (const [name, d] of [['A (SEENYOU)', A], ['B (HANDSHAKE)', B]]) {
    d.clock.t = EPOCH + 11;
    assert.equal(await tickReset(d, name), true, `${name}: tick() at +11 s must reset`);
    assert.equal(d.dev.state, 'FACE', `${name}: back to FACE`);
    assert.match(d.dev.sessionNonce, NONCE_RE);
    assert.notEqual(d.dev.sessionNonce, nonces[name[0]], `${name}: the reset must draw a NEW sessionNonce`);
    assert.ok(d.dev.role == null && d.dev.targetPk == null && d.dev.peerNonce == null && d.dev.lockedAt == null, `${name}: role, target, peer nonce and lock time are cleared`);
    assert.ok(d.dev.core == null && d.dev.receipt == null, `${name}: no core or receipt survives the reset`);
    assert.equal(await tickReset(d, name), false, `${name}: a second tick() in FACE does nothing`);
    const f = await d.dev.frame();
    assert.equal(f.F.type, 'FACE');
    assert.equal(f.F.nonce, d.dev.sessionNonce, `${name}: the next FACE carries the new nonce`);
  }
  // Liveness: after the timeout the same two devices complete a fresh ceremony.
  assert.ok(await pump(A, B), `after a timeout reset the devices must be able to bloom again (states ${A.dev.state} / ${B.dev.state})`);
  const { rI } = await assertCeremony(P, A, B, 'after-timeout');
  assert.ok(rI.nonce_A !== nonces.A && rI.nonce_B !== nonces.B, 'the new receipt uses the new session nonces');

  // FACE and BLOOM are never reset by tick().
  const idle = await spawnDevice(P);
  idle.clock.t = EPOCH + 3600;
  const idleNonce = idle.dev.sessionNonce;
  assert.equal(await tickReset(idle, 'idle device'), false, 'tick() in FACE does nothing');
  assert.equal(idle.dev.sessionNonce, idleNonce);
  A.clock.t += 3600;
  const bloomed = snapshot(A.dev);
  assert.equal(await tickReset(A, 'bloomed device'), false, 'tick() in BLOOM does nothing');
  assert.deepEqual(snapshot(A.dev), bloomed, 'the receipt survives tick() in BLOOM');

  // reset() returns any device to FACE.
  await A.dev.reset();
  assert.equal(A.dev.state, 'FACE', 'reset() returns to FACE');
  assert.ok(A.dev.role == null && A.dev.targetPk == null && A.dev.lockedAt == null, 'reset() clears role, target and lock time');
});

for (const [name, geoA, geoB] of [['initiator has no position', null, GEO_B], ['responder has no position', GEO_A, null], ['neither has a position', null, null]]) {
  gate(`09d geo() === null: frames and receipt carry no geo key for that device and the receipt passes verify.mjs (${name})`, async (t, P) => {
    const { A, B, frames } = await toBloom(P, { geoA, geoB });
    assertFrameShape(frames.fa, 'FACE', !!geoA, 'initiator FACE');
    assertFrameShape(frames.sa, 'SEENYOU', !!geoA, 'initiator SEENYOU');
    assertFrameShape(frames.fb, 'FACE', !!geoB, 'responder FACE');
    assertFrameShape(frames.sb, 'SEENYOU', !!geoB, 'responder SEENYOU');
    assertFrameShape(frames.hs, 'HANDSHAKE', !!geoB, 'responder HANDSHAKE');
    const { rI, rR } = await assertCeremony(P, A, B, `geo-null-${name.replace(/\s+/g, '-')}`);
    for (const [who, r] of [['initiator', rI], ['responder', rR]]) {
      assert.equal('geo_A' in r, !!geoA, `${who} receipt: geo_A must be ${geoA ? 'present' : 'absent (not null, not {})'}`);
      assert.equal('geo_B' in r, !!geoB, `${who} receipt: geo_B must be ${geoB ? 'present' : 'absent (not null, not {})'}`);
      if (geoA) assert.deepEqual(r.geo_A, { ...geoA });
      if (geoB) assert.deepEqual(r.geo_B, { ...geoB });
    }
  });
}

gate('09e a device reporting acc 0.5 gives sentinel_verdict SUSPICIOUS and verify.mjs rejects with suspicious_spoofed_accuracy', async (t, P) => {
  for (const [who, opts] of [['initiator', { geoA: { ...GEO_A, acc: 0.5 } }], ['responder', { geoB: { ...GEO_B, acc: 0.5 } }], ['initiator (acc 0)', { geoA: { ...GEO_A, acc: 0 } }]]) {
    const { A, B } = await toBloom(P, opts);
    const { rI, rR } = await assertCeremony(P, A, B, `acc-spoof-${who}`, { verdict: 'SUSPICIOUS', verify: 'suspicious_spoofed_accuracy' });
    assert.equal(rI.geo_A.acc, opts.geoA ? opts.geoA.acc : GEO_A.acc, 'the reported accuracy is carried, not hidden');
    assert.equal(rR.geo_B.acc, opts.geoB ? opts.geoB.acc : GEO_B.acc, 'the reported accuracy is carried, not hidden');
  }
});

gate('09f the initiator refuses a HANDSHAKE whose t_B - t_A is below 0 or above 10 with WINDOW', async (t, P) => {
  const craft = async (B, hs, tB) => resignAs(B, {
    ...hs.F, t_B: tB, sig_B: await subtleSign(B.kp.privateKey, nodeCore(hs.F.pk_A, hs.F.pk_B, hs.F.nonce_A, hs.F.nonce_B, tB)),
  });
  for (const delta of [12, 11, -1, -3]) {
    const { A, B } = await toHandshake(P);
    const hs = await B.dev.frame();
    const before = snapshot(A.dev);
    // sig_F and sig_B are both genuine for the altered t_B: only the window is wrong.
    assertRefused(await A.dev.process(await craft(B, hs, hs.F.t_A + delta)), ['WINDOW'], `HANDSHAKE with t_B - t_A = ${delta}`);
    assert.deepEqual(snapshot(A.dev), before, 'a WINDOW refusal must not change the initiator');
    assertAccepted(await A.dev.process(hs), 'BLOOM_MINTED', 'the genuine HANDSHAKE afterwards');
  }
  // The edge of the window is inside it: 10 s is accepted, passes verify.mjs, and is SUSPICIOUS (> 7.5 s).
  const { A, B } = await toHandshake(P);
  const hs = await B.dev.frame();
  assertAccepted(await A.dev.process(await craft(B, hs, hs.F.t_A + 10)), 'BLOOM_MINTED', 'HANDSHAKE with t_B - t_A = 10');
  const r = A.dev.receipt;
  assertReceiptShape(P, r, 'window-edge receipt');
  assert.equal(r.t_B - r.t_A, 10);
  await expectVerify(P, r, 'window-edge-10s', 'valid');
  assert.equal(r.sentinel_verdict, 'SUSPICIOUS', 't_B - t_A = 10 s exceeds the 7.5 s sentinel window');
});

// ===========================================================================
// 10. verifyReceipt against node verify.mjs
// ===========================================================================
gate('10a verifyReceipt agrees with node verify.mjs on every file in vectors/', async (t, P) => {
  const files = fs.readdirSync(VECTORS_DIR).filter((f) => f.endsWith('.json')).sort();
  assert.ok(files.length >= 11, `suite self-check: expected at least 11 vectors, found ${files.length}`);
  const problems = [];
  let valid = 0;
  for (const f of files) {
    const cli = runVerifyFile(path.join(VECTORS_DIR, f));
    assert.ok(cli.code === 'valid' ? cli.status === 0 : cli.status === 1, `suite self-check: verify.mjs on ${f} printed "${cli.stdout}" with exit ${cli.status}`);
    const r = await settle(() => P.verifyReceipt(readVector(f)));
    if (!r.ok) {
      problems.push(`${f}: verifyReceipt threw ${r.error && r.error.message}; verify.mjs: "${cli.stdout}"`);
    } else if (!r.value || r.value.valid !== cli.valid || reasonCode(r.value.reason) !== cli.code) {
      problems.push(`${f}: verifyReceipt ${fmt(r.value)}; verify.mjs: "${cli.stdout}" (exit ${cli.status})`);
    }
    if (cli.valid) valid += 1;
  }
  assert.deepEqual(problems, [], `verifyReceipt disagrees with verify.mjs on ${problems.length} of ${files.length} vectors`);
  t.diagnostic(`${files.length} vectors: ${valid} valid, ${files.length - valid} invalid, all agreed`);
});

function mutatedReceipts() {
  const g = () => readVector('genuine.json');
  const s = () => readVector('spacetime_genuine.json');
  const a = () => readVector('audio_genuine.json');
  const m = (name, base, expect, edit) => {
    const r = base();
    edit(r);
    return { name, expect, receipt: r };
  };
  const london = { lat: 51.5074, lon: -0.1278, acc: 10.0 };
  const out = [
    m('version_1', g, 'unsupported_version', (r) => { r.v = 1; }),
    m('version_missing', g, 'unsupported_version', (r) => { delete r.v; }),
    m('version_string', g, 'unsupported_version', (r) => { r.v = '0'; }),
    ...['pk_A', 'pk_B', 'nonce_A', 'nonce_B', 't_A', 't_B', 'sig_A', 'sig_B'].map((f) => m(`missing_${f}`, g, 'missing_field', (r) => { delete r[f]; })),
    m('pk_A_null', g, 'missing_field', (r) => { r.pk_A = null; }),
    m('t_A_string', g, 'timestamps_must_be_numbers', (r) => { r.t_A = String(r.t_A); }),
    m('negative_skew', g, 'negative_time_skew', (r) => { r.t_A = r.t_B + 1; }),
    m('window_11_unsigned_t_A', g, 'ceremony_window_exceeded', (r) => { r.t_A = r.t_B - 11; }),
    m('window_10_unsigned_t_A', g, 'valid', (r) => { r.t_A = r.t_B - 10; }),
    m('window_0', g, 'valid', (r) => { r.t_A = r.t_B; }),
    m('pk_A_short', g, 'malformed_public_key_A', (r) => { r.pk_A = r.pk_A.slice(0, 128); }),
    m('pk_B_nonhex', g, 'malformed_public_key_B', (r) => { r.pk_B = `04${'zz'.repeat(64)}`; }),
    m('pk_A_prefix_03', g, 'malformed_public_key_A', (r) => { r.pk_A = `03${r.pk_A.slice(2)}`; }),
    m('pk_A_off_curve', g, 'invalid_public_key_A', (r) => { r.pk_A = flipHex(r.pk_A, 129); }),
    m('pk_B_off_curve', g, 'invalid_public_key_B', (r) => { r.pk_B = flipHex(r.pk_B, 129); }),
    m('pk_uppercase', g, 'valid', (r) => { r.pk_A = `04${r.pk_A.slice(2).toUpperCase()}`; r.pk_B = `04${r.pk_B.slice(2).toUpperCase()}`; }),
    m('nonce_A_short', g, 'malformed_nonce_A', (r) => { r.nonce_A = r.nonce_A.slice(0, 15); }),
    m('nonce_B_nonhex', g, 'malformed_nonce_B', (r) => { r.nonce_B = 'zzzzzzzzzzzzzzzz'; }),
    m('nonce_A_number', g, 'malformed_nonce_A', (r) => { r.nonce_A = 1234567812345678; }),
    m('nonce_uppercase', g, 'valid', (r) => { r.nonce_A = r.nonce_A.toUpperCase(); r.nonce_B = r.nonce_B.toUpperCase(); }),
    m('sig_A_short', g, 'malformed_signature_A', (r) => { r.sig_A = r.sig_A.slice(0, 126); }),
    m('sig_B_nonhex', g, 'malformed_signature_B', (r) => { r.sig_B = 'zz'.repeat(64); }),
    m('sig_A_zero', g, 'sig_A_invalid', (r) => { r.sig_A = '00'.repeat(64); }),
    m('sig_B_zero', g, 'sig_B_invalid', (r) => { r.sig_B = '00'.repeat(64); }),
    m('sigs_swapped', g, 'sig_A_invalid', (r) => { [r.sig_A, r.sig_B] = [r.sig_B, r.sig_A]; }),
    m('sig_uppercase', g, 'valid', (r) => { r.sig_A = r.sig_A.toUpperCase(); r.sig_B = r.sig_B.toUpperCase(); }),
    m('t_B_plus_1', g, 'sig_A_invalid', (r) => { r.t_B += 1; }),
    m('nonce_A_changed', g, 'sig_A_invalid', (r) => { r.nonce_A = flipHex(r.nonce_A, 0); }),
    m('nonce_B_changed', g, 'sig_A_invalid', (r) => { r.nonce_B = flipHex(r.nonce_B, 15); }),
    m('roles_swapped', g, 'sig_A_invalid', (r) => { [r.pk_A, r.pk_B, r.sig_A, r.sig_B] = [r.pk_B, r.pk_A, r.sig_B, r.sig_A]; }),
    m('extra_fields', g, 'valid', (r) => { r.note = 'additive fields are ignored'; r.schema = 'aukora.copresence.receipt.v1'; }),
    m('geo_lat_string', s, 'invalid_geo_coordinates', (r) => { r.geo_A.lat = '37.7749'; }),
    m('geo_acc_half', s, 'suspicious_spoofed_accuracy', (r) => { r.geo_A.acc = 0.5; }),
    m('geo_acc_negative', s, 'suspicious_spoofed_accuracy', (r) => { r.geo_B.acc = -3; }),
    m('geo_acc_missing_defaults_15', s, 'valid', (r) => { delete r.geo_A.acc; }),
    m('geo_acc_exactly_1', s, 'valid', (r) => { r.geo_A.acc = 1.0; r.geo_B.acc = 1.0; }),
    m('geo_far_claimed_consistent', s, 'suspicious_spacetime_contradiction', (r) => { r.geo_B = london; }),
    m('geo_far_labelled_suspicious', s, 'valid', (r) => { r.geo_B = london; r.sentinel_verdict = 'SUSPICIOUS'; }),
    m('geo_far_no_verdict', s, 'valid', (r) => { r.geo_B = london; delete r.sentinel_verdict; }),
    m('geo_60m_inside_bound', s, 'valid', (r) => { r.geo_B = { lat: r.geo_A.lat + 0.00054, lon: r.geo_A.lon, acc: 5.0 }; }),
    m('geo_70m_outside_bound', s, 'suspicious_spacetime_contradiction', (r) => { r.geo_B = { lat: r.geo_A.lat + 0.00063, lon: r.geo_A.lon, acc: 5.0 }; }),
    m('geo_only_A', s, 'valid', (r) => { delete r.geo_B; }),
    m('geo_A_null', s, 'valid', (r) => { r.geo_A = null; }),
    m('audio_nonce_short', a, 'malformed_audio_nonce', (r) => { r.audio.nonce = r.audio.nonce.slice(0, 30); }),
    m('audio_matched_string', a, 'invalid_audio_matched', (r) => { r.audio.matched = 'yes'; }),
    m('audio_matched_false', a, 'suspicious_audio_nonce_mismatch', (r) => { r.audio.matched = false; }),
    m('audio_matched_false_and_slow', a, 'suspicious_audio_nonce_mismatch', (r) => { r.audio.matched = false; r.audio.delay_ms = 280; }),
    m('audio_delay_string', a, 'invalid_audio_delay', (r) => { r.audio.delay_ms = '24.5'; }),
    m('audio_delay_4_9', a, 'suspicious_audio_delay_impossible', (r) => { r.audio.delay_ms = 4.9; }),
    m('audio_delay_150_1', a, 'suspicious_audio_relay_detected', (r) => { r.audio.delay_ms = 150.1; }),
    m('audio_delay_150', a, 'valid', (r) => { r.audio.delay_ms = 150; }),
    m('audio_delay_5', a, 'valid', (r) => { r.audio.delay_ms = 5; }),
    m('audio_empty_object', a, 'valid', (r) => { r.audio = {}; }),
    m('audio_null', a, 'valid', (r) => { r.audio = null; }),
    m('audio_without_nonce', a, 'valid', (r) => { delete r.audio.nonce; }),
  ];
  return out;
}

gate('10b verifyReceipt agrees with node verify.mjs on mutated receipts (differential over every verify.mjs branch)', async (t, P) => {
  const problems = [];
  const cases = mutatedReceipts();
  for (const c of cases) {
    const cli = runVerify(c.receipt, `mut-${c.name}`);
    assert.equal(cli.code, c.expect, `suite self-check: verify.mjs on ${c.name} printed "${cli.stdout}" (exit ${cli.status})`);
    const r = await settle(() => P.verifyReceipt(JSON.parse(JSON.stringify(c.receipt))));
    if (!r.ok) {
      problems.push(`${c.name}: verifyReceipt threw ${r.error && r.error.message}; verify.mjs: "${cli.stdout}"`);
    } else if (!r.value || r.value.valid !== cli.valid || reasonCode(r.value.reason) !== cli.code) {
      problems.push(`${c.name}: verifyReceipt ${fmt(r.value)}; verify.mjs: "${cli.stdout}"`);
    }
  }
  assert.deepEqual(problems, [], `verifyReceipt disagrees with verify.mjs on ${problems.length} of ${cases.length} mutated receipts`);
  t.diagnostic(`${cases.length} mutated receipts agreed with verify.mjs`);
});

// ===========================================================================
// 11. Honesty invariants, the sentinel, finalizeReceipt
// ===========================================================================
function specDoesNotProve() {
  const spec = fs.readFileSync(SPEC_MD, 'utf8');
  const start = spec.indexOf('### Verbatim "Does Not Prove" List');
  assert.ok(start >= 0, 'suite self-check: SPEC-v1.md section 4 has the "Does Not Prove" list');
  const rest = spec.slice(start);
  const end = rest.indexOf('\n---');
  const items = (end >= 0 ? rest.slice(0, end) : rest).split('\n').map((l) => l.trim()).filter((l) => /^\d+\.\s+/.test(l));
  assert.equal(items.length, 6, 'suite self-check: SPEC-v1.md lists six items');
  return items.map(normaliseClaim);
}
const normaliseClaim = (s) => String(s).trim().replace(/^\d+[.)]\s*/, '').replace(/[;.,:\s]+$/, '');

gate('11a DOES_NOT_PROVE is the six SPEC-v1.md section 4 strings, verbatim and in order', (t, P) => {
  const spec = specDoesNotProve();
  assert.ok(Array.isArray(P.DOES_NOT_PROVE), 'DOES_NOT_PROVE must be an array');
  assert.equal(P.DOES_NOT_PROVE.length, 6, 'DOES_NOT_PROVE must have 6 entries');
  assert.ok(P.DOES_NOT_PROVE.every((s) => typeof s === 'string'), 'DOES_NOT_PROVE entries must be strings');
  assert.deepEqual(P.DOES_NOT_PROVE.map(normaliseClaim), spec, 'each entry must be the SPEC text verbatim (modulo the list number and trailing punctuation)');
});

gate('11b honesty invariants hold on every minted receipt: two labels only, no confidence / percent / score key, does_not_prove intact', async (t, P) => {
  const minted = [];
  const add = async (label, opts) => {
    const s = await toBloom(P, opts);
    minted.push([`${label} initiator`, s.A.dev.receipt], [`${label} responder`, s.B.dev.receipt]);
    return s;
  };
  await add('genuine', {});
  await add('no geo', { geoA: null, geoB: null });
  await add('one geo', { geoA: null });
  await add('acc 0.5', { geoA: { ...GEO_A, acc: 0.5 } });
  await add('skew 3 s', { skewB: -3 });
  await add('far apart', { geoB: { lat: 51.5074, lon: -0.1278, acc: 10.0 } });
  const seenVerdicts = new Set();
  for (const [label, r] of minted) {
    assert.ok(r, `${label}: no receipt`);
    assertReceiptShape(P, r, label);
    seenVerdicts.add(r.sentinel_verdict);
    const text = JSON.stringify(r);
    assert.doesNotMatch(text, /GENUINE|MEASURED|VERIFIED_HUMAN|PROOF_OF_HUMAN|\d\s*%/, `${label}: receipts never claim measurement, humanity or a percentage`);
  }
  assert.deepEqual([...seenVerdicts].sort(), ['CONSISTENT_CLAIMED', 'SUSPICIOUS'], 'both labels were exercised and no third label exists');
  const far = minted.find(([label]) => label === 'far apart initiator')[1];
  assert.equal(far.sentinel_verdict, 'SUSPICIOUS', 'positions 5,570 km apart must be SUSPICIOUS');
  const cli = runVerify(far, 'far-apart');
  assert.ok(cli.valid, `a receipt that honestly labels a far-apart ceremony SUSPICIOUS still passes verify.mjs, got "${cli.stdout}"`);
});

gate('11c sentinel() applies the spacetime_sentinel.py thresholds and never reports a confidence', (t, P) => {
  const base = { geo_A: { ...GEO_A }, geo_B: { ...GEO_B }, t_A: EPOCH, t_B: EPOCH + 2 };
  const north = (metres) => ({ lat: GEO_A.lat + metres / 111194.93, lon: GEO_A.lon, acc: 6.0 }); // bound is 8 + 6 + 50 = 64 m
  const rows = [
    ['baseline', {}, 'CONSISTENT_CLAIMED', 'NOT_PERFORMED'],
    ['timestamps only', { geo_A: undefined, geo_B: undefined }, 'CONSISTENT_CLAIMED', 'NOT_PERFORMED'],
    ['acc_A = 0', { geo_A: { ...GEO_A, acc: 0 } }, 'SUSPICIOUS'],
    ['acc_B = 0.9', { geo_B: { ...GEO_B, acc: 0.9 } }, 'SUSPICIOUS'],
    ['acc_A = -1', { geo_A: { ...GEO_A, acc: -1 } }, 'SUSPICIOUS'],
    ['acc = 1.0 on both', { geo_A: { ...GEO_A, acc: 1.0 }, geo_B: { ...GEO_B, acc: 1.0 } }, 'CONSISTENT_CLAIMED'],
    ['60 m apart (bound 64 m)', { geo_B: north(60) }, 'CONSISTENT_CLAIMED'],
    ['70 m apart (bound 64 m)', { geo_B: north(70) }, 'SUSPICIOUS'],
    ['New York vs London', { geo_A: { lat: 40.7128, lon: -74.006, acc: 10 }, geo_B: { lat: 51.5074, lon: -0.1278, acc: 10 } }, 'SUSPICIOUS'],
    ['latency 200 ms', { optical_latency_ms: 200 }, 'CONSISTENT_CLAIMED'],
    ['latency 380 ms', { optical_latency_ms: 380 }, 'CONSISTENT_CLAIMED'],
    ['latency 381 ms', { optical_latency_ms: 381 }, 'SUSPICIOUS'],
    ['latency 25 ms', { optical_latency_ms: 25 }, 'CONSISTENT_CLAIMED'],
    ['latency 24 ms', { optical_latency_ms: 24 }, 'SUSPICIOUS'],
    ['t_B - t_A = 0', { t_B: EPOCH }, 'CONSISTENT_CLAIMED'],
    ['t_B - t_A = 7', { t_B: EPOCH + 7 }, 'CONSISTENT_CLAIMED'],
    ['t_B - t_A = 8', { t_B: EPOCH + 8 }, 'SUSPICIOUS'],
    ['t_B - t_A = -1', { t_B: EPOCH - 1 }, 'SUSPICIOUS'],
    ['audio 24.5 ms matched', { audio: { delay_ms: 24.5, matched: true } }, 'CONSISTENT_CLAIMED', 'VERIFIED_LOCAL'],
    ['audio 5 ms matched', { audio: { delay_ms: 5, matched: true } }, 'CONSISTENT_CLAIMED', 'VERIFIED_LOCAL'],
    ['audio 150 ms matched', { audio: { delay_ms: 150, matched: true } }, 'CONSISTENT_CLAIMED', 'VERIFIED_LOCAL'],
    ['audio 151 ms matched', { audio: { delay_ms: 151, matched: true } }, 'SUSPICIOUS', 'SUSPICIOUS'],
    ['audio 280 ms matched', { audio: { delay_ms: 280, matched: true } }, 'SUSPICIOUS', 'SUSPICIOUS'],
    ['audio 4.9 ms matched', { audio: { delay_ms: 4.9, matched: true } }, 'SUSPICIOUS', 'SUSPICIOUS'],
    ['audio nonce mismatch', { audio: { delay_ms: 24.5, matched: false } }, 'SUSPICIOUS', 'SUSPICIOUS'],
    ['audio mismatch, no delay', { audio: { matched: false } }, 'SUSPICIOUS', 'SUSPICIOUS'],
  ];
  const problems = [];
  for (const [what, patch, verdict, acoustic] of rows) {
    const input = { ...base, ...patch };
    for (const k of Object.keys(input)) if (input[k] === undefined) delete input[k];
    let out;
    try {
      out = P.sentinel(input);
    } catch (err) {
      problems.push(`${what}: sentinel threw ${err.message}`);
      continue;
    }
    if (!out || out.verdict !== verdict) problems.push(`${what}: expected ${verdict}, got ${fmt(out)}`);
    else if (acoustic && out.acoustic_channel !== acoustic) problems.push(`${what}: expected acoustic_channel ${acoustic}, got ${fmt(out.acoustic_channel)}`);
    else if (!Array.isArray(out.anomalies) || (out.anomalies.length > 0) !== (verdict === 'SUSPICIOUS')) problems.push(`${what}: anomalies ${fmt(out.anomalies)} inconsistent with ${verdict}`);
    else if (out.position_source !== 'SELF_REPORTED_UNVERIFIABLE') problems.push(`${what}: position_source ${fmt(out.position_source)}`);
    else if (deepKeys(out).some((k) => FORBIDDEN_KEY.test(k.key))) problems.push(`${what}: sentinel output carries a confidence / percentage / score key: ${fmt(out)}`);
  }
  assert.deepEqual(problems, [], `sentinel() departs from the frozen thresholds on ${problems.length} of ${rows.length} rows`);
});

gate('11d finalizeReceipt returns a new receipt with the sentinel recomputed and never upgrades a SUSPICIOUS receipt', async (t, P) => {
  const { A } = await toBloom(P);
  const r = A.dev.receipt;
  const pristine = JSON.parse(JSON.stringify(r));
  const audioOk = { nonce: 'a1b2c3d4e5f60718293a4b5c6d7e8f90', delay_ms: 24.5, matched: true };
  const rows = [
    ['no extras', {}, 'CONSISTENT_CLAIMED', null],
    ['latency 200 ms', { optical_latency_ms: 200 }, 'CONSISTENT_CLAIMED', null],
    ['latency 500 ms', { optical_latency_ms: 500 }, 'SUSPICIOUS', null],
    ['latency 20 ms', { optical_latency_ms: 20 }, 'SUSPICIOUS', null],
    ['audio matched at 24.5 ms', { optical_latency_ms: 200, audio: audioOk }, 'CONSISTENT_CLAIMED', 'VERIFIED_LOCAL'],
    ['audio relayed at 280 ms', { audio: { ...audioOk, delay_ms: 280 } }, 'SUSPICIOUS', 'SUSPICIOUS'],
    ['audio nonce mismatch', { audio: { ...audioOk, matched: false } }, 'SUSPICIOUS', 'SUSPICIOUS'],
  ];
  for (const [what, extras, verdict, acoustic] of rows) {
    const out = await P.finalizeReceipt(r, extras);
    assert.ok(out && typeof out === 'object' && out !== r, `${what}: finalizeReceipt must return a new object`);
    assert.deepEqual(JSON.parse(JSON.stringify(r)), pristine, `${what}: finalizeReceipt must not mutate its input`);
    assertReceiptShape(P, out, `finalised (${what})`);
    for (const f of FROZEN) assert.deepEqual(out[f], r[f], `${what}: frozen field ${f} must be untouched`);
    assert.equal(out.sentinel_verdict, verdict, `${what}: sentinel_verdict (anomalies ${fmt(out.anomalies)})`);
    if (acoustic) assert.equal(out.acoustic_channel, acoustic, `${what}: acoustic_channel`);
    // Whatever shape the finalised receipt takes, the in-page verifier and the CLI must agree on it.
    const cli = runVerify(out, `finalised-${what}`);
    const page = await P.verifyReceipt(out);
    assert.equal(page.valid, cli.valid, `${what}: verifyReceipt ${fmt(page)} vs verify.mjs "${cli.stdout}"`);
    assert.equal(reasonCode(page.reason), cli.code, `${what}: verifyReceipt ${fmt(page)} vs verify.mjs "${cli.stdout}"`);
    if (verdict === 'CONSISTENT_CLAIMED') assert.ok(cli.valid, `${what}: a CONSISTENT_CLAIMED receipt must pass verify.mjs, got "${cli.stdout}"`);
  }
  // Benign extras can never launder a suspicious ceremony.
  const spoofed = (await toBloom(P, { geoA: { ...GEO_A, acc: 0.5 } })).A.dev.receipt;
  const skewed = (await toBloom(P, { skewB: -3 })).B.dev.receipt;
  for (const [what, bad] of [['acc 0.5', spoofed], ['3 s clock skew', skewed]]) {
    assert.equal(bad.sentinel_verdict, 'SUSPICIOUS', `${what}: minted SUSPICIOUS`);
    for (const extras of [{}, { optical_latency_ms: 200 }, { optical_latency_ms: 200, audio: audioOk }]) {
      const out = await P.finalizeReceipt(bad, extras);
      assert.equal(out.sentinel_verdict, 'SUSPICIOUS', `${what}: finalizeReceipt(${fmt(extras)}) must stay SUSPICIOUS, got ${out.sentinel_verdict} (anomalies ${fmt(out.anomalies)})`);
    }
  }
});

// ===========================================================================
// 12. Pentora
// ===========================================================================
gate('12a pentoraDigits / pentoraDigest match every vector in tests/pentora-vectors.json', async (t, P) => {
  if (!fs.existsSync(PENTORA_VECTORS)) {
    t.skip('tests/pentora-vectors.json is not present; the normative pentora.display.v1 vectors could not be checked');
    return;
  }
  const vectors = JSON.parse(fs.readFileSync(PENTORA_VECTORS, 'utf8'));
  assert.ok(Array.isArray(vectors) && vectors.length > 0, 'pentora-vectors.json must be a non-empty array');
  for (const [n, v] of vectors.entries()) {
    assert.ok(/^[0-9a-f]{64}$/.test(v.head) && /^[0-9a-f]{64}$/.test(v.sha256) && /^(00|01|02){110}$/.test(v.wire_hex),
      `suite self-check: vector ${n} must be { head, sha256, wire_hex } (64 hex, 64 hex, 110 bytes of 0..2)`);
    const head = unhex(v.head);
    const digest = await P.pentoraDigest(head);
    assert.ok(digest instanceof Uint8Array && digest.length === 32, `vector ${n}: pentoraDigest must resolve to a Uint8Array(32)`);
    assert.equal(hex(digest), v.sha256, `vector ${n} (head ${v.head.slice(0, 16)}...): digest`);
    const digits = await P.pentoraDigits(head);
    assert.ok(digits instanceof Uint8Array && digits.length === 110, `vector ${n}: pentoraDigits must resolve to a Uint8Array(110)`);
    assert.equal(hex(digits), v.wire_hex, `vector ${n} (head ${v.head.slice(0, 16)}...): the 110 ternary digits`);
    assert.equal(await P.shortDigest(head), v.sha256.slice(0, 8).toUpperCase(), `vector ${n}: shortDigest`);
  }
  t.diagnostic(`${vectors.length} pentora.display.v1 vectors matched`);
});

gate('12b shortDigest is 8 uppercase hex chars, the first 4 digest bytes, and identical on both devices of one ceremony', async (t, P) => {
  const { A, B } = await toBloom(P);
  const a = await P.shortDigest(A.dev.core);
  const b = await P.shortDigest(B.dev.core);
  assert.match(a, /^[0-9A-F]{8}$/, 'shortDigest must be 8 uppercase hex chars');
  assert.equal(a, hex((await P.pentoraDigest(A.dev.core)).slice(0, 4)).toUpperCase(), 'shortDigest is the first 4 bytes of pentoraDigest(core)');
  assert.equal(a, b, 'both devices of one ceremony show the same digest');
  assert.equal(hex(await P.pentoraDigits(A.dev.core)), hex(await P.pentoraDigits(B.dev.core)), 'both devices bloom the same 110 cells');
  const other = await toBloom(P);
  assert.notEqual(await P.shortDigest(other.A.dev.core), a, 'a different ceremony shows a different digest');
  const digits = await P.pentoraDigits(A.dev.core);
  assert.ok(digits instanceof Uint8Array && digits.length === 110 && digits.every((d) => d <= 2), 'pentoraDigits is a Uint8Array(110) of 0..2');
  assert.equal(hex(await P.pentoraDigits(A.dev.core)), hex(digits), 'pentoraDigits is deterministic');
});

gate('12c faceHead(pk) is SHA-256("copresence.face.v0" || 0x00 || pk bytes)', async (t, P) => {
  for (const label of ['face-1', 'face-2', 'face-3']) {
    const { pk } = nodeKey(label);
    const expected = crypto.createHash('sha256').update(Buffer.concat([Buffer.from('copresence.face.v0', 'utf8'), Buffer.from([0]), Buffer.from(pk, 'hex')])).digest('hex');
    const head = await P.faceHead(pk);
    assert.ok(head instanceof Uint8Array && head.length === 32, 'faceHead must resolve to a Uint8Array(32)');
    assert.equal(hex(head), expected, `faceHead for ${label}`);
  }
});

// ===========================================================================
// 13. Audio (acoustic sense), pure functions
// ===========================================================================
const AUDIO_SYMBOLS = 43;
const AUDIO_SYMBOL_S = 0.045;
const AUDIO_TONES = Array.from({ length: 8 }, (_, k) => 18000 + 400 * k);
const AUDIO_GAIN = 0.5;

async function audioFixture(P) {
  const g = readVector('genuine.json');
  const nonce = await P.audioNonce(g.pk_A, g.nonce_A);
  const otherNonce = await P.audioNonce(g.pk_B, g.nonce_B);
  return { g, nonce, otherNonce, symbols: Array.from(await P.audioSymbols(nonce)), otherSymbols: Array.from(await P.audioSymbols(otherNonce)) };
}
// Normalised so that a steady tone of amplitude a gives a^2.
function goertzel(x, start, len, freq, sampleRate) {
  const c = 2 * Math.cos((2 * Math.PI * freq) / sampleRate);
  let s1 = 0;
  let s2 = 0;
  for (let i = start; i < start + len; i += 1) {
    const s0 = x[i] + c * s1 - s2;
    s2 = s1;
    s1 = s0;
  }
  return (s1 * s1 + s2 * s2 - c * s1 * s2) / ((len * len) / 4);
}
// `seconds` of uniform noise with the signal dropped in at a seeded offset,
// at least 250 ms from either end.
function embed({ signal, sampleRate, seed, seconds = 4, noiseAmp = 0.004, scale = 1 }) {
  const rnd = mulberry32(seed);
  const total = Math.round(seconds * sampleRate);
  const buf = new Float32Array(total);
  for (let i = 0; i < total; i += 1) buf[i] = (rnd() * 2 - 1) * noiseAmp;
  let offset = -1;
  if (signal) {
    const margin = Math.round(0.25 * sampleRate);
    assert.ok(signal.length + 2 * margin < total, 'suite self-check: the signal fits inside the noise bed');
    offset = margin + Math.floor(rnd() * (total - signal.length - 2 * margin));
    for (let i = 0; i < signal.length; i += 1) buf[offset + i] += signal[i] * scale;
  }
  return { buf, offset };
}
// Streams `buf` into a fresh detector in chunks and polls match() roughly every
// 4096 samples (reading R5). Returns whether any poll matched, and the best poll.
async function listen(P, sampleRate, buf, expected, chunker) {
  const det = await P.createAudioDetector(sampleRate);
  let pos = 0;
  let sincePoll = 0;
  let matched = false;
  let best = null;
  const poll = async () => {
    const r = await det.match(expected);
    assert.ok(r && typeof r.matched === 'boolean' && Number.isFinite(r.hits) && Number.isFinite(r.total), `match() must return { matched, hits, total }, got ${fmt(r)}`);
    assert.ok(r.hits <= r.total, `hits (${r.hits}) cannot exceed total (${r.total})`);
    if (!best || r.hits > best.hits) best = r;
    if (r.matched) matched = true;
  };
  while (pos < buf.length && !matched) {
    const n = Math.min(chunker(), buf.length - pos);
    await det.push(buf.slice(pos, pos + n));
    pos += n;
    sincePoll += n;
    if (sincePoll >= 4096 || pos >= buf.length) {
      sincePoll = 0;
      await poll();
    }
  }
  return { matched, best, heardUntil: pos };
}
// Streams buf[0, endSample) into a fresh detector and asks once, at the end.
async function hearUpTo(P, sampleRate, buf, expected, endSample, chunk = 2048) {
  const det = await P.createAudioDetector(sampleRate);
  for (let pos = 0; pos < endSample; pos += chunk) await det.push(buf.slice(pos, Math.min(endSample, pos + chunk)));
  const r = await det.match(expected);
  assert.ok(r && typeof r.matched === 'boolean' && Number.isFinite(r.hits) && Number.isFinite(r.total), `match() must return { matched, hits, total }, got ${fmt(r)}`);
  return r;
}
const fixedChunks = (n) => () => n;
const quantumChunks = (seed) => {
  const rnd = mulberry32(seed);
  return () => 128 * (1 + Math.floor(rnd() * 32)); // 128..4096 in render quanta
};

gate('13a audioNonce and audioSymbols: 16 bytes, 43 symbols of 0..7, deterministic, every nonce bit bound', async (t, P) => {
  const { g, nonce, otherNonce, symbols } = await audioFixture(P);
  assert.ok(nonce instanceof Uint8Array && nonce.length === 16, 'audioNonce must resolve to a Uint8Array(16)');
  assert.equal(hex(await P.audioNonce(g.pk_A, g.nonce_A)), hex(nonce), 'audioNonce is deterministic');
  assert.notEqual(hex(otherNonce), hex(nonce), 'another device and session give another nonce');
  assert.notEqual(hex(await P.audioNonce(g.pk_A, g.nonce_B)), hex(nonce), 'the session nonce is bound into the audio nonce');
  assert.notEqual(hex(await P.audioNonce(g.pk_B, g.nonce_A)), hex(nonce), 'the pk is bound into the audio nonce');
  assert.equal(symbols.length, AUDIO_SYMBOLS, 'audioSymbols must return 43 symbols');
  assert.ok(symbols.every((s) => Number.isInteger(s) && s >= 0 && s <= 7), 'symbols are integers 0..7');
  assert.deepEqual(Array.from(await P.audioSymbols(nonce)), symbols, 'audioSymbols is deterministic');
  for (let bit = 0; bit < 128; bit += 1) {
    const flipped = Uint8Array.from(nonce);
    flipped[bit >> 3] ^= 1 << (bit & 7);
    assert.notDeepEqual(Array.from(await P.audioSymbols(flipped)), symbols, `flipping nonce bit ${bit} must change the symbol sequence (all 16 bytes are sent)`);
  }
});

for (const sampleRate of [44100, 48000]) {
  gate(`13b audioSynth at ${sampleRate} Hz: 43 x 45 ms, peak <= gain, one of eight 18.0-20.8 kHz tones per symbol, nothing audible`, async (t, P) => {
    const symbols = Array.from({ length: AUDIO_SYMBOLS }, (_, j) => (j * 3 + (j >> 3)) % 8);
    assert.equal(new Set(symbols).size, 8, 'suite self-check: all eight symbols are used');
    const x = await P.audioSynth(symbols, sampleRate, AUDIO_GAIN);
    assert.ok(x instanceof Float32Array, 'audioSynth must return a Float32Array');
    const expectedLen = AUDIO_SYMBOLS * AUDIO_SYMBOL_S * sampleRate;
    assert.ok(Math.abs(x.length - expectedLen) <= 0.03 * expectedLen, `length ${x.length} samples is not 43 x 45 ms (${Math.round(expectedLen)} samples) within 3 %`);
    let peak = 0;
    for (const v of x) {
      assert.ok(Number.isFinite(v), 'samples must be finite');
      peak = Math.max(peak, Math.abs(v));
    }
    assert.ok(peak <= AUDIO_GAIN * 1.001, `peak ${peak} exceeds the requested gain ${AUDIO_GAIN}`);
    assert.ok(peak >= AUDIO_GAIN * 0.5, `peak ${peak} is far below the requested gain ${AUDIO_GAIN}`);
    const audible = [440, 1000, 2000, 4000, 8000, 12000, 16000, 17000];
    const symLen = AUDIO_SYMBOL_S * sampleRate;
    const toneOf = new Map();
    for (let j = 0; j < AUDIO_SYMBOLS; j += 1) {
      const start = Math.round(j * symLen + 0.25 * symLen);
      const len = Math.round(0.5 * symLen);
      const power = AUDIO_TONES.map((f) => goertzel(x, start, len, f, sampleRate));
      const top = power.indexOf(Math.max(...power));
      const second = Math.max(...power.filter((_, k) => k !== top));
      assert.ok(power[top] >= 0.05 * AUDIO_GAIN * AUDIO_GAIN, `symbol ${j}: no tone on the 18.0-20.8 kHz grid (strongest ${Math.sqrt(power[top]).toFixed(4)} amplitude)`);
      assert.ok(power[top] >= 4 * second, `symbol ${j}: tone ${AUDIO_TONES[top]} Hz does not dominate the other grid tones`);
      for (const f of audible) {
        assert.ok(goertzel(x, start, len, f, sampleRate) <= 0.01 * power[top], `symbol ${j}: audible energy at ${f} Hz`);
      }
      if (toneOf.has(symbols[j])) assert.equal(top, toneOf.get(symbols[j]), `symbol value ${symbols[j]} must always use the same tone`);
      else toneOf.set(symbols[j], top);
    }
    assert.equal(new Set(toneOf.values()).size, 8, 'the eight symbol values must use eight distinct tones');
  });
}

gate('13c synth -> detector matches the right nonce at 44100 and 48000 Hz, embedded at a seeded offset in 4 s of low-level noise', async (t, P) => {
  const { symbols } = await audioFixture(P);
  const runs = [
    [44100, 'chunks of 4096', fixedChunks(4096), 0x13c1],
    [48000, 'chunks of 2048', fixedChunks(2048), 0x13c2],
    [44100, 'chunks of 1024', fixedChunks(1024), 0x13c3],
    [48000, 'irregular 128..4096 chunks', quantumChunks(0x13c4), 0x13c4],
  ];
  for (const [sampleRate, how, chunker, seed] of runs) {
    const signal = await P.audioSynth(symbols, sampleRate, AUDIO_GAIN);
    const { buf, offset } = embed({ signal, sampleRate, seed });
    const heard = await listen(P, sampleRate, buf, symbols, chunker);
    assert.ok(heard.matched, `${sampleRate} Hz, ${how}, signal at sample ${offset} (${(offset / sampleRate).toFixed(3)} s): no match, best poll ${fmt(heard.best)}`);
    // Once the whole chirp is in (plus 240 ms), the verdict must rest on all 43 symbols, not on a prefix.
    const whole = await hearUpTo(P, sampleRate, buf, symbols, offset + signal.length + Math.round(0.24 * sampleRate));
    assert.ok(whole.matched && whole.total === symbols.length && whole.hits >= 39,
      `${sampleRate} Hz, ${how}: after the whole chirp match() must report matched over all ${symbols.length} symbols (hits >= 39), got ${fmt(whole)}`);
    t.diagnostic(`${sampleRate} Hz, ${how}: first matched at ${heard.best.hits}/${heard.best.total} after ${(heard.heardUntil / sampleRate).toFixed(2)} s (signal at ${(offset / sampleRate).toFixed(3)} s); whole chirp ${whole.hits}/${whole.total}`);
  }
});

gate('13d the detector still matches a signal 20 dB weaker than synthesised (a real speaker-to-microphone path is weaker still)', async (t, P) => {
  const { symbols } = await audioFixture(P);
  for (const [sampleRate, seed] of [[44100, 0x13d1], [48000, 0x13d2]]) {
    const signal = await P.audioSynth(symbols, sampleRate, AUDIO_GAIN);
    const { buf, offset } = embed({ signal, sampleRate, seed, scale: 0.1 });
    const heard = await listen(P, sampleRate, buf, symbols, fixedChunks(2048));
    assert.ok(heard.matched, `${sampleRate} Hz at -20 dB (amplitude ${AUDIO_GAIN * 0.1} over noise 0.004), signal at sample ${offset}: no match, best poll ${fmt(heard.best)}`);
  }
});

gate('13e the detector does not match a different nonce, silence, noise, or a steady tone, and does not throw on empty input', async (t, P) => {
  const { symbols, otherSymbols } = await audioFixture(P);
  assert.notDeepEqual(otherSymbols, symbols, 'suite self-check: the two nonces give different symbols');
  for (const [sampleRate, seed] of [[44100, 0x13e1], [48000, 0x13e2]]) {
    const signal = await P.audioSynth(symbols, sampleRate, AUDIO_GAIN);
    const withSignal = embed({ signal, sampleRate, seed }).buf;
    const wrong = await listen(P, sampleRate, withSignal, otherSymbols, fixedChunks(4096));
    assert.ok(!wrong.matched, `${sampleRate} Hz: a chirp for another nonce matched (${fmt(wrong.best)})`);
    const silence = await listen(P, sampleRate, new Float32Array(4 * sampleRate), symbols, fixedChunks(4096));
    assert.ok(!silence.matched, `${sampleRate} Hz: silence matched (${fmt(silence.best)})`);
    const quiet = await listen(P, sampleRate, embed({ signal: null, sampleRate, seed: seed + 1 }).buf, symbols, fixedChunks(4096));
    assert.ok(!quiet.matched, `${sampleRate} Hz: low-level noise alone matched (${fmt(quiet.best)})`);
    const loud = await listen(P, sampleRate, embed({ signal: null, sampleRate, seed: seed + 2, noiseAmp: 0.3 }).buf, symbols, fixedChunks(4096));
    assert.ok(!loud.matched, `${sampleRate} Hz: loud white noise alone matched (${fmt(loud.best)})`);
    const tone = new Float32Array(4 * sampleRate);
    for (let i = 0; i < tone.length; i += 1) tone[i] = 0.3 * Math.sin((2 * Math.PI * 19200 * i) / sampleRate);
    const steady = await listen(P, sampleRate, tone, symbols, fixedChunks(4096));
    assert.ok(!steady.matched, `${sampleRate} Hz: a steady 19.2 kHz tone matched (${fmt(steady.best)})`);
    // A chirp that starts as the right nonce and turns into another one after 16 symbols is not the
    // right nonce: heard in full, it must not be matched.
    const hybridSymbols = symbols.slice(0, 16).concat(otherSymbols.slice(16));
    assert.ok(hybridSymbols.filter((v, i) => v !== symbols[i]).length >= 16, 'suite self-check: the hybrid differs in at least 16 of its last 27 symbols');
    const hybrid = await P.audioSynth(hybridSymbols, sampleRate, AUDIO_GAIN);
    const mixed = embed({ signal: hybrid, sampleRate, seed: seed + 3 });
    const done = await hearUpTo(P, sampleRate, mixed.buf, symbols, mixed.offset + hybrid.length + Math.round(0.24 * sampleRate));
    assert.equal(done.matched, false, `${sampleRate} Hz: a chirp carrying only the first 16 symbols of the nonce is still matched after it has been heard in full (${fmt(done)})`);
  }
  for (const sampleRate of [44100, 48000]) {
    const fresh = await settle(async () => {
      const det = await P.createAudioDetector(sampleRate);
      const first = await det.match(symbols);
      await det.push(new Float32Array(0));
      const second = await det.match(symbols);
      const empty = await det.match([]);
      return { first, second, empty };
    });
    assert.ok(fresh.ok, `${sampleRate} Hz: the detector threw on empty input: ${fresh.error && fresh.error.message}`);
    assert.equal(fresh.value.first.matched, false, 'a detector that has heard nothing must not match');
    assert.equal(fresh.value.second.matched, false, 'pushing an empty buffer must not create a match');
    assert.notEqual(fresh.value.empty && fresh.value.empty.matched, true, 'an empty expectation must not count as a match');
  }
});

// ===========================================================================
// 14. Static checks on the page bytes
// ===========================================================================
const htmlWithoutComments = () => HTML.replace(/<!--[\s\S]*?-->/g, '');
function attr(tag, name) {
  const m = tag.match(new RegExp(`(?:^|\\s)${name}\\s*=\\s*(?:"([^"]*)"|'([^']*)'|([^\\s>]+))`, 'i'));
  return m ? (m[1] ?? m[2] ?? m[3]) : null;
}
function scriptBlocks() {
  const out = [];
  const re = /<script\b([^>]*)>([\s\S]*?)<\/script\s*>/gi;
  let m;
  while ((m = re.exec(htmlWithoutComments()))) out.push({ attrs: m[1], body: m[2], src: attr(m[1], 'src'), type: attr(m[1], 'type'), integrity: attr(m[1], 'integrity'), nonce: attr(m[1], 'nonce') });
  return out;
}
function styleBlocks() {
  const out = [];
  const re = /<style\b([^>]*)>([\s\S]*?)<\/style\s*>/gi;
  let m;
  while ((m = re.exec(htmlWithoutComments()))) out.push({ attrs: m[1], body: m[2], nonce: attr(m[1], 'nonce') });
  return out;
}
function cspPolicies() {
  return (htmlWithoutComments().match(/<meta\b[^>]*>/gi) || [])
    .filter((tag) => /content-security-policy/i.test(attr(tag, 'http-equiv') || ''))
    .map((tag) => attr(tag, 'content') || '');
}
function cspDirective(policy, ...names) {
  const map = new Map();
  for (const part of policy.split(';')) {
    const tokens = part.trim().split(/\s+/).filter(Boolean);
    if (tokens.length) map.set(tokens[0].toLowerCase(), tokens.slice(1));
  }
  for (const n of names) if (map.has(n)) return map.get(n);
  return [];
}
const cspHashes = (text) => ['sha256', 'sha384', 'sha512'].map((alg) => `'${alg}-${crypto.createHash(alg).update(text.replace(/\r\n?/g, '\n'), 'utf8').digest('base64')}'`);

gate('14a the page shows the six does-not-prove strings and both sentinel labels', () => {
  for (const claim of specDoesNotProve()) assert.ok(HTML.includes(claim), `portal/index.html must contain the SPEC string verbatim: "${claim}"`);
  assert.ok(HTML.includes('CONSISTENT_CLAIMED'), 'portal/index.html must contain CONSISTENT_CLAIMED');
  assert.ok(HTML.includes('SUSPICIOUS'), 'portal/index.html must contain SUSPICIOUS');
  assert.ok(HTML.includes('SELF_REPORTED_UNVERIFIABLE'), 'portal/index.html must contain SELF_REPORTED_UNVERIFIABLE');
});

gate('14b exactly one <script id="portal-core"> block, with no DOM or network access inside it', () => {
  const count = (HTML.match(/<script\s[^>]*\bid\s*=\s*["']portal-core["'][^>]*>/gi) || []).length;
  assert.equal(count, 1, `expected exactly one <script id="portal-core"> block, found ${count}`);
  const core = scriptBlocks().find((s) => /\bid\s*=\s*["']portal-core["']/i.test(s.attrs));
  assert.ok(core, 'the portal-core block must be a plain <script id="portal-core"> element');
  assert.equal(core.src, null, 'portal-core must be inline');
  const code = core.body.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');
  // Member access or a call only, so prose inside string literals ("the time window. It ...") does not count.
  const banned = /\b(?:document|window|navigator|localStorage|sessionStorage|indexedDB)\.[A-Za-z_$]|\bfetch\s*\(|\bnew\s+(?:WebSocket|XMLHttpRequest|EventSource)\b|\bimportScripts\s*\(/.exec(code);
  const context = banned ? code.slice(Math.max(0, banned.index - 60), banned.index + 60).replace(/\s+/g, ' ') : '';
  assert.ok(!banned, `portal-core must be pure logic with no DOM or network access; found ${banned && JSON.stringify(banned[0])} in: ...${context}...`);
});

gate("14c a Content-Security-Policy meta tag with default-src 'none' and no 'unsafe-inline' / 'unsafe-eval'", () => {
  const policies = cspPolicies();
  assert.ok(policies.length >= 1, 'portal/index.html must carry <meta http-equiv="Content-Security-Policy" content="...">');
  for (const policy of policies) {
    assert.match(policy, /(^|;)\s*default-src\s+'none'\s*(;|$)/i, `the policy must contain default-src 'none': ${policy}`);
    assert.doesNotMatch(policy, /unsafe-inline/i, `the policy must not contain 'unsafe-inline': ${policy}`);
    assert.doesNotMatch(policy, /unsafe-eval/i, `the policy must not contain 'unsafe-eval': ${policy}`);
  }
});

gate('14d every <script src> is one of the two pinned vendor files and carries the sha384 integrity of the file on disk', (t) => {
  const external = scriptBlocks().filter((s) => s.src !== null);
  const allowed = ['vendor/jsQR.min.js', 'vendor/qrcode.min.js'];
  for (const s of external) {
    const src = s.src.replace(/^\.\//, '');
    assert.ok(allowed.includes(src), `<script src="${s.src}"> is not one of ${allowed.join(', ')}`);
    const onDisk = path.resolve(PORTAL_DIR, src);
    assert.ok(fs.existsSync(onDisk), `${src} does not exist next to the page (${onDisk})`);
    const expected = `sha384-${crypto.createHash('sha384').update(fs.readFileSync(onDisk)).digest('base64')}`;
    assert.equal(s.integrity, expected, `<script src="${s.src}"> must carry integrity="${expected}"`);
  }
  assert.equal(new Set(external.map((s) => s.src.replace(/^\.\//, ''))).size, external.length, 'no vendor script is loaded twice');
  t.diagnostic(`${external.length} external script(s), all pinned by sha384`);
});

gate('14e no http:// or https:// URL appears in the page outside comments', () => {
  const hits = [];
  const re = /https?:\/\//gi;
  let m;
  while ((m = re.exec(HTML))) {
    const k = m.index;
    const inHtmlComment = HTML.lastIndexOf('<!--', k) > HTML.lastIndexOf('-->', k);
    const inBlockComment = HTML.lastIndexOf('/*', k) > HTML.lastIndexOf('*/', k);
    const lineStart = HTML.lastIndexOf('\n', k) + 1;
    const inLineComment = /(^|[^:])\/\//.test(HTML.slice(lineStart, k));
    if (!inHtmlComment && !inBlockComment && !inLineComment) {
      const line = HTML.slice(0, k).split('\n').length;
      hits.push(`line ${line}: ${HTML.slice(Math.max(lineStart, k - 30), k + 60).split('\n')[0].trim()}`);
    }
  }
  assert.deepEqual(hits.slice(0, 10), [], `${hits.length} http(s) URL(s) outside comments (first 10 shown)`);
});

gate('14f the CSP allow-lists what the page ships: every inline <script> and <style> by hash, every vendor script by self or hash', () => {
  const policies = cspPolicies();
  assert.ok(policies.length >= 1, 'no Content-Security-Policy meta tag');
  const problems = [];
  for (const policy of policies) {
    const scriptSrc = cspDirective(policy, 'script-src-elem', 'script-src', 'default-src');
    const styleSrc = cspDirective(policy, 'style-src-elem', 'style-src', 'default-src');
    for (const [n, s] of scriptBlocks().entries()) {
      if (s.type && !/^(text\/javascript|application\/javascript|module)$/i.test(s.type)) continue; // data blocks are not executed
      if (s.src !== null) {
        const ok = scriptSrc.includes("'self'") || (s.integrity && scriptSrc.includes(`'${s.integrity}'`));
        if (!ok) problems.push(`<script src="${s.src}"> is blocked: script-src needs 'self' or '${s.integrity}'`);
      } else {
        const hashes = cspHashes(s.body);
        const ok = hashes.some((h) => scriptSrc.includes(h)) || (s.nonce && scriptSrc.includes(`'nonce-${s.nonce}'`));
        if (!ok) problems.push(`inline <script> #${n} (${s.attrs.trim() || 'no attributes'}) is blocked: script-src needs ${hashes[0]}`);
      }
    }
    for (const [n, s] of styleBlocks().entries()) {
      const hashes = cspHashes(s.body);
      const ok = hashes.some((h) => styleSrc.includes(h)) || (s.nonce && styleSrc.includes(`'nonce-${s.nonce}'`));
      if (!ok) problems.push(`inline <style> #${n} is blocked: style-src needs ${hashes[0]}`);
    }
  }
  assert.deepEqual(problems, [], 'under its own CSP a browser would refuse to run or style parts of the page');
});
