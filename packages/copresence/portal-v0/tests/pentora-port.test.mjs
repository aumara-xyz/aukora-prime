// The shared Pentora module and frozen portal must agree with the imported vectors.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { createHash, webcrypto } from 'node:crypto';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { PENTORA, pentoraDigest, pentoraDigits } from '../../../../apps/aukora-desktop/pentora.mjs';
import { loadCore } from './load-core.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const MODULE_JS = new URL('../../../../apps/aukora-desktop/pentora.mjs', import.meta.url);
const VECTORS_JSON = path.join(here, 'pentora-vectors.json');
// Read-only reference implementation. Override the location for other machines.
const IDENTITY_ROOT = process.env.PENTORA_IDENTITY_ROOT || path.join(here, 'data', 'identity');

const portText = fs.readFileSync(MODULE_JS, 'utf8');

// Injected hash, in the shape a browser supplies it.
const sha256 = async bytes => new Uint8Array(await webcrypto.subtle.digest('SHA-256', bytes));

const hex = bytes => Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
const unhex = text => Uint8Array.from(text.match(/../g), pair => parseInt(pair, 16));
const dist = (p, q) => Math.hypot(p[0] - q[0], p[1] - q[1], p[2] - q[2]);
const edgeKey = (i, j) => (i < j ? `${i},${j}` : `${j},${i}`);

// Spec section 3, "Shared corners (double_corner_indices)".
const SPEC_DOUBLE_CORNERS = [0, 1, 10, 12, 16, 18, 27, 28, 52, 53, 57, 58, 82, 83, 92, 94, 98, 100, 109, 110];
// Points are stored to 6 decimals, so each coordinate is within 0.5e-6 of exact.
const COORD_EPS = 5.000001e-7;
// A cube inscribed in the unit sphere (corners at radius 1) has edge 2/sqrt(3).
const CUBE_EDGE = 2 / Math.sqrt(3);
// Local slot order is product((-1,0,+1), repeat=3): index = 9*(x+1) + 3*(y+1) + (z+1).
const local = (x, y, z) => 9 * (x + 1) + 3 * (y + 1) + (z + 1);

// Deterministic head generator (xorshift32). No Math.random.
function* pseudoRandomHeads(seed, count) {
  let s = seed >>> 0;
  for (let n = 0; n < count; n += 1) {
    const head = new Uint8Array(32);
    for (let i = 0; i < 32; i += 1) {
      s ^= s << 13; s >>>= 0;
      s ^= s >>> 17;
      s ^= s << 5; s >>>= 0;
      head[i] = s & 0xff;
    }
    yield head;
  }
}

test('shared module exports the derivation without dependencies or Node APIs', () => {
  const code = portText.replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/[^\n]*/g, '');
  const iConst = code.indexOf('export const PENTORA = {');
  const iDigest = code.indexOf('export async function pentoraDigest(head32, sha256)');
  const iDigits = code.indexOf('export async function pentoraDigits(head32, sha256)');
  assert.ok(iConst >= 0 && iDigest > iConst && iDigits > iDigest, 'PENTORA, pentoraDigest, pentoraDigits in that order');
  assert.doesNotMatch(code, /\b(import|require|process|Buffer|BigInt|crypto|module|globalThis|window)\b/);
  assert.doesNotMatch(code, /\d\.\d{7,}/, 'no numeric literal beyond 6 decimal places');
  assert.doesNotMatch(code.slice(0, iDigest), /\bawait\b/, 'no top-level await');
  assert.match(portText, /^\/\*[^]*?PENTORA-EXPANSION-v1-NORMATIVE\.md[^]*?[0-9a-f]{64}[^]*?\*\//, 'header names the spec and the pin');
  assert.doesNotMatch(portText, /<\/script/i);
});

test('(a) known-answer vectors: digest and all 110 digits match', async () => {
  const vectors = JSON.parse(fs.readFileSync(VECTORS_JSON, 'utf8'));
  assert.equal(vectors.length, 64, 'first 48 + last 16 records of expansion_vectors_1006.json');
  for (const [n, vector] of vectors.entries()) {
    assert.deepEqual(Object.keys(vector), ['head', 'sha256', 'wire_hex'], `vector ${n} fields`);
    assert.match(vector.head, /^[0-9a-f]{64}$/);
    assert.match(vector.wire_hex, /^(00|01|02){110}$/, `vector ${n} wire form is 110 bytes of 0..2`);
    const head = unhex(vector.head);
    const digest = await pentoraDigest(head, sha256);
    assert.ok(digest instanceof Uint8Array && digest.length === 32);
    assert.equal(hex(digest), vector.sha256, `vector ${n} digest`);
    const digits = await pentoraDigits(head, sha256);
    assert.ok(digits instanceof Uint8Array, 'digits are a Uint8Array');
    assert.equal(digits.length, 110);
    const expected = unhex(vector.wire_hex);
    for (let i = 0; i < 110; i += 1) assert.equal(digits[i], expected[i], `vector ${n} digit ${i}`);
    assert.equal(hex(head), vector.head, 'head input is not modified');
  }
});

test('frozen portal matches the shared module on vectors, generated heads and geometry', async () => {
  const portal = loadCore();
  const vectors = JSON.parse(fs.readFileSync(VECTORS_JSON, 'utf8'));
  const heads = [...vectors.map(vector => unhex(vector.head)), ...pseudoRandomHeads(0x9e3779b9, 200)];
  for (const head of heads) {
    const digest = await pentoraDigest(head, sha256);
    assert.deepEqual(await portal.pentoraDigest(head), digest, `digest for ${hex(head)}`);
    assert.deepEqual(await portal.pentoraDigits(head), await pentoraDigits(head, sha256), `digits for ${hex(head)}`);
    assert.equal(await portal.shortDigest(head), hex(digest.subarray(0, 4)).toUpperCase(), `short digest for ${hex(head)}`);
  }
  assert.equal(heads.length, 264);
  assert.equal(portal.PENTORA.centre, PENTORA.centre);
  assert.deepEqual(portal.PENTORA.mutable, PENTORA.mutable);
  assert.deepEqual(portal.PENTORA.edges, PENTORA.edges);
  assert.equal(portal.PENTORA.points.length, PENTORA.points.length);
  for (const [i, point] of PENTORA.points.entries()) {
    assert.equal(portal.PENTORA.points[i].length, 3);
    for (let axis = 0; axis < 3; axis += 1) {
      assert.ok(Math.abs(point[axis] - portal.PENTORA.points[i][axis]) <= 5.000001e-6,
        `portal point ${i} coordinate ${axis} agrees at its 5-decimal precision`);
    }
  }
});

test('expansion: independent BigInt recomputation, sync and ArrayBuffer hashes agree', async () => {
  const syncHash = bytes => new Uint8Array(createHash('sha256').update(bytes).digest());
  const bufferHash = bytes => webcrypto.subtle.digest('SHA-256', bytes);
  for (const head of pseudoRandomHeads(0x51f15e, 16)) {
    const message = new Uint8Array(51);
    message.set(new TextEncoder().encode('pentora.display.v1'), 0); // byte 18 is the NUL
    message.set(head, 19);
    let n = BigInt('0x' + createHash('sha256').update(message).digest('hex'));
    const want = [];
    for (let i = 0; i < 110; i += 1) { want.push(Number(n % 3n)); n /= 3n; }
    for (const hash of [sha256, syncHash, bufferHash]) {
      assert.deepEqual(Array.from(await pentoraDigits(head, hash)), want);
    }
  }
});

test('input rejection: head must be exactly 32 bytes, hash must return 32 bytes', async () => {
  for (const length of [0, 1, 31, 33, 64]) {
    await assert.rejects(pentoraDigits(new Uint8Array(length), sha256), { name: 'RangeError', message: 'pentora:head-invalid' }, `length ${length}`);
    await assert.rejects(pentoraDigest(new Uint8Array(length), sha256), { name: 'RangeError', message: 'pentora:head-invalid' }, `length ${length}`);
  }
  for (const bad of [undefined, null, 'a'.repeat(32), '0'.repeat(64), Array(32).fill(0), new Uint16Array(32), new ArrayBuffer(32)]) {
    await assert.rejects(pentoraDigits(bad, sha256), { name: 'RangeError', message: 'pentora:head-invalid' });
  }
  for (const badHash of [async () => new Uint8Array(20), async () => 32, async () => '0'.repeat(32), async () => null]) {
    await assert.rejects(pentoraDigits(new Uint8Array(32), badHash), { name: 'TypeError', message: 'pentora:hash-invalid' });
  }
  let seen = null;
  await pentoraDigest(new Uint8Array(32).fill(7), async bytes => { seen = Uint8Array.from(bytes); return new Uint8Array(32); });
  assert.equal(seen.length, 51);
  assert.equal(new TextDecoder().decode(seen.subarray(0, 18)), 'pentora.display.v1');
  assert.equal(seen[18], 0);
  assert.deepEqual(Array.from(seen.subarray(19)), Array(32).fill(7));
});

test('(b) geometry counts: 111 points, 110 mutable cells without the centre, 60 cube edges', () => {
  assert.deepEqual(Object.keys(PENTORA), ['centre', 'mutable', 'points', 'edges', 'cubes']);
  assert.equal(PENTORA.centre, 55);
  assert.equal(PENTORA.points.length, 111);
  for (const point of PENTORA.points) {
    assert.equal(point.length, 3);
    for (const v of point) assert.ok(Number.isFinite(v) && Math.abs(v * 1e6 - Math.round(v * 1e6)) < 1e-6, `6 decimals: ${v}`);
  }
  assert.deepEqual(PENTORA.points[55], [0, 0, 0], 'centre sits at the origin');
  // Global order is lexicographic in the real coordinates (spec section 3).
  for (let i = 1; i < 111; i += 1) {
    const [p, q] = [PENTORA.points[i - 1], PENTORA.points[i]];
    const k = p.findIndex((v, axis) => v !== q[axis]);
    assert.ok(k >= 0 && p[k] < q[k], `points ${i - 1} < ${i} lexicographically`);
  }

  assert.equal(PENTORA.mutable.length, 110);
  assert.ok(!PENTORA.mutable.includes(55), 'centre is not mutable');
  assert.deepEqual(PENTORA.mutable, Array.from({ length: 111 }, (_, i) => i).filter(i => i !== 55), 'ascending 0..110 without 55');

  const radii = PENTORA.points.map(p => Math.hypot(...p));
  const maxRadius = Math.max(...radii);
  assert.ok(Math.abs(maxRadius - 1) <= 1e-6, `largest radius is 1 at 6-decimal precision, got ${maxRadius}`);
  const outer = radii.flatMap((r, i) => (Math.abs(r - 1) <= 1e-6 ? [i] : []));
  assert.deepEqual(outer, SPEC_DOUBLE_CORNERS, 'the unit-radius points are exactly the 20 shared corners');

  assert.equal(PENTORA.edges.length, 60);
  assert.equal(new Set(PENTORA.edges.map(([i, j]) => edgeKey(i, j))).size, 60, 'edges are deduplicated');
  for (const [i, j] of PENTORA.edges) {
    assert.ok(Number.isInteger(i) && Number.isInteger(j) && i >= 0 && j <= 110 && i < j, `edge [${i},${j}] indices`);
    const length = dist(PENTORA.points[i], PENTORA.points[j]);
    assert.ok(Math.abs(length - CUBE_EDGE) <= 2e-6, `edge [${i},${j}] length ${length} != ${CUBE_EDGE}`);
  }
});

test('(b) cubes: 27-slot lattices whose corner adjacency is exactly the edge list', () => {
  assert.equal(PENTORA.cubes.length, 5);
  const fromCubes = new Set();
  for (const [c, cube] of PENTORA.cubes.entries()) {
    assert.equal(cube.length, 27);
    assert.equal(new Set(cube).size, 27, `cube ${c} slots are distinct`);
    assert.equal(cube[local(0, 0, 0)], 55, `cube ${c} local centre is global 55`);
    const at = (x, y, z) => PENTORA.points[cube[local(x, y, z)]];
    const axes = [at(1, 0, 0), at(0, 1, 0), at(0, 0, 1)];
    for (const [a, axis] of axes.entries()) {
      assert.ok(Math.abs(Math.hypot(...axis) - CUBE_EDGE / 2) <= 2e-6, `cube ${c} axis ${a} length`);
      const next = axes[(a + 1) % 3];
      assert.ok(Math.abs(axis[0] * next[0] + axis[1] * next[1] + axis[2] * next[2]) <= 2e-6, `cube ${c} axes orthogonal`);
    }
    for (const x of [-1, 0, 1]) for (const y of [-1, 0, 1]) for (const z of [-1, 0, 1]) {
      const p = at(x, y, z);
      for (let k = 0; k < 3; k += 1) {
        const want = x * axes[0][k] + y * axes[1][k] + z * axes[2][k];
        assert.ok(Math.abs(p[k] - want) <= 4 * COORD_EPS, `cube ${c} slot (${x},${y},${z}) coordinate ${k}`);
      }
    }
    const corners = [];
    for (const x of [-1, 1]) for (const y of [-1, 1]) for (const z of [-1, 1]) corners.push([x, y, z]);
    for (const p of corners) for (const q of corners) {
      const differing = p.filter((v, k) => v !== q[k]).length;
      if (differing === 1) fromCubes.add(edgeKey(cube[local(...p)], cube[local(...q)]));
    }
  }
  assert.equal(fromCubes.size, 60, '5 cubes x 12 edges, none shared');
  assert.deepEqual([...fromCubes].sort(), PENTORA.edges.map(([i, j]) => edgeKey(i, j)).sort());
});

test('(c) the 20 spec double corners each appear in exactly two cubes', () => {
  assert.equal(SPEC_DOUBLE_CORNERS.length, 20);
  const uses = Array(111).fill(0);
  for (const cube of PENTORA.cubes) for (const index of cube) uses[index] += 1;
  for (const index of SPEC_DOUBLE_CORNERS) assert.equal(uses[index], 2, `global ${index} cube count`);
  assert.equal(uses[55], 5, 'centre is shared by all five cubes');
  const tally = { 1: 0, 2: 0, 5: 0 };
  for (const count of uses) tally[count] += 1;
  assert.deepEqual(tally, { 1: 90, 2: 20, 5: 1 }, '90 private, 20 shared corners, 1 centre');
  // 135 slots over 111 locations, and the shared locations are the cube corners.
  const cornerSlots = PENTORA.cubes.flatMap(cube => [-1, 1].flatMap(x => [-1, 1].flatMap(y => [-1, 1].map(z => cube[local(x, y, z)]))));
  assert.deepEqual([...new Set(cornerSlots)].sort((a, b) => a - b), SPEC_DOUBLE_CORNERS);
  assert.deepEqual([...new Set(PENTORA.edges.flat())].sort((a, b) => a - b), SPEC_DOUBLE_CORNERS);
});

// (d) Differential check against the real modules. They are imported, never copied or modified.
let real = null;
let skipDifferential = false;
try {
  const dir = path.join(IDENTITY_ROOT, 'src', 'pentora');
  const expansion = await import(pathToFileURL(path.join(dir, 'expansion.mjs')).href);
  const geometry = await import(pathToFileURL(path.join(dir, 'geometry.mjs')).href);
  real = { dir, expandHead: expansion.expandHead, GEOMETRY: geometry.GEOMETRY };
} catch (error) {
  skipDifferential = `reference implementation not importable from ${IDENTITY_ROOT} (${error.code || error.name}: ${String(error.message).slice(0, 160)})`;
}

test('(d) differential: expandHead agrees on 200 pseudo-random heads', { skip: skipDifferential }, async () => {
  let compared = 0;
  const edgeHeads = [new Uint8Array(32), new Uint8Array(32).fill(0xff), Uint8Array.from({ length: 32 }, (_, i) => i)];
  for (const head of [...edgeHeads, ...pseudoRandomHeads(0x9e3779b9, 200)]) {
    const want = real.expandHead(head);
    const got = await pentoraDigits(head, sha256);
    assert.equal(want.length, 110);
    assert.deepEqual(Array.from(got), Array.from(want), `head ${hex(head)}`);
    compared += 1;
  }
  assert.equal(compared, 203);
  for (const length of [31, 33]) {
    assert.throws(() => real.expandHead(new Uint8Array(length)), RangeError);
    await assert.rejects(pentoraDigits(new Uint8Array(length), sha256), RangeError);
  }
});

test('(d) differential: geometry equals the real GEOMETRY up to one uniform scale', { skip: skipDifferential }, () => {
  const G = real.GEOMETRY;
  assert.equal(PENTORA.centre, G.centreIndex);
  assert.equal(G.centreValue, 0);
  assert.deepEqual(PENTORA.mutable, [...G.mutableIndices]);
  assert.deepEqual(PENTORA.cubes, G.cubes.map(cube => [...cube.slots]));
  const realEdges = new Set(G.cubes.flatMap(cube => cube.edges.map(([i, j]) => edgeKey(i, j))));
  assert.deepEqual(PENTORA.edges.map(([i, j]) => edgeKey(i, j)).sort(), [...realEdges].sort());
  assert.deepEqual(G.points.flatMap(p => (p.multiplicity === 2 ? [p.globalIndex] : [])), SPEC_DOUBLE_CORNERS);

  assert.equal(G.points.length, 111);
  const scale = Math.max(...G.points.map(p => Math.hypot(...p.xyz)));
  assert.ok(Math.abs(scale - Math.sqrt(3)) < 1e-12, 'reference corners sit at radius sqrt(3)');
  let worst = 0;
  for (const [i, point] of G.points.entries()) {
    assert.equal(point.globalIndex, i);
    for (let k = 0; k < 3; k += 1) {
      const error = Math.abs(point.xyz[k] / scale - PENTORA.points[i][k]);
      worst = Math.max(worst, error);
      assert.ok(error <= COORD_EPS, `point ${i} coordinate ${k}: ${PENTORA.points[i][k]} vs ${point.xyz[k] / scale}`);
    }
  }
  assert.ok(worst <= COORD_EPS);
});

test('(d) differential: header pin is the pinned-data.mjs pin and the hash of the geometry file', { skip: skipDifferential }, () => {
  const pin = portText.match(/sha256 pin ([0-9a-f]{64})/)?.[1];
  assert.ok(pin, 'header carries a sha256 pin');
  const pinned = fs.readFileSync(path.join(real.dir, 'pinned-data.mjs'), 'utf8');
  assert.ok(pinned.includes(`'geometry_index_table_v1.json': '${pin}'`), 'pin matches src/pentora/pinned-data.mjs');
  const data = fs.readFileSync(path.join(IDENTITY_ROOT, 'spec', 'pentora-v1', 'data', 'geometry_index_table_v1.json'));
  assert.equal(createHash('sha256').update(data).digest('hex'), pin);
});
