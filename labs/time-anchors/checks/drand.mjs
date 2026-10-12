// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Aukora
// Check pinned offline verification and detect removal of its protections.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { bls12_381 } from '../../../packages/authority/upstream/vendor/authority/deps/@noble/curves@2.2.0/bls12-381.js';
import { verifyDrandRound } from '../drand.mjs';

// Public quicknet fixture retained from the donor test (captured 2026-07-08).
const FIX = {
  round: 30226057,
  randomness: '95443ca4a22318a59f34f9a1933d2afa8cfc1df8a05bc0f1020993c351e1f109',
  signature: '8a60dcbcfc1036a69c229bbc5ff59ced72d960fa13dcb7e1561201afa918210fb5a668c9b251fc794d54705dcb5c3369',
};
const unverified = { ok: false, code: 'drand_signature_unverified' };
const cases = {
  'captured round verifies'(verify) {
    assert.equal(verify(FIX.round, FIX.signature).ok, true);
  },
  'tampered round is refused'(verify) {
    assert.deepEqual(verify(FIX.round + 1, FIX.signature), unverified);
  },
  'tampered signature is refused'(verify) {
    assert.deepEqual(verify(FIX.round, 'a' + FIX.signature.slice(1)), unverified);
    assert.deepEqual(verify(FIX.round, bls12_381.G1.Point.BASE.toHex()), unverified);
  },
  'round bounds refuse unsafe integers and coercion'(verify) {
    for (const round of [0, -1, 1.5, NaN, Infinity, 2 ** 53, 2 ** 64, '30226057', 30226057n, null, undefined, {}]) {
      assert.deepEqual(verify(round, FIX.signature), { ok: false, code: 'drand_round_invalid' });
    }
    assert.deepEqual(verify(Number.MAX_SAFE_INTEGER, FIX.signature), unverified);
  },
  'signature shape refuses malformed inputs without coercion'(verify) {
    let coerced = 0;
    const object = { length: 96, toString() { coerced++; return FIX.signature; }, toLowerCase() { return FIX.signature; } };
    for (const signature of ['', 'zz'.repeat(48), FIX.signature.slice(2), FIX.signature + '00',
      FIX.signature + '\n', null, undefined, 1, Symbol('signature'), object]) {
      assert.doesNotThrow(() => assert.deepEqual(verify(FIX.round, signature), { ok: false, code: 'drand_signature_invalid' }));
    }
    assert.equal(coerced, 0);
  },
  'malformed and infinity points never throw or verify'(verify) {
    for (const signature of ['00'.repeat(48), 'c0' + '00'.repeat(47), '80' + '00'.repeat(47)]) {
      assert.doesNotThrow(() => assert.deepEqual(verify(FIX.round, signature), unverified));
    }
  },
  'foreign signing key is refused'(verify) {
    const be8 = Buffer.alloc(8);
    be8.writeBigUInt64BE(BigInt(FIX.round));
    const digest = createHash('sha256').update(be8).digest();
    const message = bls12_381.shortSignatures.hash(digest, 'BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_');
    // A disposable scalar of one gives the public G2 generator; no signing secret is retained.
    const scalar = new Uint8Array(32);
    scalar[31] = 1;
    const signature = bls12_381.shortSignatures.sign(message, scalar);
    assert.equal(bls12_381.shortSignatures.verify(signature, message, bls12_381.G2.Point.BASE), true);
    assert.deepEqual(verify(FIX.round, signature.toHex()), unverified);
  },
  'randomness is derived from verified bytes, including uppercase hex'(verify) {
    for (const signature of [FIX.signature, FIX.signature.toUpperCase()]) {
      const result = verify(FIX.round, signature, 'untrusted randomness');
      assert.equal(result.ok, true);
      assert.equal(result.signature, FIX.signature);
      assert.equal(result.randomness, FIX.randomness);
    }
  },
  'result carries only advisory round evidence'(verify) {
    assert.deepEqual(verify(FIX.round, FIX.signature), {
      ok: true,
      chainHash: '52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971',
      ...FIX,
      advisoryOnly: true,
      grantsAuthority: false,
    });
  },
  'verification is synchronous with zero fetches'(verify) {
    const original = globalThis.fetch;
    let fetched = 0;
    globalThis.fetch = () => { fetched++; throw new Error('unexpected network request'); };
    try {
      assert.equal(verify(FIX.round, FIX.signature).ok, true);
      assert.deepEqual(verify(FIX.round + 1, FIX.signature), unverified);
      assert.equal(fetched, 0);
    } finally {
      globalThis.fetch = original;
    }
  },
};

for (const [name, check] of Object.entries(cases)) {
  check(verifyDrandRound);
  console.log(`PASS ${name}`);
}

// Import transformed copies in memory; the production module is never rewritten.
const url = new URL('../drand.mjs', import.meta.url);
const source = (await readFile(url, 'utf8')).replace(/from '(\.\.\/[^']+)';/g,
  (_match, path) => `from '${new URL(path, url).href}';`);
const mutants = [
  ['safe integer', 'Number.isSafeInteger(round)', 'Number.isInteger(round)', 'round bounds refuse unsafe integers and coercion'],
  ['positive round', ' || round <= 0', '', 'round bounds refuse unsafe integers and coercion'],
  ['signature type', "typeof signatureHex !== 'string' || ", '', 'signature shape refuses malformed inputs without coercion'],
  ['signature length', '[0-9a-f]{96}', '[0-9a-f]+', 'signature shape refuses malformed inputs without coercion'],
  ['signature hex', '!/^[0-9a-f]{96}$/i.test(signatureHex)', 'false', 'signature shape refuses malformed inputs without coercion'],
  ['round binding', 'BigInt(round)', '30226057n', 'tampered round is refused'],
  ['round byte order', 'writeBigUInt64BE', 'writeBigUInt64LE', 'captured round verifies'],
  ['message hash', 'hash(sha256(be8), DST)', 'hash(be8, DST)', 'captured round verifies'],
  ['domain separation', 'SHA-256_SSWU_RO_NUL_', 'SHA-256_SSWU_RO_POP_', 'captured round verifies'],
  ['pinned key', 'bls12_381.G2.Point.fromHex(DRAND_PUBLIC_KEY)', 'bls12_381.G2.Point.BASE', 'foreign signing key is refused'],
  ['BLS verification', '!bls12_381.shortSignatures.verify(signature, message, publicKey)', 'false', 'tampered round is refused'],
  ['malformed point refusal', "} catch {\n    return { ok: false, code: 'drand_signature_unverified' };", '} catch {\n    throw new Error("malformed point");', 'malformed and infinity points never throw or verify'],
  ['randomness derivation', "sha256(Buffer.from(signatureHex, 'hex'))", "sha256(Buffer.from(signatureHex))", 'randomness is derived from verified bytes, including uppercase hex'],
  ['advisory only', 'advisoryOnly: true', 'advisoryOnly: false', 'result carries only advisory round evidence'],
  ['no authority', 'grantsAuthority: false', 'grantsAuthority: true', 'result carries only advisory round evidence'],
  ['offline only', 'const be8 = Buffer.alloc(8);', "globalThis.fetch('https://example.invalid');\n    const be8 = Buffer.alloc(8);", 'verification is synchronous with zero fetches'],
];
for (const [name, before, after, check] of mutants) {
  assert.equal(source.split(before).length, 2, `unique mutation site: ${name}`);
  const code = source.replace(before, after);
  const mutated = await import(`data:text/javascript;base64,${Buffer.from(code).toString('base64')}`);
  assert.throws(() => cases[check](mutated.verifyDrandRound), assert.AssertionError, `surviving mutant: ${name}`);
  console.log(`PASS mutation killed: ${name}`);
}
console.log(`PASS time-anchors: ${Object.keys(cases).length} checks; ${mutants.length} mutants killed`);
