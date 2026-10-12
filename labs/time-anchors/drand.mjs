// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Aukora
// Verify quicknet rounds offline against a pinned key; derive advisory randomness.
import { createHash } from 'node:crypto';
import { bls12_381 } from '../../packages/authority/upstream/vendor/authority/deps/@noble/curves@2.2.0/bls12-381.js';

export const DRAND_CHAIN_HASH = '52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971';
export const DRAND_PUBLIC_KEY =
  '83cf0f2896adee7eb8b5f01fcad3912212c437e0073e911fb90022d3e760183c8c4b450b6a0a6c3ac6a5776a2d1064510d1fec758c921cc22b0e17e63aaf4bcb5ed66304de9cf809bd274ca73bab4af5a6e9c76a4bc09e76eae8991ef5ece45a';
const DST = 'BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_';

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest();
}

export function verifyDrandRound(round, signatureHex) {
  if (!Number.isSafeInteger(round) || round <= 0) {
    return { ok: false, code: 'drand_round_invalid' };
  }
  if (typeof signatureHex !== 'string' || !/^[0-9a-f]{96}$/i.test(signatureHex)) {
    return { ok: false, code: 'drand_signature_invalid' };
  }
  try {
    const be8 = Buffer.alloc(8);
    be8.writeBigUInt64BE(BigInt(round));
    const signature = bls12_381.G1.Point.fromHex(signatureHex);
    const publicKey = bls12_381.G2.Point.fromHex(DRAND_PUBLIC_KEY);
    const message = bls12_381.shortSignatures.hash(sha256(be8), DST);
    if (!bls12_381.shortSignatures.verify(signature, message, publicKey)) {
      return { ok: false, code: 'drand_signature_unverified' };
    }
    return {
      ok: true,
      chainHash: DRAND_CHAIN_HASH,
      round,
      signature: signatureHex.toLowerCase(),
      randomness: sha256(Buffer.from(signatureHex, 'hex')).toString('hex'),
      advisoryOnly: true,
      grantsAuthority: false,
    };
  } catch {
    return { ok: false, code: 'drand_signature_unverified' };
  }
}
