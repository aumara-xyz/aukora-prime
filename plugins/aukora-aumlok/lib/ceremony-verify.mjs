// Phrase fingerprints preserve the v3 normalized preimage and constant-time comparison.
import { createHash, timingSafeEqual, randomBytes, scryptSync } from 'node:crypto'

/** `aumlokBindCeremony.ts:39` — seven, and it is a named constant for a reason. */
export const BIND_PHRASE_WORDS = 7

export { normalizePhrase } from './ceremony-phrase.mjs'
import { normalizePhrase } from './ceremony-phrase.mjs'

// Preserve the legacy fingerprint preimage; this fast hash does not impose the root KDF cost.
export function saltedFingerprint(saltHex, phrase) {
  return createHash('sha256').update(`${saltHex}|${normalizePhrase(phrase)}`, 'utf-8').digest('hex')
}

/** `PHRASE_KDF_V2` — the donor's exact parameters. */
export const PHRASE_KDF_V2 = Object.freeze({ N: 1 << 15, r: 8, p: 1, keyLen: 32, maxmem: 128 * 1024 * 1024 })

/** @returns {string} the scrypt hash of the normalized phrase, hex. */
export function scryptHex(phrase, saltHex, N = PHRASE_KDF_V2.N, r = PHRASE_KDF_V2.r, p = PHRASE_KDF_V2.p) {
  return scryptSync(normalizePhrase(phrase), Buffer.from(saltHex, 'hex'), PHRASE_KDF_V2.keyLen,
    { N, r, p, maxmem: PHRASE_KDF_V2.maxmem }).toString('hex')
}

/** Constant-time hex compare. Length mismatch short-circuits, contents do not. */
export function safeEqualHex(a, b) {
  const ab = Buffer.from(String(a), 'utf-8')
  const bb = Buffer.from(String(b), 'utf-8')
  return ab.length === bb.length && timingSafeEqual(ab, bb)
}

/** A fresh salt per write. Never the genesis reference, never reused. */
export function newSaltHex() { return randomBytes(16).toString('hex') }

/**
 * Seal a phrase for storage: scrypt v2 with a fresh salt.
 *
 * Returns only what a receipt may carry. The phrase itself is not returned, not logged, and not
 * retained by this function.
 * @param {string} phrase - the phrase as typed.
 * @returns {{version: 'v2', saltHex: string, hashHex: string, N: number, r: number, p: number}} the seal.
 */
export function sealPhrase(phrase) {
  const saltHex = newSaltHex()
  return {
    version: 'v2',
    saltHex,
    hashHex: scryptHex(phrase, saltHex),
    N: PHRASE_KDF_V2.N, r: PHRASE_KDF_V2.r, p: PHRASE_KDF_V2.p,
  }
}

/** `verifyPhraseAgainstFingerprint` — both stored shapes, constant-time. */
export function verifyPhrase(typedPhrase, sealed) {
  if (!sealed || typeof sealed !== 'object') return false
  const s = sealed
  if (s.version === 'v1') {
    return safeEqualHex(saltedFingerprint(String(s.saltHex ?? ''), typedPhrase), s.sha256Hex)
  }
  if (s.version === 'v2') {
    return safeEqualHex(
      scryptHex(typedPhrase, String(s.saltHex ?? ''), Number(s.N), Number(s.r), Number(s.p)),
      s.hashHex,
    )
  }
  return false
}

/** Verifying a phrase grants nothing. In aukora-one the Ed25519 key signs; here the seam decides. */
export function verifyGrantsAuthority() {
  return false
}
