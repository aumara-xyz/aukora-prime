// SPDX-License-Identifier: AGPL-3.0-or-later
// Frozen draft-irtf-cfrg-hybrid-kems-03 KitchenSink + RFC 9180 base mode.
// EXPERIMENTAL: 0xbc48 is the draft's proposed, unassigned KEM identifier.
import { KitchenSink_ml_kem768_x25519 as kem } from '../../packages/authority/upstream/vendor/authority/deps/@noble/post-quantum@0.6.1/hybrid.js';
import { extract, expand } from '../../packages/authority/upstream/vendor/authority/deps/@noble/hashes@2.2.0/hkdf.js';
import { sha256 } from '../../packages/authority/upstream/vendor/authority/deps/@noble/hashes@2.2.0/sha2.js';
import { gcm } from '../../packages/authority/upstream/vendor/authority/deps/@noble/ciphers@2.2.0/aes.js';
import { bytesToHex, hexToBytes, concatBytes, utf8ToBytes } from '../../packages/authority/upstream/vendor/authority/deps/@noble/hashes@2.2.0/utils.js';

const envelopeSchema = 'aukora-prime-pq-key-wrap-v1';
export { envelopeSchema as KEY_WRAP_SCHEMA };
export const KEY_WRAP_PROFILE = 'draft-hybrid-kems-03-kitchensink-mlkem768-x25519-hpke-base-hkdf-sha256-aes256gcm';
const SUITE_ID = hexToBytes('48504b45bc4800010002');
const HPKE_VERSION = utf8ToBytes('HPKE-v1');
const DOMAIN = utf8ToBytes('aukora-prime.pq-hybrid.key-wrap.v1\0');
const EMPTY = new Uint8Array();
const typedArrayLength = Object.getOwnPropertyDescriptor(Object.getPrototypeOf(Uint8Array.prototype), 'length').get;

function invalid() { throw new Error('pq_key_wrap_invalid'); }
function closed(value, required, optional = []) {
  if (!value || typeof value !== 'object' || ![Object.prototype, null].includes(Object.getPrototypeOf(value))) invalid();
  const keys = Reflect.ownKeys(value);
  if (keys.some(k => typeof k !== 'string' || ![...required, ...optional].includes(k))) invalid();
  if (required.some(k => !Object.hasOwn(value, k))) invalid();
  for (const key of keys) {
    const d = Object.getOwnPropertyDescriptor(value, key);
    if (!d || !Object.hasOwn(d, 'value') || !d.enumerable) invalid();
  }
}
function bytes(value, size) {
  if (!ArrayBuffer.isView(value) || !(value instanceof Uint8Array) || typedArrayLength.call(value) !== size) invalid();
  const keys = Reflect.ownKeys(value);
  if (keys.length !== size) invalid();
  const copy = new Uint8Array(size);
  for (let i = 0; i < size; i++) {
    if (keys[i] !== String(i)) invalid();
    copy[i] = value[i];
  }
  return copy;
}
function contextBytes(value) {
  if (!ArrayBuffer.isView(value) || !(value instanceof Uint8Array)) invalid();
  const length = typedArrayLength.call(value);
  if (length < 1 || length > 1024) invalid();
  return bytes(value, length);
}
function hex(value, size) {
  if (typeof value !== 'string' || value.length !== size * 2 || !/^[0-9a-f]+$/.test(value)) invalid();
  return hexToBytes(value);
}
function equal(a, b) {
  if (a.length !== b.length) return false;
  let different = 0;
  for (let i = 0; i < a.length; i++) different |= a[i] ^ b[i];
  return different === 0;
}
function labeledExtract(salt, label, ikm = EMPTY) {
  return extract(sha256, concatBytes(HPKE_VERSION, SUITE_ID, utf8ToBytes(label), ikm), salt);
}
function labeledExpand(prk, label, info, length) {
  return expand(sha256, prk, concatBytes(new Uint8Array([length >>> 8, length & 255]), HPKE_VERSION, SUITE_ID, utf8ToBytes(label), info), length);
}
function infoFor(publicKey, encapsulation, context) {
  // Fixed-size public key and encapsulation boundaries; context is the final bytes.
  return concatBytes(DOMAIN, publicKey, encapsulation, context);
}
function keySchedule(sharedSecret, info) {
  // RFC 9180 §5.1: shared_secret is the EXTRACT SALT, not its IKM.
  const pskIdHash = labeledExtract(EMPTY, 'psk_id_hash');
  const infoHash = labeledExtract(EMPTY, 'info_hash', info);
  const scheduleContext = concatBytes(new Uint8Array([0]), pskIdHash, infoHash);
  const secret = labeledExtract(sharedSecret, 'secret');
  try {
    return {
      key: labeledExpand(secret, 'key', scheduleContext, 32),
      nonce: labeledExpand(secret, 'base_nonce', scheduleContext, 12),
    };
  } finally {
    secret.fill(0); pskIdHash.fill(0); infoHash.fill(0); scheduleContext.fill(0);
  }
}

/** Wrap one 32-byte content key. A fresh encapsulation is required for every call.
 * Optional randomness is the pinned KEM's 64-byte test/reproducibility input.
 * Production callers must omit it; the pinned library then uses its CSPRNG.
 */
export function wrapKey(dataKey, options) {
  let plaintext, sharedSecret, schedule, randomness;
  try {
    closed(options, ['recipientPublicKey', 'context'], ['randomness']);
    plaintext = bytes(dataKey, 32);
    const publicKey = bytes(options.recipientPublicKey, 1216);
    const context = contextBytes(options.context);
    randomness = Object.hasOwn(options, 'randomness') ? bytes(options.randomness, 64) : undefined;
    const encapsulated = kem.encapsulate(publicKey, randomness);
    sharedSecret = bytes(encapsulated.sharedSecret, 32);
    encapsulated.sharedSecret.fill(0);
    const enc = bytes(encapsulated.cipherText, 1120);
    const info = infoFor(publicKey, enc, context);
    schedule = keySchedule(sharedSecret, info);
    // Single-shot sequence 0: nonce is exactly the RFC-derived base_nonce.
    const ciphertext = gcm(schedule.key, schedule.nonce, info).encrypt(plaintext);
    return {
      schema: envelopeSchema,
      profile: KEY_WRAP_PROFILE,
      encapsulation: bytesToHex(enc),
      wrapped_key: bytesToHex(ciphertext),
      context: bytesToHex(context),
    };
  } catch { invalid(); }
  finally {
    plaintext?.fill(0); randomness?.fill(0); sharedSecret?.fill(0); schedule?.key.fill(0); schedule?.nonce.fill(0);
  }
}

/** Independently pinned recipient keys and expected context are mandatory.
 * HPKE BASE MODE DOES NOT AUTHENTICATE A SENDER or grant any authority.
 */
export function unwrapKey(envelope, options) {
  let privateKey, sharedSecret, schedule;
  try {
    closed(envelope, ['schema', 'profile', 'encapsulation', 'wrapped_key', 'context']);
    closed(options, ['recipientPrivateKey', 'recipientPublicKey', 'expectedContext']);
    if (envelope.schema !== envelopeSchema || envelope.profile !== KEY_WRAP_PROFILE) invalid();
    privateKey = bytes(options.recipientPrivateKey, 32);
    const publicKey = bytes(options.recipientPublicKey, 1216);
    const expectedContext = contextBytes(options.expectedContext);
    const context = hex(envelope.context, expectedContext.length);
    if (!equal(context, expectedContext) || !equal(kem.getPublicKey(privateKey), publicKey)) invalid();
    const enc = hex(envelope.encapsulation, 1120);
    const ciphertext = hex(envelope.wrapped_key, 48);
    const decapsulated = kem.decapsulate(enc, privateKey);
    sharedSecret = bytes(decapsulated, 32);
    decapsulated.fill(0);
    const info = infoFor(publicKey, enc, context);
    schedule = keySchedule(sharedSecret, info);
    const plaintext = gcm(schedule.key, schedule.nonce, info).decrypt(ciphertext);
    if (plaintext.length !== 32) invalid();
    return plaintext;
  } catch { invalid(); }
  finally {
    privateKey?.fill(0); sharedSecret?.fill(0); schedule?.key.fill(0); schedule?.nonce.fill(0);
  }
}

export function keyWrapGrantsAuthority() { return false; }
