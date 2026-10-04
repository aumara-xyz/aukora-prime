// SPDX-License-Identifier: AGPL-3.0-only
// Pure sign/verify port of AUKORA-MEMBRANE/core/pqc.ts. Caller-supplied
// signatures are evidence only: this lab module grants no authority.
// It has no key generation, custody, storage, or signing-service path.
import { ml_dsa65 } from '../../packages/authority/upstream/vendor/authority/deps/@noble/post-quantum@0.6.1/ml-dsa.js';
import { ed25519 } from '../../packages/authority/upstream/vendor/authority/deps/@noble/curves@2.2.0/ed25519.js';

export const RECEIPT_SIGN_DOMAIN = 'aukora-membrane-receipt-v1';
export const HYBRID_ALGORITHM = 'ml-dsa-65+ed25519';
export const SIGNATURE_BUNDLE_SCHEMA = 'aukora-membrane-hybrid-signature-v1';

const ML_PUBLIC_KEY_BYTES = 1952;
const ML_SECRET_KEY_BYTES = 4032;
const ML_SIGNATURE_BYTES = 3309;
const ED_PUBLIC_KEY_BYTES = 32;
const ED_SECRET_KEY_BYTES = 32;
const ED_SIGNATURE_BYTES = 64;
const DIGEST_HEX = /^[0-9a-f]{64}$/;
const ML_SIGNATURE_HEX = /^[0-9a-f]{6618}$/;
const ED_SIGNATURE_HEX = /^[0-9a-f]{128}$/;
const BUNDLE_FIELDS = ['schema', 'algorithm', 'message', 'mlDsa65', 'ed25519'];
const KEY_FIELDS = ['mlDsa65', 'ed25519'];
const KEYPAIR_FIELDS = ['publicKey', 'secretKey'];
const encoder = new TextEncoder();
const receiptContext = encoder.encode(RECEIPT_SIGN_DOMAIN);
const typedArrayLength = Object.getOwnPropertyDescriptor(
  Object.getPrototypeOf(Uint8Array.prototype), 'length',
).get;

// Snapshot only the values of a closed, plain record's own data properties.
// Accessor properties, symbols, inherited fields, and extra fields are invalid.
function closedDataRecord(input, fields) {
  if (input === null || typeof input !== 'object') {
    throw new TypeError('hybrid_signature_input_invalid');
  }
  const prototype = Object.getPrototypeOf(input);
  if (prototype !== Object.prototype && prototype !== null) {
    throw new TypeError('hybrid_signature_input_invalid');
  }
  const ownKeys = Reflect.ownKeys(input);
  if (ownKeys.length !== fields.length || ownKeys.some((key) => typeof key !== 'string')) {
    throw new TypeError('hybrid_signature_input_invalid');
  }
  const record = Object.create(null);
  for (const field of fields) {
    const descriptor = Object.getOwnPropertyDescriptor(input, field);
    if (!descriptor || !Object.hasOwn(descriptor, 'value') || !descriptor.enumerable) {
      throw new TypeError('hybrid_signature_input_invalid');
    }
    record[field] = descriptor.value;
  }
  return record;
}

// Native byte views only; never call a caller's iterator, species, or methods.
// Copying also keeps signing and verification from mutating supplied key bytes.
function copyBytes(input, length) {
  if (!ArrayBuffer.isView(input) || !(input instanceof Uint8Array)
      || typedArrayLength.call(input) !== length) {
    throw new TypeError('hybrid_signature_input_invalid');
  }
  const ownKeys = Reflect.ownKeys(input);
  if (ownKeys.length !== length) {
    throw new TypeError('hybrid_signature_input_invalid');
  }
  const bytes = new Uint8Array(length);
  for (let index = 0; index < length; index += 1) {
    if (ownKeys[index] !== String(index)) {
      throw new TypeError('hybrid_signature_input_invalid');
    }
    bytes[index] = input[index];
  }
  return bytes;
}

function sameBytes(left, right) {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index += 1) {
    difference |= left[index] ^ right[index];
  }
  return difference === 0;
}

function toHex(bytes) {
  let hex = '';
  for (const byte of bytes) hex += byte.toString(16).padStart(2, '0');
  return hex;
}

// Call only after the exact lowercase hexadecimal shape has been checked.
function fromHex(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let index = 0; index < bytes.length; index += 1) {
    bytes[index] = Number.parseInt(hex.slice(index * 2, index * 2 + 2), 16);
  }
  return bytes;
}

/** Sign one exact lowercase 64-hex digest with both supplied keypairs. */
export function hybridSign(message, keys) {
  if (typeof message !== 'string' || message.length !== 64 || !DIGEST_HEX.test(message)) {
    throw new TypeError('hybrid_sign_message_invalid');
  }
  let mlSecret;
  let edSecret;
  try {
    const keyRecord = closedDataRecord(keys, KEY_FIELDS);
    const mlKeys = closedDataRecord(keyRecord.mlDsa65, KEYPAIR_FIELDS);
    const edKeys = closedDataRecord(keyRecord.ed25519, KEYPAIR_FIELDS);
    const mlPublic = copyBytes(mlKeys.publicKey, ML_PUBLIC_KEY_BYTES);
    const edPublic = copyBytes(edKeys.publicKey, ED_PUBLIC_KEY_BYTES);
    mlSecret = copyBytes(mlKeys.secretKey, ML_SECRET_KEY_BYTES);
    edSecret = copyBytes(edKeys.secretKey, ED_SECRET_KEY_BYTES);
    if (!sameBytes(ml_dsa65.getPublicKey(mlSecret), mlPublic)
        || !sameBytes(ed25519.getPublicKey(edSecret), edPublic)) {
      throw new TypeError('hybrid_sign_keys_invalid');
    }

    const msg = encoder.encode(message);
    // Adaptation from the donor's randomized default: use deterministic ML-DSA
    // signing. The fixed receipt context and signed message bytes are unchanged.
    const mlSignature = copyBytes(ml_dsa65.sign(msg, mlSecret, {
      context: receiptContext,
      extraEntropy: false,
    }), ML_SIGNATURE_BYTES);
    // Preserve the donor's asymmetry: plain Ed25519 signs the same bare UTF-8
    // digest, with neither an ML context nor an Ed25519ctx/prehash wrapper.
    const edSignature = copyBytes(ed25519.sign(msg, edSecret), ED_SIGNATURE_BYTES);
    // Fail closed if malformed private-key encodings cannot produce evidence
    // under the supplied public keys, even when public-key derivation matched.
    const mlOk = ml_dsa65.verify(mlSignature, msg, mlPublic, { context: receiptContext });
    const edOk = ed25519.verify(edSignature, msg, edPublic);
    if (!mlOk || !edOk) throw new Error('hybrid_sign_failed');

    return {
      schema: SIGNATURE_BUNDLE_SCHEMA,
      algorithm: HYBRID_ALGORITHM,
      message,
      mlDsa65: toHex(mlSignature),
      ed25519: toHex(edSignature),
    };
  } catch {
    // Keep validation/library failures content-free; never include key bytes.
    throw new Error('hybrid_sign_keys_or_signature_invalid');
  } finally {
    if (mlSecret !== undefined) mlSecret.fill(0);
    if (edSecret !== undefined) edSecret.fill(0);
  }
}

/** Verify both halves; every malformed input or failed half returns false. */
export function hybridVerify(bundle, message, pubs) {
  try {
    if (typeof message !== 'string' || message.length !== 64 || !DIGEST_HEX.test(message)) {
      return false;
    }
    const signature = closedDataRecord(bundle, BUNDLE_FIELDS);
    if (signature.schema !== SIGNATURE_BUNDLE_SCHEMA
        || signature.algorithm !== HYBRID_ALGORITHM
        || signature.message !== message
        || typeof signature.mlDsa65 !== 'string'
        || signature.mlDsa65.length !== ML_SIGNATURE_BYTES * 2
        || !ML_SIGNATURE_HEX.test(signature.mlDsa65)
        || typeof signature.ed25519 !== 'string'
        || signature.ed25519.length !== ED_SIGNATURE_BYTES * 2
        || !ED_SIGNATURE_HEX.test(signature.ed25519)) {
      return false;
    }
    const publicKeys = closedDataRecord(pubs, KEY_FIELDS);
    const mlPublic = copyBytes(publicKeys.mlDsa65, ML_PUBLIC_KEY_BYTES);
    const edPublic = copyBytes(publicKeys.ed25519, ED_PUBLIC_KEY_BYTES);
    const msg = encoder.encode(message);
    const mlOk = ml_dsa65.verify(fromHex(signature.mlDsa65), msg, mlPublic, {
      context: receiptContext,
    });
    const edOk = ed25519.verify(fromHex(signature.ed25519), msg, edPublic);
    return mlOk === true && edOk === true;
  } catch {
    return false;
  }
}

/** Signature evidence never grants authority. */
export function pqcGrantsAuthority() {
  return false;
}
