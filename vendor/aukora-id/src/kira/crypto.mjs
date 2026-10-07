// Kira piece AEAD, distinct from NIP44 journal transport. Disposable custody only.
import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import { b64, canonicalBytes, closed, fail, h32, parseBytes, sha256, snapshotBytes, u64 } from '../bytes/index.mjs';
import { parseEnvelope, parseManifest, parseMapRecord } from './schema.mjs';
import registry from '../../spec/layer0-v1/registry.json' with { type: 'json' };

export const CIPHER_PROFILE = 'aukora.kira.aes256gcm.v1';
export const LEGACY_CIPHER_PROFILE = 'aukora.kira.chacha20poly1305.v1';
export const AAD_SCHEMA = 'aukora.kira.aad-context.v1';
export const MAX_PLAINTEXT_BYTES = 6128;
export const MAX_SEALS_PER_KEY = 1048576;
export const PROVENANCE_PROFILE = 'aukora.kira.provenance.claims.v1';
const writers = new WeakMap();
const demand = (ok, code = 'CLOSED_SCHEMA') => { if (!ok) fail(code); };
const literal = expected => actual => demand(actual === expected);
const readableProfile = value => demand(value === CIPHER_PROFILE || value === LEGACY_CIPHER_PROFILE, 'UNSUPPORTED_PROFILE');
export const encodeData = value => canonicalBytes(parseBytes(Buffer.from(JSON.stringify(value))));

export function parseAadContext(bytes) {
  const value = parseBytes(bytes);
  closed(value, { schema: literal(AAD_SCHEMA), subject_id: h32, chain_id: h32,
    map_id: h32, revision: u64, piece_id: id => { if (id !== null) h32(id); },
    key_ref: h32, cipher_profile: readableProfile });
  return value;
}
export function aadBytes(contextBytes) {
  return Buffer.concat([Buffer.from('aukora.kira.aad.v1\0', 'ascii'), canonicalBytes(parseAadContext(contextBytes))]);
}
// Pure map metadata check for the shared verifier: no keys, plaintext or effects.
// Registry activation is owned by CHAT2. Legacy decryption grants no map authority.
export function validateMapCryptoProfile(recordBytes) {
  const record = parseMapRecord(recordBytes), map = record.body, envelope = map.manifest;
  demand(envelope.cipher_profile === CIPHER_PROFILE && registry.accepted_cipher_profiles.includes(CIPHER_PROFILE), 'UNSUPPORTED_PROFILE');
  demand(map.provenance_profile === PROVENANCE_PROFILE && registry.accepted_provenance_profiles?.includes(PROVENANCE_PROFILE), 'UNSUPPORTED_PROFILE');
  b64(envelope.nonce, 12);
  const blob = Buffer.from(envelope.ciphertext, 'base64url');
  demand(blob.length >= 16 && blob.length <= MAX_PLAINTEXT_BYTES + 16, 'LIMIT_EXCEEDED');
  const aad = aadBytes(encodeData({ schema: AAD_SCHEMA, subject_id: record.subject_id, chain_id: record.chain_id,
    map_id: map.map_id, revision: map.revision, piece_id: null, key_ref: envelope.key_ref, cipher_profile: envelope.cipher_profile }));
  demand(sha256(aad).toString('hex') === envelope.aad_digest, 'WRONG_AUTHORITY');
  return record;
}
export function createWriteKey() {
  const handle = Object.freeze({ key_ref: randomBytes(32).toString('hex'), cipher_profile: CIPHER_PROFILE });
  writers.set(handle, { key: randomBytes(32), next: 0n });
  return handle;
}
function writer(handle) {
  const value = writers.get(handle);
  demand(value !== undefined, 'WRONG_AUTHORITY');
  return value;
}
export function writeKeyRef(handle) { writer(handle); return handle.key_ref; }
// Explicit out-of-band transfer for disposable tests, NEVER part of an archive.
// The returned key cannot be imported as a writer. Callers protect/erase copies.
export function exportDisposableReadKey(handle) {
  const state = writer(handle);
  return encodeData({ schema: 'aukora.kira.disposable-read-key.v1', key_ref: handle.key_ref,
    cipher_profile: CIPHER_PROFILE, key: state.key.toString('base64url') });
}
export function destroyWriteKey(handle) {
  const state = writer(handle);
  state.key.fill(0); writers.delete(handle);
}
function takeNonce(state) {
  demand(state.next < BigInt(MAX_SEALS_PER_KEY), 'LIMIT_EXCEEDED');
  let n = state.next++; // Burn before the cipher is attempted; never persisted or resumed.
  const nonce = Buffer.alloc(12);
  for (let i = 11; i >= 0; i--) { nonce[i] = Number(n & 255n); n >>= 8n; }
  return nonce;
}
function seal(plaintextBytes, contextBytes, handle, manifest) {
  const plaintext = Buffer.from(snapshotBytes(plaintextBytes, MAX_PLAINTEXT_BYTES));
  try {
    const context = parseAadContext(contextBytes), state = writer(handle);
    demand(context.cipher_profile === CIPHER_PROFILE, 'UNSUPPORTED_PROFILE');
    demand((context.piece_id === null) === manifest, 'WRONG_DOMAIN');
    demand(context.key_ref === handle.key_ref, 'WRONG_AUTHORITY');
    const aad = aadBytes(canonicalBytes(context)), nonce = takeNonce(state);
    const cipher = createCipheriv('aes-256-gcm', state.key, nonce, { authTagLength: 16 });
    cipher.setAAD(aad, { plaintextLength: plaintext.length });
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final(), cipher.getAuthTag()]);
    return encodeData({ cipher_profile: CIPHER_PROFILE, key_ref: handle.key_ref,
      nonce: nonce.toString('base64url'), ciphertext: ciphertext.toString('base64url'),
      aad_digest: sha256(aad).toString('hex') });
  } finally { plaintext.fill(0); }
}
function open(envelopeBytes, expectedContextBytes, readKeyBytes, manifest) {
  const envelope = parseEnvelope(envelopeBytes), expected = parseAadContext(expectedContextBytes);
  readableProfile(envelope.cipher_profile);
  demand(envelope.cipher_profile === expected.cipher_profile, 'WRONG_AUTHORITY');
  demand((expected.piece_id === null) === manifest, 'WRONG_DOMAIN');
  demand(envelope.key_ref === expected.key_ref, 'WRONG_AUTHORITY');
  b64(envelope.nonce, 12);
  const ciphertext = Buffer.from(envelope.ciphertext, 'base64url');
  demand(ciphertext.length >= 16 && ciphertext.length <= MAX_PLAINTEXT_BYTES + 16, 'LIMIT_EXCEEDED');
  const aad = aadBytes(canonicalBytes(expected));
  demand(envelope.aad_digest === sha256(aad).toString('hex'), 'WRONG_AUTHORITY');
  const custody = parseBytes(readKeyBytes);
  closed(custody, { schema: literal('aukora.kira.disposable-read-key.v1'), key_ref: h32,
    cipher_profile: readableProfile, key: value => b64(value, 32) });
  demand(custody.key_ref === expected.key_ref && custody.cipher_profile === expected.cipher_profile, 'WRONG_AUTHORITY');
  const key = Buffer.from(custody.key, 'base64url');
  let provisional;
  try {
    const algorithm = envelope.cipher_profile === CIPHER_PROFILE ? 'aes-256-gcm' : 'chacha20-poly1305';
    const cipher = createDecipheriv(algorithm, key, Buffer.from(envelope.nonce, 'base64url'), { authTagLength: 16 });
    cipher.setAAD(aad, { plaintextLength: ciphertext.length - 16 });
    cipher.setAuthTag(ciphertext.subarray(-16));
    provisional = cipher.update(ciphertext.subarray(0, -16));
    const tail = cipher.final(); // Release nothing before full tag verification.
    return Buffer.concat([provisional, tail]);
  } catch { fail('BAD_SIGNATURE', 'Kira authentication failed'); }
  finally { key.fill(0); provisional?.fill(0); }
}
export const sealPiece = (bytes, contextBytes, handle) => seal(bytes, contextBytes, handle, false);
export const openPiece = (bytes, contextBytes, keyBytes) => open(bytes, contextBytes, keyBytes, false);
export function sealManifest(bytes, contextBytes, handle) {
  const manifest = parseManifest(bytes), context = parseAadContext(contextBytes);
  for (const field of ['subject_id', 'chain_id', 'map_id', 'revision']) demand(manifest[field] === context[field], 'WRONG_AUTHORITY');
  return seal(canonicalBytes(manifest), canonicalBytes(context), handle, true);
}
export function openManifest(bytes, contextBytes, keyBytes) {
  const plaintext = open(bytes, contextBytes, keyBytes, true);
  try {
    const manifest = parseManifest(plaintext), context = parseAadContext(contextBytes);
    for (const field of ['subject_id', 'chain_id', 'map_id', 'revision']) demand(manifest[field] === context[field], 'WRONG_AUTHORITY');
    return canonicalBytes(manifest);
  } finally { plaintext.fill(0); }
}
