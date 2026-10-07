// Disposable LOCAL laboratory keys only. Trusted Node/JS memory is the custody
// boundary; this module makes no hardware, biometric or secret-erasure claim.
import { randomBytes } from 'node:crypto';
import { schnorr, secp256k1 } from '@noble/curves/secp256k1';
import { applicationDigest, b64, canonicalBytes, canonicalJson, closed, fail, h32, keyId,
  parseBytes, parseContent, parseRecord, sha256, snapshotBytes, CLASSICAL_PROFILE } from '../bytes/index.mjs';

const keyBytes = input => {
  const key = snapshotBytes(input, 32);
  if (key.length !== 32 || !secp256k1.utils.isValidPrivateKey(key)) fail('CLOSED_SCHEMA', 'Invalid BIP340 secret scalar');
  return key;
};
export function generateDisposableKey() {
  let secret;
  do { secret = randomBytes(32); } while (!secp256k1.utils.isValidPrivateKey(secret));
  return secret;
}
export function descriptorBytes(secretKeyBytes) {
  const secret = keyBytes(secretKeyBytes);
  try {
    return canonicalJson(Buffer.from(JSON.stringify({ profile: CLASSICAL_PROFILE, bip340_public_key: Buffer.from(schnorr.getPublicKey(secret)).toString('hex') })));
  } finally { secret.fill(0); }
}
export function verifyBip340(signatureBytes, digestBytes, pubkeyBytes) {
  const signature = snapshotBytes(signatureBytes, 64), digest = snapshotBytes(digestBytes, 32), pubkey = snapshotBytes(pubkeyBytes, 32);
  if (signature.length !== 64 || digest.length !== 32 || pubkey.length !== 32) return false;
  try { return schnorr.verify(signature, digest, pubkey); } catch { return false; }
}
export function signRecord(recordBytes, keyEntriesBytes) {
  const record = parseRecord(recordBytes);
  // Current schemas require one application role, except the exact transition
  // proof set. A supplied plan cannot add roles or omit transition acceptance.
  // The contract does not require different keys for different transition roles.
  const roles = record.signer_plan.map(signer => signer.role);
  const transitionRoles = record.body.next_root_key === null ? ['journal_append', 'root'] : ['journal_append', 'root', 'successor_possession'];
  if (record.kind === 'epoch_transition'
    ? roles.length !== transitionRoles.length || roles.some((role, index) => role !== transitionRoles[index])
    : roles.length !== 1) fail('WRONG_AUTHORITY', 'Incompatible signing roles');
  const digest = applicationDigest(canonicalBytes(record));
  const entries = parseBytes(keyEntriesBytes);
  if (!Array.isArray(entries) || entries.length < 1 || entries.length > record.signer_plan.length) fail('CLOSED_SCHEMA');
  const secrets = new Map();
  try {
    for (const entry of entries) {
      closed(entry, { key_id: h32, secret_key: value => b64(value, 32) });
      if (secrets.has(entry.key_id)) fail('CLOSED_SCHEMA', 'Duplicate signing key');
      const secret = keyBytes(Buffer.from(entry.secret_key, 'base64url'));
      if (keyId(descriptorBytes(secret)).toString('hex') !== entry.key_id) { secret.fill(0); fail('WRONG_SIGNER'); }
      secrets.set(entry.key_id, secret);
    }
    const requiredKeys = new Set(record.signer_plan.map(signer => signer.key_id));
    if (requiredKeys.size !== secrets.size || [...requiredKeys].some(key => !secrets.has(key))) fail('WRONG_SIGNER');
    const proofs = record.signer_plan.map((signer, signer_index) => {
      const secret = secrets.get(signer.key_id);
      if (!secret) fail('WRONG_SIGNER');
      return { signer_index, algorithm: 'bip340', signature: Buffer.from(schnorr.sign(digest, secret)).toString('base64url') };
    });
    const contentBytes = canonicalJson(Buffer.from(JSON.stringify({ record, proofs })));
    parseContent(contentBytes);
    return contentBytes;
  } finally { for (const secret of secrets.values()) secret.fill(0); }
}
export function recover(_requestBytes) {
  return Object.freeze({ verdict: 'UNKNOWN', reason_codes: Object.freeze(['RECOVERY_UNREVIEWED']) });
}
export function constructEvent(contentBytes, appendSecretBytes) {
  const content = parseContent(contentBytes);
  const secret = keyBytes(appendSecretBytes);
  try {
    const outer = content.record.outer_context;
    if (Buffer.from(schnorr.getPublicKey(secret)).toString('hex') !== outer.pubkey) fail('WRONG_SIGNER');
    const contentText = canonicalBytes(content).toString('utf8');
    const digest = sha256(Buffer.from(JSON.stringify([0, outer.pubkey, outer.created_at, outer.kind, outer.tags, contentText])));
    const event = { id: digest.toString('hex'), ...outer, content: contentText, sig: Buffer.from(schnorr.sign(digest, secret)).toString('hex') };
    return canonicalJson(Buffer.from(JSON.stringify(event)));
  } finally { secret.fill(0); }
}
