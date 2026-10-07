// Structural validation only. Parsed private data must stay in the trusted host.
// Canonical bytes, scalar validation, bounds and errors come from W1.
import { assertParsed, b64, canonicalBytes, closed, fail, h32, parseBytes,
  parseRecord, sha256, text, u64 } from '../bytes/index.mjs';

const insist = (condition, code = 'CLOSED_SCHEMA') => { if (!condition) fail(code); };
const literal = expected => value => insist(value === expected);
const nullable = validator => value => { if (value !== null) validator(value); };
const choice = values => value => insist(values.includes(value));
function set(validator) {
  return values => {
    assertParsed(values);
    insist(Array.isArray(values));
    values.forEach(validator);
    for (let i = 1; i < values.length; i++) {
      insist(Buffer.compare(canonicalBytes(values[i - 1]), canonicalBytes(values[i])) < 0);
    }
  };
}
const refs = set(h32);
const unique = (values, field) => insist(new Set(values.map(value => value[field])).size === values.length);
const schema = (value, expected) => {
  assertParsed(value);
  insist(value !== null && typeof value === 'object' && !Array.isArray(value));
  text(value.schema);
  if (value.schema !== expected) fail('UNSUPPORTED_SCHEMA');
};
function location(value) {
  closed(value, { scheme: choice(['https', 'content_addressed']), locator: text, ciphertext_digest: h32 });
}
function envelope(value) {
  return closed(value, { cipher_profile: text, key_ref: h32, nonce: b64, ciphertext: b64, aad_digest: h32 });
}
function provenance(value) {
  return closed(value, {
    origin_id: h32, kind: choice(['model_generated', 'owner_statement', 'observed', 'unknown']),
    source_namespace: text, source_event_ref: nullable(h32), exact_source_digest: nullable(h32),
    source_coordinate: nullable(text), parents: refs, evidence_roots: refs,
    dependency_groups: refs, grants_authority: literal(false),
  });
}
function piece(value) {
  closed(value, { piece_id: h32, ciphertext_digest: h32, plaintext_digest: h32, key_ref: h32,
    cipher_profile: text, nonce: b64, aad_digest: h32, locations: set(location),
    origin_ids: refs, record_refs: refs, size_bytes: u64 });
  for (const entry of value.locations) insist(entry.ciphertext_digest === value.ciphertext_digest);
  return value;
}
function digestObject(value) {
  return closed(value, { digest: h32, size_bytes: u64, media_type: text });
}
export function parseEnvelope(bytes) { return envelope(parseBytes(bytes)); }
export function parsePieceDescriptor(bytes) { return piece(parseBytes(bytes)); }
export function parseProvenance(bytes) { return provenance(parseBytes(bytes)); }
export function parseDigestObject(bytes) { return digestObject(parseBytes(bytes)); }
export function parseManifest(bytes) {
  const value = parseBytes(bytes);
  schema(value, 'aukora.kira.manifest.v1');
  closed(value, { schema: literal('aukora.kira.manifest.v1'), subject_id: h32, chain_id: h32,
    map_id: h32, revision: u64, basis_journal_event: h32, pieces: set(piece),
    tombstone_refs: refs, provenance_records: set(provenance) });
  unique(value.pieces, 'piece_id');
  unique(value.provenance_records, 'origin_id');
  return value;
}
export function parseExportManifest(bytes) {
  const value = parseBytes(bytes);
  schema(value, 'aukora.export.v1');
  closed(value, { schema: literal('aukora.export.v1'), subject_id: h32, chain_id: h32,
    basis_checkpoint: h32, journal_objects: set(digestObject), encrypted_pieces: set(digestObject),
    trust_anchor_refs: refs, provenance_profile: text, authority_state_status: literal('historical_only') });
  unique(value.journal_objects, 'digest');
  unique(value.encrypted_pieces, 'digest');
  return value;
}
export function parseMapRecord(bytes) {
  const record = parseRecord(bytes);
  insist(record.kind === 'kira_map', 'WRONG_DOMAIN');
  const map = record.body;
  // This checks the hash of opaque supplied bytes, not encryption or authentication.
  insist(sha256(Buffer.from(map.manifest.ciphertext, 'base64url')).toString('hex') === map.manifest_ciphertext_digest);
  insist(record.signer_plan.length === 1 && record.signer_plan[0].role === 'storage', 'WRONG_AUTHORITY');
  const signer = record.signer_plan[0];
  insist(signer.key_id === map.storage_key_id, 'WRONG_SIGNER');
  insist(signer.key_source === 'certificate' && record.authority_refs.includes(signer.certificate_ref), 'WRONG_AUTHORITY');
  // Location syntax alone cannot prove absence of secret tokens/plaintext paths.
  // No public locator profile is approved: refuse disclosure of ALL hints.
  if (map.public_location_hints.length) fail('UNSUPPORTED_PROFILE');
  return record;
}
export function bindManifestToMap(recordBytes, manifestBytes) {
  const record = parseMapRecord(recordBytes), manifest = parseManifest(manifestBytes);
  insist(manifest.subject_id === record.subject_id && manifest.chain_id === record.chain_id, 'WRONG_AUTHORITY');
  for (const key of ['map_id', 'revision', 'basis_journal_event']) insist(manifest[key] === record.body[key], 'INCONSISTENT_HEAD');
  // Structural comparison only: neither argument is verified/decrypted here.
  return manifest;
}
