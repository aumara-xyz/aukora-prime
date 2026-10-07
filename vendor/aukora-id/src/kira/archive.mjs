// Private, bounded, LOCAL archive. AEAD custody is not storage-role certification.
import { b64, canonicalBytes, closed, fail, h32, parseBytes, parseEvent, sha256, snapshotBytes, u64 } from '../bytes/index.mjs';
import { inspectProvenance } from './provenance.mjs';
import { verifyEvent } from '../verifier/index.mjs';
import registry from '../../spec/layer0-v1/registry.json' with { type: 'json' };
import { parseManifest, parseEnvelope, parseProvenance, parseMapRecord } from './schema.mjs';
import { AAD_SCHEMA, CIPHER_PROFILE, MAX_PLAINTEXT_BYTES, encodeData, openManifest, openPiece,
  parseAadContext, sealManifest, sealPiece, writeKeyRef, validateMapCryptoProfile } from './crypto.mjs';

export const ARCHIVE_SCHEMA = 'aukora.kira.local-archive.v1';
export const MAX_ARCHIVE_BYTES = 262144;
export const MAX_PIECES = 16;
const demand = (ok, code = 'CLOSED_SCHEMA') => { if (!ok) fail(code); };
const literal = value => actual => demand(actual === value);
const digest = bytes => sha256(bytes).toString('hex');
const wire = value => canonicalBytes(value);
function requireVerified(result) {
  if (result.verdict === 'valid') return;
  // Reasons are sorted lexically; select within the verifier's verdict class.
  const reasons = registry.reason_codes[result.verdict] ?? [];
  const code = result.reason_codes.find(reason => reasons.includes(reason)) ?? 'MISSING_EVIDENCE';
  fail(code, `Kira verification ${result.verdict}: ${result.reason_codes.join(', ')}`);
}
function list(check, maximum = MAX_PIECES) {
  return value => { demand(Array.isArray(value)); demand(value.length <= maximum, 'LIMIT_EXCEEDED'); value.forEach(check); };
}
function ids(value) {
  list(h32, 256)(value);
  for (let i = 1; i < value.length; i++) demand(value[i - 1] < value[i]);
}
const sorted = values => values.toSorted((a, b) => Buffer.compare(encodeData(a), encodeData(b)));
const same = (a, b) => encodeData(a).equals(encodeData(b));
function contextFor(base, pieceId) { return encodeData({ ...base, piece_id: pieceId }); }
function parsePayload(bytes) {
  const payload = parseBytes(snapshotBytes(bytes, MAX_PLAINTEXT_BYTES));
  closed(payload, { schema: literal('aukora.kira.piece.v1'), records: list(value => b64(value), 16),
    sources: list(value => closed(value, { origin_id: h32, bytes: b64 }), 16) });
  demand(new Set(payload.sources.map(value => value.origin_id)).size === payload.sources.length);
  return payload;
}
function request(bytes) {
  const value = parseBytes(bytes);
  closed(value, { schema: literal('aukora.kira.export-request.v1'), subject_id: h32, chain_id: h32,
    map_id: h32, revision: u64, basis_journal_event: h32, tombstone_refs: ids,
    provenance_records: list(origin => parseProvenance(wire(origin)), 256), pieces: list(piece => closed(piece, {
      piece_id: h32, origin_ids: ids, record_refs: ids, payload: b64 })) });
  demand(new Set(value.pieces.map(piece => piece.piece_id)).size === value.pieces.length);
  return value;
}
function validatePayload(payload, piece, manifest, collectedRecords, collectedSources) {
  const recordRefs = [];
  for (const encoded of payload.records) {
    const bytes = Buffer.from(encoded, 'base64url'), parsed = parseEvent(bytes);
    demand(parsed.record.subject_id === manifest.subject_id && parsed.record.chain_id === manifest.chain_id, 'WRONG_AUTHORITY');
    const id = parsed.event.id;
    demand(!collectedRecords.has(id), 'CLOSED_SCHEMA');
    collectedRecords.set(id, bytes); recordRefs.push(id);
  }
  demand(same(recordRefs.sort(), piece.record_refs), 'MISSING_EVIDENCE');
  const origins = new Map(manifest.provenance_records.map(origin => [origin.origin_id, origin]));
  for (const id of piece.origin_ids) demand(origins.has(id), 'MISSING_EVIDENCE');
  for (const source of payload.sources) {
    const origin = origins.get(source.origin_id), bytes = Buffer.from(source.bytes, 'base64url');
    demand(origin !== undefined && piece.origin_ids.includes(source.origin_id), 'MISSING_EVIDENCE');
    demand(origin.exact_source_digest !== null && digest(bytes) === origin.exact_source_digest, 'BAD_SIGNATURE');
    const prior = collectedSources.get(source.origin_id);
    demand(prior === undefined || prior.equals(bytes), 'BAD_SIGNATURE');
    collectedSources.set(source.origin_id, bytes);
  }
}
function validateOrigins(manifest, records, sources) {
  const ids = new Set(manifest.provenance_records.map(origin => origin.origin_id));
  for (const origin of manifest.provenance_records) {
    demand(origin.parents.every(parent => ids.has(parent)), 'MISSING_EVIDENCE');
    if (origin.source_event_ref !== null) demand(records.has(origin.source_event_ref), 'MISSING_EVIDENCE');
    if (origin.exact_source_digest !== null) demand(sources.has(origin.origin_id), 'MISSING_EVIDENCE');
  }
  // Reject cycles and retain model ancestry; no evidence root becomes a fact.
  return inspectProvenance(wire(manifest));
}

export function exportKira(requestBytes, handle) {
  const input = request(requestBytes), encrypted = [], descriptors = [];
  const base = { schema: AAD_SCHEMA, subject_id: input.subject_id, chain_id: input.chain_id,
    map_id: input.map_id, revision: input.revision, piece_id: null,
    key_ref: writeKeyRef(handle), cipher_profile: CIPHER_PROFILE };
  // Validate a caller handle at the cipher boundary before reading payloads.
  parseAadContext(encodeData(base));
  const records = new Map(), sources = new Map();
  for (const piece of input.pieces) {
    const plaintext = Buffer.from(piece.payload, 'base64url');
    try {
      const payload = parsePayload(plaintext);
      const envelope = parseEnvelope(sealPiece(plaintext, contextFor(base, piece.piece_id), handle));
      descriptors.push({ piece_id: piece.piece_id, ciphertext_digest: digest(Buffer.from(envelope.ciphertext, 'base64url')),
        plaintext_digest: digest(plaintext), key_ref: envelope.key_ref, cipher_profile: envelope.cipher_profile,
        nonce: envelope.nonce, aad_digest: envelope.aad_digest, locations: [], origin_ids: piece.origin_ids,
        record_refs: piece.record_refs, size_bytes: String(plaintext.length) });
      encrypted.push({ piece_id: piece.piece_id, envelope });
      validatePayload(payload, piece, input, records, sources);
    } finally { plaintext.fill(0); }
  }
  const manifest = parseManifest(encodeData({ schema: 'aukora.kira.manifest.v1', subject_id: input.subject_id,
    chain_id: input.chain_id, map_id: input.map_id, revision: input.revision, basis_journal_event: input.basis_journal_event,
    pieces: sorted(descriptors), tombstone_refs: input.tombstone_refs, provenance_records: input.provenance_records }));
  validateOrigins(manifest, records, sources);
  const sealed = parseEnvelope(sealManifest(wire(manifest), contextFor(base, null), handle));
  return encodeData({ schema: ARCHIVE_SCHEMA, manifest: sealed, pieces: sorted(encrypted) });
}

function archive(bytes) {
  const value = parseBytes(snapshotBytes(bytes, MAX_ARCHIVE_BYTES));
  closed(value, { schema: literal(ARCHIVE_SCHEMA), manifest: entry => parseEnvelope(wire(entry)),
    pieces: list(entry => closed(entry, { piece_id: h32, envelope: item => parseEnvelope(wire(item)) })) });
  demand(new Set(value.pieces.map(piece => piece.piece_id)).size === value.pieces.length);
  for (let i = 1; i < value.pieces.length; i++) demand(Buffer.compare(wire(value.pieces[i - 1]), wire(value.pieces[i])) < 0);
  return value;
}
// Ciphertext-only projection for the trusted journal's storage-role signer.
export function archiveManifestEnvelope(archiveBytes) { return wire(archive(archiveBytes).manifest); }
function verificationInputs(bytes) {
  const values = parseBytes(bytes);
  list(value => closed(value, { event_id: h32, context: b64, evidence: b64 }), 64)(values);
  demand(new Set(values.map(value => value.event_id)).size === values.length);
  return new Map(values.map(value => [value.event_id, value]));
}

// Trusted caller supplies expected AAD + verification contexts independently of
// the archive. No callback, importer script, path, authority writer or key signer.
export async function importKira(archiveBytes, expectedContextBytes, readKeyBytes, verificationBytes) {
  // Snapshot all inputs before the first asynchronous operation.
  const input = archive(archiveBytes), base = parseAadContext(expectedContextBytes);
  const custody = Buffer.from(snapshotBytes(readKeyBytes));
  const expected = verificationInputs(verificationBytes), records = new Map(), sources = new Map(), plaintexts = [];
  try {
    const manifest = parseManifest(openManifest(wire(input.manifest), wire(base), custody));
    demand(input.pieces.length === manifest.pieces.length, 'MISSING_EVIDENCE');
    const sealed = new Map(input.pieces.map(piece => [piece.piece_id, piece.envelope]));
    for (const descriptor of manifest.pieces) {
      const envelope = sealed.get(descriptor.piece_id);
      demand(envelope !== undefined, 'MISSING_EVIDENCE');
      for (const field of ['key_ref', 'cipher_profile', 'nonce', 'aad_digest']) demand(envelope[field] === descriptor[field], 'WRONG_AUTHORITY');
      demand(digest(Buffer.from(envelope.ciphertext, 'base64url')) === descriptor.ciphertext_digest, 'BAD_SIGNATURE');
      const plaintext = openPiece(wire(envelope), contextFor(base, descriptor.piece_id), custody);
      plaintexts.push(plaintext);
      demand(String(plaintext.length) === descriptor.size_bytes && digest(plaintext) === descriptor.plaintext_digest, 'BAD_SIGNATURE');
      validatePayload(parsePayload(plaintext), descriptor, manifest, records, sources);
    }
    const provenance = validateOrigins(manifest, records, sources);
    demand(expected.size === records.size, 'MISSING_EVIDENCE');
    if (records.size) {
      for (const [id, record] of records) {
        const verification = expected.get(id);
        demand(verification !== undefined, 'MISSING_EVIDENCE');
        const contextBytes = Buffer.from(verification.context, 'base64url'), context = parseBytes(contextBytes);
        demand(context.purpose === 'historical_integrity' && context.expected_subject_id === base.subject_id &&
          context.expected_chain_id === base.chain_id, 'WRONG_AUTHORITY');
        const result = verifyEvent(record, contextBytes, Buffer.from(verification.evidence, 'base64url'));
        requireVerified(result);
      }
    }
    // All-or-nothing release after every ciphertext, source and record passes.
    // No current-control, grants, retired keys or sessions are returned or written.
    return parseBytes(encodeData({ schema: 'aukora.kira.recall.v1', authority_state_status: 'historical_only',
      grants_authority: false, authentication: 'aead_and_historical_records', map_signature_status: 'unverified',
      subject_id: manifest.subject_id, chain_id: manifest.chain_id, map_id: manifest.map_id, revision: manifest.revision,
      basis_journal_event: manifest.basis_journal_event, provenance,
      records: [...records].map(([event_id, bytes]) => ({ event_id, bytes: bytes.toString('base64url') })),
      sources: [...sources].map(([origin_id, bytes]) => ({ origin_id, bytes: bytes.toString('base64url'), trusted_instruction: false })) }));
  } finally {
    custody.fill(0);
    for (const bytes of [...plaintexts, ...records.values(), ...sources.values()]) bytes.fill(0);
  }
}

// This path stays refusing while shared verification cannot accept kira_map.
// It never overrides UNKNOWN, DRAFT or REJECT from the shared verifier.
export async function importKiraFromMap(archiveBytes, mapEventBytes, mapContextBytes, evidenceBytes, readKeyBytes, verificationBytes) {
  const savedArchive = Buffer.from(snapshotBytes(archiveBytes, MAX_ARCHIVE_BYTES));
  const savedEvent = Buffer.from(snapshotBytes(mapEventBytes));
  const savedContext = Buffer.from(snapshotBytes(mapContextBytes));
  const savedEvidence = Buffer.from(snapshotBytes(evidenceBytes, 4194304));
  const savedKey = Buffer.from(snapshotBytes(readKeyBytes));
  const savedVerification = Buffer.from(snapshotBytes(verificationBytes));
  try {
    const parsed = parseEvent(savedEvent), record = parseMapRecord(wire(parsed.record)), context = parseBytes(savedContext);
    demand(context.purpose === 'historical_integrity' && context.expected_kind === 'kira_map', 'WRONG_AUTHORITY');
    const result = verifyEvent(savedEvent, savedContext, savedEvidence);
    requireVerified(result);
    validateMapCryptoProfile(wire(record));
    demand(same(archive(savedArchive).manifest, record.body.manifest), 'BAD_SIGNATURE');
    const aad = encodeData({ schema: AAD_SCHEMA, subject_id: record.subject_id, chain_id: record.chain_id,
      map_id: record.body.map_id, revision: record.body.revision, piece_id: null,
      key_ref: record.body.manifest.key_ref, cipher_profile: CIPHER_PROFILE });
    const recall = await importKira(savedArchive, aad, savedKey, savedVerification);
    demand(recall.basis_journal_event === record.body.basis_journal_event, 'INCONSISTENT_HEAD');
    return parseBytes(encodeData({ ...recall, map_signature_status: 'verified_historical', map_event_id: parsed.event.id }));
  } finally { savedKey.fill(0); }
}
