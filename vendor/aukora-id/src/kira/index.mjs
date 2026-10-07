import { parseMapRecord } from './schema.mjs';
import registry from '../../spec/layer0-v1/registry.json' with { type: 'json' };
export { parseEnvelope, parsePieceDescriptor, parseProvenance, parseDigestObject,
  parseManifest, parseExportManifest, parseMapRecord, bindManifestToMap } from './schema.mjs';
export { inspectProvenance, inspectProvenanceBytes } from './provenance.mjs';
export { readMapMetadata, exportMapMetadata, importMapMetadata } from './metadata.mjs';
export { CIPHER_PROFILE, LEGACY_CIPHER_PROFILE, AAD_SCHEMA, PROVENANCE_PROFILE, MAX_PLAINTEXT_BYTES,
  MAX_SEALS_PER_KEY, createWriteKey, destroyWriteKey, exportDisposableReadKey, parseAadContext, aadBytes,
  sealPiece, openPiece, sealManifest, openManifest, validateMapCryptoProfile } from './crypto.mjs';
export { ARCHIVE_SCHEMA, MAX_ARCHIVE_BYTES, MAX_PIECES, exportKira, importKira,
  archiveManifestEnvelope, importKiraFromMap } from './archive.mjs';

// Fixed closed W0 refusal, NOT a second verifier/verdict engine. W1 ByteErrors
// propagate unchanged for malformed input. No injected or data-selected cipher.
const unavailable = Object.freeze({ verdict: 'UNKNOWN', reason_codes: Object.freeze(['UNSUPPORTED_PROFILE']),
  record_digest: null, event_id: null, validated_through: null,
  missing_evidence: Object.freeze([]), conflicts: Object.freeze([]) });

export function inspectMap(recordBytes) { parseMapRecord(recordBytes); return unavailable; }

export const claimInventory = Object.freeze({
  scope: 'bounded Kira AEAD and historical recall; no restored authority',
  implemented_write_profiles: Object.freeze(['aukora.kira.aes256gcm.v1']),
  legacy_read_only_profiles: Object.freeze(['aukora.kira.chacha20poly1305.v1']),
  accepted_signed_map_profiles: Object.freeze([...registry.accepted_cipher_profiles]),
  encryption: 'implemented', encrypted_restore: 'implemented',
  signature_and_journal_verification: 'shared verifyEvent; independent historical context required',
  provenance_evidence_verification: 'claims only; established independent support remains zero',
  restored_authority: false, profile_injection: false, network_fetch: false, storage_writes: false,
  canonical_bytes_and_errors: 'src/bytes/index.mjs (W1)',
  verdict_boundary: 'shared verifier must return valid; structural inspectMap alone never authenticates',
  dependencies: Object.freeze(['W1 strict byte module', 'trusted Node']),
  pending: Object.freeze(['production key custody/wrapping', 'retained current authority-floor reconciliation',
    'public locator disclosure profile', 'browser application packaging', 'independent acceptance']),
});
