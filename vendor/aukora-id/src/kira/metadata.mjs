import { canonicalBytes, closed, h32, parseBytes, u64 } from '../bytes/index.mjs';
import { parseMapRecord } from './schema.mjs';

// Local diagnostic projection, NOT ExportManifest or a new protocol wire schema.
// These five fields carry no content, location, keys, verifier or authority state.
export function readMapMetadata(bytes) {
  return closed(parseBytes(bytes), { subject_id: h32, chain_id: h32, map_id: h32,
    revision: u64, basis_journal_event: h32 });
}
export function exportMapMetadata(recordBytes) {
  const record = parseMapRecord(recordBytes);
  const local = { subject_id: record.subject_id, chain_id: record.chain_id,
    map_id: record.body.map_id, revision: record.body.revision, basis_journal_event: record.body.basis_journal_event };
  return canonicalBytes(readMapMetadata(Buffer.from(JSON.stringify(local))));
}
export function importMapMetadata(bytes) {
  // Return an inert display/history candidate. No store, signer or control handles.
  const metadata = readMapMetadata(bytes);
  return Object.freeze({ metadata, authenticated: false, trusted_instruction: false,
    grants_authority: false, authority_state_status: 'historical_only' });
}
