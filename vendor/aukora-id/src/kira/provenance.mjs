import { canonicalBytes, fail, parseBytes } from '../bytes/index.mjs';
import { parseManifest } from './schema.mjs';

// Only locally constructed data reaches JSON.stringify, never caller objects.
const frozen = value => parseBytes(Buffer.from(JSON.stringify(value)));
const sorted = values => [...new Set(values)].sort();

// PRIVATE inspection of claims. No evidence verifier is available in this slice.
// In particular, a signed/source-labelled/model-copied statement is never trusted.
export function inspectProvenance(manifestBytes) {
  const manifest = parseManifest(manifestBytes);
  const nodes = new Map(manifest.provenance_records.map(value => [value.origin_id, value]));
  const complete = new Map(), active = new Set();
  function ancestors(id) {
    if (complete.has(id)) return complete.get(id);
    if (active.has(id)) fail('CLOSED_SCHEMA', 'Origin cycle');
    const node = nodes.get(id);
    if (!node) return new Set([id]); // Missing origins remain visible, with no support.
    active.add(id);
    const ids = new Set([id]);
    for (const parent of node.parents) for (const inherited of ancestors(parent)) ids.add(inherited);
    active.delete(id);
    complete.set(id, ids);
    return ids;
  }
  // Reject cycles even when no current piece points at that part of the graph.
  for (const id of nodes.keys()) ancestors(id);
  const pieces = manifest.pieces.map(piece => {
    const ids = sorted(piece.origin_ids.flatMap(id => [...ancestors(id)]));
    const present = ids.map(id => nodes.get(id)).filter(Boolean);
    const missing = ids.filter(id => !nodes.has(id));
    return {
      piece_id: piece.piece_id, origin_ids: ids, missing_origin_ids: missing,
      model_origin_ids: sorted(present.filter(node => node.kind === 'model_generated').map(node => node.origin_id)),
      unknown_source_origin_ids: sorted(present.filter(node => node.kind === 'unknown' || node.source_event_ref === null ||
        node.exact_source_digest === null || node.source_coordinate === null || node.source_namespace === '').map(node => node.origin_id)),
      claimed_evidence_roots: sorted(present.flatMap(node => node.evidence_roots)),
      claimed_dependency_groups: sorted(present.flatMap(node => node.dependency_groups)),
      distinct_claimed_source_digests: sorted(present.map(node => node.exact_source_digest).filter(value => value !== null)),
      evidence_status: 'unverified', established_independent_support: 0,
      trusted_instruction: false, grants_authority: false,
    };
  });
  return frozen({ visibility: 'private', authenticated: false, authority_state_status: 'historical_only', pieces });
}

export function inspectProvenanceBytes(manifestBytes) {
  return canonicalBytes(inspectProvenance(manifestBytes));
}
