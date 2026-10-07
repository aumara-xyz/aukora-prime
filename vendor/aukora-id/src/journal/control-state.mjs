import { createHash } from 'node:crypto';
// INTERNAL derived state only, never an external object/parser entry point.
// Entries have already passed the bounded byte schema. Their canonical strings
// are retained in sorted sets. Assemble the exact existing wire grammar without
// feeding an ever-growing derived array back through the external array cap.
export function derivedControlBytes(meta, revokedEntries, spentEntries, policyRefs) {
  const fields = {
    active_append_key_id: JSON.stringify(meta.active_append_key_id),
    active_policy_refs: JSON.stringify([...policyRefs].sort()),
    active_root_key_id: JSON.stringify(meta.active_root_key_id),
    basis_event: JSON.stringify(meta.basis_event), chain_id: JSON.stringify(meta.chain_id),
    epoch: JSON.stringify(meta.epoch), revoked_targets: '[' + [...revokedEntries].join(',') + ']',
    schema: '"aukora.control-state.v1"', spent_operations: '[' + [...spentEntries].join(',') + ']',
    subject_id: JSON.stringify(meta.subject_id),
  };
  return Buffer.from('{' + Object.keys(fields).sort().map(key => JSON.stringify(key) + ':' + fields[key]).join(',') + '}');
}
export function derivedControlDigest(bytes) {
  return createHash('sha256').update('aukora.control-state.v1\0', 'ascii').update(bytes).digest('hex');
}
