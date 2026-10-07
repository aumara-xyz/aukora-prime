import { canonicalBytes, hashDomain, parseBytes, fail } from './parser.mjs';
import { validateRecord, validateDescriptor, validateEnvelope, parseContent } from './schema.mjs';
export * from './parser.mjs';
export * from './schema.mjs';
export const parseJson = parseBytes;
export function parseRecord(bytes) { return validateRecord(parseBytes(bytes)); }
export function canonicalRecord(bytes) { return canonicalBytes(parseRecord(bytes)); }
export function applicationDigest(bytes) {
  const record = parseRecord(bytes);
  // validateRecord selects the closed version before its signed hash domain.
  return hashDomain(record.schema, canonicalBytes(record));
}
export function keyId(bytes) { return hashDomain('aukora.key.v1', canonicalBytes(validateDescriptor(parseBytes(bytes)))); }
export function parseEvent(bytes) {
  const event = validateEnvelope(parseBytes(bytes));
  const content = parseContent(Buffer.from(event.content, 'utf8'));
  const outer = content.record.outer_context;
  if (outer.pubkey !== event.pubkey || outer.created_at !== event.created_at || outer.kind !== event.kind ||
      !canonicalBytes(outer.tags).equals(canonicalBytes(event.tags))) fail('CLOSED_SCHEMA', 'Outer context mismatch');
  return Object.freeze({ event, record: content.record, proofs: content.proofs });
}
export function nostrPreimage(bytes) {
  const { event } = parseEvent(bytes);
  return nostrPreimageParsed(event);
}
export function nostrPreimageParsed(event) {
  validateEnvelope(event);
  // NIP-01 array order is separate from application JCS object ordering.
  return Buffer.from(JSON.stringify([0, event.pubkey, event.created_at, event.kind, event.tags, event.content]), 'utf8');
}
