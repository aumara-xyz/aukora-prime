// SPDX-License-Identifier: AGPL-3.0-or-later

// Data association only. The host supplies the verified capture projection, and
// the citation reader later verifies the exact gate source and any record ID.
// This helper does not authenticate a capture, qualify a citation, or grant authority.

const JOURNAL_ID = 'aukora-gate-pilot';
const ASSOCIATION_KIND = 'aukora-kira-aura-association/v1';
const HEX64 = /^[0-9a-f]{64}$/;
const NOTE_ID = /^rem:[0-9a-f]{64}$/;

const isHex64 = value => typeof value === 'string' && value.length === 64 && HEX64.test(value);
const isNoteId = value => typeof value === 'string' && value.length === 68 && NOTE_ID.test(value);

function dataFields(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return null;
  try {
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) return null;
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const fields = Object.create(null);
    for (const key of Reflect.ownKeys(descriptors)) {
      if (typeof key !== 'string') return null;
      const descriptor = descriptors[key];
      if (!Object.hasOwn(descriptor, 'value')) return null;
      fields[key] = descriptor.value;
    }
    return fields;
  } catch {
    return null;
  }
}

function closedFields(value, required, optional = []) {
  const fields = dataFields(value);
  if (fields === null) return null;
  const keys = Object.keys(fields);
  if (required.some(key => !Object.hasOwn(fields, key))) return null;
  if (keys.some(key => !required.includes(key) && !optional.includes(key))) return null;
  return fields;
}

function parseSource(value) {
  const fields = closedFields(value, ['journal_id', 'position', 'hash']);
  if (fields === null || fields.journal_id !== JOURNAL_ID) return null;
  if (!Number.isSafeInteger(fields.position) || fields.position <= 0) return null;
  if (!isHex64(fields.hash)) return null;
  return { journal_id: JOURNAL_ID, position: fields.position, hash: fields.hash };
}

/** Accept only the verifier's closed { source } projection; return detached data. */
export function parseAuraSourceProjection(value) {
  const fields = closedFields(value, ['source']);
  return fields === null ? null : parseSource(fields.source);
}

/** Stable identity for exact source coordinates, suitable for note deduplication. */
export function sourceIdentity(source) {
  const parsed = parseSource(source);
  return parsed === null ? null : JSON.stringify(parsed);
}

/**
 * Bind already verified source coordinates to the final remembered-note ID.
 * recordId is optional persisted data, never a claim that this helper verified it.
 */
export function createAuraAssociation(noteId, source, recordId) {
  if (!isNoteId(noteId)) return null;
  const parsed = parseSource(source);
  if (parsed === null) return null;
  if (recordId !== undefined && !isHex64(recordId)) return null;
  const association = { v: 1, kind: ASSOCIATION_KIND, note_id: noteId, source: parsed };
  if (recordId !== undefined) association.record_id = recordId;
  return association;
}

/**
 * Return a selector only when the closed association matches the note's exact
 * ID and its ID-covered source. Historical notes never acquire an association
 * by inference. Full note integrity and privacy eligibility belong to Kira's
 * tracked-memory reader; actual source/record verification belongs to Aura.
 */
export function referenceForAssociatedNote(note) {
  const fields = dataFields(note);
  if (fields === null || fields.grantsAuthority !== false) return null;
  if (!isNoteId(fields.id)) return null;
  const association = closedFields(fields.auraAssociation,
    ['v', 'kind', 'note_id', 'source'], ['record_id']);
  if (association === null || association.v !== 1 || association.kind !== ASSOCIATION_KIND) return null;
  if (association.note_id !== fields.id) return null;
  const associatedSource = parseSource(association.source);
  const noteSource = dataFields(fields.source);
  const coveredSource = noteSource === null ? null : parseSource(noteSource.aura_source);
  if (associatedSource === null || coveredSource === null) return null;
  if (sourceIdentity(associatedSource) !== sourceIdentity(coveredSource)) return null;
  if (Object.hasOwn(association, 'record_id') && !isHex64(association.record_id)) return null;
  const reference = { source: associatedSource };
  if (Object.hasOwn(association, 'record_id')) reference.record_id = association.record_id;
  return reference;
}
