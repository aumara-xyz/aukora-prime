// Pure core composition: no journal writes, signing, adapters or durability claim.
import { types } from 'node:util';
import { canonicalBytes, closed, parseBytes, parseEvent, PROJECTION_ORDER } from '../bytes/index.mjs';
import { draftRecord, inspectTyped, insist, wrapDraft } from '../delegation/index.mjs';
import { verifyEvent } from '../verifier/index.mjs';
import { createAcceptedExchangeRenderer } from '../pentora/index.mjs';
import { copyBoundedBytes, plainFields } from '../pentora/bytes.mjs';

export { renderHead } from '../pentora/index.mjs';
export { createDurableEventPulseSource, createPrefixPulseSource } from './pulse.mjs';
export const HEAD_ORDER = PROJECTION_ORDER;

// Caller supplies the complete frozen checkpoint record. Heads remain in the
// canonical role order; no sorting, missing-head fabrication or currentness claim.
// Only the trusted existing key/host path may later sign and admit this proposal.
export function createCheckpointDraft(recordBytes) {
  const record = draftRecord(recordBytes, 'coherence_checkpoint', ['journal_append']);
  insist(BigInt(record.body.basis_sequence) < BigInt(record.sequence), 'INCONSISTENT_HEAD');
  for (const head of record.body.heads) {
    insist(head.sequence === null || BigInt(head.sequence) <= BigInt(record.body.basis_sequence), 'INCONSISTENT_HEAD');
  }
  return wrapDraft(record);
}

// Explicit preparation for the existing trusted W1 signing API. This does not
// sign/admit a checkpoint, infer heads, or turn an incomplete vector into valid.
export function checkpointRecordFromDraft(draftBytes) {
  const draft = parseBytes(draftBytes);
  closed(draft, {
    schema: value => insist(value === 'aukora.draft.v1', 'CLOSED_SCHEMA'),
    record: value => insist(value !== null && typeof value === 'object', 'CLOSED_SCHEMA'),
    proofs: value => insist(Array.isArray(value) && value.length === 0, 'CLOSED_SCHEMA'),
  });
  const checked = parseBytes(createCheckpointDraft(canonicalBytes(draft.record)));
  return canonicalBytes(checked.record);
}

// Reuse the shared typed wrapper and W2 verifier, including four-way precedence.
// Verification of a signed observed vector does not establish atomic acquisition,
// disk persistence, latest/fresh state or consensus among independent writers.
export function verifyCheckpoint(eventBytes, contextBytes, evidenceBytes) {
  return inspectTyped(eventBytes, contextBytes, evidenceBytes, 'coherence_checkpoint').verification;
}

// Host composition ONLY. trustedTake() has no caller-selected head/cursor/flag.
// It must drain an actual newly/durably accepted internal notification once,
// carrying independently anchored event/context/evidence bytes. No current host
// feed exists. Null disables pulses. History/import/reconnect are never a feed.
// The D-PULSE-1 live-at-most-once/lost-pulse contract still needs owner review.
export function createAuraPulseSource(trustedTake = null) {
  if (trustedTake !== null && (typeof trustedTake !== 'function' || types.isProxy(trustedTake))) {
    throw new TypeError('trusted host take capability required');
  }
  let inFlight = false, pending = null;
  const render = createAcceptedExchangeRenderer(verifyEvent, () => pending);
  return Object.freeze({
    async take() {
      // No queue or replay is reconstructed. Concurrent takes may lose a pulse;
      // they cannot overlap shared pending bytes or repeat a displayed event ID.
      if (trustedTake === null || inFlight) return null;
      inFlight = true;
      try {
        const taken = trustedTake();
        if (types.isProxy(taken)) return null;
        const value = types.isPromise(taken) ? await taken : taken;
        if (value === null) return null;
        const bundle = plainFields(value, ['eventBytes', 'contextBytes', 'evidenceBytes']);
        if (bundle === null) return null;
        pending = {
          eventBytes: copyBoundedBytes(bundle.eventBytes, 262144, 'event'),
          contextBytes: copyBoundedBytes(bundle.contextBytes, 262144, 'context'),
          evidenceBytes: copyBoundedBytes(bundle.evidenceBytes, 4194304, 'evidence'),
        };
        const { event } = parseEvent(pending.eventBytes);
        const model = await render(Buffer.from(event.id, 'hex'));
        return model.activity.pulse === null ? null : model;
      } catch { return null; }
      finally { pending = null; inFlight = false; }
    },
  });
}
