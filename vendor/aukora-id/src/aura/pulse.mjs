// Pure activity data. Only a trusted host may supply the live commit capability.
// Signatures establish integrity; the host alone observes successful durability.
import { types } from 'node:util';
import { parseBytes, parseEvent } from '../bytes/index.mjs';
import { verifyEvent } from '../verifier/index.mjs';
import * as prefixVerification from '../verifier/index.mjs';
import { copyBoundedBytes, plainFields } from '../pentora/bytes.mjs';

export function createDurableEventPulseSource(trustedTake = null) {
  if (trustedTake !== null && (typeof trustedTake !== 'function' || types.isProxy(trustedTake))) {
    throw new TypeError('trusted host take capability required');
  }
  let busy = false, closed = false, anchor = null, sequence = -1n;
  return Object.freeze({
    async take() {
      if (closed || busy || trustedTake === null) return null;
      busy = true;
      try {
        // No caller-selected ID, cursor, verifier or accepted flag crosses here.
        const taken = trustedTake();
        // Awaiting a raw object consults its then property. Refuse proxies first
        // and await only genuine promises from the pinned trusted capability.
        if (types.isProxy(taken)) return null;
        const supplied = types.isPromise(taken) ? await taken : taken;
        if (closed || supplied === null) return null;
        const bundle = plainFields(supplied, ['eventBytes', 'contextBytes', 'evidenceBytes']);
        if (bundle === null) return null;
        const eventBytes = copyBoundedBytes(bundle.eventBytes, 262144, 'event');
        const contextBytes = copyBoundedBytes(bundle.contextBytes, 262144, 'context');
        const evidenceBytes = copyBoundedBytes(bundle.evidenceBytes, 4194304, 'evidence');
        const { event, record } = parseEvent(eventBytes);
        const context = parseBytes(contextBytes, { mode: 'evidence' });
        const result = verifyEvent(eventBytes, contextBytes, evidenceBytes);
        if (result.verdict !== 'valid' || result.reason_codes.length !== 1 || result.reason_codes[0] !== 'VERIFIED' ||
            result.event_id !== event.id || result.validated_through !== event.id || result.record_digest === null ||
            result.missing_evidence.length !== 0 || result.conflicts.length !== 0) return null;
        const binding = JSON.stringify([context.expected_subject_id, context.expected_chain_id,
          context.expected_genesis, context.expected_root_key_id, context.expected_profile]);
        const next = BigInt(record.sequence);
        // One ordered journal per source. A verified event has one signed sequence;
        // this watermark suppresses duplicates without retaining an unbounded set.
        // Out-of-order notifications may be lost, never replayed as live activity.
        if ((anchor !== null && anchor !== binding) || next <= sequence) return null;
        anchor = binding; sequence = next;
        return Object.freeze({ schema: 'aukora.aura.pulse.v1', event_id: event.id,
          record_digest: result.record_digest, sequence: record.sequence, grants_authority: false });
      } catch { return null; }
      finally { busy = false; }
    },
    close() { closed = true; },
  });
}

// Trusted host construction only. The synchronous source drains actual durable
// notifications under its writer lock and supplies W2's opaque verification
// handle. Neither the handle nor this raw bundle may cross controller IPC.
export function createPrefixPulseSource(trustedTake = null) {
  if (trustedTake !== null && (typeof trustedTake !== 'function' || types.isProxy(trustedTake))) {
    throw new TypeError('trusted host take capability required');
  }
  let busy = false, closed = false, anchor = null, sequence = -1n;
  return Object.freeze({
    take() {
      if (closed || busy || trustedTake === null) return null;
      busy = true;
      try {
        // No await/thenable assimilation: the agreed host source is synchronous.
        const supplied = trustedTake();
        if (closed || supplied === null) return null;
        const bundle = plainFields(supplied, ['eventBytes', 'contextBytes', 'evidenceBytes', 'prefix']);
        if (bundle === null) return null;
        const eventBytes = copyBoundedBytes(bundle.eventBytes, 262144, 'event');
        const contextBytes = copyBoundedBytes(bundle.contextBytes, 262144, 'context');
        const evidenceBytes = copyBoundedBytes(bundle.evidenceBytes, 4194304, 'evidence');
        const { event, record } = parseEvent(eventBytes);
        const context = parseBytes(contextBytes, { mode: 'evidence' });
        // Fixed W2 export, never a supplied method/verdict. An unavailable export,
        // forged handle or closed prefix refuses without falling back to cold W2.
        const result = prefixVerification.verifyPrefixEvent(bundle.prefix, eventBytes, contextBytes, evidenceBytes);
        if (result.verdict !== 'valid' || result.reason_codes.length !== 1 || result.reason_codes[0] !== 'VERIFIED' ||
            result.event_id !== event.id || result.validated_through !== event.id || result.record_digest === null ||
            result.missing_evidence.length !== 0 || result.conflicts.length !== 0) return null;
        const binding = JSON.stringify([context.expected_subject_id, context.expected_chain_id,
          context.expected_genesis, context.expected_root_key_id, context.expected_profile]);
        const next = BigInt(record.sequence);
        if ((anchor !== null && anchor !== binding) || next <= sequence) return null;
        anchor = binding; sequence = next;
        return Object.freeze({ schema: 'aukora.aura.pulse.v1', event_id: event.id,
          record_digest: result.record_digest, sequence: record.sequence, grants_authority: false });
      } catch { return null; }
      finally { busy = false; }
    },
    close() { closed = true; },
  });
}
