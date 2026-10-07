import { writeSync } from 'node:fs';

import { fixedPayloadBytes, isFixedPayload } from '../aperture/fixed-message.mjs';
export { fixedPayloadBytes, isFixedPayload };
const H32 = /^[0-9a-f]{64}$/;

// observerFd is inherited from the trusted process controller, never a proposal.
// The notice contains public references only. It is instrumentation, not a D08
// observation statement, receipt, proof of custody, or completion attestation.
export function createFixedLocalSink(observerFd) {
  if (!Number.isSafeInteger(observerFd) || observerFd < 3) throw new TypeError('observer fd required');
  let entries = 0;
  return Object.freeze({
    enter(payload, operationId, intentRef) {
      if (!isFixedPayload(payload) || typeof operationId !== 'string' || typeof intentRef !== 'string' || !H32.test(operationId) || !H32.test(intentRef)) {
        throw new TypeError('fixed LOCAL sink input refused');
      }
      noticeSinkEntry(observerFd, operationId, intentRef);
      entries += 1;
    },
    count() { return entries; },
  });
}

// Trusted host instrumentation after an independently checked observer response.
export function noticeSinkEntry(observerFd, operationId, intentRef) {
  if (!Number.isSafeInteger(observerFd) || observerFd < 3 ||
      typeof operationId !== 'string' || typeof intentRef !== 'string' ||
      !H32.test(operationId) || !H32.test(intentRef)) throw new TypeError('sink notice refused');
  const notice = Buffer.from(JSON.stringify({ type: 'sink_entry', operation_id: operationId, intent_ref: intentRef }) + '\n');
  let offset = 0;
  while (offset < notice.length) offset += writeSync(observerFd, notice, offset);
}
