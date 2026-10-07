import { fail, snapshotBytes } from '../bytes/index.mjs';

export const MAX_EVENT = 262144;
export const MAX_EVIDENCE = 4194304;
export const HEADER_BYTES = 12;
const MAGIC = Buffer.from('AID1');

// Local pipe framing only. The event and evidence remain their original bytes;
// this header is not a Nostr envelope, signature, authority or network protocol.
export function encodeFrame(eventBytes, evidenceBytes) {
  const event = snapshotBytes(eventBytes, MAX_EVENT);
  const evidence = snapshotBytes(evidenceBytes, MAX_EVIDENCE);
  if (!event.length || !evidence.length) fail('MALFORMED_BYTES');
  const header = Buffer.alloc(HEADER_BYTES);
  MAGIC.copy(header); header.writeUInt32BE(event.length, 4); header.writeUInt32BE(evidence.length, 8);
  return Buffer.concat([header, event, evidence]);
}

// One bounded allocation per frame, no quadratic concatenate-on-every-byte.
// Callback belongs to the trusted host, never to parsed/plugin data.
export function createFrameDecoder(onFrame) {
  let header = Buffer.alloc(HEADER_BYTES), used = 0, body = null, eventLength = 0;
  const reset = () => { header.fill(0); body?.fill(0); used = 0; body = null; eventLength = 0; };
  return Object.freeze({
    get partial() { return used !== 0 || body !== null; },
    push(bytes) {
      const chunk = Buffer.from(snapshotBytes(bytes, MAX_EVENT + MAX_EVIDENCE + HEADER_BYTES));
      let offset = 0;
      try {
        while (offset < chunk.length) {
          const target = body ?? header;
          const count = Math.min(target.length - used, chunk.length - offset);
          chunk.copy(target, used, offset, offset + count); used += count; offset += count;
          if (used !== target.length) continue;
          if (body === null) {
            if (!header.subarray(0, 4).equals(MAGIC)) fail('MALFORMED_BYTES');
            eventLength = header.readUInt32BE(4);
            const evidenceLength = header.readUInt32BE(8);
            if (!eventLength || !evidenceLength) fail('MALFORMED_BYTES');
            if (eventLength > MAX_EVENT || evidenceLength > MAX_EVIDENCE) fail('LIMIT_EXCEEDED');
            body = Buffer.alloc(eventLength + evidenceLength); used = 0;
          } else {
            const event = Buffer.from(body.subarray(0, eventLength));
            const evidence = Buffer.from(body.subarray(eventLength));
            reset(); onFrame(event, evidence);
          }
        }
      } catch (error) { reset(); throw error; }
      finally { chunk.fill(0); }
    },
    end() { const truncated = used !== 0 || body !== null; reset(); if (truncated) fail('MALFORMED_BYTES'); },
    close: reset,
  });
}
