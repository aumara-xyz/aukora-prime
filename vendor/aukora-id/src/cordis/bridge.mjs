import { fail, snapshotBytes } from '../bytes/index.mjs';

const MAX_REQUEST = 262144, MAX_OPENING = 1024, HEADER = 12;
const MAGIC = Buffer.from('AUQ1');

export function encodeProposal(requestBytes, openingBytes) {
  const request = snapshotBytes(requestBytes, MAX_REQUEST), opening = snapshotBytes(openingBytes, MAX_OPENING);
  if (!request.length || !opening.length) fail('MALFORMED_BYTES');
  const header = Buffer.alloc(HEADER); MAGIC.copy(header);
  header.writeUInt32BE(request.length, 4); header.writeUInt32BE(opening.length, 8);
  const result = Buffer.concat([header, request, opening]); opening.fill(0); return result;
}

// Trusted construction only. The bridge forwards copied byte proposals to W3;
// it holds no key, context, clock, storage, observer or direct dispatch handle.
export function createProposalBridge(proposal) {
  let closed = false, pending = false;
  return Object.freeze({
    async submit(frameBytes) {
      if (closed || pending) fail('WRONG_AUTHORITY');
      const frame = Buffer.from(snapshotBytes(frameBytes, HEADER + MAX_REQUEST + MAX_OPENING));
      let request, opening;
      try {
        if (frame.length < HEADER || !frame.subarray(0, 4).equals(MAGIC)) fail('MALFORMED_BYTES');
        const nr = frame.readUInt32BE(4), no = frame.readUInt32BE(8);
        if (nr > MAX_REQUEST || no > MAX_OPENING) fail('LIMIT_EXCEEDED');
        if (!nr || !no || frame.length !== HEADER + nr + no) fail('MALFORMED_BYTES');
        request = Buffer.from(frame.subarray(HEADER, HEADER + nr));
        opening = Buffer.from(frame.subarray(HEADER + nr));
        pending = true;
        // Every attempt crosses the ID aperture's current authority checks.
        // Fiber lifetime never grants permission; disposal during an awaited
        // attempt cannot revive this bridge or trigger a retry on resumption.
        const result = await proposal.submitLocal(request, opening);
        if (closed) fail('WRONG_AUTHORITY');
        return result;
      } finally { pending = false; request?.fill(0); opening?.fill(0); frame.fill(0); }
    },
    close() { closed = true; },
  });
}
