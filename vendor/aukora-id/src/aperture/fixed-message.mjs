import { snapshotBytes } from '../bytes/index.mjs';

// Pure fixed-message bytes shared by core validation and the LOCAL adapter.
const FIXED = Buffer.from('41554b4f5241204c4f43414c20544553540a', 'hex');

export function fixedPayloadBytes() {
  return Buffer.from(FIXED);
}

export function isFixedPayload(bytes) {
  try {
    const copy = snapshotBytes(bytes, FIXED.length);
    return copy.length === FIXED.length && Buffer.from(copy).equals(FIXED);
  } catch { return false; }
}

