import { createHash } from 'node:crypto';
import { copyBytes, lowTrits, readBigEndian } from './bytes.mjs';

const DISPLAY_DOMAIN = Buffer.from('pentora.display.v1\0', 'ascii');
const PACKED_LIMIT = 3n ** 110n;

export function expandHead(raw32) {
  const head = copyBytes(raw32, 32, 'head');
  const digest = createHash('sha256').update(DISPLAY_DOMAIN).update(head).digest();
  return lowTrits(readBigEndian(digest), 110);
}

export function copyWire(wire110) {
  const wire = copyBytes(wire110, 110, 'wire');
  for (const digit of wire) {
    if (digit > 2) throw new RangeError('wire digits must be 0, 1 or 2');
  }
  return wire;
}

export function packWire(wire110) {
  const wire = copyWire(wire110);
  let n = 0n;
  for (let i = 109; i >= 0; i -= 1) n = n * 3n + BigInt(wire[i]);
  const packed = new Uint8Array(22);
  for (let i = 21; i >= 0; i -= 1) {
    packed[i] = Number(n & 255n);
    n >>= 8n;
  }
  return packed;
}

export function unpackPacked(packed22) {
  const packed = copyBytes(packed22, 22, 'packed');
  const n = readBigEndian(packed);
  if (n >= PACKED_LIMIT) throw new RangeError('packed integer must be less than 3^110');
  return lowTrits(n, 110);
}
