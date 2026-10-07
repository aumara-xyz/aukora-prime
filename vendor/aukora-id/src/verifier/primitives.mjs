// W1 is the sole parser/canonicalizer/hash/cryptography implementation.
import {
  parseBytes, canonicalBytes as canonicalParsed, hashDomain, sha256, nostrPreimageParsed, ByteError,
} from '../bytes/index.mjs';
export { parseBytes, hashDomain, sha256, nostrPreimageParsed, ByteError };
export { verifyBip340 } from '../keys/index.mjs';

// INTERNAL ONLY. All values here originate in the strict parser or are constructed
// by this verifier. No public API accepts objects. Reparse derived plain data to
// obtain W1's immutable brand; never serialize an external argument.
export function canonicalBytes(value) {
  return canonicalParsed(parseBytes(Buffer.from(JSON.stringify(value), 'utf8'), {
    mode: 'evidence', maxBytes: 4194304,
  }));
}
export const hex = bytes => Buffer.from(bytes).toString('hex');
export const digest = (label,value) => hex(hashDomain(label,canonicalBytes(value)));
