import { types } from 'node:util';
import { createHash } from 'node:crypto';

export class ByteError extends Error {
  constructor(code, message = code) { super(message); this.name = 'ByteError'; this.code = code; }
}
export const fail = (code, message) => { throw new ByteError(code, message); };
const typed = Object.getPrototypeOf(Uint8Array.prototype);
const getLength = Object.getOwnPropertyDescriptor(typed, 'byteLength').get;
const getBuffer = Object.getOwnPropertyDescriptor(typed, 'buffer').get;
const getResizable = Object.getOwnPropertyDescriptor(ArrayBuffer.prototype, 'resizable')?.get;
const copyInto = Uint8Array.prototype.set;
const branded = new WeakSet();
const decoder = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });
export const LIMITS = Object.freeze({ maxBytes: 262144, maxDepth: 16, maxNodes: 16384, maxArray: 256, maxStringBytes: 8192, maxContentBytes: 196608 });

// The native brand check and typed-array operations do not invoke caller getters,
// iteration, valueOf, toJSON, proxy traps, or a caller's byteLength property.
// Shared/resizable backing stores cannot guarantee a coherent copy: refuse them.
export function snapshotBytes(input, max = LIMITS.maxBytes) {
  if (!types.isUint8Array(input)) fail('MALFORMED_BYTES', 'Expected Uint8Array bytes');
  let n;
  try {
    const buffer = getBuffer.call(input);
    if (types.isSharedArrayBuffer(buffer) || (getResizable && getResizable.call(buffer))) fail('MALFORMED_BYTES');
    n = getLength.call(input);
  } catch { fail('MALFORMED_BYTES'); }
  if (n > max) fail('LIMIT_EXCEEDED');
  try { const copy = new Uint8Array(n); copyInto.call(copy, input); return copy; }
  catch { fail('MALFORMED_BYTES'); }
}
export function assertParsed(value) {
  if (value !== null && typeof value === 'object' && !branded.has(value)) fail('MALFORMED_BYTES', 'Unparsed object');
  return value;
}
function scalarString(value) {
  for (let i = 0; i < value.length; i++) {
    const u = value.charCodeAt(i);
    if (u >= 0xd800 && u <= 0xdbff) {
      const v = value.charCodeAt(++i);
      if (!(v >= 0xdc00 && v <= 0xdfff)) fail('MALFORMED_BYTES', 'Unpaired surrogate');
    } else if (u >= 0xdc00 && u <= 0xdfff) fail('MALFORMED_BYTES', 'Unpaired surrogate');
  }
  return value;
}
export function parseBytes(input, options = undefined) {
  // Options belong to the trusted caller, never to a proposal. They may only
  // tighten defaults, except the explicitly bounded evidence/container modes.
  const mode = options?.mode;
  const limits = { ...LIMITS, ...(mode === 'evidence' ? { maxBytes: 4194304 } : {}) };
  for (const key of Object.keys(LIMITS)) {
    if (options?.[key] !== undefined) {
      if (!Number.isSafeInteger(options[key]) || options[key] < 0) fail('LIMIT_EXCEEDED');
      limits[key] = Math.min(limits[key], options[key]);
    }
  }
  const bytes = snapshotBytes(input, limits.maxBytes);
  if (bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf) fail('MALFORMED_BYTES');
  let source;
  try { source = decoder.decode(bytes); } catch { fail('MALFORMED_BYTES', 'Invalid UTF-8'); }
  let at = 0, nodes = 0, decodedEvidenceBytes = 0;
  const ws = () => { while (/[\x20\t\r\n]/.test(source[at] ?? '\0')) at++; };
  function string(path) {
    const start = at++;
    while (at < source.length) {
      const c = source.charCodeAt(at++);
      if (c === 34) {
        let result;
        try { result = JSON.parse(source.slice(start, at)); } catch { fail('MALFORMED_BYTES'); }
        scalarString(result);
        const serializedEvidence = mode === 'evidence' && (
          (path.length === 2 && path[0] === 'events' && Number.isInteger(path[1])) ||
          (path.length === 1 && path[0] === 'control_state') ||
          (path.length === 3 && Number.isInteger(path[1]) && ((path[0] === 'policies' && path[2] === 'document') || (path[0] === 'artifacts' && path[2] === 'blob'))));
        const cap = serializedEvidence ? Math.ceil(4194304 * 4 / 3) : path.length === 1 && path[0] === 'content' ? limits.maxContentBytes : limits.maxStringBytes;
        if (Buffer.byteLength(result) > cap) fail('LIMIT_EXCEEDED');
        if (serializedEvidence) {
          if (!/^[A-Za-z0-9_-]*$/.test(result)) fail('CLOSED_SCHEMA');
          const decoded = Buffer.from(result, 'base64url');
          if (decoded.toString('base64url') !== result) fail('CLOSED_SCHEMA');
          decodedEvidenceBytes += decoded.length;
          if (decodedEvidenceBytes > 4194304) fail('LIMIT_EXCEEDED');
        }
        return result;
      }
      if (c < 32) fail('MALFORMED_BYTES');
      if (c === 92) at++; // JSON.parse validates the complete escaped string.
    }
    fail('MALFORMED_BYTES', 'Unterminated string');
  }
  function value(depth, path) {
    if (depth > limits.maxDepth || ++nodes > limits.maxNodes) fail('LIMIT_EXCEEDED');
    ws();
    const c = source[at];
    if (c === '"') return string(path);
    if (c === '{') {
      at++; ws(); const out = Object.create(null), seen = new Set();
      if (source[at] !== '}') while (true) {
        if (source[at] !== '"') fail('MALFORMED_BYTES');
        const key = string([]);
        if (seen.has(key)) fail('DUPLICATE_KEY');
        seen.add(key); ws();
        if (source[at++] !== ':') fail('MALFORMED_BYTES');
        out[key] = value(depth + 1, [...path, key]); ws();
        if (source[at] !== ',') break;
        at++; ws();
      }
      if (source[at++] !== '}') fail('MALFORMED_BYTES');
      branded.add(out); return Object.freeze(out);
    }
    if (c === '[') {
      at++; ws(); const out = [];
      if (source[at] !== ']') while (true) {
        if (out.length >= limits.maxArray) fail('LIMIT_EXCEEDED');
        out.push(value(depth + 1, [...path, out.length])); ws();
        if (source[at] !== ',') break;
        at++; ws();
      }
      if (source[at++] !== ']') fail('MALFORMED_BYTES');
      branded.add(out); return Object.freeze(out);
    }
    for (const [token, result] of [['true', true], ['false', false], ['null', null]]) {
      if (source.startsWith(token, at)) { at += token.length; return result; }
    }
    const match = /^(?:0|[1-9][0-9]*)/.exec(source.slice(at));
    if (!match) fail('MALFORMED_BYTES');
    at += match[0].length;
    const n = Number(match[0]);
    if (!Number.isSafeInteger(n)) fail('MALFORMED_BYTES');
    return n;
  }
  const result = value(0, []); ws();
  if (at !== source.length) fail('MALFORMED_BYTES', 'Trailing or noninteger token');
  return result;
}
function serialize(value) {
  assertParsed(value);
  if (typeof value === 'string') return JSON.stringify(scalarString(value));
  if (value === null || typeof value === 'boolean') return JSON.stringify(value);
  if (typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 && !Object.is(value, -0)) return String(value);
  if (Array.isArray(value)) return '[' + value.map(serialize).join(',') + ']';
  if (typeof value === 'object') return '{' + Object.keys(value).sort().map(key => JSON.stringify(key) + ':' + serialize(value[key])).join(',') + '}';
  fail('MALFORMED_BYTES');
}
export function canonicalBytes(parsed) { return Buffer.from(serialize(parsed), 'utf8'); }
export function canonicalJson(bytes) { return canonicalBytes(parseBytes(bytes)); }
export function sha256(bytes) { return createHash('sha256').update(snapshotBytes(bytes, 4194304)).digest(); }
export function hashDomain(label, bytes) {
  if (typeof label !== 'string' || !/^[a-z0-9.-]+$/.test(label)) fail('CLOSED_SCHEMA');
  return createHash('sha256').update(label, 'ascii').update(Buffer.from([0])).update(snapshotBytes(bytes, 4194304)).digest();
}
