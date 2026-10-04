// SPDX-License-Identifier: AGPL-3.0-or-later
// The native-JSON duplicate/depth scan is adapted from Genesis 645d3213b8aede3b544269b4224ae09df06b0a42
// plugins/aukora-kira/lib/strict-read.mjs (Prime's packages/authority/upstream copy), AGPL-3.0-or-later.
// Only its pure parsing pattern is used here; no filesystem or Node imports.
export class ContractValidationError extends TypeError {
 constructor(reason, path = '$') {
  super(`INVALID: ${reason} at ${path}`);
  this.name = 'ContractValidationError'; this.code = 'INVALID'; this.error_code = 'INVALID';
  this.reason = reason; this.path = path;
 }
}
export function invalid(reason, path) { throw new ContractValidationError(reason, path); }
export const MAX_JSON_DEPTH = 64;
export const MAX_JSON_BYTES = 8 * 1024 * 1024;
export function assertUnicode(value, path = '$') {
 if (/[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/u.test(value)) invalid('JSON_LONE_SURROGATE', path);
}
export function canonicalJson(value) {
 const ancestors = new Set();
 function encode(node, depth) {
  if (depth > MAX_JSON_DEPTH) invalid('JSON_DEPTH');
  if (node === null || typeof node === 'boolean') return JSON.stringify(node);
  if (typeof node === 'string') { assertUnicode(node); return JSON.stringify(node); }
  if (typeof node === 'number') {
   if (Object.is(node, -0)) invalid('JSON_NEGATIVE_ZERO');
   if (!Number.isSafeInteger(node)) invalid('JSON_UNSAFE_NUMBER');
   return JSON.stringify(node);
  }
  if (!node || typeof node !== 'object') invalid('JSON_VALUE');
  if (ancestors.has(node)) invalid('JSON_CYCLE');
  const array = Array.isArray(node), proto = Object.getPrototypeOf(node);
  if (array ? proto !== Array.prototype : proto !== Object.prototype && proto !== null) invalid('JSON_PROTOTYPE');
  const keys = Reflect.ownKeys(node);
  for (const key of keys) {
   if (array && key === 'length') continue;
   const d = Object.getOwnPropertyDescriptor(node, key);
   if (typeof key !== 'string' || !d?.enumerable || !Object.hasOwn(d, 'value')) invalid('JSON_DATA_PROPERTY');
   assertUnicode(key);
  }
  if (array && (keys.length !== node.length + 1 || Array.from({length: node.length}, (_, i) => Object.hasOwn(node, i)).some(present => !present))) invalid('JSON_ARRAY');
  ancestors.add(node);
  const result = array ? '[' + node.map(item => encode(item, depth + 1)).join(',') + ']'
   : '{' + Object.keys(node).sort().map(key => JSON.stringify(key) + ':' + encode(node[key], depth + 1)).join(',') + '}';
  ancestors.delete(node);
  return result;
 }
 return encode(value, 0);
}

// Check the mathematical value before native parsing can round a decimal token
// such as 1.00000000000000001 to the safe integer 1. Exact 1e0/1.0 remain usable.
function exactNumber(token) {
 const m = /^(-?)(\d+)(?:\.(\d+))?(?:[eE]([+-]?\d+))?$/.exec(token);
 let digits = (m[2] + (m[3] ?? '')).replace(/^0+/, '');
 if (!digits) { if (m[1]) invalid('JSON_NEGATIVE_ZERO'); return; }
 const scale = Number(m[4] ?? 0) - (m[3]?.length ?? 0);
 if (!Number.isSafeInteger(scale)) invalid('JSON_UNSAFE_NUMBER');
 if (scale < 0) {
  const count = -scale;
  if (count > digits.length || !/^0*$/.test(digits.slice(-count))) invalid('JSON_UNSAFE_NUMBER');
  digits = digits.slice(0, -count);
 } else {
  if (digits.length + scale > 16) invalid('JSON_UNSAFE_NUMBER');
  digits += '0'.repeat(scale);
 }
 if (digits.length > 16 || BigInt(digits) > BigInt(Number.MAX_SAFE_INTEGER)) invalid('JSON_UNSAFE_NUMBER');
}
export function parseStrictJson(text, options = {}) {
 if (!options || typeof options !== 'object' || Array.isArray(options)) invalid('JSON_LIMIT');
 const {maxBytes = MAX_JSON_BYTES, maxDepth = MAX_JSON_DEPTH} = options;
 if (typeof text !== 'string') invalid('JSON_TEXT_REQUIRED');
 if (!Number.isSafeInteger(maxBytes) || maxBytes < 1 || maxBytes > MAX_JSON_BYTES
  || !Number.isSafeInteger(maxDepth) || maxDepth < 0 || maxDepth > MAX_JSON_DEPTH) invalid('JSON_LIMIT');
 assertUnicode(text);
 if (text.length > maxBytes || new TextEncoder().encode(text).length > maxBytes) invalid('JSON_SIZE');
 // Bound depth BEFORE the native parser. Escaped quotes/brackets do not count.
 let depth = 0;
 for (let i = 0; i < text.length; i++) {
  if (text[i] === '"') { for (i++; i < text.length && text[i] !== '"'; i++) if (text[i] === '\\') i++; }
  else if (text[i] === '{' || text[i] === '[') { if (++depth > maxDepth) invalid('JSON_DEPTH'); }
  else if (text[i] === '}' || text[i] === ']') depth--;
 }
 let value;
 try { value = JSON.parse(text); } catch { invalid('JSON_MALFORMED'); }
 // Scan the SAME validated text for decoded keys, scoped to each object, before
 // returning a value whose duplicate keys would already have been discarded.
 const stack = [];
 for (let i = 0; i < text.length; i++) {
  const ch = text[i];
  if (ch === '"') {
   const start = i;
   for (i++; text[i] !== '"'; i++) if (text[i] === '\\') i++;
   let probe = i + 1;
   while (/^[\x20\t\r\n]$/.test(text[probe] ?? '')) probe++;
   if (text[probe] === ':') {
    const key = JSON.parse(text.slice(start, i + 1)), frame = stack[stack.length - 1];
    if (frame.has(key)) invalid('JSON_DUPLICATE_KEY');
    frame.add(key);
   }
  } else if (ch === '{') stack.push(new Set());
  else if (ch === '[') stack.push(null);
  else if (ch === '}' || ch === ']') stack.pop();
  else if (ch === '-' || /[0-9]/.test(ch)) {
   const start = i;
   while (i + 1 < text.length && /[0-9.eE+-]/.test(text[i + 1])) i++;
   exactNumber(text.slice(start, i + 1));
  }
 }
 canonicalJson(value); // Includes decoded lone surrogates in values AND keys.
 return value;
}
