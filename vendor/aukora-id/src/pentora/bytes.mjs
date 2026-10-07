import { types } from 'node:util';

const typedArray = Object.getPrototypeOf(Uint8Array.prototype);
const getLength = Object.getOwnPropertyDescriptor(typedArray, 'length').get;
const getBuffer = Object.getOwnPropertyDescriptor(typedArray, 'buffer').get;
const getOffset = Object.getOwnPropertyDescriptor(typedArray, 'byteOffset').get;
const setBytes = typedArray.set;
const getResizable = Object.getOwnPropertyDescriptor(ArrayBuffer.prototype, 'resizable')?.get;

// Read intrinsic slots, never caller length/iterator/species/getter properties.
// Shared/resizable storage cannot promise a coherent snapshot: refuse it.
export function copyBytes(value, length, label = 'bytes') {
  if (types.isProxy(value) || !types.isUint8Array(value)) {
    throw new TypeError(`${label} must be Uint8Array or Buffer`);
  }
  const size = Reflect.apply(getLength, value, []);
  if (size !== length) throw new RangeError(`${label} must contain exactly ${length} bytes`);
  const buffer = Reflect.apply(getBuffer, value, []);
  if (types.isSharedArrayBuffer(buffer) || (getResizable && Reflect.apply(getResizable, buffer, []))) {
    throw new TypeError(`${label} must use fixed, unshared storage`);
  }
  const view = new Uint8Array(buffer, Reflect.apply(getOffset, value, []), size);
  const snapshot = new Uint8Array(size);
  Reflect.apply(setBytes, snapshot, [view]);
  return snapshot;
}

export function copyBoundedBytes(value, maximum, label) {
  if (types.isProxy(value) || !types.isUint8Array(value)) {
    throw new TypeError(`${label} must be Uint8Array or Buffer`);
  }
  const size = Reflect.apply(getLength, value, []);
  if (size === 0 || size > maximum) throw new RangeError(`${label} length out of bounds`);
  return copyBytes(value, size, label);
}

export function readBigEndian(bytes) {
  let n = 0n;
  for (const byte of bytes) n = n * 256n + BigInt(byte);
  return n;
}

export function lowTrits(n, count) {
  const digits = new Uint8Array(count);
  for (let i = 0; i < count; i += 1) {
    digits[i] = Number(n % 3n);
    n /= 3n;
  }
  return digits;
}

export function freezeData(value) {
  if (value !== null && typeof value === 'object') {
    for (const child of Object.values(value)) freezeData(child);
    Object.freeze(value);
  }
  return value;
}

// Only used on the trusted host's response; still refuse executable properties.
export function plainFields(value, keys) {
  if (value === null || typeof value !== 'object' || types.isProxy(value)) return null;
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) return null;
  const fields = Object.getOwnPropertyDescriptors(value);
  if (Reflect.ownKeys(fields).length !== keys.length) return null;
  const result = Object.create(null);
  for (const key of keys) {
    const descriptor = fields[key];
    if (!descriptor || !Object.hasOwn(descriptor, 'value')) return null;
    result[key] = descriptor.value;
  }
  return result;
}
