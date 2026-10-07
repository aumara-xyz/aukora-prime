import { readSync, writeSync } from 'node:fs';
import { performance } from 'node:perf_hooks';
import { Socket } from 'node:net';
import { closed, fail, h32, parseBytes, parseEvent, snapshotBytes, u64, uint } from '../bytes/index.mjs';

// Private inherited duplex pipe only, no listener or configurable destination.
// Four length-delimited fields keep large signed events out of JSON string leaves.
const MAGIC = Buffer.from('AOB1');
const HEADER = 20;
export const FIELD_LIMITS = Object.freeze([262144, 262144, 4194304, 8192]);
export const FRAME_LIMIT = HEADER + FIELD_LIMITS.reduce((a, b) => a + b, 0);
const pause = new Int32Array(new SharedArrayBuffer(4));
export function frameBytes(fields) {
  if (!Array.isArray(fields) || fields.length !== 4) fail('CLOSED_SCHEMA');
  const copies = fields.map((value, index) => Buffer.from(snapshotBytes(value, FIELD_LIMITS[index])));
  try {
    const header = Buffer.alloc(HEADER); MAGIC.copy(header);
    copies.forEach((value, index) => header.writeUInt32BE(value.length, 4 + index * 4));
    return Buffer.concat([header, ...copies]);
  } finally { copies.forEach(value => value.fill(0)); }
}
export function frameLength(bytes) {
  if (bytes.length < HEADER) return null;
  if (!bytes.subarray(0, 4).equals(MAGIC)) fail('MALFORMED_BYTES');
  let length = HEADER;
  for (let i = 0; i < 4; i++) {
    const size = bytes.readUInt32BE(4 + i * 4);
    if (size > FIELD_LIMITS[i]) fail('LIMIT_EXCEEDED');
    length += size;
  }
  return length;
}
export function frameFields(bytes) {
  if (frameLength(bytes) !== bytes.length) fail('MALFORMED_BYTES');
  let offset = HEADER;
  return FIELD_LIMITS.map((_, index) => {
    const end = offset + bytes.readUInt32BE(4 + index * 4);
    const result = Buffer.from(bytes.subarray(offset, end)); offset = end; return result;
  });
}
function retryIO(fn, deadline) {
  for (;;) {
    if (performance.now() >= deadline) fail('MISSING_EVIDENCE', 'Observer deadline expired');
    try { return fn(); }
    catch (error) {
      if (error?.code !== 'EAGAIN' && error?.code !== 'EWOULDBLOCK' && error?.code !== 'EINTR') throw error;
      Atomics.wait(pause, 0, 0, Math.min(5, Math.max(0, deadline - performance.now())));
    }
  }
}
// Trusted host: one send only. Any partial I/O/timeout poisons this channel;
// later operations cannot consume a late response as their own observation.
export function createObserverChannel(fd) {
  if (!Number.isSafeInteger(fd) || fd < 5) fail('WRONG_AUTHORITY');
  let poisoned = false;
  // libuv initializes an inherited socket as nonblocking here. A bare inherited
  // fd can be blocking despite the controller's pipe mode, which would defeat
  // the synchronous deadline. Keep the stream paused: only readSync consumes it.
  const socket = new Socket({ fd, readable: true, writable: true });
  socket.pause(); socket.unref();
  socket.on('error', () => { poisoned = true; });
  let cursor = Object.freeze({ id: null, sequence: null, count: 0 });
  const exchange = fields => {
    if (poisoned) fail('MISSING_EVIDENCE');
    const request = frameBytes(fields), header = Buffer.alloc(HEADER);
    let response;
    const deadline = performance.now() + 5000;
    const read = buffer => {
      let offset = 0;
      while (offset < buffer.length) {
        const n = retryIO(() => readSync(fd, buffer, offset, buffer.length - offset), deadline);
        if (n === 0) fail('MISSING_EVIDENCE');
        offset += n;
      }
    };
    try {
      let offset = 0;
      while (offset < request.length) {
        const n = retryIO(() => writeSync(fd, request, offset, request.length - offset), deadline);
        if (n === 0) fail('MISSING_EVIDENCE');
        offset += n;
      }
      read(header);
      response = Buffer.alloc(frameLength(header)); header.copy(response);
      read(response.subarray(HEADER));
      return frameFields(response);
    } catch (error) { poisoned = true; throw error; }
    finally { request.fill(0); header.fill(0); response?.fill(0); }
  };
  return Object.freeze({
    close() { poisoned = true; socket.destroy(); },
    head() { return cursor; },
    // Public event bytes only, on the already-private inherited channel. The
    // cursor is an acknowledgement, never evidence of current authorization.
    synchronize(eventBytes, contextBytes, evidenceBytes) {
      const event = snapshotBytes(eventBytes), parsed = parseEvent(event);
      const response = exchange([event, contextBytes, evidenceBytes, Buffer.alloc(0)]);
      try {
        if (response.slice(1).some(value => value.length !== 0)) fail('CLOSED_SCHEMA');
        const ack = parseBytes(response[0]);
        closed(ack, { schema: value => { if (value !== 'aukora.local.observer-prefix-ack.v1') fail('CLOSED_SCHEMA'); },
          event_id: h32, sequence: u64, count: uint });
        if (ack.event_id !== parsed.event.id || ack.sequence !== parsed.record.sequence || ack.count !== cursor.count + 1) fail('INCONSISTENT_HEAD');
        cursor = Object.freeze({ id: ack.event_id, sequence: ack.sequence, count: ack.count });
        return cursor;
      } catch (error) { poisoned = true; throw error; }
      finally { response.forEach(value => value.fill(0)); }
    },
    exchange,
  });
}
