// SPDX-License-Identifier: AGPL-3.0-or-later
// Private byte carrier for the existing DSH process and terminal interfaces.
// Only the root-owned wrapper may select the OpenShell SSH proxy and gateway.
import { spawn } from 'node:child_process';
import { Duplex, PassThrough } from 'node:stream';
import { unavailable } from './transport.mjs';

const MAX_LINE = 1024 * 1024;
const CHUNK = 32 * 1024;
const MAX_PENDING = 32;
const exact = (value, keys) => value !== null && typeof value === 'object' && !Array.isArray(value)
  && Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));
const deferred = () => {
  let resolve, reject;
  const promise = new Promise((a, b) => { resolve = a; reject = b; });
  // A synchronous service returns before consumers attach their handlers.
  promise.catch(() => {});
  return { promise, resolve, reject };
};
const failure = code => unavailable(code, 'the guest execution transport is unavailable');

/** Launch the fixed carrier; the proposed argv is data sent inside OpenShell. */
export function openGuestStream(request, settings, layout, signal, spawnCarrier = spawn) {
  signal?.throwIfAborted();
  const ready = deferred(), done = deferred(), empty = deferred(), resolved = deferred();
  const stdout = new PassThrough(), stderr = new PassThrough(), output = new PassThrough();
  const pending = new Map();
  let child, nextId = 1, finished = false, closing = false, quiescent = false, outcome, line = Buffer.alloc(0);
  let writeTail = Promise.resolve(), termination, startupTimer, cleanupTimer;
  let control;

  const fail = code => {
    if (finished) return;
    finished = true;
    clearTimeout(startupTimer); clearTimeout(cleanupTimer);
    signal?.removeEventListener('abort', abort);
    const error = failure(code);
    ready.reject(error); done.reject(error); empty.reject(error); resolved.reject(error);
    for (const entry of pending.values()) { clearTimeout(entry.timer); entry.reject(error); }
    pending.clear();
    // Killing the host carrier is not guest absence evidence. empty rejects.
    child?.stdin?.destroy(); child?.kill('SIGKILL');
    for (const stream of [stdout, stderr, output, control]) stream?.destroy();
  };
  const send = frame => {
    const bytes = Buffer.from(JSON.stringify(frame) + '\n');
    if (bytes.length > MAX_LINE) return Promise.reject(failure('FRAME_LIMIT'));
    const operation = writeTail.then(() => new Promise((accept, reject) => {
      if (finished || !child?.stdin?.writable) { reject(failure('TRANSPORT_CLOSED')); return; }
      child.stdin.write(bytes, error => error ? reject(failure('TRANSPORT_WRITE')) : accept());
    }));
    writeTail = operation.catch(() => {});
    return operation;
  };
  const bytes = async (type, data) => {
    if (closing) throw failure('TRANSPORT_CLOSING');
    const buffer = Buffer.isBuffer(data) ? data : Buffer.from(data);
    for (let offset = 0; offset < buffer.length; offset += CHUNK) {
      await send({ type, data: buffer.subarray(offset, offset + CHUNK).toString('base64') });
    }
  };
  const rpc = (op, args = {}) => {
    if (finished || quiescent || closing && op !== 'terminate') return Promise.reject(failure('TRANSPORT_CLOSED'));
    if (pending.size >= MAX_PENDING) return Promise.reject(failure('REQUEST_LIMIT'));
    const id = nextId++, entry = deferred();
    entry.timer = setTimeout(() => { fail('REQUEST_TIMEOUT'); }, settings.cleanupTimeoutMs);
    pending.set(id, entry);
    send({ type: 'request', id, op, args }).catch(() => fail('TRANSPORT_WRITE'));
    return entry.promise;
  };
  const terminate = () => {
    if (quiescent) return empty.promise;
    if (termination) return termination;
    closing = true;
    termination = rpc('terminate').then(() => empty.promise);
    termination.catch(() => {});
    cleanupTimer = setTimeout(() => fail('GUEST_CLEANUP_UNKNOWN'), settings.cleanupTimeoutMs);
    return termination;
  };
  const abort = () => { void terminate().catch(() => {}); };
  control = new Duplex({
    read() {},
    write(chunk, encoding, callback) {
      bytes('control', chunk).then(() => callback(), error => callback(error));
    },
    final(callback) {
      send({ type: 'control-end' }).then(() => callback(), error => callback(error));
    },
  });
  // Transport errors reject done/empty; do not create unhandled stream errors.
  control.on('error', () => fail('CONTROL_WRITE'));
  const receive = frame => {
    if (!frame || typeof frame !== 'object' || Array.isArray(frame)) throw failure('FRAME_INVALID');
    if (frame.type === 'error' && exact(frame, ['type', 'error']) && /^[A-Z0-9_]+$/.test(frame.error)) {
      fail('GUEST_REFUSED'); return;
    }
    if (frame.type === 'ready' && exact(frame, ['type', 'pid']) && Number.isSafeInteger(frame.pid) && frame.pid > 1) {
      if (request.kind === 'lookup' || outcome || quiescent || ready.seen) throw failure('FRAME_ORDER');
      ready.seen = true; clearTimeout(startupTimer); ready.resolve(frame.pid); return;
    }
    if (frame.type === 'resolved' && exact(frame, ['type', 'path']) && typeof frame.path === 'string'
      && frame.path.startsWith('/') && !/[\0\r\n]/.test(frame.path)) {
      if (request.kind !== 'lookup' || resolved.seen) throw failure('FRAME_ORDER');
      resolved.seen = true; resolved.resolve(frame.path); return;
    }
    if (frame.type === 'control-end' && exact(frame, ['type']) && ready.seen && request.control && !outcome) {
      control.push(null); return;
    }
    if (['stdout', 'stderr', 'control', 'output'].includes(frame.type) && exact(frame, ['type', 'data'])) {
      if (!ready.seen || outcome || quiescent || typeof frame.data !== 'string'
        || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(frame.data)) throw failure('FRAME_INVALID');
      if ((request.kind === 'terminal') !== (frame.type === 'output')
        || frame.type === 'control' && !request.control) throw failure('FRAME_STREAM');
      const data = Buffer.from(frame.data, 'base64');
      const stream = { stdout, stderr, output, control }[frame.type];
      if (stream.readableLength + (stream.writableLength ?? 0) + data.length > MAX_LINE) throw failure('OUTPUT_BACKPRESSURE');
      if (frame.type === 'control') stream.push(data);
      else stream.write(data);
      return;
    }
    if (frame.type === 'reply' && (exact(frame, ['type', 'id', 'result']) || exact(frame, ['type', 'id', 'error']))) {
      const entry = pending.get(frame.id);
      if (!entry) throw failure('FRAME_REPLY');
      pending.delete(frame.id); clearTimeout(entry.timer);
      if (Object.hasOwn(frame, 'error')) entry.reject(failure('GUEST_REQUEST_REFUSED'));
      else entry.resolve(frame.result);
      return;
    }
    if (frame.type === 'outcome' && exact(frame, ['type', 'exitCode', 'signal'])
      && (frame.exitCode === null || Number.isSafeInteger(frame.exitCode) && frame.exitCode >= 0 && frame.exitCode <= 255)
      && (frame.signal === null || /^SIG[A-Z0-9]+$/.test(frame.signal))) {
      if (!ready.seen || outcome || quiescent) throw failure('FRAME_ORDER');
      outcome = { exitCode: frame.exitCode, signal: frame.signal };
      for (const stream of [stdout, stderr, output]) stream.end();
      control.push(null); done.resolve(outcome); return;
    }
    if (frame.type === 'quiescent' && exact(frame, ['type'])) {
      if (quiescent || (request.kind === 'lookup' ? !resolved.seen : !outcome)) throw failure('FRAME_ORDER');
      quiescent = true; clearTimeout(startupTimer); clearTimeout(cleanupTimer);
      closing = true;
      cleanupTimer = setTimeout(() => fail('CARRIER_CLOSE_UNKNOWN'), settings.cleanupTimeoutMs);
      child.stdin.end(); return;
    }
    throw failure('FRAME_INVALID');
  };
  try {
    child = spawnCarrier('/usr/bin/env', ['-i', 'PATH=/usr/bin:/bin', 'LC_ALL=C',
      '/usr/bin/sudo', '-n', '-u', 'auma', layout.sbxExec, '--stream', String(settings.timeoutSeconds)], {
      cwd: '/', env: {}, stdio: ['pipe', 'pipe', 'pipe'],
    });
    child.on('error', () => fail('CARRIER_SPAWN'));
    child.stdin.on('error', () => fail('TRANSPORT_WRITE'));
    // Host wrapper/SSH diagnostics never enter model output or protocol data.
    let diagnosticBytes = 0;
    child.stderr.on('data', chunk => { diagnosticBytes += chunk.length; if (diagnosticBytes > MAX_LINE) fail('CARRIER_DIAGNOSTIC_LIMIT'); });
    child.stdout.on('data', chunk => {
      if (finished) return;
      line = Buffer.concat([line, chunk]);
      try {
        for (;;) {
          const end = line.indexOf(10);
          if (end < 0) break;
          if (end > MAX_LINE) throw failure('FRAME_LIMIT');
          const item = line.subarray(0, end); line = line.subarray(end + 1);
          receive(JSON.parse(item.toString('utf8')));
        }
        if (line.length > MAX_LINE) throw failure('FRAME_LIMIT');
      } catch { fail('PROTOCOL_INVALID'); }
    });
    child.on('close', code => {
      if (finished) return;
      if (!quiescent || line.length || code !== 0) { fail('GUEST_CLEANUP_UNKNOWN'); return; }
      finished = true; clearTimeout(cleanupTimer); signal?.removeEventListener('abort', abort);
      for (const entry of pending.values()) { clearTimeout(entry.timer); entry.reject(failure('TRANSPORT_CLOSED')); }
      pending.clear();
      // No pending writes or RPC callbacks survive successful terminal cleanup.
      writeTail.then(() => empty.resolve(true), () => empty.reject(failure('TRANSPORT_WRITE')));
    });
    startupTimer = setTimeout(() => fail('GUEST_STARTUP_TIMEOUT'), settings.startupTimeoutMs);
    signal?.addEventListener('abort', abort, { once: true });
    send(request).catch(() => fail('TRANSPORT_WRITE'));
    if (signal?.aborted) abort();
  } catch { fail('CARRIER_SPAWN'); }
  return Object.freeze({ ready: ready.promise, done: done.promise, empty: empty.promise,
    resolved: resolved.promise, stdout, stderr, output, control, rpc, terminate,
    detachAllocationSignal: () => signal?.removeEventListener('abort', abort),
    writeStdin: data => bytes('stdin', data), endStdin: () => send({ type: 'stdin-end' }) });
}
