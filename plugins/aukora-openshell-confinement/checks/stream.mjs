// SPDX-License-Identifier: AGPL-3.0-or-later
// Source mock checks only: no OpenShell, wrapper, service, or host process runs.
import assert from 'node:assert/strict';
import { EventEmitter, once } from 'node:events';
import { PassThrough, Writable } from 'node:stream';
import test from 'node:test';
import { openGuestStream } from '../lib/stream.mjs';

const MAX_PENDING_BYTES = 1024 * 1024;
const CHUNK = 32 * 1024;
const settings = Object.freeze({ timeoutSeconds: 60, startupTimeoutMs: 200, cleanupTimeoutMs: 200 });
const layout = Object.freeze({ sbxExec: '/usr/local/lib/aukora-boundary/sbx-exec' });
const turn = () => new Promise(resolve => setImmediate(resolve));
const unavailable = error => error?.code === 'SANDBOX_UNAVAILABLE';
const launch = (kind = 'process') => ({
  type: 'launch', version: 1, kind,
  argv: kind === 'terminal' ? ['/bin/bash', '--noprofile', '--norc', '-i']
    : ['/usr/bin/node', '--max-old-space-size=128', '/sandbox/ptc-process.js', '1048576'],
  cwd: '/sandbox', env: {}, stdin: 'pipe', control: kind === 'process',
  grace_ms: 20, rows: kind === 'terminal' ? 24 : 0, cols: kind === 'terminal' ? 80 : 0,
  terminal_type: kind === 'terminal' ? 'dumb' : '',
});

function carrier(t, onFrame = () => {}) {
  const child = new EventEmitter();
  child.stdout = new PassThrough();
  child.stderr = new PassThrough();
  child.frames = [];
  child.kills = [];
  child.calls = [];
  let input = Buffer.alloc(0), closed = false;
  child.stdin = new Writable({
    write(chunk, encoding, callback) {
      input = Buffer.concat([input, chunk]);
      for (;;) {
        const end = input.indexOf(10);
        if (end < 0) break;
        const frame = JSON.parse(input.subarray(0, end).toString('utf8'));
        input = input.subarray(end + 1);
        child.frames.push(frame);
        queueMicrotask(() => onFrame(frame, child));
      }
      callback();
    },
  });
  child.frame = value => child.stdout.write(Buffer.from(JSON.stringify(value) + '\n'));
  child.bytes = (type, data) => child.frame({ type, data: Buffer.from(data).toString('base64') });
  child.kill = signal => { child.kills.push(signal); return true; };
  child.close = code => {
    if (closed) return;
    closed = true;
    child.stdout.end(); child.stderr.end();
    child.emit('close', code);
  };
  child.spawn = (...args) => { child.calls.push(args); return child; };
  t.after(() => {
    child.close(1);
    child.stdin.destroy(); child.stdout.destroy(); child.stderr.destroy();
  });
  return child;
}

function complete(child) {
  child.frame({ type: 'outcome', exitCode: 0, signal: null });
  child.frame({ type: 'quiescent' });
}

test('byte echo and FD7 half-close use only the fixed sanitized as-auma carrier', { timeout: 2000 }, async t => {
  const child = carrier(t, (frame, peer) => {
    if (frame.type === 'launch') peer.frame({ type: 'ready', pid: 42 });
    if (frame.type === 'stdin') peer.bytes('stdout', Buffer.from(frame.data, 'base64'));
    if (frame.type === 'control') peer.bytes('control', Buffer.from(frame.data, 'base64'));
    if (frame.type === 'control-end') peer.frame({ type: 'control-end' });
  });
  const request = launch();
  const session = openGuestStream(request, settings, layout, undefined, child.spawn);
  const stdout = [], stderr = [], control = [];
  session.stdout.on('data', bytes => stdout.push(bytes));
  session.stderr.on('data', bytes => stderr.push(bytes));
  session.control.on('data', bytes => control.push(bytes));
  assert.equal(await session.ready, 42);
  const binary = Buffer.from([0, 255, 13, 10, 195, 169, 128]);
  const controlBytes = Buffer.concat([Buffer.alloc(CHUNK + 9, 255), binary]);
  const controlEnd = once(session.control, 'end');
  const controlFinished = once(session.control, 'finish');
  await session.writeStdin(binary);
  await session.endStdin();
  session.control.end(controlBytes);
  await Promise.all([controlEnd, controlFinished]);
  // Half-closing FD7 must not close the independent model-output channel.
  child.bytes('stdout', Buffer.from('after-control-end\n'));
  child.bytes('stderr', binary);
  assert.deepEqual(Buffer.concat(control), controlBytes);
  assert.deepEqual(Buffer.concat(stdout), Buffer.concat([binary, Buffer.from('after-control-end\n')]));
  assert.deepEqual(Buffer.concat(stderr), binary);
  assert.equal(child.calls.length, 1);
  assert.deepEqual(child.calls[0], ['/usr/bin/env', [
    '-i', 'PATH=/usr/bin:/bin', 'LC_ALL=C', '/usr/bin/sudo', '-n', '-u', 'auma',
    layout.sbxExec, '--stream', '60',
  ], { cwd: '/', env: {}, stdio: ['pipe', 'pipe', 'pipe'] }]);
  assert.deepEqual(child.frames[0], request);
  assert.equal(child.frames.filter(frame => frame.type === 'control').length, 2);
  complete(child);
  assert.deepEqual(await session.done, { exitCode: 0, signal: null });
  child.close(0);
  assert.equal(await session.empty, true);
});

test('quiescent followed by trailing bytes or nonzero carrier exit never certifies cleanup', { timeout: 2000 }, async t => {
  for (const ending of ['trailing-bytes', 'nonzero-exit']) {
    const child = carrier(t);
    const session = openGuestStream(launch(), settings, layout, undefined, child.spawn);
    child.frame({ type: 'ready', pid: 43 });
    await session.ready;
    let certified = false;
    session.empty.then(() => { certified = true; }).catch(() => {});
    complete(child);
    await turn();
    assert.equal(certified, false, `${ending}: a frame alone must not certify carrier completion`);
    if (ending === 'trailing-bytes') child.stdout.write(Buffer.from('unfinished-frame'));
    child.close(ending === 'nonzero-exit' ? 9 : 0);
    await assert.rejects(session.empty, error => unavailable(error) && error.reason === 'GUEST_CLEANUP_UNKNOWN');
    assert.equal(certified, false);
    assert.deepEqual(child.kills, ['SIGKILL']);
  }
});

test('published terminal detaches allocation cancellation and retains live guest I/O', { timeout: 2000 }, async t => {
  const child = carrier(t, (frame, peer) => {
    if (frame.type === 'launch') peer.frame({ type: 'ready', pid: 44 });
    if (frame.type === 'stdin') peer.bytes('output', Buffer.from(frame.data, 'base64'));
    if (frame.type === 'request' && frame.op === 'foreground') peer.frame({
      type: 'reply', id: frame.id, result: { processGroupId: 44, inputWaiting: true },
    });
  });
  const controller = new AbortController();
  const session = openGuestStream(launch('terminal'), settings, layout, controller.signal, child.spawn);
  const output = [];
  session.output.on('data', bytes => output.push(bytes));
  assert.equal(await session.ready, 44);
  session.detachAllocationSignal();
  controller.abort(new Error('allocation caller completed'));
  await turn();
  assert.equal(child.frames.some(frame => frame.op === 'terminate'), false);
  assert.deepEqual(child.kills, []);
  await session.writeStdin('guest terminal remains live\n');
  assert.deepEqual(await session.rpc('foreground'), { processGroupId: 44, inputWaiting: true });
  assert.equal(Buffer.concat(output).toString('utf8'), 'guest terminal remains live\n');
  complete(child);
  child.close(0);
  assert.equal(await session.empty, true);
});

test('a stalled pipe bounds readable plus writable queues and leaves cleanup unknown', { timeout: 2000 }, async t => {
  const child = carrier(t);
  const session = openGuestStream(launch(), settings, layout, undefined, child.spawn);
  child.frame({ type: 'ready', pid: 45 });
  await session.ready;
  let certified = false, largestQueue = 0, frames = 0;
  session.empty.then(() => { certified = true; }).catch(() => {});
  const data = Buffer.alloc(CHUNK, 65);
  while (!session.stdout.destroyed && frames < 100) {
    child.bytes('stdout', data);
    frames++;
    largestQueue = Math.max(largestQueue, session.stdout.readableLength + session.stdout.writableLength);
  }
  assert.equal(session.stdout.destroyed, true, 'stalled output must fail before buffering an unbounded stream');
  assert.ok(frames <= MAX_PENDING_BYTES / CHUNK + 2, 'failure must occur at the combined queue limit');
  assert.ok(largestQueue <= MAX_PENDING_BYTES);
  await assert.rejects(session.done, unavailable);
  await assert.rejects(session.empty, unavailable);
  assert.equal(certified, false, 'killing a carrier must not certify guest absence');
  assert.deepEqual(child.kills, ['SIGKILL']);
});

test('an oversized first guest output frame refuses before entering either pipe queue', { timeout: 2000 }, async t => {
  const child = carrier(t);
  const session = openGuestStream(launch(), settings, layout, undefined, child.spawn);
  child.frame({ type: 'ready', pid: 46 });
  await session.ready;
  // This is below the JSON line limit but above the guest's byte-chunk limit.
  child.bytes('stdout', Buffer.alloc(CHUNK + 1, 65));
  assert.equal(session.stdout.readableLength, 0);
  assert.equal(session.stdout.writableLength, 0);
  assert.equal(session.stdout.destroyed, true);
  await assert.rejects(session.done, unavailable);
  await assert.rejects(session.empty, unavailable);
  assert.deepEqual(child.kills, ['SIGKILL']);
});

test('termination after transport failure preserves unknown cleanup without a fresh timer', { timeout: 2000 }, async t => {
  const timers = [];
  const originalTimeout = globalThis.setTimeout;
  t.mock.method(globalThis, 'setTimeout', (...args) => {
    const timer = originalTimeout(...args);
    timers.push(timer);
    return timer;
  });
  // Failed assertions must also leave the mock check without active timers.
  t.after(() => { for (const timer of timers) clearTimeout(timer); });
  const child = carrier(t);
  const session = openGuestStream(launch(), settings, layout, undefined, child.spawn);
  child.frame({ type: 'ready', pid: 47 });
  await session.ready;
  child.close(1);
  await assert.rejects(session.empty, unavailable);
  const timersBeforeTerminate = timers.length;
  const requestsBeforeTerminate = child.frames.length;
  await assert.rejects(session.terminate(), unavailable);
  assert.equal(timers.length, timersBeforeTerminate, 'failed transport must not start another cleanup deadline');
  assert.equal(child.frames.length, requestsBeforeTerminate, 'failed transport must not dispatch another request');
  await assert.rejects(session.empty, unavailable);
  assert.deepEqual(child.kills, ['SIGKILL']);
});
