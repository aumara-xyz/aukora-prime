import { Socket } from 'node:net';
import { createReceiptObserver } from './index.mjs';
import { frameBytes, frameLength, frameFields, FRAME_LIMIT } from './channel.mjs';

// fd3 is inherited directly from the trusted host, never a proposal pipe. IPC is
// startup/teardown only and cannot request a receipt or supply observed evidence.
let observer, channel, pending = Buffer.alloc(0), stopped = false;
const send = message => { if (process.connected) process.send(message); };
const close = () => {
  if (stopped) return;
  stopped = true; pending.fill(0); observer?.close(); channel?.destroy();
  if (process.connected) process.disconnect();
};
const receive = chunk => {
  if (stopped) { chunk.fill(0); return; }
  try {
    if (pending.length + chunk.length > FRAME_LIMIT) throw new Error('bounded channel');
    const old = pending; pending = Buffer.concat([old, chunk]); old.fill(0); chunk.fill(0);
    const size = frameLength(pending);
    if (size === null || pending.length < size) return;
    // Synchronous one-request/response protocol. Pipelining is not supported.
    if (pending.length !== size) throw new Error('ambiguous channel');
    const fields = frameFields(pending); pending.fill(0); pending = Buffer.alloc(0);
    let response;
    try { response = frameBytes(observer.receive(fields)); }
    finally { fields.forEach(value => value.fill(0)); }
    // Prefix synchronization is authentication only, never a receiver effect.
    if (fields[3].length !== 0) send({ type: 'observed', count: observer.count() });
    channel.write(response, error => { response.fill(0); if (error) close(); });
  } catch { send({ type: 'observation_unavailable' }); close(); }
};
process.on('message', message => {
  try {
    if (message?.command === 'start' && !observer && !stopped) {
      const config = Buffer.from(message.config, 'base64url');
      try { observer = createReceiptObserver(config); } finally { config.fill(0); }
      channel = new Socket({ fd: 3, readable: true, writable: true });
      channel.on('data', receive); channel.on('error', close); channel.on('end', close);
      send({ type: 'ready', pid: process.pid, binding: observer.publicBinding });
    } else if (message?.command === 'close') close();
    else { send({ type: 'observation_unavailable' }); close(); }
  } catch { send({ type: 'startup_refused' }); close(); }
});
process.on('disconnect', close); process.on('SIGTERM', close); process.on('SIGINT', close);
