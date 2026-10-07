import { writeSync } from 'node:fs';
import { Socket } from 'node:net';
import { createLocalHost } from './index.mjs';
import { createPrefixPulseSource } from '../aura/index.mjs';
import { operationResult } from '../aperture/local-profile.mjs';

// Child-process entry point. fd3 = proposal bytes / OperationResult lines;
// fd4 = nonsecret barrier/sink notices; IPC = trusted controller only.
// No TCP/HTTP/Unix-domain listener, plugin loader or user callback is installed.
const MAX_REQUEST = 262144, MAX_OPENING = 1024, MAX_FRAME = 8 + MAX_REQUEST + MAX_OPENING;
const barrier = process.argv[2] || null;
let host = null, pulse = null, proposal = null, pending = Buffer.alloc(0), exiting = false;
const send = message => { if (process.connected) process.send(message); };
const respond = result => {
  const line = Buffer.from(JSON.stringify(result) + '\n');
  let offset = 0;
  while (offset < line.length) offset += writeSync(3, line, offset);
};
const close = () => {
  if (exiting) return;
  exiting = true;
  proposal?.destroy(); pending.fill(0); pulse?.close();host?.close();
  send({ type: 'closed' });
  if (process.connected) process.disconnect();
  process.exitCode = 0;
};
const fail = () => {
  try { respond(operationResult({ reasons: ['LIMIT_EXCEEDED'] })); } catch { /* disconnected proposer */ }
  close();
};
function onBytes(chunk) {
  if (exiting) return;
  if (pending.length + chunk.length > 2 * MAX_FRAME) return fail();
  const previous = pending;
  pending = Buffer.concat([pending, chunk]); previous.fill(0); chunk.fill(0);
  while (pending.length >= 8) {
    const requestLength = pending.readUInt32BE(0), openingLength = pending.readUInt32BE(4);
    if (requestLength > MAX_REQUEST || openingLength > MAX_OPENING) return fail();
    const frameLength = 8 + requestLength + openingLength;
    if (pending.length < frameLength) break;
    const request = Buffer.from(pending.subarray(8, 8 + requestLength));
    const opening = Buffer.from(pending.subarray(8 + requestLength, frameLength));
    const remaining = Buffer.from(pending.subarray(frameLength)); pending.fill(0); pending = remaining;
    try { respond(host.submitLocal(request, opening)); }
    finally { opening.fill(0); request.fill(0); }
  }
}
process.on('message', message => {
  // IPC is a trusted controller channel. Proposal bytes cannot select commands.
  if (!message || typeof message !== 'object' || exiting) return;
  try {
    if (message.command === 'start' && host === null) {
      const config = Buffer.from(message.config, 'base64url');
      try { host = createLocalHost(config, { observerFd: 4, barrier,
        receiptObserverBytes: message.observer_binding === null || message.observer_binding === undefined ? null : Buffer.from(message.observer_binding, 'base64url'),
        receiptObserverFd: message.observer_binding ? 5 : null }); }
      finally { config.fill(0); }
      pulse=createPrefixPulseSource(()=>host.takeAcceptedEvent());
      proposal = new Socket({ fd: 3, readable: true, writable: true });
      proposal.on('data', onBytes);
      proposal.on('error', close);
      proposal.on('end', close);
      send({ type: 'ready', pid: process.pid });
    } else if (message.command === 'close') close();
    else if (!host) send({ type: 'control_error', id: message.id, reason_codes: ['MISSING_EVIDENCE'] });
    else if (message.command === 'take_pulse') {
      send({type:'control_result',id:message.id,result:pulse.take()});
    }
    else if (message.command === 'derive_child') send({type:'control_result',id:message.id,
      result:host.deriveChild(Buffer.from(message.restriction,'base64url'))});
    else if (message.command === 'prepare_child') send({type:'control_result',id:message.id,
      result:host.prepareChild(Buffer.from(message.handle,'base64url'),Buffer.from(message.proposal,'base64url'),Buffer.from(message.record,'base64url'))});
    else if (message.command === 'revoke_child') send({type:'control_result',id:message.id,
      result:host.revokeChild(Buffer.from(message.handle,'base64url'))});
    else if (message.command === 'submit_child') send({type:'control_result',id:message.id,
      result:host.submitChild(Buffer.from(message.handle,'base64url'),Buffer.from(message.request,'base64url'),Buffer.from(message.opening,'base64url'))});
    else if (message.command === 'read_receipt') send({ type: 'control_result', id: message.id,
      result: host.readReceipt(Buffer.from(message.query, 'base64url')) });
    else if (message.command === 'snapshot') send({ type: 'control_result', id: message.id, result: host.snapshot() });
    else if (message.command === 'admit_current') send({ type: 'control_result', id: message.id,
      result: host.admitCurrent(Buffer.from(message.event, 'base64url'), Buffer.from(message.expected_signers, 'base64url')) });
    else if (message.command === 'inspect') send({ type: 'control_result', id: message.id, result: host.inspect() });
    else if (message.command === 'advance_clock') send({ type: 'control_result', id: message.id, result: host.advanceClock(message.now) });
    else if (message.command === 'append_verified') send({ type: 'control_result', id: message.id,
      result: host.appendVerified(Buffer.from(message.event, 'base64url'), Buffer.from(message.expected_signers, 'base64url')) });
    else send({ type: 'control_error', id: message.id, reason_codes: ['WRONG_AUTHORITY'] });
  } catch (error) {
    // Never put key material, payload/salt, arbitrary thrown text or stacks on a
    // wire or log. W1/W2 codes are the only public diagnostics.
    const allowed = ['BAD_SIGNATURE', 'CLOSED_SCHEMA', 'MALFORMED_BYTES', 'MISSING_EVIDENCE', 'WRONG_AUTHORITY', 'WRONG_SIGNER',
      'ROLLBACK_UNRESOLVED', 'JOURNAL_CONFLICT', 'LIMIT_EXCEEDED', 'UNTRUSTED_TIME', 'STALE_CONTROL'];
    send({ type: host ? 'control_error' : 'startup_refused', id: message.id,
      reason_codes: [allowed.includes(error?.code) ? error.code : 'MISSING_EVIDENCE'] });
    if (!host) close();
  }
});
process.on('disconnect', close);
process.on('SIGTERM', close);
process.on('SIGINT', close);
