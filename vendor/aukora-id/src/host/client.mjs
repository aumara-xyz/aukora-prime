import { fork } from 'node:child_process';
import { EventEmitter } from 'node:events';
import { fileURLToPath } from 'node:url';
import { snapshotBytes } from '../bytes/index.mjs';
import { BARRIER_NAMES } from './barriers.mjs';
import { startReceiptObserver } from '../observer/client.mjs';
import { trustedBytes } from '../aperture/local-profile.mjs';

export const serviceEntryPoint = fileURLToPath(new URL('./service.mjs', import.meta.url));

// Trusted test controller. Return only proposal.submitLocal to a proposal
// producer; process/control/notices are controller capabilities, not proposals.
export async function startLocalService({ configBytes, observerConfigBytes = null, barrier = null, execArgv = [] }) {
  if (barrier !== null && !BARRIER_NAMES.includes(barrier)) throw new TypeError('unknown test barrier');
  const config = snapshotBytes(configBytes);
  let receiptObserver;
  try { receiptObserver = observerConfigBytes === null ? null : await startReceiptObserver({ configBytes: observerConfigBytes, execArgv }); }
  catch (error) { config.fill(0); throw error; }
  let child;
  try { child = fork(serviceEntryPoint, barrier ? [barrier] : [], {
    execArgv, serialization: 'advanced', stdio: ['ignore', 'pipe', 'pipe', 'pipe', 'pipe', ...(receiptObserver ? [receiptObserver.stream] : []), 'ipc'],
    // No network/server address, key file, or user script is launched here.
  }); } catch (error) { config.fill(0); await receiptObserver?.close(); throw error; }
  // fork duplicated the endpoint into host fd5. The controller cannot consume
  // observation replies after handing off its copy.
  receiptObserver?.stream.destroy();
  const notices = new EventEmitter();
  const pending = [], controls = new Map();
  let nextId = 0, responseBuffer = '', noticeBuffer = '', finished = false, stoppedAtBarrier = false;
  let resolveExit;
  const exited = new Promise(resolve => { resolveExit = resolve; });
  const rejectOutstanding = error => {
    while (pending.length) pending.shift().reject(error);
    for (const deferred of controls.values()) deferred.reject(error);
    controls.clear();
  };
  child.once('exit', (code, signal) => {
    finished = true; rejectOutstanding(new Error('LOCAL service exited'));
    receiptObserver?.close();
    resolveExit({ code, signal }); notices.emit('exit', { code, signal });
  });
  child.on('error', error => rejectOutstanding(error));
  child.stdio[3].on('error', error => rejectOutstanding(error));
  child.stdio[3].setEncoding('utf8');
  child.stdio[3].on('data', chunk => {
    responseBuffer += chunk;
    let newline;
    while ((newline = responseBuffer.indexOf('\n')) >= 0) {
      const line = responseBuffer.slice(0, newline); responseBuffer = responseBuffer.slice(newline + 1);
      const waiting = pending.shift();
      if (!waiting) continue;
      try { stoppedAtBarrier = false; waiting.resolve(JSON.parse(line)); } catch { waiting.reject(new Error('invalid service response')); }
    }
  });
  child.stdio[4].setEncoding('utf8');
  child.stdio[4].on('data', chunk => {
    noticeBuffer += chunk;
    let newline;
    while ((newline = noticeBuffer.indexOf('\n')) >= 0) {
      const line = noticeBuffer.slice(0, newline); noticeBuffer = noticeBuffer.slice(newline + 1);
      try { const notice = JSON.parse(line); if (notice.type === 'barrier') stoppedAtBarrier = true; notices.emit('notice', notice); notices.emit(notice.type, notice); }
      catch { notices.emit('protocol_error'); }
    }
  });
  child.on('message', message => {
    const waiting = controls.get(message.id);
    if (!waiting) return;
    controls.delete(message.id);
    if (message.type === 'control_result') waiting.resolve(message.result);
    else waiting.reject(Object.assign(new Error('LOCAL control refused'), { reason_codes: message.reason_codes }));
  });
  const ready = new Promise((resolve, reject) => {
    const onExit = () => { cleanup(); reject(new Error('LOCAL service did not start')); };
    const onMessage = message => {
      if (message.type === 'ready') { cleanup(); resolve(); }
      else if (message.type === 'startup_refused') {
        cleanup(); reject(Object.assign(new Error('LOCAL startup refused'), { reason_codes: message.reason_codes }));
      }
    };
    const timer = setTimeout(() => { cleanup(); child.kill('SIGKILL'); reject(new Error('LOCAL startup timed out')); }, 10000);
    const cleanup = () => { clearTimeout(timer); child.off('message', onMessage); child.off('exit', onExit); };
    child.on('message', onMessage); child.once('exit', onExit);
  });
  child.send({ command: 'start', config: Buffer.from(config).toString('base64url'),
    observer_binding: receiptObserver ? trustedBytes(receiptObserver.binding).toString('base64url') : null }); config.fill(0);
  try { await ready; } catch (error) { child.kill('SIGKILL'); await exited; await receiptObserver?.close(); throw error; }
  const control = (command, data = {}) => new Promise((resolve, reject) => {
    if (finished) return reject(new Error('LOCAL service closed'));
    const id = ++nextId;
    controls.set(id, { resolve, reject });
    child.send({ command, id, ...data }, error => {
      if (error) { controls.delete(id); reject(error); }
    });
  });
  return Object.freeze({
    process: child, notices, exited,
    observer: receiptObserver ? Object.freeze({ process: receiptObserver.process, notices: receiptObserver.notices, exited: receiptObserver.exited }) : null,
    proposal: Object.freeze({
      submitLocal(requestEventBytes, payloadEvidenceBytes) {
        const request = snapshotBytes(requestEventBytes), opening = snapshotBytes(payloadEvidenceBytes, 1024);
        if (finished) return Promise.reject(new Error('LOCAL service closed'));
        if (pending.length >= 256) return Promise.reject(new Error('LOCAL proposal queue full'));
        const header = Buffer.alloc(8); header.writeUInt32BE(request.length, 0); header.writeUInt32BE(opening.length, 4);
        const frame = Buffer.concat([header, request, opening]); opening.fill(0);
        return new Promise((resolve, reject) => {
          pending.push({ resolve, reject });
          child.stdio[3].write(frame, error => {
            frame.fill(0);
            if (error) rejectOutstanding(error);
          });
        });
      },
    }),
    deriveChild: restrictionBytes => control('derive_child', {
      restriction:Buffer.from(snapshotBytes(restrictionBytes,2048)).toString('base64url'),
    }),
    prepareChild: (handleBytes,proposalBytes,requestRecordBytes) => control('prepare_child', {
      handle:Buffer.from(snapshotBytes(handleBytes,256)).toString('base64url'),
      proposal:Buffer.from(snapshotBytes(proposalBytes,2048)).toString('base64url'),
      record:Buffer.from(snapshotBytes(requestRecordBytes)).toString('base64url'),
    }),
    revokeChild: handleBytes => control('revoke_child', {handle:Buffer.from(snapshotBytes(handleBytes,256)).toString('base64url')}),
    childProposal(handleBytes) {
      // Bind once in trusted controller construction. Give only this endpoint
      // to the child bridge; never the service or lifecycle controller itself.
      const handle=Buffer.from(snapshotBytes(handleBytes,256)).toString('base64url');
      let pending=false;
      return Object.freeze({submitLocal(requestBytes,openingBytes) {
        if(pending)return Promise.reject(new Error('LOCAL child proposal already pending'));
        const request=Buffer.from(snapshotBytes(requestBytes)).toString('base64url');
        const opening=Buffer.from(snapshotBytes(openingBytes,1024)).toString('base64url');
        pending=true;
        return control('submit_child',{handle,request,opening}).finally(()=>{pending=false;});
      }});
    },
    readReceipt: queryBytes => control('read_receipt', { query: Buffer.from(snapshotBytes(queryBytes,256)).toString('base64url') }),
    inspect: () => control('inspect'),
    takePulse: () => control('take_pulse'),
    snapshot: () => control('snapshot'),
    admitCurrent: (eventBytes, signersBytes) => control('admit_current', {
      event: Buffer.from(snapshotBytes(eventBytes)).toString('base64url'),
      expected_signers: Buffer.from(snapshotBytes(signersBytes)).toString('base64url'),
    }),
    advanceClock: now => control('advance_clock', { now }),
    appendVerified: (eventBytes, signersBytes) => control('append_verified', {
      event: Buffer.from(snapshotBytes(eventBytes)).toString('base64url'),
      expected_signers: Buffer.from(snapshotBytes(signersBytes)).toString('base64url'),
    }),
    async close() {
      if (finished) { await receiptObserver?.close(); return exited; }
      // Closing a halted fault test must not resume its pending dispatch.
      if (stoppedAtBarrier) { child.kill('SIGKILL'); const result = await exited; await receiptObserver?.close(); return result; }
      child.send({ command: 'close' }); child.stdio[3].end();
      const timeout = setTimeout(() => child.kill('SIGKILL'), 3000);
      const result = await exited; clearTimeout(timeout); await receiptObserver?.close(); return result;
    },
  });
}
