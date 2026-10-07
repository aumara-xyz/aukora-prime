import { fork } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { snapshotBytes } from '../bytes/index.mjs';
import { MAX_EVENT, MAX_EVIDENCE } from './framing.mjs';
import { createEvidenceReceiver } from './receiver.mjs';

export { createEvidenceReceiver, DATA_KINDS } from './receiver.mjs';
export const transportEntryPoint = fileURLToPath(new URL('./process.mjs', import.meta.url));

// Trusted LOCAL test controller, not a capability given to an untrusted plugin.
// Exactly two transport processes connected by inherited anonymous pipes through
// this controller; no endpoint allocation and no public NIP-01 relay service.
export async function startLocalTransportPair({ leftContextsBytes, rightContextsBytes, execArgv = [] }) {
  const contexts = [leftContextsBytes, rightContextsBytes].map(bytes => Buffer.from(snapshotBytes(bytes)));
  contexts.forEach(createEvidenceReceiver); // Validate before acquiring resources.
  const children = [], exits = [], pending = [null, null];
  let closed = false;
  const rejectPending = error => {
    for (let i = 0; i < 2; i++) {
      if (pending[i]) { clearTimeout(pending[i].timer); pending[i].reject(error); pending[i] = null; }
    }
  };
  const stop = () => {
    if (closed) return;
    closed = true; rejectPending(new Error('LOCAL transport closed; no automatic resend'));
    for (const child of children) { child.stdio[3]?.destroy(); child.stdio[4]?.destroy(); child.kill('SIGTERM'); }
  };
  try {
    const readiness = [];
    for (let i = 0; i < 2; i++) {
      const child = fork(transportEntryPoint, [], { execArgv, serialization: 'advanced',
        stdio: ['ignore', 'ignore', 'ignore', 'pipe', 'pipe', 'ipc'],
        // Do not inherit tokens, NODE_OPTIONS, credentials or loader environment.
        env: {}, cwd: fileURLToPath(new URL('.', import.meta.url)),
      });
      children.push(child);
      exits.push(new Promise(resolve => {
        child.once('exit', (code, signal) => { resolve({ pid: child.pid, code, signal }); stop(); });
        child.once('error', () => { resolve({ pid: child.pid ?? null, code: null, signal: null }); stop(); });
      }));
      child.stdio[3].on('error', stop); child.stdio[4].on('error', stop);
      readiness.push(new Promise((resolve, reject) => {
        const timer = setTimeout(() => { reject(new Error('LOCAL transport startup timed out')); stop(); }, 10000);
        const onExit = () => { clearTimeout(timer); reject(new Error('LOCAL transport startup failed')); };
        child.once('exit', onExit); child.once('error', onExit);
        child.on('message', message => {
          if (message.type === 'ready') { clearTimeout(timer); child.off('exit', onExit); child.off('error', onExit); resolve(); }
          else if (message.type === 'transport_error') {
            clearTimeout(timer); const error = Object.assign(new Error('LOCAL transport refused'), { code: message.code });
            reject(error); rejectPending(error); stop();
          } else if (message.type === 'delivery') {
            const waiting = pending[1 - i];
            if (!waiting) { stop(); return; }
            pending[1 - i] = null; clearTimeout(waiting.timer);
            waiting.resolve({ ...message.result, receiver_pid: message.receiver_pid });
          }
        });
      }));
    }
    children[0].stdio[4].pipe(children[1].stdio[3]);
    children[1].stdio[4].pipe(children[0].stdio[3]);
    for (let i = 0; i < 2; i++) children[i].send({ command: 'start', contexts: contexts[i] }, error => { if (error) stop(); });
    await Promise.all(readiness);
  } catch (error) { stop(); await Promise.all(exits); throw error; }
  return Object.freeze({
    processes: Object.freeze([...children]), exited: Promise.all(exits),
    transfer(from, eventBytes, evidenceBytes) {
      if (from !== 'left' && from !== 'right') throw new TypeError('expected left or right');
      const i = from === 'left' ? 0 : 1;
      const event = snapshotBytes(eventBytes, MAX_EVENT), evidence = snapshotBytes(evidenceBytes, MAX_EVIDENCE);
      if (closed) return Promise.reject(new Error('LOCAL transport closed'));
      if (pending[i]) return Promise.reject(new Error('one transfer per direction at a time'));
      return new Promise((resolve, reject) => {
        const timer = setTimeout(() => { rejectPending(new Error('LOCAL transfer timed out; no resend')); stop(); }, 15000);
        pending[i] = { resolve, reject, timer };
        children[i].send({ command: 'publish', event, evidence }, error => { if (error) { rejectPending(error); stop(); } });
      });
    },
    async close() {
      stop();
      const timer = setTimeout(() => { for (const child of children) if (child.exitCode === null) child.kill('SIGKILL'); }, 2000);
      try { return await Promise.all(exits); } finally { clearTimeout(timer); }
    },
  });
}
