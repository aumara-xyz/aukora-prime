import { fork } from 'node:child_process';
import { EventEmitter } from 'node:events';
import { fileURLToPath } from 'node:url';
import { snapshotBytes } from '../bytes/index.mjs';

// Trusted controller helper. Only the duplex stream is inherited by the host;
// the observer's separate startup IPC carries its disposable secret key.
export async function startReceiptObserver({ configBytes, execArgv = [] }) {
  const config = snapshotBytes(configBytes);
  const child = fork(fileURLToPath(new URL('./service.mjs', import.meta.url)), [], {
    execArgv, stdio: ['ignore', 'pipe', 'pipe', 'pipe', 'ipc'], serialization: 'advanced' });
  const notices = new EventEmitter();
  let stopped = false, closing = null;
  const exited = new Promise(resolve => child.once('exit', (code, signal) => { stopped = true; resolve({ code, signal }); }));
  child.on('message', message => notices.emit('notice', message));
  child.stdio[3].on('error', () => { /* Host exchange fails closed on pipe errors. */ });
  const ready = new Promise((resolve, reject) => {
    const cleanup = () => { clearTimeout(timer); child.off('message', message); child.off('exit', failed); child.off('error', failed); };
    const failed = () => { cleanup(); reject(new Error('LOCAL observer unavailable')); };
    const message = value => {
      if (value?.type === 'ready') { cleanup(); resolve(value.binding); }
      else if (value?.type === 'startup_refused') failed();
    };
    const timer = setTimeout(failed, 10000);
    child.on('message', message); child.once('exit', failed); child.once('error', failed);
  });
  child.send({ command: 'start', config: Buffer.from(config).toString('base64url') }); config.fill(0);
  let binding;
  try { binding = await ready; }
  catch (error) { child.kill('SIGKILL'); await exited; throw error; }
  return Object.freeze({ process: child, stream: child.stdio[3], binding, notices, exited,
    close() {
      if (closing) return closing;
      closing = (async () => {
        if (stopped) return exited;
        if (child.connected) child.send({ command: 'close' }, () => {});
        const timer = setTimeout(() => child.kill('SIGKILL'), 1000);
        const result = await exited; clearTimeout(timer); return result;
      })();
      return closing;
    } });
}
