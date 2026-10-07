import { writeSync } from 'node:fs';

export const BARRIER_NAMES = Object.freeze([
  'before_atomic_commit',
  'after_consume_intent_durable',
  'after_dispatch_marker_durable',
  'after_sink_entry',
]);

// Trusted startup settings only. No closure, barrier command, path, hook, or
// callback is accepted from proposal bytes. SIGSTOP is synchronous; the holder
// retains the writer lock. Controller can SIGKILL or SIGCONT this real process.
export function createTestBarriers({ name = null, observerFd = 4 } = {}) {
  if (name !== null && !BARRIER_NAMES.includes(name)) throw new TypeError('unknown test barrier');
  if (!Number.isSafeInteger(observerFd) || observerFd < 3) throw new TypeError('observer fd required');
  let fired = false;
  const notice = value => {
    const line = Buffer.from(JSON.stringify(value) + '\n');
    let offset = 0;
    while (offset < line.length) offset += writeSync(observerFd, line, offset);
  };
  return Object.freeze({
    intentSigned(operationId) { notice({ type: 'intent_signed', operation_id: operationId }); },
    reach(point, operationId) {
      if (fired || name !== point) return;
      fired = true;
      notice({ type: 'barrier', name: point, operation_id: operationId });
      process.kill(process.pid, 'SIGSTOP');
    },
  });
}
