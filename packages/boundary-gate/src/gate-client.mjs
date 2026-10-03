// Harness-side client of the gate's PROPOSE socket. It deliberately has no approve function: the harness can
// read, propose, revert (as a new proposal), read history/state/log and close (reject/cancel) its own popup.
// Every failure is fail-closed. `gateProbes` are the self-check probes that MUST fail from the harness user.
import net from 'node:net'
import { call } from './server.mjs'
import { resolveLayout } from './layout.mjs'

export function gateClient(layout = resolveLayout(), timeoutMs = 15000) {
  const c = (op, args) => call(layout.proposeSocket, op, args, timeoutMs)
  return Object.freeze({
    ping: () => c('ping', {}),
    targets: () => c('targets', {}),
    read: (target) => c('read', { target }),
    propose: ({ target, content, why, base_sha256, session, call_id }) => c('propose', { target, content, why, claimed_base: base_sha256, session, call_id }),
    revert: ({ target, to_sha256 = 'previous', why, session, call_id }) => c('revert', { target, to_sha: to_sha256, why, session, call_id }),
    history: (target) => c('history', { target }),
    state: (id) => c('state', { id }),
    reject: (id) => c('close', { id, outcome: 'rejected' }),
    cancel: (id) => c('close', { id, outcome: 'cancelled' }),
    log: (limit, target) => c('log', { limit, target }),
    verify: () => c('verify', {}),
    harnessStart: (pid) => c('harness_start', { pid }),
    selfcheck: (result) => c('selfcheck', { result }),
  })
}

// Each probe resolves only if the forbidden action SUCCEEDED (see selfcheck.mjs extraProbes).
export function gateProbes(layout = resolveLayout()) {
  return [
    ['connect gate owner socket (approve channel)', () => new Promise((res, rej) => { const s = net.createConnection(layout.ownerSocket); s.on('connect', () => { s.destroy(); res() }); s.on('error', rej) })],
    ['approve on the propose socket', () => call(layout.proposeSocket, 'approve', { id: 'selfcheck' })],
    ['approving close on the propose socket', () => call(layout.proposeSocket, 'close', { id: 'selfcheck', outcome: 'allowed-once' })],
  ]
}
