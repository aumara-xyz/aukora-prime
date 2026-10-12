// SPDX-License-Identifier: AGPL-3.0-or-later
// Read gate ledger identity without appending records or guessing unexposed source heads.
import { isAbsolute, join, normalize } from 'node:path'
import type { IncomingMessage, ServerResponse } from 'node:http'
import { makeAuraSnapshot } from './snapshot.ts'
import type { AuraSnapshot, AuraSnapshotSource } from './snapshot.ts'

export const AURA_SNAPSHOT_ENDPOINT = '/api/aukora/aura-snapshot'
const CACHE_MS = 1500
const SOCKET_TIMEOUT_MS = 3000
const HEX64 = /^[0-9a-f]{64}$/u
const DEFAULT_GATE_SOCKET = '/run/aukora-gate/gate.sock'

interface RouteGate {
  requestRejection(request: { readonly headers: IncomingMessage['headers'] }): 401 | 403 | undefined
}

type GateCall = (socket: string, op: string, args: object, timeout: number) => Promise<unknown>

function absent(name: AuraSnapshotSource['name'], absence: string, entries: number | null = null): AuraSnapshotSource {
  return { name, head: null, entries, absence }
}

/** A failed verification never contributes a head to the snapshot. */
export function gateLedgerSource(value: unknown): AuraSnapshotSource {
  const verified = value as { ok?: unknown, entries?: unknown, head?: unknown } | null
  if (verified?.ok !== true) return absent('gate-ledger', 'gate-ledger-unverified')
  if (verified.entries === 0 && verified.head === 'GENESIS') return absent('gate-ledger', 'gate-ledger-empty', 0)
  if (!Number.isSafeInteger(verified.entries) || (verified.entries as number) < 1
    || typeof verified.head !== 'string' || !HEX64.test(verified.head)) {
    return absent('gate-ledger', 'gate-ledger-invalid')
  }
  return { name: 'gate-ledger', head: verified.head, entries: verified.entries as number, absence: null }
}

/** Match the composition's gateSocket option; an invalid explicit socket is never replaced with the default. */
export function snapshotGateSocket(config: { gateSocket?: unknown }, env: NodeJS.ProcessEnv = process.env): string | null {
  const socket = config.gateSocket === undefined ? env['AUKORA_GATE_SOCKET'] ?? DEFAULT_GATE_SOCKET : config.gateSocket
  return typeof socket === 'string' && socket.length <= 1024 && isAbsolute(socket)
    && normalize(socket) === socket && !/[\u0000-\u001f\u007f]/u.test(socket) ? socket : null
}

/** The carried Buzz transport allows log; only its verify result leaves this reader. */
export async function readAuraSnapshot(releaseRoot: string, socket: string | null): Promise<AuraSnapshot> {
  let gate = absent('gate-ledger', socket === null ? 'gate-socket-invalid' : 'gate-ledger-unavailable')
  if (socket !== null) {
    try {
      const client = await import(join(releaseRoot, 'plugins/aukora-buzz-door/lib/index.mjs')) as { gateCall?: GateCall }
      if (typeof client.gateCall !== 'function') gate = absent('gate-ledger', 'gate-client-not-carried')
      else {
        const response = await client.gateCall(socket, 'log', { limit: 1 }, SOCKET_TIMEOUT_MS) as { verify?: unknown } | null
        gate = gateLedgerSource(response?.verify)
      }
    } catch { /* Unavailable is explicit; errors and private paths do not leave the route. */ }
  }
  return makeAuraSnapshot([gate,
    absent('kira-chain', 'kira-head-not-exposed'),
    absent('code-chain', 'code-head-not-exposed')])
}

/** Concurrent windows share one in-flight read and at most one verification per cache interval. */
export function createAuraSnapshotReader(read: () => Promise<AuraSnapshot>, now: () => number = Date.now): () => Promise<AuraSnapshot> {
  let cached: Promise<AuraSnapshot> | undefined
  let expires = 0
  let reading = false
  return () => {
    if (cached !== undefined && (reading || now() < expires)) return cached
    reading = true
    cached = read().finally(() => { reading = false; expires = now() + CACHE_MS })
    return cached
  }
}

/** Authenticate before reading; the route accepts only GET and caches no response. */
export function auraSnapshotHandler(connection: () => RouteGate | undefined, read: () => Promise<AuraSnapshot>) {
  return async (req: IncomingMessage, res: ServerResponse): Promise<void> => {
    const gate = connection()
    const rejection = typeof gate?.requestRejection === 'function' ? gate.requestRejection(req) : 403
    if (rejection !== undefined) {
      res.writeHead(rejection, { 'cache-control': 'no-store' })
      res.end()
      return
    }
    if (req.method !== 'GET') {
      res.writeHead(405, { allow: 'GET', 'cache-control': 'no-store' })
      res.end()
      return
    }
    const snapshot = await read()
    res.writeHead(200, {
      'cache-control': 'no-store',
      'content-type': 'application/json; charset=utf-8',
      'x-content-type-options': 'nosniff',
    })
    res.end(JSON.stringify(snapshot))
  }
}
