// SPDX-License-Identifier: AGPL-3.0-or-later
// Read source identities without exposing records or accepting partial heads.
import { createHash } from 'node:crypto'
import { constants as FS } from 'node:fs'
import { open } from 'node:fs/promises'
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
const KIRA_ABSENCES = new Set(['kira-ledger-missing', 'kira-ledger-empty', 'kira-ledger-unreadable',
  'kira-ledger-torn', 'kira-ledger-malformed', 'kira-ledger-broken', 'kira-ledger-unavailable',
  'kira-head-invalid', 'kira-ledger-head-invalid', 'kira-ledger-state-root-invalid'])
const BROWSER_MEMORY_REASONS = new Set(['kira.memory:aumlok-not-linked', 'kira.memory:aumlok-linked',
  'kira.memory:browser-binding-config', 'kira.memory:browser-binding-unreadable',
  'kira.memory:browser-overlay-unavailable', 'kira.memory:browser-identity-mismatch',
  'kira.memory:activation-failed'])

function absent(name: AuraSnapshotSource['name'], absence: string, entries: number | null = null): AuraSnapshotSource {
  return { name, head: null, entries, absence, ...(name === 'kira-chain' ? { browserMemory: null } : {}) }
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

/** Copy only validated head/count fields and fixed refusal names from the read-only service. */
export function kiraChainSource(value: unknown): AuraSnapshotSource {
  if (value === undefined) return absent('kira-chain', 'kira-service-unavailable')
  const { head, entries, absence, browserMemory } = (value ?? {}) as {
    head?: unknown, entries?: unknown, absence?: unknown, browserMemory?: unknown
  }
  const readiness = (() => {
    const state = browserMemory as { active?: unknown, reason?: unknown } | null
    if (state === null || state === undefined) return null
    const active = state.active, reason = state.reason
    return typeof active === 'boolean' && typeof reason === 'string' && BROWSER_MEMORY_REASONS.has(reason)
      && active === (reason === 'kira.memory:aumlok-linked') ? { active, reason } : null
  })()
  if (head === null && typeof absence === 'string' && KIRA_ABSENCES.has(absence)
    && (entries === null || entries === 0)) {
    return { ...absent('kira-chain', absence, entries), browserMemory: readiness }
  }
  if (absence !== null || typeof head !== 'string' || !HEX64.test(head)
    || !Number.isSafeInteger(entries) || (entries as number) < 1) {
    return { ...absent('kira-chain', 'kira-head-invalid'), browserMemory: readiness }
  }
  return { name: 'kira-chain', head, entries: entries as number, absence: null, browserMemory: readiness }
}

/** Read bounded regular files without following a record symlink or waiting on a FIFO. */
async function readReleaseFact(file: string): Promise<Buffer> {
  const handle = await open(file, FS.O_RDONLY | FS.O_NOFOLLOW | FS.O_NONBLOCK)
  try {
    const stat = await handle.stat()
    if (!stat.isFile() || stat.size > 32 * 1024 * 1024) throw Object.assign(new Error('code-record-unreadable'), { code: 'code-record-unreadable' })
    const bytes = Buffer.alloc(stat.size + 1)
    let offset = 0
    while (offset < bytes.length) {
      const read = await handle.read(bytes, offset, bytes.length - offset, null)
      if (read.bytesRead === 0) return bytes.subarray(0, offset)
      offset += read.bytesRead
    }
    throw Object.assign(new Error('code-record-unreadable'), { code: 'code-record-unreadable' })
  } finally { await handle.close() }
}

/** The code head is the exact RECORD digest, checked against the record beside this loaded face. */
export async function readCodeSource(releaseRoot: string): Promise<AuraSnapshotSource> {
  let manifestBytes: Buffer, recordBytes: Buffer
  try {
    manifestBytes = await readReleaseFact(join(releaseRoot, '.dsh-build/aukora-release.json'))
    recordBytes = await readReleaseFact(join(releaseRoot, '.dsh-build/genesis-artifacts.json'))
  } catch (error) {
    return absent('code-chain', (error as NodeJS.ErrnoException).code === 'ENOENT'
      ? 'code-record-missing' : 'code-record-unreadable')
  }
  let digest: unknown
  try {
    digest = (JSON.parse(manifestBytes.toString('utf8')) as { record?: { sha256?: unknown } } | null)?.record?.sha256
    const record = JSON.parse(recordBytes.toString('utf8')) as { formatVersion?: unknown, kind?: unknown } | null
    if (typeof digest !== 'string' || !HEX64.test(digest)
      || record?.formatVersion !== 1 || record.kind !== 'genesis-artifact-record') {
      return absent('code-chain', 'code-record-invalid')
    }
  } catch { return absent('code-chain', 'code-record-invalid') }
  if (createHash('sha256').update(recordBytes).digest('hex') !== digest) {
    return absent('code-chain', 'code-record-mismatch')
  }
  return { name: 'code-chain', head: digest as string, entries: 1, absence: null }
}

/** Match the composition's gateSocket option; an invalid explicit socket is never replaced with the default. */
export function snapshotGateSocket(config: { gateSocket?: unknown }, env: NodeJS.ProcessEnv = process.env): string | null {
  const socket = config.gateSocket === undefined ? env['AUKORA_GATE_SOCKET'] ?? DEFAULT_GATE_SOCKET : config.gateSocket
  return typeof socket === 'string' && socket.length <= 1024 && isAbsolute(socket)
    && normalize(socket) === socket && !/[\u0000-\u001f\u007f]/u.test(socket) ? socket : null
}

/** The carried Buzz transport allows log; only its verify result leaves this reader. */
export async function readAuraSnapshot(releaseRoot: string, socket: string | null, readKira?: () => unknown): Promise<AuraSnapshot> {
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
  let kira = absent('kira-chain', 'kira-ledger-unreadable')
  try { kira = kiraChainSource(await readKira?.()) } catch { /* Never forward service errors or private data. */ }
  return makeAuraSnapshot([gate, kira, await readCodeSource(releaseRoot)])
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
