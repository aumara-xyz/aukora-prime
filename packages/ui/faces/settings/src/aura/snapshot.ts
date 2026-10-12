// SPDX-License-Identifier: AGPL-3.0-or-later
// Hash the fixed ordered source heads, including explicit absence.
import { createHash } from 'node:crypto'

export const AURA_SNAPSHOT_SCHEMA = 'aukora-face/aura-snapshot:v1'
export const AURA_SNAPSHOT_SOURCES = ['gate-ledger', 'kira-chain', 'code-chain'] as const
const DOMAIN = 'aukora.aura.snapshot.v1\0'
const HEX64 = /^[0-9a-f]{64}$/u

export interface AuraSnapshotSource {
  name: typeof AURA_SNAPSHOT_SOURCES[number]
  head: string | null
  entries: number | null
  absence: string | null
}

export interface AuraSnapshot {
  schema: typeof AURA_SNAPSHOT_SCHEMA
  head: string
  sources: AuraSnapshotSource[]
}

function refuse(code: string): never {
  throw Object.assign(new TypeError(code), { code })
}

function lengthPrefixed(bytes: Uint8Array): Buffer {
  const length = Buffer.alloc(4)
  length.writeUInt32BE(bytes.length)
  return Buffer.concat([length, bytes])
}

/** Absence has a zero-length head; diagnostic counts and reasons do not change record identity. */
export function makeAuraSnapshot(input: readonly AuraSnapshotSource[]): AuraSnapshot {
  if (!Array.isArray(input) || input.length !== AURA_SNAPSHOT_SOURCES.length
    || AURA_SNAPSHOT_SOURCES.some(name => input.filter(source => source?.name === name).length !== 1)) {
    refuse('aura-snapshot:source-set-invalid')
  }
  const sources = AURA_SNAPSHOT_SOURCES.map(name => {
    const source = input.find(candidate => candidate.name === name)!
    if (source.head !== null && (typeof source.head !== 'string' || !HEX64.test(source.head))) {
      refuse('aura-snapshot:head-invalid')
    }
    if (source.entries !== null && (!Number.isSafeInteger(source.entries) || source.entries < 0)) {
      refuse('aura-snapshot:entries-invalid')
    }
    if (source.head === null
      ? (source.entries !== null && source.entries !== 0) || typeof source.absence !== 'string' || source.absence.length === 0
      : source.absence !== null || source.entries === null || source.entries < 1) {
      refuse('aura-snapshot:availability-invalid')
    }
    return { name, head: source.head, entries: source.entries, absence: source.absence }
  })
  const hash = createHash('sha256').update(DOMAIN, 'utf8')
  for (const source of sources) {
    hash.update(lengthPrefixed(Buffer.from(source.name, 'utf8')))
    hash.update(lengthPrefixed(source.head === null ? Buffer.alloc(0) : Buffer.from(source.head, 'hex')))
  }
  return { schema: AURA_SNAPSHOT_SCHEMA, head: hash.digest('hex'), sources }
}
