// SPDX-License-Identifier: AGPL-3.0-or-later
/** Accept named head observations and count only observed entry advances. */
export interface AuraSnapshotSource {
  name: string
  head: string | null
  entries: number | null
  absence: string | null
}
export interface AuraSnapshot {
  schema: 'aukora-face/aura-snapshot:v1'
  head: string
  sources: AuraSnapshotSource[]
}
export interface AuraSourceAdvance {
  source: string
  head: string
  entries: number
  observedAt: number
}
const NAMES = ['gate-ledger', 'kira-chain', 'code-chain']
const HEAD = /^[0-9a-f]{64}$/u
function refuse(code: string): never {
  throw Object.assign(new TypeError(code), { code })
}
function object(value: unknown): Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) refuse('aura-snapshot:format')
  return value as Record<string, unknown>
}
export function parseAuraSnapshot(value: unknown): AuraSnapshot {
  const row = object(value)
  if (row.schema !== 'aukora-face/aura-snapshot:v1' || typeof row.head !== 'string' || !HEAD.test(row.head)
    || !Array.isArray(row.sources) || row.sources.length !== NAMES.length) refuse('aura-snapshot:format')
  const sources = row.sources.map((value: unknown, index: number) => {
    const source = object(value)
    if (source.name !== NAMES[index]) refuse('aura-snapshot:source-order')
    if (source.head === null) {
      if ((source.entries !== null && source.entries !== 0)
        || typeof source.absence !== 'string' || !source.absence) refuse('aura-snapshot:absence')
    } else if (typeof source.head !== 'string' || !HEAD.test(source.head) || source.absence !== null
      || !Number.isSafeInteger(source.entries) || (source.entries as number) < 1) refuse('aura-snapshot:source-head')
    return { name: source.name as string, head: source.head as string | null,
      entries: source.entries as number | null, absence: source.absence as string | null }
  })
  return { schema: 'aukora-face/aura-snapshot:v1', head: row.head, sources }
}
export function advanceSourceEntries(previous: ReadonlyMap<string, number>, sources: readonly AuraSnapshotSource[]) {
  const counters = new Map(previous)
  let entries = 0
  for (const source of sources) {
    if (source.entries === null) continue
    const before = counters.get(source.name)
    if (before !== undefined) entries += Math.max(0, source.entries - before)
    counters.set(source.name, Math.max(before ?? source.entries, source.entries))
  }
  return { counters, entries }
}

/** Record only non-initial source heads that this screen observed changing. */
export function observeSourceAdvances(previous: ReadonlyMap<string, string | null>,
  sources: readonly AuraSnapshotSource[], observedAt: number) {
  const heads = new Map(previous)
  const advances: AuraSourceAdvance[] = []
  for (const source of sources) {
    const seen = heads.has(source.name)
    const before = heads.get(source.name)
    if (seen && source.head !== null && source.head !== before) {
      advances.push({ source: source.name, head: source.head, entries: source.entries ?? 0, observedAt })
    }
    heads.set(source.name, source.head)
  }
  return { heads, advances }
}
