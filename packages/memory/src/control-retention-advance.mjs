// SPDX-License-Identifier: AGPL-3.0-or-later
import { canonicalJSON } from '../genesis/plugins/aukora-kira/lib/record.mjs'
import { requireMemory } from './codecs.mjs'
import { MEMORY_CONTROL_TABLES, inspectMemoryControlState } from './control-state.mjs'

const RETAINED_TABLES = ['purges', 'requests', 'tombstones', 'redactions', 'replay_fences']
const FENCE_BINDING = ['owner_subject', 'operation_id', 'operation_digest', 'grant_id', 'action', 'request_id', 'request_digest']
const rowKey = (row, name) => canonicalJSON(MEMORY_CONTROL_TABLES[name].key.map(column => row[column]))
const rowsByKey = (rows, name) => new Map(rows.map(row => [rowKey(row, name), row]))
const sameRow = (left, right, name) => right !== undefined && MEMORY_CONTROL_TABLES[name].columns.every(column =>
  MEMORY_CONTROL_TABLES[name].byteColumns.includes(column) ? left[column].equals(right[column]) : left[column] === right[column])
const matchingFence = (effect, fence) => fence !== undefined && FENCE_BINDING.every(column => effect[column] === fence[column])

/**
 * Check retained-control continuity only; return no authority, grant or restore permission.
 * Both bundles must already be complete owner-bound control-state/v1 representations.
 * Changed head hashes are allowed for the trusted publisher of live D source state. This
 * check does not prove a chain prefix, authenticate that publisher or permit bootstrap.
 */
export function assertMemoryControlAdvance(previousBundle, nextBundle, host, {contracts} = {}) {
  const previous = inspectMemoryControlState(previousBundle, host, {contracts})
  const next = inspectMemoryControlState(nextBundle, host, {contracts})
  for (const domain of Object.keys(previous.heads)) requireMemory(Object.hasOwn(next.heads, domain),
    'memory:control-advance-head-missing')
  const headsChanged = canonicalJSON(previous.heads) !== canonicalJSON(next.heads)

  for (const name of RETAINED_TABLES) {
    const nextRows = rowsByKey(next.tables[name], name)
    for (const row of previous.tables[name]) requireMemory(sameRow(row, nextRows.get(rowKey(row, name)), name),
      'memory:control-advance-retained-row-changed')
  }

  const nextControls = rowsByKey(next.tables.controls, 'controls')
  for (const row of previous.tables.controls) {
    const retained = nextControls.get(rowKey(row, 'controls'))
    requireMemory(retained !== undefined, 'memory:control-advance-control-scope-missing')
    requireMemory(headsChanged || sameRow(row, retained, 'controls'), 'memory:control-advance-control-without-head-change')
  }

  const previousEffects = rowsByKey(previous.tables.effects, 'effects')
  const nextIntents = rowsByKey(next.tables.intents, 'intents')
  const nextEffects = rowsByKey(next.tables.effects, 'effects')
  const nextFences = rowsByKey(next.tables.replay_fences, 'replay_fences')
  for (const intent of previous.tables.intents) {
    const key = rowKey(intent, 'intents'), retained = nextIntents.get(key), effect = previousEffects.get(key)
    if (retained !== undefined) requireMemory(sameRow(intent, retained, 'intents'), 'memory:control-advance-intent-changed')
    else {
      // A newly claimed fence cannot close an intent with no previously retained effect.
      requireMemory(effect !== undefined, 'memory:control-advance-unresolved-intent-missing')
      requireMemory(matchingFence(effect, nextFences.get(key)), 'memory:control-advance-intent-fence-missing')
    }
  }
  for (const effect of previous.tables.effects) {
    const key = rowKey(effect, 'effects'), retained = nextEffects.get(key)
    requireMemory(retained !== undefined ? sameRow(effect, retained, 'effects') : matchingFence(effect, nextFences.get(key)),
      'memory:control-advance-effect-changed')
  }
}
