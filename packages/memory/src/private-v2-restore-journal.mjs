// SPDX-License-Identifier: AGPL-3.0-or-later
// D-owned ordered query scope for Bridge restoreRetainedJournal at checkpoint
// 9b43424778db7d7089ea0f6cfdb1d5dc54136db6. The existing nine owned SQL templates
// remain unchanged. Root supplies the actual protected, chronological ancestor
// interval under the genuine owner session; this scope grants no C permission.
import { types } from 'node:util'
import { canonicalJSON } from '../genesis/plugins/aukora-kira/lib/record.mjs'
import { MAX_BYTES, parseOriginal, requireMemory } from './codecs.mjs'
import { privateV2Detach, privateV2Fields } from './private-v2-coordinator.mjs'
import { assertPrivateHost, assertPrivateProfile, assertWorkflowRow, assertProgressV2,
  PRIVATE_WORKFLOW_FIELDS, progressDigest, decodeControlV3, assertForwardControlV3 } from './private-v2-control.mjs'
import { RETAINED_JOURNAL_DESCRIPTORS, isPrivateV2JournalStatement } from './private-v2-journal-statements.mjs'
import { isPrivateV2OwnerClient } from './private-v2-participant.mjs'

const check = (ok, reason) => requireMemory(ok, 'memory:private-v2-restore-journal-' + reason)
const same = (a, b) => canonicalJSON(a) === canonicalJSON(b)
const PROGRESS_FIELDS = ['owner_subject','owner_id','task_id','operation_id','progress_bytes','progress_digest']
const MUTABLE_FIELDS = ['record_id','phase','request_id','request_digest','receipt_digest']
const compare = (a, b) => Buffer.compare(Buffer.from(a.operation_id), Buffer.from(b.operation_id))
const ownerFields = ['owner_subject','owner_id','task_id','operation_id']
const own = (o, key) => {
  const d = Object.getOwnPropertyDescriptor(o, key)
  check(d && Object.hasOwn(d, 'value'), 'inert-value-required')
  return d.value
}
function nativeBuffer(value) {
  check(value && typeof value === 'object' && !types.isProxy(value) && types.isUint8Array(value) && Buffer.isBuffer(value)
    && Object.getPrototypeOf(value) === Buffer.prototype,
  'native-bytes-required')
  const ds = Object.getOwnPropertyDescriptors(value)
  check(Reflect.ownKeys(ds).every(key => typeof key === 'string' && /^(?:0|[1-9][0-9]*)$/.test(key)
    && Object.hasOwn(ds[key], 'value') && ds[key].enumerable), 'inert-native-bytes-required')
  check(value.length > 0 && value.length <= MAX_BYTES, 'native-bytes-limit')
  return Buffer.from(value)
}
function method(object, key) {
  check(object && typeof object === 'object' && !types.isProxy(object), 'client-required')
  let cursor = object
  while (cursor) {
    const d = Object.getOwnPropertyDescriptor(cursor, key)
    if (d) {check(Object.hasOwn(d, 'value') && typeof d.value === 'function', 'client-method-required'); return d.value.bind(object)}
    cursor = Object.getPrototypeOf(cursor); check(!cursor || !types.isProxy(cursor), 'client-method-required')
  }
  check(false, 'client-method-required')
}
function denseArray(value, limit) {
  check(Array.isArray(value) && !types.isProxy(value) && Object.getPrototypeOf(value) === Array.prototype,
    'inert-array-required')
  const ds = Object.getOwnPropertyDescriptors(value)
  check(ds.length && Object.hasOwn(ds.length, 'value') && ds.length.value <= limit
    && Reflect.ownKeys(ds).length === ds.length.value + 1, 'inert-array-required')
  const result = []
  for (let n = 0; n < ds.length.value; n++) {
    check(ds[n] && Object.hasOwn(ds[n], 'value') && ds[n].enumerable, 'inert-array-required')
    result.push(ds[n].value)
  }
  return result
}
function scalarRow(input, fields) {
  return privateV2Detach(privateV2Fields(input, fields, 'restore-journal-row-fields'))
}

/** Internal trusted composition only. No raw client, path-selection method,
 * schema installer, transaction command, or recovery method reaches Bridge.
 * `assertActive` checks lifetime; it never supplies authorization/publication.
 */
export function createPrivateV2RestoreJournalScope(input) {
  const config = privateV2Fields(input, ['client','host','ancestry','profile','contracts','assertActive','statements'],
    'restore-journal-configuration')
  const host = privateV2Detach(assertPrivateHost(config.host))
  const profile = privateV2Detach(assertPrivateProfile(config.profile))
  check(isPrivateV2OwnerClient(config.client, host, 'write'), 'genuine-owner-client-required')
  const queryClient = method(config.client, 'query')
  check(typeof config.assertActive === 'function', 'active-check-required')
  const assertActive = config.assertActive
  check(config.contracts && typeof config.contracts === 'object' && !types.isProxy(config.contracts), 'contracts-required')
  const cds = Object.getOwnPropertyDescriptors(config.contracts)
  const names = ['canonicalJson','validateContract','operationDigest']
  check(names.every(key => cds[key] && Object.hasOwn(cds[key], 'value') && typeof cds[key].value === 'function'),
    'contracts-required')
  const contracts = Object.freeze(Object.fromEntries(names.map(key => [key, cds[key].value.bind(config.contracts)])))
  const statements = privateV2Detach({statements: config.statements}).statements
  check(Array.isArray(statements) && statements.length === RETAINED_JOURNAL_DESCRIPTORS.length,
    'all-fixed-statements-required')
  const byName = new Map(), byText = new Map()
  for (const statement of statements) {
    check(isPrivateV2JournalStatement(statement) && !byName.has(statement.name) && !byText.has(statement.text),
      'fixed-statement-required')
    byName.set(statement.name, statement); byText.set(statement.text, statement)
  }
  // The wrapped detachment preserves the historical object-root parser. Its
  // aggregate byte/node limits apply to the entire interval before any query.
  const ancestry = privateV2Detach({ancestry: config.ancestry}).ancestry
  check(Array.isArray(ancestry) && ancestry.length > 0 && ancestry.length <= 10000, 'ancestry-required')
  const projections = ancestry.map(control => {
    const decoded = decodeControlV3(control, host, {profile, contracts})
    const workflows = [...decoded.tables.runtime_workflows].sort(compare)
    const progress = decoded.tables.workflow_closure_progress.map(row => ({row,
      progress: assertProgressV2(parseOriginal(row.progress_bytes), {profile, contracts})})).sort((a, b) => compare(a.row, b.row))
    return {control, workflows, progress, owned: new Map(workflows.map(row => [row.operation_id, row])),
      stages: new Map(progress.map(entry => [entry.row.operation_id, entry]))}
  })
  for (let n = 1; n < projections.length; n++)
    assertForwardControlV3(projections[n - 1].control, projections[n].control, host, {profile, contracts})

  const plan = []
  function append(name, values, expected, kind) {
    const statement = byName.get(name); check(statement, 'fixed-statement-required')
    const detachedValues = values.map(value => Buffer.isBuffer(value) ? Buffer.from(value) : value)
    check(detachedValues.every(value => value === null || ['string','number','boolean'].includes(typeof value)
      || Buffer.isBuffer(value)), 'derived-bind-invalid')
    plan.push(Object.freeze({statement, values: Object.freeze(detachedValues), expected, kind}))
  }
  function reads(projection) {
    append('lockOwnerWorkflows', [host.owner_subject, host.owner_id], projection.workflows, 'workflows')
    append('lockOwnerProgress', [host.owner_subject, host.owner_id], projection.progress.map(entry => entry.row), 'progress')
  }
  reads(projections[0])
  for (let n = 1; n < projections.length; n++) {
    const before = projections[n - 1], after = projections[n]
    for (const row of after.workflows) {
      const prior = before.owned.get(row.operation_id) ?? null
      if (after.stages.has(row.operation_id) || prior !== null && same(prior, row)) continue
      append(prior === null ? 'insertWorkflow' : 'updateWorkflow', prior === null
        ? PRIVATE_WORKFLOW_FIELDS.map(key => row[key])
        : [...PRIVATE_WORKFLOW_FIELDS.map(key => prior[key]), ...MUTABLE_FIELDS.map(key => row[key])], [row], 'workflows')
    }
    for (const entry of after.progress) {
      const prior = before.stages.get(entry.row.operation_id) ?? null
      const equal = prior !== null && PROGRESS_FIELDS.every(key => key === 'progress_bytes'
        ? prior.row[key].equals(entry.row[key]) : prior.row[key] === entry.row[key])
      if (equal) continue
      const target = [entry.row.progress_bytes, entry.row.progress_digest]
      if (prior === null) append('insertProgress', [...ownerFields.map(key => entry.row[key]), ...target], [entry.row], 'progress')
      else if (entry.progress.stage === 'complete') {
        const workflow = before.owned.get(entry.row.operation_id); check(workflow, 'complete-workflow-preimage-required')
        append('completeProgress', [...PRIVATE_WORKFLOW_FIELDS.map(key => workflow[key]), prior.row.progress_bytes,
          prior.row.progress_digest, prior.progress.stage, ...target], [entry.row], 'progress')
      } else append('updateProgress', [...ownerFields.map(key => entry.row[key]), prior.row.progress_bytes,
        prior.row.progress_digest, prior.progress.stage, ...target], [entry.row], 'progress')
    }
    reads(after)
  }
  Object.freeze(plan)
  const state = {active: true, pending: new Set()}
  let position = 0, busy = false, failure = null, finished = false
  function sticky(error) {if (failure === null) failure = error; return failure}
  function active() {
    if (failure !== null) throw failure
    check(state.active === true && !finished && isPrivateV2OwnerClient(config.client, host, 'write'), 'scope-inactive')
  }
  function compareParameters(supplied, expected) {
    const values = denseArray(supplied, 64)
    check(values.length === expected.length, 'parameters-mismatch')
    for (let n = 0; n < values.length; n++) {
      if (Buffer.isBuffer(expected[n])) check(nativeBuffer(values[n]).equals(expected[n]), 'parameters-mismatch')
      else check(values[n] === expected[n], 'parameters-mismatch')
    }
  }
  function nativeRow(row, kind) {
    if (kind === 'workflows') return assertWorkflowRow(scalarRow(row, PRIVATE_WORKFLOW_FIELDS), {host})
    const fields = privateV2Fields(row, PROGRESS_FIELDS, 'restore-journal-progress-fields')
    const bytes = nativeBuffer(fields.progress_bytes)
    const scalar = scalarRow(Object.fromEntries(PROGRESS_FIELDS.filter(key => key !== 'progress_bytes')
      .map(key => [key, fields[key]])), PROGRESS_FIELDS.filter(key => key !== 'progress_bytes'))
    const parsed = assertProgressV2(parseOriginal(bytes), {profile, contracts})
    check(bytes.equals(Buffer.from(contracts.canonicalJson(parsed))) && scalar.progress_digest === progressDigest(parsed, {contracts}),
      'native-progress-bytes-mismatch')
    return {...scalar, progress_bytes: bytes}
  }
  function resultRows(result, expected) {
    check(result && typeof result === 'object' && !types.isProxy(result), 'query-result-invalid')
    const rows = denseArray(own(result, 'rows'), 10000).map(row => nativeRow(row, expected.kind))
    const count = Object.getOwnPropertyDescriptor(result, 'rowCount')
    check(!count || Object.hasOwn(count, 'value') && count.value === rows.length, 'query-count-invalid')
    rows.sort(compare)
    check(rows.length === expected.expected.length && rows.every((row, n) => {
      const target = expected.expected[n]
      return (expected.kind === 'workflows' ? PRIVATE_WORKFLOW_FIELDS : PROGRESS_FIELDS).every(key =>
        key === 'progress_bytes' ? row[key].equals(target[key]) : row[key] === target[key])
    }), 'query-postimage-mismatch')
    return Object.freeze({rows: Object.freeze(rows), rowCount: rows.length})
  }
  const tx = Object.freeze({query: async (nameOrText, suppliedValues) => {
    let work
    try {
      active(); check(!busy, 'concurrent-query-forbidden')
      const expected = plan[position]; check(expected, 'extra-query-forbidden')
      const statement = suppliedValues === undefined ? byName.get(nameOrText) : byText.get(nameOrText)
      check(statement === expected.statement, 'query-order-mismatch')
      if (suppliedValues !== undefined) compareParameters(suppliedValues, expected.values)
      busy = true
      work = Promise.resolve().then(async () => {
        active(); check(await assertActive() === undefined, 'active-check-invalid'); active()
        // Copy every byte binding again; no expected plan buffer is exposed to
        // the driver or supplied by the callback.
        const values = expected.values.map(value => Buffer.isBuffer(value) ? Buffer.from(value) : value)
        const result = await queryClient(expected.statement.text, values)
        active(); const projected = resultRows(result, expected); position++
        return projected
      }).catch(error => {throw sticky(error)})
      state.pending.add(work)
      return await work
    } catch (error) {throw sticky(error)}
    finally {if (work) {state.pending.delete(work); busy = false}}
  }})
  function finish() {
    try {
      active(); check(!busy && state.pending.size === 0 && position === plan.length, 'schedule-incomplete')
      finished = true; state.active = false
      assertComplete()
    } catch (error) {throw sticky(error)}
  }
  function assertComplete() {
    try {
      if (failure !== null) throw failure
      check(finished && state.active === false && !busy && state.pending.size === 0 && position === plan.length,
        'schedule-incomplete')
    } catch (error) {throw sticky(error)}
  }
  return Object.freeze({tx, state, finish, assertComplete, ancestry})
}
