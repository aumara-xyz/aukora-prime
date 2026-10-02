// SPDX-License-Identifier: AGPL-3.0-or-later
import { types } from 'node:util'
import { canonicalJSON } from '../genesis/plugins/aukora-kira/lib/record.mjs'
import { MemoryRefusal, parseOriginal, requireMemory } from './codecs.mjs'
import { isMemoryOwnerSerializer } from './owner-serialization.mjs'
import { assertPrivateHost, assertPrivateProfile, readControlV3, decodeControlV3,
  PRIVATE_WORKFLOW_FIELDS, PRIVATE_REFERENCE_FIELDS, progressDigest, workflowRowDigest } from './private-v2-control.mjs'
import { assertForwardControlV3 } from './private-v2-advance.mjs'
import { requirePrivateV2Guards } from './private-v2-guards.mjs'
import { isPrivateV2JournalStatement } from './private-v2-journal-statements.mjs'
import { createPrivateV2RestoreJournalScope } from './private-v2-restore-journal.mjs'
import { isPrivateV2EffectController, isPrivateV2EffectOwnerClient } from './private-v2-effect-participant.mjs'
import { isPrivateV2Coordinator, privateV2Fields, privateV2Detach, privateV2Checkpoint, checkedPrivateV2Transition } from './private-v2-coordinator.mjs'

const participants = new WeakSet(), transactions = new WeakMap(), ownedClients = new WeakMap()
const same = (a, b) => canonicalJSON(a) === canonicalJSON(b)
const check = (ok, code) => requireMemory(ok, `memory:private-v2-participant-${code}`)
const own = (o, name) => { const d = Object.getOwnPropertyDescriptor(o, name); check(d && Object.hasOwn(d, 'value'), 'selector-invalid'); return d.value }
const UUID4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/
const sameParameter = (a, b) => Buffer.isBuffer(a) ? Buffer.isBuffer(b) && a.equals(b) : a === b
const BASELINE_WORKFLOW_SELECTORS = new Set(PRIVATE_WORKFLOW_FIELDS.map(key => 'baseline.workflow.' + key))
const DERIVED_SELECTORS = new Set(['baseline.progress.progress_bytes','baseline.progress.progress_digest',
  'baseline.progress.stage','derived.target_progress_digest'])
export const isPrivateV2Participant = value => participants.has(value)
export const isPrivateV2Transaction = value => transactions.get(value)?.active === true
export function isPrivateV2OwnerClient(client, host, access = 'read') {
  const bound = ownedClients.get(client)
  if (!bound) return isPrivateV2EffectOwnerClient(client, host, access)
  if (!bound || !['read','write'].includes(access) || (access === 'write' && bound.mode !== 'write')
    || !host || types.isProxy(host)) return false
  const ds = Object.getOwnPropertyDescriptors(host)
  return ['owner_id','owner_subject','task_id','authorization_epoch'].every(key => ds[key]
    && Object.hasOwn(ds[key], 'value') && ds[key].value === bound.host[key])
}

export const PRIVATE_V2_FACTUAL_READ_TABLES = Object.freeze(['prime_memory_tombstones','prime_memory_records',
  'prime_memory_redactions','prime_memory_heads','prime_memory_chain','prime_memory_events',
  'prime_memory_controls','prime_memory_originals','prime_memory_snapshots'])

// The factual callback never sees a PoolClient. This deliberately small grammar accepts
// only owner-bound reads over ordinary columns, with no expression/function/CTE surface.
export function assertPrivateV2ReadQuery(sql, values, host) {
  check(typeof sql === 'string' && /^SELECT (?:\*|[a-z][a-z0-9_]*(?:,[a-z][a-z0-9_]*)*) FROM prime_memory_[a-z][a-z0-9_]* WHERE owner_subject=\$1(?: AND [a-z][a-z0-9_]*=\$(?:[2-9]|[1-9][0-9]+))*(?: ORDER BY [a-z][a-z0-9_]*(?:,[a-z][a-z0-9_]*)*)?$/.test(sql),
    'factual-query-forbidden')
  const table = / FROM ([a-z][a-z0-9_]*) WHERE /.exec(sql)[1]
  check(PRIVATE_V2_FACTUAL_READ_TABLES.includes(table), 'factual-relation-forbidden')
  check(Array.isArray(values) && !types.isProxy(values), 'factual-parameters-invalid')
  const ds = Object.getOwnPropertyDescriptors(values)
  const count = Math.max(...Array.from(sql.matchAll(/\$(\d+)/g), m => Number(m[1])))
  check(count <= 64 && ds.length?.value === count && Reflect.ownKeys(ds).length === count + 1
    && Array.from({length:count}, (_, i) => ds[i]).every(d => d && Object.hasOwn(d,'value')
      && (d.value === null || typeof d.value === 'string' || typeof d.value === 'boolean' || Number.isSafeInteger(d.value))),
    'factual-parameters-invalid')
  const owner = privateV2Detach(assertPrivateHost(host)).owner_subject
  check(ds[0].value === owner, 'factual-owner-mismatch')
  return Object.freeze(Array.from({length:count}, (_, i) => ds[i].value))
}

// Fixed descriptors are installed only by reviewed local worker source. The facade cannot
// turn a statement name, arbitrary query text, or caller-selected parameters into authority.
export function createPrivateV2Participant(input) {
  const {pool, serializer, coordinator, profile: rawProfile, contracts: suppliedContracts, statements: rawStatements} = privateV2Fields(input,
    ['pool', 'serializer', 'coordinator', 'profile', 'contracts', 'statements'], 'configuration-required')
  check(pool && typeof pool === 'object' && !types.isProxy(pool), 'pool-required')
  check(isMemoryOwnerSerializer(serializer) && isPrivateV2Coordinator(coordinator), 'owned-participants-required')
  const profile = privateV2Detach(assertPrivateProfile(rawProfile))
  check(same(profile, coordinator.profile), 'profile-mismatch')
  check(suppliedContracts && typeof suppliedContracts === 'object' && !types.isProxy(suppliedContracts), 'contracts-required')
  const cds = Object.getOwnPropertyDescriptors(suppliedContracts), contractNames = ['canonicalJson','validateContract','operationDigest']
  check(contractNames.every(key => cds[key] && Object.hasOwn(cds[key], 'value')
    && typeof cds[key].value === 'function'), 'contracts-required')
  const contracts = Object.freeze(Object.fromEntries(contractNames.map(key => [key, cds[key].value.bind(suppliedContracts)])))
  const canonicalJson = contracts.canonicalJson
  const statements = privateV2Detach({statements: rawStatements}).statements
  check(Array.isArray(statements), 'statements-required')
  const byName = new Map(), byText = new Map()
  for (const inputStatement of statements) {
    const s = privateV2Fields(inputStatement, ['name', 'text', 'parameters'], 'statement-fields-invalid')
    check(typeof s.name === 'string' && /^[A-Za-z][A-Za-z0-9_.-]{0,127}$/.test(s.name)
      && !byName.has(s.name) && typeof s.text === 'string' && Buffer.byteLength(s.text) <= 32768
      && isPrivateV2JournalStatement(s) && !byText.has(s.text), 'statement-invalid')
    check(Array.isArray(s.parameters) && s.parameters.length > 0 && s.parameters.length <= 64
      && s.parameters.includes('host.owner_subject') && s.parameters.every(p => typeof p === 'string'
        && (/^host\.(?:owner_subject|owner_id|task_id)$/.test(p)
          || /^transition\.[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)*$/.test(p)
          || BASELINE_WORKFLOW_SELECTORS.has(p) || DERIVED_SELECTORS.has(p))), 'statement-parameters-invalid')
    const subjectIndex = s.parameters.indexOf('host.owner_subject') + 1
    check(new RegExp('\\$' + subjectIndex + '(?![0-9])').test(s.text), 'statement-owner-filter-missing')
    byName.set(s.name, s); byText.set(s.text, s)
  }
  const host = inputHost => privateV2Detach(assertPrivateHost(inputHost))
  const ownerHost = h => ({owner_id: h.owner_id, owner_subject: h.owner_subject, authorization_epoch: h.authorization_epoch})
  const guard = (client, h) => requirePrivateV2Guards(client, {owner_subject: h.owner_subject, owner_id: h.owner_id,
    expected_store_id: profile.expected_memory_store_id, profile})
  const control = async (client, h) => privateV2Detach(await readControlV3(client,
    {owner_subject: h.owner_subject, owner_id: h.owner_id, profile}, {contracts}))
  function bindParameter(selector, h, transition, previous) {
    if (BASELINE_WORKFLOW_SELECTORS.has(selector)) {
      check(previous.workflow !== null, 'previous-workflow-required')
      return own(previous.workflow, selector.slice('baseline.workflow.'.length))
    }
    if (DERIVED_SELECTORS.has(selector)) {
      if (selector === 'derived.target_progress_digest') {
        check(Object.hasOwn(transition, 'target_progress'), 'target-progress-required')
        return progressDigest(transition.target_progress, {contracts})
      }
      check(previous.progress !== null, 'previous-progress-required')
      if (selector === 'baseline.progress.progress_bytes') return Buffer.from(previous.progress.progress_bytes)
      if (selector === 'baseline.progress.progress_digest') return previous.progress.progress_digest
      return previous.progress.stage
    }
    const keys = selector.split('.'); let value = keys.shift() === 'host' ? h : transition
    for (const key of keys) value = own(value, key)
    if (value !== null && typeof value === 'object') {
      if (selector === 'transition.target_progress') return Buffer.from(canonicalJson(value))
      if (selector === 'transition.reference' || selector === 'transition.closure') return Buffer.from(canonicalJSON(value))
      check(false, 'object-selector-unavailable')
    }
    check(value === null || ['string', 'number', 'boolean'].includes(typeof value), 'selector-value-invalid')
    return value
  }
  function journalBaseline(h, transition, previousControl) {
    // CAS preimages come from the same independently guarded SQL projection as
    // the retained predecessor. They are never accepted from callback arguments.
    const decoded = decodeControlV3(previousControl, h, {profile, contracts})
    const reference = transition.reference
    const matches = row => ['owner_subject','owner_id','task_id','operation_id'].every(key => row[key] === reference[key])
    const workflow = decoded.tables.runtime_workflows.find(matches) ?? null
    const progressRow = decoded.tables.workflow_closure_progress.find(matches) ?? null
    if (workflow !== null) check(PRIVATE_REFERENCE_FIELDS.every(key => workflow[key] === reference[key])
      && workflow.idempotency_key_sha256 === transition.idempotency_key_sha256, 'baseline-workflow-reference-mismatch')
    const progress = progressRow === null ? null : parseOriginal(progressRow.progress_bytes)
    if (transition.kind === 'prime-runtime-workflow-mutation/v3') {
      check(progressRow === null, 'baseline-closure-already-started')
      check(transition.previous_workflow_digest === null ? workflow === null : workflow !== null
        && workflowRowDigest(workflow, {contracts}) === transition.previous_workflow_digest,
        'baseline-workflow-digest-mismatch')
    } else {
      check(workflow !== null, 'baseline-workflow-required')
      check(transition.previous_progress_digest === null ? progressRow === null : progressRow !== null
        && progressRow.progress_digest === transition.previous_progress_digest,
        'baseline-progress-digest-mismatch')
      if (progress !== null) check(progress.closing_authorization_epoch === h.authorization_epoch,
        'baseline-progress-epoch-mismatch')
    }
    return {workflow: workflow === null ? null : privateV2Detach(workflow),
      progress: progressRow === null ? null : {progress_bytes: Buffer.from(progressRow.progress_bytes),
        progress_digest: progressRow.progress_digest, stage: progress.stage}}
  }
  function facade(client, h, transition, baseline) {
    const state = {active: true, pending: new Set()}
    const tx = Object.freeze({query: async (nameOrText, suppliedValues) => {
      check(state.active && serializer.current()?.client === client, 'transaction-inactive')
      const s = suppliedValues === undefined ? byName.get(nameOrText) : byText.get(nameOrText)
      check(s, 'statement-unregistered')
      const values = s.parameters.map(p => bindParameter(p, h, transition, baseline))
      if (suppliedValues !== undefined) {
        check(Array.isArray(suppliedValues) && !types.isProxy(suppliedValues), 'parameters-mismatch')
        const ds = Object.getOwnPropertyDescriptors(suppliedValues)
        check(ds.length?.value === values.length && Reflect.ownKeys(ds).length === values.length + 1
          && values.every((v, i) => ds[i] && Object.hasOwn(ds[i], 'value')
            && !types.isProxy(ds[i].value) && sameParameter(v, ds[i].value)), 'parameters-mismatch')
      }
      const promise = Promise.resolve().then(() => {
        check(state.active && serializer.current()?.client === client, 'transaction-inactive')
        return client.query(s.text, values)
      })
      state.pending.add(promise)
      try { return await promise } finally { state.pending.delete(promise) }
    }})
    transactions.set(tx, state)
    return {tx, state}
  }
  function unknown(cause, h, request) {
    const error = new MemoryRefusal('memory:private-v2-outcome-unknown')
    error.cause = cause; error.cause_code = typeof cause?.code === 'string' ? cause.code : null
    error.reconciliation_required = true; error.automatic_retry = false
    error.owner_id = h.owner_id; error.owner_subject = h.owner_subject
    error.transition_id = request.transition_id; error.transition_digest = request.transition_digest
    error.operation_id = request.transition.reference.operation_id
    error.operation_digest = request.transition.reference.operation_digest
    return error
  }
  function checkedRequest(rawRequest, h) {
    const r = privateV2Fields(rawRequest, ['transition_id', 'transition', 'transition_digest'], 'request-fields-invalid')
    check(typeof r.transition_id === 'string' && UUID4.test(r.transition_id), 'transition-id-invalid')
    const bound = checkedPrivateV2Transition(r.transition, h, profile, contracts)
    check(r.transition_digest === bound.digest, 'transition-digest-invalid')
    return privateV2Detach({...r, transition: bound.transition})
  }
  async function run(hostInput, rawRequest, mutate, allowed, privatePurpose = false) {
    const h = host(hostInput), request = checkedRequest(rawRequest, h)
    check(allowed.includes(request.transition.kind) && typeof mutate === 'function', 'purpose-required')
    let pendingMayExist = false
    try {
      // Include the entire serializer lifetime. Final lock inspection/unlock/release is part of success.
      return await serializer.run(ownerHost(h), async scope => {
        const client = scope.client; let begun = false, committed = false
        check(!ownedClients.has(client), 'nested-participant-unavailable'); ownedClients.set(client, {host:h,mode:'write'})
        try {
          await client.query('BEGIN ISOLATION LEVEL READ COMMITTED READ WRITE'); begun = true
          await client.query('SET LOCAL synchronous_commit = on')
          await guard(client, h)
          const previous = await control(client, h)
          // Native SQL and independent protected evidence precede durable pending creation.
          const restoring = request.transition.kind === 'prime-memory-control-restore-transition/v3'
          const retained = restoring ? await coordinator.readVerifiedRestoreCurrent(h, previous)
            : await coordinator.readVerifiedCurrent(h, previous)
          // Only the independently protected CURRENT predecessor chain chooses
          // the restore interval. A callback cannot supply or truncate ancestry.
          let restoreScope = null, restoreUsed = false, restoreFinished = false, restoreCall = null, restoreActive = true
          let restoreInvocationFailure = null
          const assertRestoreComplete = () => {
            if (restoreInvocationFailure) throw restoreInvocationFailure
            if (restoreScope) restoreScope.assertComplete()
          }
          if (restoring) {
            const index = retained.lineage.findIndex(envelope => same(envelope.control_state, previous))
            check(index >= 0 && retained.current.checkpoint_sha256 === request.transition.anchor_checkpoint_sha256
              && retained.current.checkpoint_sha256 === request.transition.expected_checkpoint_sha256,
              'restore-anchor-mismatch')
            const ancestry = privateV2Detach({ancestry:retained.lineage.slice(0,index+1).reverse()
              .map(envelope => envelope.control_state)}).ancestry
            restoreScope = createPrivateV2RestoreJournalScope({client,host:h,ancestry,profile,contracts,
              statements:[...byName.values()],assertActive:() => {
                check(restoreActive && serializer.current() === scope && ownedClients.get(client)?.host === h,
                  'restore-transaction-inactive')
              }})
            transactions.set(restoreScope.tx, restoreScope.state)
          }
          const baseline = privatePurpose ? null : journalBaseline(h, request.transition, previous)
          pendingMayExist = true
          const context = await coordinator.beginTyped({host: h, ...request}, previous)
          if (restoring) check(same(context.predecessor, retained.current), 'restore-current-changed')
          let result
          if (privatePurpose) {
            const restoreJournal = restoring ? adapter => {
              try {
                if (restoreInvocationFailure) throw restoreInvocationFailure
                check(restoreActive && !restoreUsed && typeof adapter === 'function', 'restore-adapter-required')
              } catch (error) {
                restoreInvocationFailure ??= error
                throw restoreInvocationFailure
              }
              restoreUsed = true
              restoreCall = (async () => {
                try {
                  check(await adapter(restoreScope.tx, restoreScope.ancestry, profile) === undefined,
                    'restore-callback-result-invalid')
                  restoreScope.finish(); restoreFinished = true
                } catch (error) {
                  restoreInvocationFailure ??= error
                  throw restoreInvocationFailure
                } finally {
                  restoreScope.state.active = false
                  if (restoreScope.state.pending.size) await Promise.allSettled([...restoreScope.state.pending])
                }
              })()
              return restoreCall
            } : undefined
            try {
              // Only D-owned record restoration receives the actual client.
              // Its reviewed Bridge helper receives the bounded facade above.
              result = await mutate(client, request.transition, previous, restoreJournal,
                restoring ? retained.current.control_state : undefined)
              if (restoring) {
                check(restoreUsed && restoreFinished, 'restore-journal-required')
                assertRestoreComplete()
              }
            } finally {
              restoreActive = false
              if (restoreScope) {
                restoreScope.state.active = false
                if (restoreScope.state.pending.size) await Promise.allSettled([...restoreScope.state.pending])
              }
              if (restoreCall) await Promise.allSettled([restoreCall])
            }
          }
          else {
            const {tx, state} = facade(client, h, request.transition, baseline)
            try {
              result = await mutate(tx, request.transition)
              check(state.pending.size === 0, 'unawaited-query')
            } finally {
              state.active = false
              if (state.pending.size) await Promise.allSettled([...state.pending])
            }
          }
          check(result === undefined, 'callback-result-invalid')
          await serializer.inspect(scope); await guard(client, h)
          const candidate = await control(client, h)
          if (request.transition.kind === 'prime-memory-control-restore-transition/v3')
            check(same(candidate, context.predecessor.control_state), 'restore-candidate-anchor-mismatch')
          else assertForwardControlV3(previous, candidate, h, {profile, contracts, transition: request.transition})
          assertRestoreComplete()
          await coordinator.prepareTyped(context, candidate)
          assertRestoreComplete()
          await client.query('COMMIT'); committed = true; begun = false
          // A separate read transaction observes actual committed state on the same held owner session.
          await client.query('BEGIN ISOLATION LEVEL READ COMMITTED READ WRITE'); begun = true
          await client.query('SET LOCAL synchronous_commit = on')
          await guard(client, h)
          const actual = await control(client, h)
          check(same(actual, candidate), 'committed-state-mismatch')
          assertRestoreComplete()
          const envelope = await coordinator.completeTyped(context, actual)
          assertRestoreComplete()
          await client.query('COMMIT'); begun = false
          assertRestoreComplete()
          const decoded = decodeControlV3(actual, h, {profile, contracts})
          return {checkpoint: privateV2Checkpoint(envelope), control: actual, decoded, envelope, reference: request.transition.reference}
        } catch (error) {
          if (begun) {
            try { await client.query('ROLLBACK') } catch (rollback) { error.rollback_cause = rollback }
          }
          if (committed) pendingMayExist = true
          throw error
        } finally { ownedClients.delete(client) }
      })
    } catch (error) { if (pendingMayExist) throw unknown(error, h, request); throw error }
  }
  function projections(out, reference, journal) {
    const row = out.decoded.tables.runtime_workflows.find(r => r.operation_id === reference.operation_id)
    check(row && row.owner_subject === reference.owner_subject && row.owner_id === reference.owner_id
      && row.task_id === reference.task_id && row.operation_digest === reference.operation_digest
      && row.action_type === reference.action_type, 'workflow-reference-mismatch')
    const result = {checkpoint: out.checkpoint, workflow_reference: privateV2Detach(row)}
    if (journal) {
      const progressRow = out.decoded.tables.workflow_closure_progress.find(r => r.operation_id === reference.operation_id)
      check(progressRow, 'progress-missing')
      result.progress = privateV2Detach(JSON.parse(progressRow.progress_bytes.toString('utf8')))
      result.progress_digest = progressRow.progress_digest
    }
    return Object.freeze(result)
  }
  async function withRetainedJournalTransition(h, request, mutate) {
    const out = await run(h, request, mutate, ['prime-runtime-unsent-journal-transition/v3'])
    return projections(out, out.reference, true)
  }
  async function withRetainedWorkflowMutation(h, request, mutate) {
    const out = await run(h, request, mutate, ['prime-runtime-workflow-mutation/v3'])
    return projections(out, out.reference, false)
  }
  async function runRetainedPurpose(h, request, mutate) {
    const out = await run(h, request, mutate, ['prime-memory-negative-closure-transition/v3',
      'prime-memory-control-restore-transition/v3'], true)
    return Object.freeze({checkpoint: out.checkpoint})
  }
  async function runRetainedRestorePurpose(h, request, mutate) {
    const out = await run(h, request, mutate, ['prime-memory-control-restore-transition/v3'], true)
    return Object.freeze({checkpoint: out.checkpoint})
  }
  // The archive interval is captured from the genuine dispatched restore while
  // actual SQL is still I. Bridge receives only the existing fixed query scope.
  // Physical record restoration may then run before this one-use journal replay.
  async function prepareRestoreEffectJournal(controller, hostInput, adapter) {
    const h = host(hostInput), scope = serializer.current()
    check(isPrivateV2EffectController(controller) && typeof adapter === 'function'
      && !types.isProxy(adapter), 'restore-effect-source-required')
    check(scope && isPrivateV2EffectOwnerClient(scope.client, h, 'write'), 'restore-effect-session-required')
    await serializer.inspect(scope); await guard(scope.client, h)
    const evidence = await controller.restoreEvidence(scope.client)
    check(byName.size === 9, 'restore-fixed-statements-required')
    const assertActive = async () => {
      check(serializer.current() === scope && isPrivateV2EffectOwnerClient(scope.client, h, 'write'),
        'restore-effect-session-inactive')
      await serializer.inspect(scope); await guard(scope.client, h)
    }
    const prepared = createPrivateV2RestoreJournalScope({client:scope.client,host:h,
      ancestry:evidence.ancestry,profile,contracts,assertActive,statements:[...byName.values()]})
    transactions.set(prepared.tx, prepared.state)
    let used = false, completed = false
    const execute = async () => {
      check(!used, 'restore-effect-journal-reused'); used = true
      try {
        await assertActive()
        const result = await adapter(prepared.tx, prepared.ancestry, profile)
        check(result === undefined, 'restore-effect-journal-result-invalid')
        prepared.finish(); prepared.assertComplete()
        await assertActive(); prepared.assertComplete()
        completed = true
      } finally {
        prepared.state.active = false
        if (prepared.state.pending.size) await Promise.allSettled([...prepared.state.pending])
      }
    }
    Object.defineProperty(execute,'assertComplete',{value:()=>{
      check(used && completed,'restore-effect-journal-incomplete')
      prepared.assertComplete()
    }})
    return Object.freeze(execute)
  }
  async function verified(hostInput, fn, restore) {
    const h = host(hostInput); check(typeof fn === 'function', 'read-callback-required')
    return serializer.run(ownerHost(h), async scope => {
      let begun = false
      check(!ownedClients.has(scope.client), 'nested-participant-unavailable')
      const state = {active:true,pending:new Set()}
      const readClient = Object.freeze({query: async (sql, values) => {
        check(state.active && serializer.current() === scope, 'factual-client-inactive')
        const bound = assertPrivateV2ReadQuery(sql, values, h)
        const promise = Promise.resolve().then(() => {
          check(state.active && serializer.current() === scope, 'factual-client-inactive')
          return scope.client.query(sql, bound)
        })
        state.pending.add(promise)
        try { return await promise } finally { state.pending.delete(promise) }
      }})
      ownedClients.set(readClient,{host:h,mode:'read'})
      try {
        await scope.client.query('BEGIN ISOLATION LEVEL READ COMMITTED READ WRITE'); begun = true
        await guard(scope.client, h)
        const actual = await control(scope.client, h)
        const retained = restore ? await coordinator.readVerifiedRestoreCurrent(h, actual)
          : {current: await coordinator.readVerifiedCurrent(h, actual)}
        let result
        try {
          result = await fn(readClient, actual, retained.current, retained.lineage)
          check(state.pending.size === 0, 'unawaited-factual-query')
        } finally {
          state.active = false; ownedClients.delete(readClient)
          if (state.pending.size) await Promise.allSettled([...state.pending])
        }
        await serializer.inspect(scope); await guard(scope.client, h)
        check(same(await control(scope.client, h), actual), 'factual-read-mutated-state')
        if (restore) await coordinator.readVerifiedRestoreCurrent(h, actual)
        else await coordinator.readVerifiedCurrent(h, actual)
        await scope.client.query('COMMIT'); begun = false
        return result
      } catch (error) {
        if (begun) { try { await scope.client.query('ROLLBACK') } catch (rollback) { error.rollback_cause = rollback } }
        // A factual refusal can identify an existing protected pending purpose,
        // but cannot recover or reapply it. Inspect only while the real owner
        // session is still held, and preserve absence/corruption as the refusal.
        if (typeof error?.code === 'string'
          && /^memory:private-v2-(?:retention|coordinator)-[^:]*pending[^:]*$/.test(error.code)) {
          try {
            await serializer.inspect(scope)
            const pending = await coordinator.reader.inspectPending(h)
            const marker = pending.marker
            error.retention_transition_id = marker.transition_id
            error.retention_transition_digest = marker.transition_digest
          } catch (inspection) { error.pending_inspection_cause = inspection }
        }
        throw error
      } finally { state.active = false; ownedClients.delete(readClient) }
    })
  }
  async function recoverRetainedPurpose(hostInput, rawRequest, journalOnly = false) {
    const h = host(hostInput), r = privateV2Fields(rawRequest, ['transition_id', 'transition_digest'], 'recovery-fields-invalid')
    let request = null
    try {
      return await serializer.run(ownerHost(h), async scope => {
        let begun = false
        check(!ownedClients.has(scope.client), 'nested-participant-unavailable'); ownedClients.set(scope.client, {host:h,mode:'write'})
        try {
          await scope.client.query('BEGIN ISOLATION LEVEL READ COMMITTED READ WRITE'); begun = true
          await scope.client.query('SET LOCAL synchronous_commit = on'); await guard(scope.client, h)
          const pending = await coordinator.reader.readPending({host: h, ...r})
          request = checkedRequest({...r, transition: pending.marker.transition}, h)
          if (journalOnly) check(request.transition.kind === 'prime-runtime-unsent-journal-transition/v3', 'journal-purpose-required')
          check(pending.prepared !== null, 'prepared-recovery-required')
          const actual = await control(scope.client, h)
          const envelope = await coordinator.recoverTyped({host: h, ...request}, actual)
          check(same(await control(scope.client, h), actual), 'recovery-state-changed')
          await clientInspect(scope)
          await scope.client.query('COMMIT'); begun = false
          return Object.freeze({checkpoint: privateV2Checkpoint(envelope)})
        } catch (error) {
          if (begun) { try { await scope.client.query('ROLLBACK') } catch (rollback) { error.rollback_cause = rollback } }
          throw error
        } finally { ownedClients.delete(scope.client) }
      })
    } catch (error) { if (request) throw unknown(error, h, request); throw error }
  }
  async function clientInspect(scope) { await serializer.inspect(scope) }
  const participant = Object.freeze({profile, contracts, coordinator,
    withRetainedJournalTransition, withRetainedWorkflowMutation, runRetainedPurpose, runRetainedRestorePurpose,
    prepareRestoreEffectJournal,
    withVerifiedControl: (h, fn) => verified(h, fn, false),
    withVerifiedRestoreControl: (h, fn) => verified(h, fn, true),
    recoverRetainedPurpose,
    recoverJournal: async inputRequest => {
      const r = privateV2Fields(inputRequest, ['host','transition_id','transition_digest'], 'recovery-fields-invalid')
      return recoverRetainedPurpose(r.host, {transition_id:r.transition_id,transition_digest:r.transition_digest}, true)
    }})
  participants.add(participant)
  return participant
}
