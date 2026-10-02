// SPDX-License-Identifier: AGPL-3.0-or-later
// Focused keyless connection-lifetime checks. The actual UI controller uses
// only the existing in-memory presentation fixture and inert timer callbacks.
// No browser assertion, real credential, network, server or effect is used.
import assert from 'node:assert/strict'
import {test} from 'node:test'
import * as contracts from '../../../contracts/src/browser.mjs'
import {createPrimeOwnerController} from '../src/client/controller.mjs'
import {createOwnerUiFixture} from './fixture.mjs'

const clock = Date.parse('2030-01-01T00:00:00Z')
const now = () => clock
const makeController = (options = {}) => createPrimeOwnerController({
  now, schedule: () => Object.freeze({synthetic_timer: true}), unschedule: () => {}, ...options,
})
function fixture({owner_id, operation = false, requiresCapabilities = true, ...options} = {}) {
  const source = createOwnerUiFixture(contracts, {now, ...options})
  const {operation: prepared, ...base} = source
  return Object.freeze({...base, ...(owner_id ? {owner_id} : {}), requiresCapabilities,
    ...(operation ? {operation: prepared} : {})})
}
function assertWitness(witness) {
  assert.ok(witness, 'a completed connection returns its own witness')
  assert.deepEqual(Object.keys(witness), ['isCurrent'])
  assert.equal(Object.isFrozen(witness), true)
  assert.equal(typeof witness.isCurrent, 'function')
  assert.equal(witness.isCurrent(), true)
}
function assertUnqualified(controller, binding) {
  const state = controller.getSnapshot()
  assert.equal(state.owner, null, 'connection is not an authenticated owner')
  assert.equal(state.authority_available, false, 'connection does not supply capability evidence')
  assert.equal(state.capabilities, null)
  assert.equal(binding.counts.login, 0)
  assert.equal(binding.counts.approve, 0)
  assert.equal(binding.counts.decline, 0)
}
function deferred() {
  let resolve
  const promise = new Promise(answer => {resolve = answer})
  return {promise, resolve}
}

test('completed frozen witness contains no owner, capability or authority grant', () => {
  const controller = makeController(), binding = fixture()
  try {
    const witness = controller.connect(binding)
    assertWitness(witness)
    assertUnqualified(controller, binding)
    controller.dispose()
    assert.equal(witness.isCurrent(), false)
    assert.equal(controller.connect(binding), null, 'disposed controller cannot reconnect')
  } finally {controller.dispose()}
})

test('same-owner distinct binding replacement invalidates the exact old witness', () => {
  const controller = makeController(), first = fixture(), second = fixture()
  assert.equal(first.owner_id, second.owner_id)
  assert.notEqual(first, second)
  try {
    const oldWitness = controller.connect(first)
    const replacement = controller.connect(second)
    assert.equal(oldWitness.isCurrent(), false)
    assertWitness(replacement)
    assertUnqualified(controller, second)
  } finally {controller.dispose()}
})

test('reconnecting the identical binding object creates a distinct lifetime', () => {
  const controller = makeController(), binding = fixture()
  try {
    const oldWitness = controller.connect(binding)
    const replacement = controller.connect(binding)
    assert.notEqual(replacement, oldWitness)
    assert.equal(oldWitness.isCurrent(), false)
    assertWitness(replacement)
    assertUnqualified(controller, binding)
  } finally {controller.dispose()}
})

test('failed transport setup and failed optional operation publish no witness', () => {
  const controller = makeController(), binding = fixture()
  try {
    const oldWitness = controller.connect(binding)
    assert.equal(controller.connect(Object.freeze({...binding, contracts: {}})), null)
    assert.equal(oldWitness.isCurrent(), false)
    assert.equal(controller.getSnapshot().owner, null)
    assert.equal(controller.getSnapshot().authority_available, false)
    assert.equal(controller.connect(Object.freeze({...binding, operation: {version: 1}})), null)
    assert.equal(controller.getSnapshot().operation_available, false)
    const recovered = controller.connect(binding)
    assertWitness(recovered)
    assertUnqualified(controller, binding)
  } finally {controller.dispose()}
})

test('notification replacement cannot inherit an unfinished connection or old operation', () => {
  const controller = makeController(), binding = fixture()
  const stale = Object.freeze({...binding, operation: {version: 1}})
  const replacement = fixture({owner_id: 'synthetic-replacement-owner'})
  let replaced = false, witness
  const off = controller.subscribe(() => {
    if (!replaced && controller.getSnapshot().owner_id === stale.owner_id) {
      replaced = true
      witness = controller.connect(replacement)
    }
  })
  try {
    assert.equal(controller.connect(stale), null)
    assert.equal(replaced, true)
    assertWitness(witness)
    assert.equal(controller.getSnapshot().owner_id, replacement.owner_id)
    assert.equal(controller.getSnapshot().operation_available, false)
    assert.equal(controller.getSnapshot().error_code, 'UNAVAILABLE')
    assertUnqualified(controller, replacement)
  } finally {off(); controller.dispose()}
})

test('synchronous notification disposal prevents completion and controller reuse', () => {
  const controller = makeController(), binding = fixture()
  let disposed = false
  const off = controller.subscribe(() => {
    if (!disposed) {disposed = true; controller.dispose()}
  })
  try {
    assert.equal(controller.connect(binding), null)
    assert.equal(disposed, true)
    assert.equal(controller.connect(binding), null)
    assert.equal(controller.getSnapshot().owner, null)
    assert.equal(controller.getSnapshot().authority_available, false)
  } finally {off(); controller.dispose()}
})

test('disconnect abort callback preserves a synchronously connected replacement', {timeout: 1000}, async () => {
  const controller = makeController(), base = fixture({requiresCapabilities: false})
  const replacement = fixture({owner_id: 'synthetic-abort-replacement'})
  const entered = deferred(), release = deferred()
  let replacementWitness, signerCalls = 0, pending
  const binding = Object.freeze({...base,
    passkeySigner: async input => {signerCalls++; return base.passkeySigner(input)},
    authority: Object.freeze({...base.authority,
      async loginChallenge(input, {signal}) {
        signal.addEventListener('abort', () => {replacementWitness = controller.connect(replacement)}, {once: true})
        entered.resolve()
        await release.promise
        return base.authority.loginChallenge(input)
      },
    }),
  })
  try {
    const oldWitness = controller.connect(binding)
    pending = controller.login()
    await entered.promise
    const outcome = await controller.disconnect()
    assert.deepEqual(outcome, {ok: false, error_code: 'UNAVAILABLE', reason: 'ui:binding-disconnect-superseded'})
    assert.equal(oldWitness.isCurrent(), false)
    assertWitness(replacementWitness)
    assert.equal(controller.getSnapshot().owner_id, replacement.owner_id)
    assertUnqualified(controller, replacement)
    release.resolve()
    assert.equal(await pending, null)
    assert.equal(signerCalls, 0, 'cancelled synthetic login never reaches a signer')
    assert.equal(base.counts.login, 0)
    assertWitness(replacementWitness)
  } finally {release.resolve(); if (pending) await pending; controller.dispose()}
})

test('disconnect timer cleanup preserves a synchronously connected replacement', async () => {
  const scheduled = [], removed = []
  let replaceOnRemoval = false, replacementWitness, controller
  const binding = fixture({requiresCapabilities: false})
  const replacement = fixture({operation: true})
  controller = makeController({
    schedule(callback, delay) {
      const handle = Object.freeze({callback, delay, index: scheduled.length})
      scheduled.push(handle)
      return handle
    },
    unschedule(handle) {
      removed.push(handle)
      if (replaceOnRemoval) {
        replaceOnRemoval = false
        replacementWitness = controller.connect(replacement)
      }
    },
  })
  try {
    const oldWitness = controller.connect(binding)
    await controller.login()
    assert.equal(binding.counts.login, 1, 'only an in-memory synthetic login establishes the old timer')
    assert.equal(scheduled.length, 1)
    const originalTimer = scheduled[0]
    replaceOnRemoval = true
    const outcome = await controller.disconnect()
    assert.equal(outcome.ok, false)
    assert.equal(outcome.error_code, 'UNAVAILABLE')
    assert.equal(outcome.reason, 'ui:binding-disconnect-superseded')
    assert.equal(oldWitness.isCurrent(), false)
    assertWitness(replacementWitness)
    assert.equal(controller.getSnapshot().owner_id, replacement.owner_id)
    assert.equal(controller.getSnapshot().operation_available, true)
    assertUnqualified(controller, replacement)
    assert.equal(scheduled.length, 1, 'a raw logged-out proposal supplies no owner or review expiry')
    assert.deepEqual(removed, [originalTimer])
    controller.dispose()
    assert.deepEqual(removed, [originalTimer])
    assert.equal(replacementWitness.isCurrent(), false)
  } finally {replaceOnRemoval = false; controller.dispose()}
})

test('timer cleanup retains a callback-created handle for its next owned cleanup', async () => {
  const scheduled = [], removed = []
  let prepareOnRemoval = false, controller
  const binding = fixture({requiresCapabilities: false, operation: true})
  controller = makeController({
    schedule(callback, delay) {
      const handle = Object.freeze({callback, delay, index: scheduled.length})
      scheduled.push(handle)
      return handle
    },
    unschedule(handle) {
      removed.push(handle)
      if (prepareOnRemoval) {
        prepareOnRemoval = false
        // A synchronous cleanup observer changes only the literal UI proposal
        // while the old synthetic owner is still visible. This schedules its
        // owner-expiry timer; it authenticates nobody and dispatches no effect.
        controller.setOperation({...binding.operation, operation_id: 'synthetic-cleanup-operation'})
      }
    },
  })
  try {
    const witness = controller.connect(binding)
    await controller.login()
    assert.equal(scheduled.length, 1)
    prepareOnRemoval = true
    await controller.disconnect()
    assert.equal(witness.isCurrent(), false)
    assert.equal(controller.getSnapshot().owner, null)
    assert.equal(controller.getSnapshot().authority_available, false)
    assert.equal(scheduled.length, 2)
    assert.deepEqual(removed, [scheduled[0]], 'outer cleanup did not overwrite the new timer handle')
    controller.dispose()
    assert.deepEqual(removed, [scheduled[0], scheduled[1]], 'subsequent cleanup still owns the callback-created handle')
    assert.equal(binding.counts.approve, 0)
    assert.equal(binding.counts.decline, 0)
  } finally {prepareOnRemoval = false; controller.dispose()}
})

test('session and operation revisions do not turn a connection witness into authority', async () => {
  const controller = makeController(), binding = fixture({operation: true})
  try {
    const witness = controller.connect(binding)
    controller.setOperation({...binding.operation, operation_id: 'synthetic-new-operation'})
    assertWitness(witness)
    controller.setCapabilities({version: 1, source_commit: 'a'.repeat(40), runtime_pid: 123,
      release_digest: 'sha256:' + 'b'.repeat(64), unavailable_capabilities: ['owner-passkey'],
      phase: 'disposable-preview', qualification: 'PENDING'})
    assertWitness(witness)
    assert.equal(controller.getSnapshot().authority_available, false)
    assert.equal(controller.getSnapshot().owner, null)
    await controller.logout()
    assertWitness(witness)
    assert.equal(binding.counts.login, 0)
    assert.equal(binding.counts.approve, 0)
    await controller.disconnect()
    assert.equal(witness.isCurrent(), false)
  } finally {controller.dispose()}
})

test('owned witness cleanup can cancel its connection before setup notifications', async () => {
  const controller = makeController(), binding = fixture()
  let retained, cleanup
  try {
    const returned = controller.connect(binding, {onConnection(witness) {
      retained = witness
      assert.equal(Object.isFrozen(witness), true)
      assert.deepEqual(Object.keys(witness), ['isCurrent'])
      assert.equal(witness.isCurrent(), false, 'retained receipt is not completed connection acknowledgement')
      cleanup = controller.disconnect(witness)
    }})
    assert.equal(returned, null)
    assert.equal(retained.isCurrent(), false)
    const outcome = await cleanup
    assert.equal(outcome.ok, false, 'an unconnected fixture has no server revocation to confirm')
    assert.equal(outcome.error_code, 'UNAVAILABLE')
    assert.equal(controller.getSnapshot().phase, 'unavailable')
    assertUnqualified(controller, binding)
    assert.equal(binding.counts.logout, 0)
  } finally {controller.dispose()}
})

test('owned witness cleanup can cancel its still-pending connection from a notification', async () => {
  const controller = makeController(), binding = fixture()
  let retained, cleanup, removed = false
  const off = controller.subscribe(() => {
    if (!removed && controller.getSnapshot().owner_id === binding.owner_id) {
      removed = true
      assert.ok(retained, 'lifecycle receipt was retained before the first setup notification')
      assert.equal(retained.isCurrent(), false)
      cleanup = controller.disconnect(retained)
    }
  })
  try {
    const returned = controller.connect(binding, {onConnection: witness => {retained = witness}})
    assert.equal(returned, null)
    assert.equal(removed, true)
    assert.equal(retained.isCurrent(), false)
    assert.equal((await cleanup).status, 'LOGGED_OUT', 'only the synthetic fixture confirms its own logout')
    assert.equal(controller.getSnapshot().phase, 'unavailable')
    assertUnqualified(controller, binding)
  } finally {off(); controller.dispose()}
})

test('owned witness cleanup rejects forged and other-controller receipts without changing the current connection', async () => {
  const controller = makeController(), other = makeController(), binding = fixture()
  const forged = Object.freeze({isCurrent: () => {throw new Error('forged predicate must never be trusted')}})
  try {
    const witness = controller.connect(binding)
    const foreign = other.connect(binding)
    assertWitness(witness)
    assertWitness(foreign)
    const snapshot = controller.getSnapshot(), logoutCalls = binding.counts.logout
    const forgedResult = await controller.disconnect(forged)
    const foreignResult = await controller.disconnect(foreign)
    assert.deepEqual(forgedResult, {ok: false, error_code: 'UNAVAILABLE', reason: 'ui:binding-disconnect-superseded'})
    assert.deepEqual(foreignResult, forgedResult)
    assert.equal(controller.getSnapshot(), snapshot, 'rejected ownership causes no observer-state publication')
    assert.equal(binding.counts.logout, logoutCalls, 'rejected receipts dispatch no logout')
    assertWitness(witness)
    assertWitness(foreign)
    assertUnqualified(controller, binding)
  } finally {controller.dispose(); other.dispose()}
})

test('owned witness cleanup from an old same-owner binding cannot disconnect a replacement', async () => {
  const controller = makeController(), oldBinding = fixture(), replacement = fixture()
  try {
    const stale = controller.connect(oldBinding)
    const current = controller.connect(replacement)
    assert.equal(oldBinding.owner_id, replacement.owner_id)
    assert.equal(stale.isCurrent(), false)
    const snapshot = controller.getSnapshot(), logoutCalls = replacement.counts.logout
    const outcome = await controller.disconnect(stale)
    assert.deepEqual(outcome, {ok: false, error_code: 'UNAVAILABLE', reason: 'ui:binding-disconnect-superseded'})
    assert.equal(controller.getSnapshot(), snapshot)
    assert.equal(replacement.counts.logout, logoutCalls)
    assertWitness(current)
    assertUnqualified(controller, replacement)
  } finally {controller.dispose()}
})

test('owned witness cleanup cannot disconnect an identical-object reconnect with its previous receipt', async () => {
  const controller = makeController(), binding = fixture()
  try {
    const stale = controller.connect(binding)
    const current = controller.connect(binding)
    assert.notEqual(stale, current)
    assert.equal(stale.isCurrent(), false)
    const snapshot = controller.getSnapshot(), logoutCalls = binding.counts.logout
    assert.equal((await controller.disconnect(stale)).reason, 'ui:binding-disconnect-superseded')
    assert.equal(controller.getSnapshot(), snapshot)
    assert.equal(binding.counts.logout, logoutCalls)
    assertWitness(current)
    await controller.disconnect(current)
    assert.equal(current.isCurrent(), false, 'the retained current receipt still owns its cleanup')
  } finally {controller.dispose()}
})

test('owned witness cleanup of a pending lifetime cannot remove its synchronous same-object replacement', async () => {
  const controller = makeController(), binding = fixture()
  let pending, replacement, cleanup
  try {
    const returned = controller.connect(binding, {onConnection(witness) {
      pending = witness
      assert.equal(pending.isCurrent(), false)
      replacement = controller.connect(binding)
      assertWitness(replacement)
      cleanup = controller.disconnect(pending)
    }})
    assert.equal(returned, null, 'superseded setup never publishes a completed connection')
    assert.equal(pending.isCurrent(), false)
    assert.equal((await cleanup).reason, 'ui:binding-disconnect-superseded')
    assertWitness(replacement)
    assertUnqualified(controller, binding)
    assert.equal(binding.counts.logout, 0, 'old pending cleanup never touches the replacement transport')
  } finally {controller.dispose()}
})
