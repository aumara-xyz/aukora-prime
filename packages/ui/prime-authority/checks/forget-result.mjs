import nodeAssert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { pathToFileURL } from 'node:url'
import { validateForgetWorkflowSnapshot, validateForgetWorkflowResult, validateCancelledForgetWorkflow } from '../../adapters/forget-result.mjs'
import { createOwnerUiFixture } from './fixture.mjs'

// SOURCE consistency only. Independent Node SHA fixtures exercise the browser
// WebCrypto verifier; no authority, memory, transport or credential is invoked.
const contracts = await import(process.argv[2] ? pathToFileURL(process.argv[2]).href
  : new URL('../../../contracts/src/runtime.mjs', import.meta.url).href)
let cases = 0, assertions = 0
const assert = new Proxy(nodeAssert, {
  apply(target, receiver, args) { assertions++; return Reflect.apply(target, receiver, args) },
  get(target, key) {
    const value = Reflect.get(target, key)
    return typeof value === 'function' ? (...args) => { assertions++; return Reflect.apply(value, target, args) } : value
  },
})
const clone = value => structuredClone(value)
const nodeDigest = (domain, value) => 'sha256:' + createHash('sha256').update(domain).update('\0').update(contracts.canonicalJson(value)).digest('hex')
const proofNonce = '4'.repeat(64), ownerSubject = 'aukora:1:' + '1'.repeat(64)
const initial = () => ({ phase:'idle',operation:null,record_summary:null,operation_digest:null,approval:'not_requested',
  forget:'not_attempted',forgotten:false,result:null,receipt:null,receipt_digest:null,authority_settlement:null,
  reconciliation_required:false,error_code:null,recovery_status:'not_requested',recovery_operation_id:null,recovery_operation_digest:null })
async function fixture({ statement = '  Literal legacy record\n<markup> 😀\t  ', attributed_to = 'owner-edit' } = {}) {
  const base = createOwnerUiFixture(contracts, { now: () => Date.parse('2030-01-01T00:00:00Z') })
  const summary = { record_id:'aura:fixture:record',revision:'fixture-revision',statement,attributed_to }
  const operation = { ...clone(base.operation),action_type:'memory.forget',audience:'aukora-prime.memory',
    target_identity:{kind:'prime-memory',owner_subject:ownerSubject},expected_state_version:'sha256:' + '2'.repeat(64),
    canonical_parameters:{profile:'prime-logical-forget/v1',...summary,canonical_sha256:'3'.repeat(64),
      at:'2030-01-01T00:00:00Z',heads:{remembered:'aukora:aura-record:v1',approved:'5'.repeat(64)}} }
  const operation_digest = await contracts.operationDigest(operation)
  const presentation = { operation:clone(operation),canonical_operation:contracts.canonicalJson(operation),operation_digest,
    forget_review:{...summary,canonical_sha256:operation.canonical_parameters.canonical_sha256} }
  const result = { record_id:summary.record_id,state:'tombstoned',canonical_payload_retained:true,physical_media_erasure:false,
    authority_approval_history_erased:false,backups_erased:false,wal_erased:false,grants_authority:false }
  const request = { version:1,action_type:'memory.forget',owner_subject:ownerSubject,operation_id:operation.operation_id,
    operation_digest,parameters:clone(operation.canonical_parameters) }
  const receipt = { version:1,kind:'prime-memory-effect/v1',operation_id:operation.operation_id,operation_digest,
    grant_id:'grant:' + proofNonce,request_id:'12345678-1234-4123-8123-123456789abc',request_digest:nodeDigest('aukora-prime.memory.effect.v1',request),
    owner_subject:ownerSubject,action_type:'memory.forget',status:'applied',result_digest:nodeDigest('aukora-prime.memory-result.v1',result),result:clone(result) }
  const snapshot = { ...initial(),phase:'forgotten',operation,record_summary:summary,operation_digest,approval:'approved',
    forget:'forgotten',forgotten:true,result,receipt,receipt_digest:nodeDigest('aukora-prime.memory-receipt.v1',receipt),authority_settlement:'completed' }
  return { snapshot,presentation,context:{presentation,approved:true,proofNonce,contracts},request }
}
async function test(name, work) {
  try { await work(); cases++ } catch (error) { error.message = `forget-result-check:${name}: ${error.message}`; throw error }
}
const namedFailure = error => error instanceof TypeError && typeof error.code === 'string' &&
  error.error_code === error.code && error.message.startsWith('ui:')
function cancelledFailure(value) {
  assert.throws(() => validateCancelledForgetWorkflow(value, contracts), error => namedFailure(error) && error.code === 'OUTCOME_UNKNOWN')
}

await test('exact-16-snapshot-detached-frozen', async () => {
  const f = await fixture(), result = validateForgetWorkflowSnapshot(f.snapshot, contracts)
  assert.equal(Object.keys(result).length, 16)
  assert.notEqual(result, f.snapshot); assert.notEqual(result.operation, f.snapshot.operation)
  assert(Object.isFrozen(result)); assert(Object.isFrozen(result.operation.canonical_parameters)); assert(Object.isFrozen(result.receipt.result))
  f.snapshot.record_summary.statement = 'Caller changed its record'
  f.snapshot.receipt.result.record_id = 'Caller changed its result'
  assert.equal(result.record_summary.statement, f.presentation.forget_review.statement)
  assert.equal(result.receipt.result.record_id, f.presentation.forget_review.record_id)
})

for (const [name, mutate] of [
  ['missing-field', value => { delete value.recovery_status }], ['extra-field', value => { value.save = 'saved' }],
  ['phase-enum', value => { value.phase = 'saved' }], ['approval-enum', value => { value.approval = 'accepted' }],
  ['forget-enum', value => { value.forget = 'saved' }], ['forgotten-coercion', value => { value.forgotten = 1 }],
  ['reconciliation-coercion', value => { value.reconciliation_required = 'false' }], ['settlement-enum', value => { value.authority_settlement = 'done' }],
  ['error-enum', value => { value.error_code = 'NETWORK_ERROR' }], ['recovery-enum', value => { value.recovery_status = 'completed' }],
  ['recovery-half-reference', value => { value.recovery_operation_id = 'an-operation' }],
  ['recovery-idle-reference', value => { value.recovery_status = 'idle'; value.recovery_operation_id = 'an-operation'; value.recovery_operation_digest = 'sha256:' + '6'.repeat(64) }],
  ['recovery-fact-missing-reference', value => { value.recovery_status = 'forgotten' }],
  ['operation-half-reference', value => { value.operation_digest = null }], ['operation-summary-half-reference', value => { value.record_summary = null }],
  ['wrong-operation-action', value => { value.operation.action_type = 'memory.save' }],
  ['extra-summary-field', value => { value.record_summary.canonical_sha256 = '3'.repeat(64) }],
  ['result-half-receipt', value => { value.result = null }], ['digest-without-receipt', value => { value.result = null; value.receipt = null }],
  ['extra-result-field', value => { value.result.saved = true }], ['extra-receipt-field', value => { value.receipt.task_id = 'not-a-receipt-field' }],
  ['receipt-action-save', value => { value.receipt.action_type = 'memory.save' }], ['receipt-unapplied', value => { value.receipt.status = 'prepared' }],
  ['receipt-id-not-v4', value => { value.receipt.request_id = '12345678-1234-1123-8123-123456789abc' }],
  ['receipt-version', value => { value.receipt.version = 2 }], ['receipt-kind', value => { value.receipt.kind = 'MemoryRecord' }],
]) await test(`snapshot-refuses-${name}`, async () => {
  const { snapshot } = await fixture(); mutate(snapshot)
  assert.throws(() => validateForgetWorkflowSnapshot(snapshot, contracts), namedFailure)
})

for (const name of ['canonical_payload_retained','physical_media_erasure','authority_approval_history_erased','backups_erased','wal_erased','grants_authority']) {
  await test(`snapshot-refuses-false-erasure-or-authority-claim-${name}`, async () => {
    const { snapshot } = await fixture(); snapshot.result[name] = !snapshot.result[name]
    assert.throws(() => validateForgetWorkflowSnapshot(snapshot, contracts), namedFailure)
  })
}

await test('snapshot-rejects-root-and-nested-accessors-without-reading', async () => {
  const root = initial(); let reads = 0
  Object.defineProperty(root, 'phase', { enumerable:true,get() { reads++; return 'idle' } })
  assert.throws(() => validateForgetWorkflowSnapshot(root, contracts), namedFailure); assert.equal(reads, 0)
  const { snapshot } = await fixture()
  Object.defineProperty(snapshot.operation.canonical_parameters, 'statement', { enumerable:true,get() { reads++; return 'changed' } })
  assert.throws(() => validateForgetWorkflowSnapshot(snapshot, contracts), namedFailure); assert.equal(reads, 0)
  assert.throws(() => validateForgetWorkflowSnapshot(Object.assign(Object.create({hidden:true}), initial()), contracts), namedFailure)
})

await test('completed-receipt-real-webcrypto-matches-independent-node-digests', async () => {
  const f = await fixture(), result = await validateForgetWorkflowResult(f.snapshot, f.context)
  assert.deepEqual(result, f.snapshot)
  assert.notEqual(result, f.snapshot); assert(Object.isFrozen(result)); assert(Object.isFrozen(result.receipt))
  assert.equal(result.forgotten, true); assert.equal(result.authority_settlement, 'completed')
  assert.equal(result.result.physical_media_erasure, false); assert.equal(result.result.grants_authority, false)
})

await test('legacy-null-attribution-and-forget-specific-statement-bound', async () => {
  const f = await fixture({ statement:'a'.repeat(4097),attributed_to:null })
  const result = await validateForgetWorkflowResult(f.snapshot, f.context)
  assert.equal(result.record_summary.statement.length, 4097)
  assert.equal(result.record_summary.attributed_to, null)
})

for (const [name, mutate] of [
  ['unapproved-flight', f => { f.context.approved = false }], ['nonce-mismatch', f => { f.context.proofNonce = '6'.repeat(64) }],
  ['nonce-malformed', f => { f.context.proofNonce = 'F'.repeat(64) }], ['nonce-coercion', f => { f.context.proofNonce = 4 }],
  ['presentation-literal', f => { f.presentation.forget_review.statement = f.presentation.forget_review.statement.trim() }],
  ['presentation-attribution', f => { f.presentation.forget_review.attributed_to = 'agent' }],
  ['presentation-record-id', f => { f.presentation.forget_review.record_id = 'another-record' }],
  ['presentation-canonical-hash', f => { f.presentation.forget_review.canonical_sha256 = '7'.repeat(64) }],
  ['presentation-canonical-bytes', f => { f.presentation.canonical_operation += ' ' }],
  ['presentation-operation-digest', f => { f.presentation.operation_digest = 'sha256:' + '7'.repeat(64) }],
  ['operation-task', f => { f.snapshot.operation.task_id = 'another-task' }], ['operation-owner', f => { f.snapshot.operation.owner_id = 'another-owner' }],
  ['operation-original-nonce', f => { f.snapshot.operation.nonce += '-changed' }], ['operation-policy', f => { f.snapshot.operation.policy_version = 'changed' }],
  ['operation-state', f => { f.snapshot.operation.expected_state_version = 'sha256:' + '7'.repeat(64) }],
  ['operation-parameter', f => { f.snapshot.operation.canonical_parameters.at = '2030-01-01T00:00:01Z' }],
  ['paired-record-literal', f => { f.snapshot.record_summary.statement += 'changed' }],
  ['paired-record-attribution', f => { f.snapshot.record_summary.attributed_to = 'agent' }],
  ['operation-and-summary-mutated-together', f => { f.snapshot.operation.canonical_parameters.statement = 'changed'; f.snapshot.record_summary.statement = 'changed' }],
  ['receipt-operation-id', f => { f.snapshot.receipt.operation_id = 'another-operation' }],
  ['receipt-operation-digest', f => { f.snapshot.receipt.operation_digest = 'sha256:' + '8'.repeat(64) }],
  ['receipt-grant', f => { f.snapshot.receipt.grant_id = 'grant:' + '8'.repeat(64) }],
  ['receipt-owner', f => { f.snapshot.receipt.owner_subject = 'aukora:1:' + '8'.repeat(64) }],
  ['receipt-result-versus-result', f => { f.snapshot.receipt.result.record_id = 'another-record' }],
  ['both-result-records', f => { f.snapshot.result.record_id = 'another-record'; f.snapshot.receipt.result.record_id = 'another-record' }],
  ['valid-looking-result-digest', f => { f.snapshot.receipt.result_digest = 'sha256:' + '8'.repeat(64) }],
  ['valid-looking-request-digest', f => { f.snapshot.receipt.request_digest = 'sha256:' + '8'.repeat(64) }],
  ['valid-looking-receipt-digest', f => { f.snapshot.receipt_digest = 'sha256:' + '8'.repeat(64) }],
  ['completed-missing-receipt-digest', f => { f.snapshot.receipt_digest = null }],
  ['completed-pending-reconciliation', f => { f.snapshot.reconciliation_required = true }],
  ['completed-unknown-error', f => { f.snapshot.error_code = 'OUTCOME_UNKNOWN' }],
  ['completed-reconciliation-error', f => { f.snapshot.error_code = 'RECONCILIATION_REQUIRED' }],
  ['pending-without-reconciliation', f => { f.snapshot.authority_settlement = 'pending' }],
  ['logical-result-without-confirmed-forgotten', f => { f.snapshot.forgotten = false }],
  ['logical-result-without-forgotten-phase', f => { f.snapshot.phase = 'refused' }],
]) await test(`full-result-refuses-${name}`, async () => {
  const f = await fixture(); mutate(f)
  await assert.rejects(validateForgetWorkflowResult(f.snapshot, f.context), namedFailure)
})

for (const [name, domain] of [
  ['result','aukora-prime.memory.result.v1'], ['request','aukora-prime.memory-effect.v1'], ['receipt','aukora-prime.memory.receipt.v1'],
]) await test(`full-result-refuses-old-or-alternate-domain-${name}`, async () => {
  const f = await fixture()
  if (name === 'result') f.snapshot.receipt.result_digest = nodeDigest(domain, f.snapshot.result)
  if (name === 'request') f.snapshot.receipt.request_digest = nodeDigest(domain, f.request)
  f.snapshot.receipt_digest = nodeDigest(name === 'receipt' ? domain : 'aukora-prime.memory-receipt.v1', f.snapshot.receipt)
  await assert.rejects(validateForgetWorkflowResult(f.snapshot, f.context), error => namedFailure(error) && error.code === 'TARGET_MISMATCH')
})

for (const includeDigest of [false,true]) await test(`pending-settlement-truthfully-retains-reconciliation-${includeDigest}`, async () => {
  const f = await fixture(); f.snapshot.authority_settlement = 'pending'; f.snapshot.reconciliation_required = true
  f.snapshot.error_code = 'RECONCILIATION_REQUIRED'
  if (!includeDigest) f.snapshot.receipt_digest = null
  const result = await validateForgetWorkflowResult(f.snapshot, f.context)
  assert.equal(result.forgotten, true); assert.equal(result.reconciliation_required, true)
  assert.equal(result.authority_settlement, 'pending')
})

await test('completed-recovery-receipt-still-binds-original-review-and-proof', async () => {
  const f = await fixture()
  f.snapshot.operation = null; f.snapshot.record_summary = null; f.snapshot.operation_digest = null
  f.snapshot.recovery_status = 'forgotten'; f.snapshot.recovery_operation_id = f.presentation.operation.operation_id
  f.snapshot.recovery_operation_digest = f.presentation.operation_digest
  assert.equal((await validateForgetWorkflowResult(f.snapshot, f.context)).forgotten, true)
  f.snapshot.recovery_operation_id = 'another-operation'
  await assert.rejects(validateForgetWorkflowResult(f.snapshot, f.context), error => namedFailure(error) && error.code === 'TARGET_MISMATCH')
})

await test('unrelated-save-recovery-is-never-relabeled-forget', async () => {
  const f = await fixture()
  const value = { ...initial(),phase:'outcome_unknown',approval:'unknown',forget:'unknown',forgotten:null,
    reconciliation_required:true,error_code:'RECONCILIATION_REQUIRED',recovery_status:'saved',
    recovery_operation_id:'another-save-operation',recovery_operation_digest:'sha256:' + '9'.repeat(64) }
  const result = await validateForgetWorkflowResult(value, f.context)
  assert.equal(result.recovery_status, 'saved'); assert.equal(result.forgotten, null)
  assert.equal(result.result, null); assert.equal(result.reconciliation_required, true)
})

for (const [name, mutate] of [
  ['approval-pending', value => { value.phase = 'approval_pending'; value.approval = 'pending' }],
  ['forget-pending', value => { value.phase = 'forget_pending'; value.approval = 'approved'; value.forget = 'pending'; value.forgotten = null }],
  ['recovery-pending', value => { value.recovery_status = 'pending' }],
  ['proof-only-without-reconciliation', value => { value.approval = 'approved' }],
  ['nullable-effect-without-reconciliation', value => { value.forgotten = null }],
  ['unknown-code-without-reconciliation', value => { value.error_code = 'OUTCOME_UNKNOWN' }],
  ['unknown-approval-without-reconciliation', value => { value.approval = 'unknown' }],
]) await test(`unfinished-handler-return-is-fenced-${name}`, async () => {
  const f = await fixture(), value = initial(); mutate(value)
  await assert.rejects(validateForgetWorkflowResult(value, f.context), error => namedFailure(error) && error.code === 'OUTCOME_UNKNOWN')
})

await test('async-validation-detaches-caller-result-and-review-before-await', async () => {
  const f = await fixture(); let release
  const gate = new Promise(resolve => { release = resolve })
  const delayed = { ...contracts,operationDigest: async operation => { await gate; return contracts.operationDigest(operation) } }
  const pending = validateForgetWorkflowResult(f.snapshot, { ...f.context,contracts:delayed })
  f.snapshot.receipt.grant_id = 'grant:' + '9'.repeat(64)
  f.snapshot.operation.task_id = 'changed-after-start'
  f.presentation.forget_review.statement = 'changed-after-start'
  f.presentation.operation.task_id = 'changed-after-start'
  release()
  const result = await pending
  assert.equal(result.receipt.grant_id, 'grant:' + proofNonce)
  assert.notEqual(result.operation.task_id, 'changed-after-start')
})

for (const phase of ['idle','unavailable']) await test(`cancelled-known-unsent-${phase}`, async () => {
  const value = { ...initial(),phase,error_code:phase === 'unavailable' ? 'UNAVAILABLE' : null }
  const result = validateCancelledForgetWorkflow(value, contracts)
  assert.equal(result.forget, 'not_attempted'); assert.equal(result.forgotten, false); assert(Object.isFrozen(result))
})
for (const phase of ['idle','unavailable']) await test(`cancelled-confirmed-completed-content-free-${phase}`, async () => {
  const value = { ...initial(),phase,approval:'approved',forget:'forgotten',forgotten:true,authority_settlement:'completed',
    error_code:phase === 'unavailable' ? 'UNAVAILABLE' : null }
  const result = validateCancelledForgetWorkflow(value, contracts)
  assert.equal(result.result, null); assert.equal(result.receipt, null); assert.equal(result.reconciliation_required, false)
})
for (const [name, mutate] of [
  ['pending-settlement', value => { value.approval = 'approved'; value.forget = 'forgotten'; value.forgotten = true; value.authority_settlement = 'pending'; value.reconciliation_required = true; value.error_code = 'RECONCILIATION_REQUIRED' }],
  ['proof-only', value => { value.approval = 'approved' }], ['approval-unknown', value => { value.approval = 'unknown'; value.reconciliation_required = true }],
  ['forget-unknown', value => { value.approval = 'approved'; value.forget = 'unknown'; value.forgotten = null; value.reconciliation_required = true }],
  ['pending-approval', value => { value.approval = 'pending' }], ['pending-forget', value => { value.forget = 'pending'; value.forgotten = null }],
  ['contradictory-completed', value => { value.authority_settlement = 'completed' }],
  ['rejected-code', value => { value.error_code = 'REVOKED' }], ['recovery-pending', value => { value.recovery_status = 'pending' }],
  ['known-unsent-recovery-reference', value => { value.recovery_status = 'known_unsent'; value.recovery_operation_id = 'an-operation'; value.recovery_operation_digest = 'sha256:' + '9'.repeat(64) }],
  ['malformed-extra-field', value => { value.saved = true }],
]) await test(`cancelled-keeps-fence-${name}`, async () => { const value = initial(); mutate(value); cancelledFailure(value) })
await test('cancelled-content-and-malformed-return-stay-fenced', async () => {
  cancelledFailure((await fixture()).snapshot)
  cancelledFailure(null); cancelledFailure(new Error('synthetic rejected handler')); cancelledFailure({})
})

console.log(JSON.stringify({ result:'PASS',cases,assertions,scope:'SOURCE synthetic forget result consistency',
  bridge_tests:false,authority_tests:false,memory_tests:false,real_authority_claim:false,
  real_credentials:false,effects:false,network:false,runtime:false,build:false }))
