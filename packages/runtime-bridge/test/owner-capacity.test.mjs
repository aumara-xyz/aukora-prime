// SPDX-License-Identifier: AGPL-3.0-or-later
// Source correctness ONLY: real B controller, C passkey/stores and D effects.
// Disposable synthetic credentials and the SQLite dialect fixture do not
// establish deployed owner isolation or PostgreSQL durability.
import {test} from 'node:test'
import assert from 'node:assert/strict'
import * as contracts from '../../contracts/src/runtime.mjs'
import {draft,ok,fixture,assertSaved} from './owner-memory-fixture.mjs'

const fromBytes=value=>JSON.parse(Buffer.from(value).toString('utf8'))
const effectFor=(f,operation)=>{
  const row=f.pool.db.prepare('SELECT result_bytes,receipt_bytes FROM prime_memory_effects WHERE operation_id=?').get(operation.operation_id)
  assert.ok(row,'each saved operation must have an actual committed D effect')
  return {result:fromBytes(row.result_bytes),receipt:fromBytes(row.receipt_bytes)}
}

test('one owner session completes 17 genuine saves and repeats its latest completion without another effect',async t=>{
  const f=await fixture(t);await f.login()
  const operations=new Set(),savedReferences=[]
  let latestInput,latestReply,latestOperation,latestEffect

  for(let index=0;index<17;index++) {
    const input=draft('same-session-completed-save-'+index)
    const operation=await f.prepare(input)
    await f.workflow.approveAndSave()
    const saved=f.workflow.getSnapshot();assertSaved(saved)
    const digest=await contracts.operationDigest(operation)
    const saveCall=f.calls.find(call=>call.method==='memory.save'&&call.input.operation.operation_id===operation.operation_id)
    assert.ok(saveCall,'each completion must come from its genuine approved save call')
    const actual=ok(f.replies.find(reply=>reply.method==='memory.save'&&reply.result.receipt?.operation_id===operation.operation_id)?.result)
    const effect=effectFor(f,operation)

    assert.deepEqual(saveCall.input.operation,operation)
    assert.equal(saveCall.input.extraction_json,input.extraction_json)
    assert.equal(saveCall.input.idempotency_key,input.idempotency_key)
    assert.equal(saveCall.input.approval_proof.operation_id,operation.operation_id)
    assert.equal(saveCall.input.approval_proof.operation_digest,digest)
    assert.equal(saveCall.input.approval_proof.owner_id,operation.owner_id)
    assert.equal(saveCall.input.approval_proof.owner_id,f.auth.identity.owner_id)
    assert.equal(saved.operation_digest,digest)
    assert.deepEqual(saved.record,effect.result)
    assert.deepEqual(saved.receipt,effect.receipt,'the workflow returns the unchanged genuine D ledger receipt')
    assert.deepEqual(actual.record,effect.result)
    assert.deepEqual(actual.receipt,effect.receipt)
    assert.equal(saved.receipt.operation_id,operation.operation_id)
    assert.equal(saved.receipt.operation_digest,digest)
    assert.equal(saved.receipt.grant_id,'grant:'+saveCall.input.approval_proof.nonce)
    assert.equal(saved.receipt.owner_subject,operation.target_identity.owner_subject)
    assert.equal(saved.receipt.owner_subject,f.auth.identity.subject)
    assert.equal(saved.receipt.action_type,'memory.save')
    assert.equal(saved.authority_settlement,'completed')
    assert.equal(saved.reconciliation_required,false)
    assert.equal(actual.authority_settlement,'completed')
    assert.equal(actual.reconciliation_required,false)
    const status=f.operationState(operation.operation_id)
    assert.equal(status.status,'COMPLETED')
    assert.equal(status.operation_digest,digest)

    const reference=await f.workflowStore.get(f.boundHost(),operation.operation_id)
    assert.equal(reference.phase,'saved')
    assert.equal(reference.record_id,saved.record.record_id)
    assert.equal(reference.request_id,saved.receipt.request_id)
    assert.equal(reference.request_digest,saved.receipt.request_digest)
    assert.equal(reference.receipt_digest,actual.receipt_digest)
    assert.ok(!operations.has(operation.operation_id),'each draft key creates a distinct approved operation')
    operations.add(operation.operation_id);savedReferences.push(reference)
    assert.equal(f.count('memory.save'),index+1)
    assert.equal(f.count('owner.approvalComplete'),index+1)
    latestInput=structuredClone(saveCall.input);latestReply=structuredClone(actual)
    latestOperation=operation;latestEffect=effect
  }

  assert.equal(operations.size,17);assert.equal(savedReferences.length,17)
  assert.equal(new Set(savedReferences.map(reference=>reference.request_id)).size,17)
  assert.equal(f.tableCount('prime_memory_records'),17)
  assert.equal(f.tableCount('prime_memory_effects'),17)
  assert.equal(f.tableCount('prime_memory_requests'),17)
  assert.equal(f.tableCount('prime_runtime_workflows'),17)
  assert.equal(f.count('memory.save'),17);assert.equal(f.count('owner.approvalComplete'),17)
  assert.equal(f.count('owner.loginComplete'),1)
  assert.equal(f.signerCalls(),18,'one login signature and one genuine approval signature per save')

  const signatures=f.signerCalls(),writes=f.count('memory.save'),approvals=f.count('owner.approvalComplete')
  delete latestInput.session_token
  const repeated=ok(await f.adapters.memory.save(latestInput))
  assert.deepEqual(repeated,latestReply,'an exact adapter retry verifies and returns the original genuine completed reply')
  assert.equal(f.count('memory.save'),writes+1,'the retry reaches the real bridge for factual completion verification')
  assert.equal(f.count('memory.save'),18)
  assert.equal(f.count('owner.approvalComplete'),approvals)
  assert.equal(f.signerCalls(),signatures)
  assert.equal(f.tableCount('prime_memory_records'),17)
  assert.equal(f.tableCount('prime_memory_effects'),17)
  assert.equal(f.tableCount('prime_memory_requests'),17)
  assert.equal(f.tableCount('prime_runtime_workflows'),17)
  assert.deepEqual(effectFor(f,latestOperation),latestEffect)
  assert.equal(f.operationState(latestOperation.operation_id).status,'COMPLETED')
  assert.equal(f.count('owner.loginComplete'),1)
})
