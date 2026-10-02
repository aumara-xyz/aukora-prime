// SPDX-License-Identifier: AGPL-3.0-or-later
// Source correctness ONLY: actual B a20812e72eed05b2981c8a799d4c7d6155f0de49
// invocation hook, C passkey verification/stores and D effects/ledger receipts.
// The expanded save seed uses raw bridge/C/D calls, not B's expanded-save join.
// Disposable synthetic credentials, SQLite and same-process calls do not
// establish deployed enrollment, human attendance, IPC/UID isolation or PG durability.
import {test} from 'node:test'
import assert from 'node:assert/strict'
import * as contracts from '../../contracts/src/runtime.mjs'
import {createOwnerForgetWorkflow} from '../src/owner-forget-workflow.mjs'
import {extraction,fixture,ok} from './owner-memory-fixture.mjs'

const fromBytes=value=>JSON.parse(Buffer.from(value).toString('utf8'))

test('pinned B private forget invocation coalesces submissions and rejects concurrent public approval before one genuine logical forget',async t=>{
  const f=await fixture(t,{actions:['memory.save','memory.forget']});await f.login()
  const session_token=ok(f.replies.find(reply=>reply.method==='owner.loginComplete').result).session_token

  // Genuine raw bridge seed: C issues the public proof template, the synthetic
  // authenticator signs its actual challenge, and C verifies before D writes.
  const seedDraft={extraction_json:JSON.stringify({statement:extraction.statement}),idempotency_key:'invocation-forget-raw-expanded-seed'}
  const proposed=ok(await f.bridgeCall('memory.proposeSave',{session_token,...seedDraft})),seedOperation=proposed.operation
  assert.deepEqual(Object.keys(proposed.memory_capture).sort(),['attributed_to','capture_metadata','evidence_quote','statement'])
  assert.deepEqual(Object.keys(seedOperation.canonical_parameters).sort(),
    ['attributed_to','capture_metadata','capture_sha256','evidence_quote','heads','idempotency_key_sha256','statement'])
  const seedReview=ok(await f.bridgeCall('owner.approvalChallenge',{session_token,operation:seedOperation}))
  const seedProof={...seedReview.proof_template,material:f.auth.assertion(seedReview.public_key.challenge)}
  contracts.validateContract('ApprovalProof',seedProof)
  const seedApproved=ok(await f.bridgeCall('owner.approvalComplete',{session_token,operation:seedOperation,proof:seedProof}))
  assert.equal(seedApproved.status,'APPROVED');assert.deepEqual(seedApproved.approval_proof,seedProof)
  const saved=ok(await f.bridgeCall('memory.save',{session_token,...seedDraft,operation:seedOperation,approval_proof:seedApproved.approval_proof}))
  contracts.validateContract('MemoryRecord',saved.record)
  assert.equal(saved.record.storage_status,'saved');assert.equal(saved.authority_settlement,'completed')
  assert.equal(saved.reconciliation_required,false);assert.equal(saved.receipt.grant_id,'grant:'+seedProof.nonce)
  assert.deepEqual(saved.receipt.result,saved.record);assert.equal(f.operationState(seedOperation.operation_id).status,'COMPLETED')
  assert.equal(f.controller.getSnapshot().phase,'authenticated','the expanded seed did not use B review or approval')
  assert.equal(f.tableCount('prime_memory_records'),1);assert.equal(f.tableCount('prime_memory_effects'),1)
  const seedRow=f.pool.db.prepare('SELECT result_bytes,receipt_bytes FROM prime_memory_effects WHERE operation_id=?').get(seedOperation.operation_id)
  assert.ok(seedRow);assert.deepEqual(fromBytes(seedRow.result_bytes),saved.record)
  assert.deepEqual(fromBytes(seedRow.receipt_bytes),saved.receipt)
  const retainedPayload=Buffer.from(f.pool.db.prepare('SELECT canonical_bytes FROM prime_memory_records WHERE record_id=?').get(saved.record.record_id).canonical_bytes)
  assert.equal(retainedPayload.toString('utf8'),saved.record.canonical_bytes)
  assert.deepEqual(f.state().state.consumedIds,['approval:'+seedProof.nonce])

  const workflow=createOwnerForgetWorkflow({controller:f.controller,memory:f.adapters.memory,contracts})
  t.after(()=>workflow.dispose())
  let hookCalls=0,hookView,hookOptions
  f.controller.setForgetAction((view,options)=>{
    hookCalls++;hookView=view;hookOptions=options
    return workflow.approveAndForget(options)
  })
  const forgetProposal=await workflow.proposeForget({record_id:saved.record.record_id}),operation=forgetProposal.operation
  assert.equal(forgetProposal.phase,'proposed');assert.equal(operation.action_type,'memory.forget')
  assert.equal(operation.canonical_parameters.statement,extraction.statement)
  assert.equal(operation.canonical_parameters.attributed_to,'owner')
  assert.notEqual(await f.controller.prepare(),null)
  const review=f.controller.getSnapshot().presentation
  assert.equal(f.controller.getSnapshot().phase,'review_ready')
  assert.deepEqual(review.operation,operation);assert.equal(review.operation_digest,forgetProposal.operation_digest)

  const signatures=f.signerCalls(),approvals=f.count('owner.approvalComplete'),gate=f.gate('owner.approvalComplete')
  const first=f.controller.submitApproval(),second=f.controller.submitApproval()
  assert.equal(first,second,'duplicate submissions share the owned invocation promise')
  await gate.entered(1)
  assert.equal(await f.controller.approve(),null,'public approval cannot share or supply the owned hook proof')
  assert.equal(f.controller.submitApproval(),first)
  assert.equal(hookCalls,1);assert.equal(hookView,review)
  assert.ok(Object.isFrozen(hookOptions));assert.deepEqual(Object.keys(hookOptions).sort(),['approve','signal'])
  assert.equal(typeof hookOptions.approve,'function');assert.ok(hookOptions.signal instanceof AbortSignal)
  assert.equal(hookOptions.signal.aborted,false)
  assert.equal(ok(gate.entries[0].result).status,'APPROVED')
  assert.equal(f.operationState(operation.operation_id).status,'APPROVED')
  assert.equal(f.signerCalls(),signatures+1);assert.equal(f.count('owner.approvalComplete'),approvals+1)
  assert.equal(f.count('memory.forget'),0);assert.equal(f.tableCount('prime_memory_tombstones'),0)
  assert.deepEqual(f.state().state.consumedIds,['approval:'+seedProof.nonce])
  gate.release();const forgotten=await first;assert.equal(await second,forgotten)
  assert.ok(forgotten,'B must confirm the result produced by its private forget invocation')

  assert.equal(forgotten.phase,'forgotten');assert.equal(forgotten.approval,'approved')
  assert.equal(forgotten.forget,'forgotten');assert.equal(forgotten.forgotten,true)
  assert.deepEqual(forgotten.result,{record_id:saved.record.record_id,state:'tombstoned',canonical_payload_retained:true,
    physical_media_erasure:false,authority_approval_history_erased:false,backups_erased:false,wal_erased:false,grants_authority:false})
  const genuine=ok(f.replies.find(reply=>reply.method==='memory.forget').result)
  const effect=f.pool.db.prepare('SELECT operation_bytes,result_bytes,receipt_bytes FROM prime_memory_effects WHERE operation_id=?').get(operation.operation_id)
  assert.ok(effect);assert.deepEqual(fromBytes(effect.operation_bytes),operation)
  assert.deepEqual(forgotten.result,fromBytes(effect.result_bytes))
  assert.deepEqual(forgotten.receipt,genuine.receipt);assert.deepEqual(forgotten.receipt,fromBytes(effect.receipt_bytes))
  const call=f.calls.find(item=>item.method==='memory.forget').input
  assert.deepEqual(call.operation,operation);assert.equal(forgotten.receipt.grant_id,'grant:'+call.approval_proof.nonce)
  assert.equal(forgotten.receipt.operation_digest,forgetProposal.operation_digest)
  assert.equal(forgotten.receipt_digest,genuine.receipt_digest)
  assert.equal(forgotten.authority_settlement,'completed');assert.equal(forgotten.reconciliation_required,false)
  assert.equal(f.operationState(operation.operation_id).status,'COMPLETED');assert.equal(f.settlementCalls(),2)
  const displayed=f.controller.getSnapshot()
  assert.equal(displayed.phase,'approved');assert.equal(displayed.error_code,null)
  assert.equal(displayed.approval_action_pending,false);assert.equal(displayed.approval_action_result,null)
  assert.deepEqual(displayed.forget_action_result,forgotten)
  assert.equal(hookCalls,1);assert.equal(f.count('memory.save'),1);assert.equal(f.count('memory.forget'),1)
  assert.equal(f.count('owner.approvalComplete'),2);assert.equal(f.signerCalls(),signatures+1)
  assert.equal(f.tableCount('prime_memory_records'),1);assert.equal(f.tableCount('prime_memory_effects'),2)
  assert.equal(f.tableCount('prime_memory_tombstones'),1)
  assert.deepEqual([...f.state().state.consumedIds].sort(),['approval:'+seedProof.nonce,'approval:'+call.approval_proof.nonce].sort())
  assert.deepEqual(Buffer.from(f.pool.db.prepare('SELECT canonical_bytes FROM prime_memory_records WHERE record_id=?').get(saved.record.record_id).canonical_bytes),retainedPayload)
  const retainedSeed=f.pool.db.prepare('SELECT result_bytes,receipt_bytes FROM prime_memory_effects WHERE operation_id=?').get(seedOperation.operation_id)
  assert.deepEqual(Buffer.from(retainedSeed.result_bytes),Buffer.from(seedRow.result_bytes))
  assert.deepEqual(Buffer.from(retainedSeed.receipt_bytes),Buffer.from(seedRow.receipt_bytes))
})
