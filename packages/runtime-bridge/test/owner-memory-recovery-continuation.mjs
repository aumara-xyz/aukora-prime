// SPDX-License-Identifier: AGPL-3.0-or-later
// Source-functional fixture ONLY. Reuse the actual H/B/C/D assembled() and
// save() helpers from owner-memory-facade.test.mjs. B's 6a63ae0f recovery hook
// must be awaited by H's actual client; this fixture never invokes it directly.
// No production qualification, PostgreSQL or deployed IPC evidence is implied.
import assert from 'node:assert/strict'
import * as contracts from '../../contracts/src/browser.mjs'
import {draft,ok,assertSaved} from './owner-memory-fixture.mjs'

export async function assertRecoveryContinuation(t,{assembled,save}) {
  const a=await assembled(t),m=a.mount();await m.login()
  a.f.delivery.set('memory.save',reply=>{ok(reply);throw new Error('test-only interruption after actual committed save')})
  assert.equal((await save(m,'continuation-interrupted-save')).save,'unknown')
  a.f.delivery.delete('memory.save')
  const oldCall=a.f.calls.find(call=>call.method==='memory.save')
  const operation=oldCall.input.operation,proof=oldCall.input.approval_proof
  const committed=ok(a.f.replies.find(reply=>reply.method==='memory.save').result)
  const effect=()=>a.f.pool.db.prepare('SELECT result_bytes,receipt_bytes FROM prime_memory_effects WHERE operation_id=?').get(operation.operation_id)
  const before=effect();assert(before)
  const signatures=a.signatures()
  const recovered=await m.client.recover({operation_id:operation.operation_id})
  assert.equal(recovered.saved,true);assert.equal(recovered.reconciliation_required,false)
  assert.equal(recovered.authority_settlement,'completed')
  assert.deepEqual(recovered.record,committed.record)
  assert.deepEqual(recovered.receipt,committed.receipt)
  assert.deepEqual(recovered.record,JSON.parse(Buffer.from(before.result_bytes).toString('utf8')))
  assert.deepEqual(recovered.receipt,JSON.parse(Buffer.from(before.receipt_bytes).toString('utf8')))
  assert.equal(recovered.receipt.operation_id,operation.operation_id)
  assert.equal(recovered.receipt.operation_digest,await contracts.operationDigest(operation))
  assert.equal(recovered.receipt.grant_id,'grant:'+proof.nonce)
  assert.equal(recovered.citation.verdict,'VERIFIED')
  assert.equal(a.f.operationState(operation.operation_id).status,'COMPLETED')
  const recoveredController=m.controller.getSnapshot()
  assert.equal(recoveredController.phase,'approved')
  assert.equal(recoveredController.error_code,null);assert.equal(recoveredController.expired,false)
  assert.equal(recoveredController.approval_action_pending,false)
  assert.equal(recoveredController.approval_action_available,true)
  const displayed=recoveredController.approval_action_result
  assert.equal(displayed.saved,true);assert.equal(displayed.save,'saved')
  assert.equal(displayed.authority_settlement,'completed');assert.equal(displayed.reconciliation_required,false)
  assert.deepEqual(displayed.record,recovered.record);assert.deepEqual(displayed.receipt,recovered.receipt)
  assert.equal(displayed.receipt_digest,recovered.receipt_digest)
  assert.deepEqual(displayed.index,recovered.index);assert.deepEqual(displayed.citation,recovered.citation)
  assert.equal(displayed.citation_status,'verified')
  assert.equal(recoveredController.presentation.canonical_operation,contracts.canonicalJson(operation))
  assert.equal(recoveredController.presentation.operation_digest,recovered.receipt.operation_digest)
  const repeated=await m.client.recover({operation_id:operation.operation_id})
  assert.equal(repeated.saved,true);assert.deepEqual(repeated.receipt,recovered.receipt)
  assert.deepEqual(m.controller.getSnapshot().approval_action_result,displayed)
  assert.equal(a.signatures(),signatures,'reconciliation must not request a new approval signature')
  assert.equal(a.f.count('memory.save'),1);assert.equal(a.f.count('owner.approvalComplete'),1)
  const after=effect()
  assert.deepEqual(Buffer.from(after.result_bytes),Buffer.from(before.result_bytes))
  assert.deepEqual(Buffer.from(after.receipt_bytes),Buffer.from(before.receipt_bytes))
  assert.equal(a.f.tableCount('prime_memory_effects'),1)
  const unrelated=draft('continuation-new-unrelated-save')
  const input=JSON.parse(unrelated.extraction_json)
  input.statement='A new synthetic note after verified receipt recovery.'
  unrelated.extraction_json=JSON.stringify(input)
  const next=await m.client.proposeSave(unrelated)
  assert.equal(next.phase,'proposed','the same controller must admit a new operation after verified recovery')
  assert.notEqual(next.operation.operation_id,operation.operation_id)
  assert.notEqual(next.operation.canonical_parameters.capture_sha256,operation.canonical_parameters.capture_sha256)
  assert(await m.controller.prepare())
  const first=m.controller.submitApproval(),second=m.controller.submitApproval()
  assert.equal(first,second)
  const newSaved=await first;assertSaved(newSaved)
  assert.equal(newSaved.operation.operation_id,next.operation.operation_id)
  assert.equal(newSaved.authority_settlement,'completed')
  assert.equal(a.signatures(),signatures+1,'only the unrelated new operation needs a new approval signature')
  assert.equal(a.f.count('memory.save'),2);assert.equal(a.f.count('owner.approvalComplete'),2)
  assert.equal(a.f.calls.filter(call=>call.method==='memory.save'&&call.input.operation.operation_id===operation.operation_id).length,1)
  assert.equal(a.f.tableCount('prime_memory_effects'),2)
  const finalOld=effect()
  assert.deepEqual(Buffer.from(finalOld.result_bytes),Buffer.from(before.result_bytes))
  assert.deepEqual(Buffer.from(finalOld.receipt_bytes),Buffer.from(before.receipt_bytes))
  assert.equal(a.f.operationState(operation.operation_id).status,'COMPLETED')
  console.log(JSON.stringify({case:'H-same-controller-genuine-recovery-continuation',result:'PASS',
    old_operation_save_calls:1,total_save_calls:2,total_approval_calls:2,total_effects:2,
    recovery_signatures:0,recovery_effects:0,controller_recovered_phase:recoveredController.phase,
    synthetic_credentials:true,sqlite_fixture:true,production_qualification:false}))
  return {recovered,recoveredController,newSaved,oldOperation:operation}
}
