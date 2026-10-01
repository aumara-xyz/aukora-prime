// SPDX-License-Identifier: AGPL-3.0-or-later
// Test ONLY source join: externally supplied B controller, actual C passkey
// verification/stores, actual D effects and H's injected UI adapter/workflow.
// Synthetic P-256 credentials, SQLite dialect fixture and same-process calls
// do not establish PostgreSQL durability, authenticated IPC or UID isolation.
// The integration runner supplies a pinned, temporary B source snapshot via
// PRIME_OWNER_HOOK_CONTROLLER; this file never edits or vendors B source.
import {test} from 'node:test'
import assert from 'node:assert/strict'
import {isAbsolute} from 'node:path'
import {pathToFileURL} from 'node:url'
import * as browserContracts from '../../contracts/src/browser.mjs'
import {createPrimeOwnerController as baselineController} from '../../ui/prime-authority/src/client/controller.mjs'
import {extraction,draft,ok,attempt,fixture,assertSaved,assertUnknown} from './owner-memory-fixture.mjs'

const dependency=process.env.PRIME_OWNER_HOOK_CONTROLLER
if(dependency&&!isAbsolute(dependency))throw new Error('PRIME_OWNER_HOOK_CONTROLLER must name an absolute temporary B controller source path')
const controllerFactory=dependency?(await import(pathToFileURL(dependency).href)).createPrimeOwnerController:baselineController
const skip=dependency?false:'B hook dependency not imported: set PRIME_OWNER_HOOK_CONTROLLER to the pinned temporary controller snapshot; local baseline is unchanged'
const joinedTest=(name,work)=>test(name,{skip},work)

async function hookedFixture(t) {
  assert.equal(typeof controllerFactory,'function','the external B snapshot must export createPrimeOwnerController')
  const f=await fixture(t,{controllerFactory,uiContracts:browserContracts})
  assert.equal(typeof f.controller.setApprovalAction,'function','the external B controller must provide the approved hook seam')
  assert.equal(typeof f.controller.submitApproval,'function','the external B controller must provide the owner submission method')
  let hookCalls=0
  const attach=()=>f.controller.setApprovalAction(()=>{hookCalls++;return f.workflow.approveAndSave()})
  attach()
  return {...f,attach,detach:()=>f.controller.setApprovalAction(null),hookCalls:()=>hookCalls}
}

async function freshReview(f,key) {
  await f.login()
  await f.workflow.proposeSave(draft(key))
  assert.equal(f.workflow.getSnapshot().phase,'proposed','a fresh authenticated proposal must be accepted after the cancelled hook finishes')
  assert.notEqual(await f.controller.prepare(),null,'the fresh proposal must support an actual C review challenge')
  assert.equal(f.controller.getSnapshot().phase,'review_ready')
}

joinedTest('external B submitApproval joins the exact owner literal to a genuine C/D saved receipt, citation and pending index',async t=>{
  const f=await hookedFixture(t);await f.login();const operation=await f.prepare(draft('joined-hook-save'))
  const review=f.controller.getSnapshot().presentation
  assert.equal(review.memory_review.statement,extraction.statement);assert.equal(review.memory_review.attributed_to,'owner')
  await f.controller.submitApproval()
  const saved=f.workflow.getSnapshot();assertSaved(saved)
  const realReply=ok(f.replies.find(reply=>reply.method==='memory.save').result)
  assert.deepEqual(saved.receipt,realReply.receipt)
  assert.equal(saved.authority_settlement,'completed');assert.equal(saved.reconciliation_required,false)
  assert.equal(saved.citation_status,'verified');assert.equal(saved.citation.verdict,'VERIFIED')
  assert.equal(saved.citation.record_id,saved.record.record_id);assert.equal(saved.citation.grants_authority,false)
  assert.equal(saved.index.status,'pending');assert.equal(saved.index.indexed,false);assert.equal(saved.index.searchable,false)
  const literal=JSON.parse(saved.record.canonical_bytes)
  assert.equal(literal.statement,review.memory_review.statement);assert.equal(literal.attributedTo,review.memory_review.attributed_to)
  assert.equal(f.controller.getSnapshot().approval_action_result.saved,true)
  assert.deepEqual(f.controller.getSnapshot().approval_action_result.receipt,saved.receipt)
  assert.equal(f.operationState(operation.operation_id).status,'COMPLETED')
  assert.equal(f.hookCalls(),1);assert.equal(f.count('owner.approvalComplete'),1);assert.equal(f.count('memory.save'),1)
  assert.equal(f.tableCount('prime_memory_records'),1);assert.equal(f.tableCount('prime_memory_effects'),1)
})

joinedTest('external B hook coalesces duplicate and reentrant owner submissions into one actual C approval and D effect',async t=>{
  const f=await hookedFixture(t);await f.login();await f.prepare(draft('joined-hook-coalesced'))
  let reentrant,requested=false
  const unsubscribe=f.controller.subscribe(()=>{
    if(f.controller.getSnapshot().approval_action_pending&&!requested) {
      requested=true;reentrant=f.controller.submitApproval()
    }
  })
  const gate=f.gate('memory.save'),first=f.controller.submitApproval(),second=f.controller.submitApproval()
  await gate.entered(1)
  assert.ok(reentrant instanceof Promise);assert.equal(first,second);assert.equal(reentrant,first)
  assert.equal(f.hookCalls(),1);assert.equal(f.count('owner.approvalComplete'),1);assert.equal(f.count('memory.save'),1)
  gate.release();await Promise.all([first,second,reentrant]);unsubscribe()
  assertSaved(f.workflow.getSnapshot())
  assert.equal(f.tableCount('prime_memory_records'),1);assert.equal(f.tableCount('prime_memory_effects'),1)
})

joinedTest('external B hook preserves unknown after a genuine D save reply is lost and blocks automatic replay',async t=>{
  const f=await hookedFixture(t);await f.login();const operation=await f.prepare(draft('joined-hook-reply-lost'))
  f.delivery.set('memory.save',answer=>{ok(answer);throw new Error('synthetic actual D save reply lost at the H delivery seam')})
  await f.controller.submitApproval();assertUnknown(f.workflow.getSnapshot())
  assert.equal(f.controller.getSnapshot().phase,'outcome_unknown')
  assert.equal(f.controller.getSnapshot().approval_action_result.save,'unknown')
  assert.equal(f.operationState(operation.operation_id).status,'COMPLETED')
  assert.equal(f.tableCount('prime_memory_records'),1);assert.equal(f.tableCount('prime_memory_effects'),1)
  f.delivery.delete('memory.save')
  await f.controller.submitApproval()
  await attempt(()=>f.workflow.proposeSave(draft('joined-hook-no-unsafe-replacement')))
  assert.equal(f.hookCalls(),1);assert.equal(f.count('memory.proposeSave'),1);assert.equal(f.count('memory.save'),1)
  assertUnknown(f.workflow.getSnapshot())
})

joinedTest('detaching the external B hook while the genuine C approval reply is held prevents any D save',async t=>{
  const f=await hookedFixture(t);await f.login();const operation=await f.prepare(draft('joined-hook-detach-held-approval'))
  const gate=f.gate('owner.approvalComplete'),pending=f.controller.submitApproval()
  await gate.entered(1);assert.equal(ok(gate.entries[0].result).status,'APPROVED')
  f.detach();gate.release();await pending
  assert.equal(f.controller.getSnapshot().owner,null)
  assert.equal(f.count('memory.save'),0)
  assert.equal(f.tableCount('prime_memory_records'),0);assert.equal(f.tableCount('prime_memory_effects'),0)
  assert.equal(f.operationState(operation.operation_id).status,'APPROVED')
  assert.equal(f.workflow.getSnapshot().receipt,null);assert.equal(f.workflow.getSnapshot().saved,false)
})

joinedTest('detaching the external B hook while a genuine applied D save reply is held preserves unknown without replay',async t=>{
  const f=await hookedFixture(t);await f.login();const operation=await f.prepare(draft('joined-hook-detach-held-save'))
  const gate=f.gate('memory.save'),pending=f.controller.submitApproval()
  await gate.entered(1);ok(gate.entries[0].result)
  assert.equal(f.tableCount('prime_memory_records'),1);assert.equal(f.tableCount('prime_memory_effects'),1)
  f.detach();assertUnknown(f.workflow.getSnapshot())
  gate.release();await pending
  assertUnknown(f.workflow.getSnapshot())
  assert.equal(f.workflow.getSnapshot().operation,null);assert.equal(f.workflow.getSnapshot().memory_capture,null)
  assert.equal(f.operationState(operation.operation_id).status,'COMPLETED')
  await f.controller.submitApproval()
  await attempt(()=>f.workflow.proposeSave(draft('joined-hook-detach-no-replay')))
  assert.equal(f.count('memory.save'),1);assert.equal(f.count('memory.proposeSave'),1)
})

for(const lifecycle of ['logout','detach']) {
  joinedTest('external B '+lifecycle+' before the hook microtask releases its flight and permits fresh login and review',async t=>{
    const f=await hookedFixture(t);await f.login();const oldOperation=await f.prepare(draft('joined-hook-before-microtask-'+lifecycle))
    const pending=f.controller.submitApproval()
    if(lifecycle==='logout')f.controller.logout()
    else f.detach()
    await pending
    assert.equal(f.hookCalls(),0);assert.equal(f.count('owner.approvalComplete'),0);assert.equal(f.count('memory.save'),0)
    assert.equal(f.operationState(oldOperation.operation_id).status,'PROPOSED')
    await freshReview(f,'joined-hook-fresh-after-microtask-'+lifecycle)
    if(lifecycle==='detach')f.attach()
    assert.notEqual(f.workflow.getSnapshot().operation.operation_id,oldOperation.operation_id)
    assert.equal(f.tableCount('prime_memory_records'),0);assert.equal(f.tableCount('prime_memory_effects'),0)
  })
}

joinedTest('disposing the external B controller from the save_pending observer prevents the known unsent D save',async t=>{
  const f=await hookedFixture(t);await f.login();const operation=await f.prepare(draft('joined-hook-controller-dispose-before-save'))
  let disposed=false
  const unsubscribe=f.workflow.subscribe(()=>{
    if(f.workflow.getSnapshot().phase==='save_pending'&&!disposed) {disposed=true;f.controller.dispose()}
  })
  await f.controller.submitApproval();unsubscribe()
  assert.equal(disposed,true);assert.equal(f.count('owner.approvalComplete'),1)
  assert.equal(f.count('memory.save'),0,'disposing B must invalidate the live owner before H can invoke memory.save')
  assert.equal(f.tableCount('prime_memory_records'),0);assert.equal(f.tableCount('prime_memory_effects'),0)
  assert.equal(f.operationState(operation.operation_id).status,'APPROVED')
})

joinedTest('external B logout during confirmed saved read replies permits fresh login and review without a mutation block',async t=>{
  const f=await hookedFixture(t);await f.login();const operation=await f.prepare(draft('joined-hook-saved-read-logout-recovery'))
  const status=f.gate('memory.status'),cite=f.gate('memory.cite'),pending=f.controller.submitApproval()
  await Promise.all([status.entered(1),cite.entered(1)])
  assertSaved(f.workflow.getSnapshot());assert.equal(f.workflow.getSnapshot().authority_settlement,'completed')
  assert.equal(f.operationState(operation.operation_id).status,'COMPLETED')
  f.controller.logout();status.release();cite.release();await pending
  assert.equal(f.workflow.getSnapshot().saved,true);assert.equal(f.workflow.getSnapshot().save,'saved')
  assert.equal(f.workflow.getSnapshot().reconciliation_required,false)
  await freshReview(f,'joined-hook-fresh-after-confirmed-read-logout')
  assert.equal(f.count('memory.save'),1)
  assert.equal(f.tableCount('prime_memory_records'),1);assert.equal(f.tableCount('prime_memory_effects'),1)
})

joinedTest('external B logout from save_pending before invocation permits fresh login and review without a mutation block',async t=>{
  const f=await hookedFixture(t);await f.login();const operation=await f.prepare(draft('joined-hook-known-unsent-logout-recovery'))
  let loggedOut=false
  const unsubscribe=f.workflow.subscribe(()=>{
    if(f.workflow.getSnapshot().phase==='save_pending'&&!loggedOut) {loggedOut=true;f.controller.logout()}
  })
  await f.controller.submitApproval();unsubscribe()
  assert.equal(loggedOut,true);assert.equal(f.count('memory.save'),0)
  assert.equal(f.workflow.getSnapshot().saved,false);assert.equal(f.workflow.getSnapshot().reconciliation_required,false)
  assert.equal(f.operationState(operation.operation_id).status,'APPROVED')
  await freshReview(f,'joined-hook-fresh-after-known-unsent-logout')
  assert.equal(f.tableCount('prime_memory_records'),0);assert.equal(f.tableCount('prime_memory_effects'),0)
})
