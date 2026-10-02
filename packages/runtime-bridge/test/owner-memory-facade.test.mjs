// SPDX-License-Identifier: AGPL-3.0-or-later
// Bounded source-functional join from the sanitized H 1b7bd3d7 baseline. Actual H client,
// browser/HTTP factories, B controller, C P-256 verification and D effects.
// Test-only boundary, in-memory HTTP bytes, SQLite and same-process cold objects
// do not establish production public qualification, PostgreSQL or isolation.
import {test} from 'node:test'
import assert from 'node:assert/strict'
import {Readable} from 'node:stream'
import {execFileSync} from 'node:child_process'
import {fileURLToPath} from 'node:url'
import * as contracts from '../../contracts/src/browser.mjs'
import {createPrimeOwnerController} from '../../ui/prime-authority/src/client/controller.mjs'
import {createOwnerMemoryClient} from '../../../harness/owner-memory-client.mjs'
import {createOwnerMemoryHttpRoutes} from '../../../harness/owner-memory-transport.mjs'
import {createOwnerMemoryHost} from '../../../harness/owner-memory-host.mjs'
import * as fixtures from './owner-memory-fixture.mjs'
import {assertRecoveryContinuation} from './owner-memory-recovery-continuation.mjs'
const profile=Object.freeze({profile:'https',origin:'https://prime.example.test',rp_id:'prime.example.test'})
// Test-only metadata; final evidence independently checks all assembled inputs.
let fixtureSourcePin=process.env.PRIME_OWNER_MEMORY_SOURCE_PIN
if(fixtureSourcePin===undefined){
 try{fixtureSourcePin=execFileSync('/usr/bin/git',['-C',fileURLToPath(new URL('../../../',import.meta.url)),'rev-parse','HEAD'],{encoding:'utf8',stdio:['ignore','pipe','ignore']}).trim()}
 catch{fixtureSourcePin='0'.repeat(40)} // Explicit synthetic marker in a cold source archive.
}
assert.match(fixtureSourcePin,/^[a-f0-9]{40}$/)
const caps={version:1,source_commit:fixtureSourcePin,runtime_pid:1,
  release_digest:'sha256:'+'b'.repeat(64),unavailable_capabilities:[],phase:'disposable-preview',qualification:'PENDING'}
const connection={requestRejection:()=>undefined},guardRequest=()=>profile

async function http(routes,url,options){
  const request=Readable.from([Buffer.from(options.body)])
  request.method=options.method;request.url=url
  request.headers={host:profile.rp_id,origin:profile.origin,'content-type':'application/json'}
  let status,headers,body
  const response={destroyed:false,writableEnded:false,writeHead(value,next){status=value;headers=next},end(value){body=value;this.writableEnded=true}}
  try{await routes.find(route=>route.path===url).handler(request,response)}finally{request.destroy()}
  return new Response(body,{status,headers})
}
async function assembled(t){
  const mounts=[],fetches=[];let signatures=0
  // End the assembled client sessions before the underlying fixture closes.
  t.after(async()=>{for(const m of mounts)if(!m.disposed){await m.client.logout();m.dispose()}})
  const f=await fixtures.fixture(t,{actions:['memory.save','memory.forget']})
  // This is an explicit test-only boundary, not handlePublic qualification.
  const routes=createOwnerMemoryHttpRoutes({contracts,connection,guardRequest,
    publicBoundary:{handlePublic:(method,input)=>f.bridgeCall(method,input)}})
  const mount=()=>{
    const controller=createPrimeOwnerController({schedule:()=>null,unschedule:()=>{}})
    const client=createOwnerMemoryClient({controller,contracts,
      ownerBinding:{owner_id:fixtures.ownerId,passkeyProfile:profile},
      passkeySigner:({public_key})=>{signatures++;return f.auth.assertion(public_key.challenge)},
      fetcher:async(url,options)=>{fetches.push(url);return http(routes,url,options)},
    })
    controller.connect(client.binding);client.attach();client.setCapabilities(caps)
    const m={client,controller,async login(){assert(await controller.login());assert.equal(controller.getSnapshot().phase,'authenticated')},
      disposed:false,dispose(){if(this.disposed)return;this.disposed=true;client.dispose();controller.dispose()}}
    mounts.push(m);return m
  }
  return {f,mount,fetches,signatures:()=>signatures}
}
async function save(m,key){
  assert.equal((await m.client.proposeSave(fixtures.draft(key))).phase,'proposed')
  assert(await m.controller.prepare())
  const first=m.controller.submitApproval(),second=m.controller.submitApproval()
  assert.equal(first,second)
  return first
}

test('H client generic hooks save, read, forget and save again with actual C/D',async t=>{
  const a=await assembled(t),m=a.mount();await m.login()
  const saved=await save(m,'facade-first');fixtures.assertSaved(saved)
  assert.equal(saved.citation.verdict,'VERIFIED');assert.equal(saved.index.searchable,false)
  const read=await m.client.refresh();assert.equal(read.record.canonical_bytes,saved.record.canonical_bytes)
  assert.equal((await m.client.proposeForget({record_id:saved.record.record_id})).phase,'proposed')
  assert(await m.controller.prepare())
  const first=m.controller.submitApproval(),second=m.controller.submitApproval();assert.equal(first,second)
  const forgotten=await first;assert.equal(forgotten.forgotten,true);assert.equal(forgotten.result.state,'tombstoned')
  assert.equal(forgotten.authority_settlement,'completed')
  const again=await save(m,'facade-second');fixtures.assertSaved(again)
  assert.equal(a.f.count('memory.save'),2);assert.equal(a.f.count('memory.forget'),1)
  assert.equal(a.f.tableCount('prime_memory_effects'),3)
  assert.equal(a.signatures(),4)
})

test('H client logs out durably, signs in again, and saves through the same binding',async t=>{
  const a=await assembled(t),m=a.mount();await m.login()
  const prior=a.f.calls.find(call=>call.method==='owner.loginComplete')
  const token=a.f.replies.find(reply=>reply.method==='owner.loginComplete').result.session_token
  assert(prior);const one=m.client.logout(),two=m.client.logout()
  assert.equal((await one).status,'LOGGED_OUT');assert.deepEqual(await two,await one)
  assert.equal(a.f.auth.service.authenticateSession({session_token:token}).ok,false)
  assert.equal(a.f.count('owner.logout'),1);await m.login()
  fixtures.assertSaved(await save(m,'after-logout'))
  assert.equal(a.f.count('memory.save'),1)
})

test('H same-controller recovered receipt is displayed and permits a new unrelated approved save without repeating the old effect',async t=>{
  await assertRecoveryContinuation(t,{assembled,save})
})

test('H new binding recovers an actual lost-save receipt after cold C/D objects without another signature or save',async t=>{
  const a=await assembled(t),m=a.mount();await m.login()
  a.f.delivery.set('memory.save',reply=>{fixtures.ok(reply);throw new Error('test-only committed reply delivery interruption')})
  assert.equal((await save(m,'facade-cold-save')).save,'unknown');a.f.delivery.delete('memory.save')
  await m.client.logout();m.dispose();await a.f.restartServer()
  const fresh=a.mount();await fresh.login();const signatures=a.signatures()
  const recovered=await fresh.client.recover();assert.equal(recovered.saved,true);assert.equal(recovered.authority_settlement,'completed')
  assert.equal(recovered.citation.verdict,'VERIFIED');assert.equal(a.signatures(),signatures)
  assert.equal(a.f.count('memory.save'),1);assert.equal(a.f.count('owner.approvalComplete'),1)
  fixtures.assertSaved(await save(fresh,'facade-cold-next'))
  assert.equal(a.f.count('memory.save'),2)
})

test('H host without a qualified channel remains unavailable before actual C/D',async t=>{
  const a=await assembled(t),before=a.f.calls.length
  assert.equal((await a.f.bridge.capability()).available,false)
  const h=createOwnerMemoryHost({contracts,connection,guardRequest})
  const response=await http(h.routes,'/api/prime/bridge/owner.loginChallenge',{method:'POST',body:contracts.canonicalJson({owner_id:fixtures.ownerId,kind:'passkey'})})
  assert.equal(response.status,503);assert.equal((await response.json()).error_code,'UNAVAILABLE')
  assert.equal(a.f.calls.length,before);assert.equal(a.f.tableCount('prime_memory_effects'),0)
})

test('H new binding recovers a reviewed unsent proposal and requires a fresh review',async t=>{
  const a=await assembled(t),m=a.mount();await m.login()
  const proposed=await m.client.proposeSave(fixtures.draft('facade-unsent'))
  assert.equal(proposed.phase,'proposed');assert(await m.controller.prepare())
  await m.client.logout();m.dispose();await a.f.restartServer()
  const fresh=a.mount();await fresh.login();const signatures=a.signatures()
  const recovered=await fresh.client.recover({operation_id:proposed.operation.operation_id})
  assert.equal(recovered.phase,'idle');assert.equal(recovered.saved,false)
  assert.equal(a.signatures(),signatures);assert.equal(a.f.count('memory.save'),0)
  const next=await fresh.client.proposeSave(fixtures.draft('facade-unsent-fresh'))
  assert.equal(next.phase,'proposed');assert.notEqual(next.operation.operation_id,proposed.operation.operation_id)
  assert(await fresh.controller.prepare());fixtures.assertSaved(await fresh.controller.submitApproval())
  assert.equal(a.f.count('memory.save'),1);assert.equal(a.f.count('owner.approvalComplete'),1)
})

test('H pending settlement recovery sends only the actual retained receipt after new login and cold objects',async t=>{
  const a=await assembled(t),m=a.mount();await m.login();a.f.setSettlementFailure(true)
  const saved=await save(m,'facade-pending-receipt');fixtures.assertSaved(saved)
  assert.equal(saved.authority_settlement,'pending');assert.equal(saved.reconciliation_required,true)
  const original=structuredClone(a.f.settlementInputs[0])
  await m.client.logout();m.dispose();a.f.setSettlementFailure(false);await a.f.restartServer()
  const fresh=a.mount();await fresh.login();const signatures=a.signatures()
  const recovered=await fresh.client.recover({operation_id:saved.operation.operation_id})
  assert.equal(recovered.saved,true);assert.equal(recovered.authority_settlement,'completed')
  assert.deepEqual(recovered.receipt,saved.receipt);assert.equal(recovered.citation.verdict,'VERIFIED')
  for(const input of a.f.settlementInputs.slice(1))assert.deepEqual(input,original)
  assert(a.f.settlementInputs.length>1);assert.equal(a.signatures(),signatures)
  assert.equal(a.f.count('memory.save'),1);assert.equal(a.f.tableCount('prime_memory_effects'),1)
})

test('H lost forget reply recovers the genuine tombstone receipt on a new binding without another effect',async t=>{
  const a=await assembled(t),m=a.mount();await m.login()
  const saved=await save(m,'facade-lost-forget');fixtures.assertSaved(saved)
  assert.equal((await m.client.proposeForget({record_id:saved.record.record_id})).phase,'proposed')
  assert(await m.controller.prepare())
  a.f.delivery.set('memory.forget',reply=>{fixtures.ok(reply);throw new Error('test-only committed forget reply delivery interruption')})
  const uncertain=await m.controller.submitApproval();assert.equal(uncertain.forget,'unknown')
  a.f.delivery.delete('memory.forget')
  const actual=a.f.replies.find(reply=>reply.method==='memory.forget').result
  await m.client.logout();m.dispose();await a.f.restartServer()
  const fresh=a.mount();await fresh.login();const signatures=a.signatures()
  const recovered=await fresh.client.recoverForget()
  assert.equal(recovered.forgotten,true);assert.equal(recovered.result.state,'tombstoned')
  assert.deepEqual(recovered.receipt,actual.receipt);assert.equal(recovered.authority_settlement,'completed')
  assert.equal(recovered.result.canonical_payload_retained,true);assert.equal(recovered.result.physical_media_erasure,false)
  assert.equal(a.signatures(),signatures);assert.equal(a.f.count('memory.forget'),1)
  assert.equal(a.f.count('owner.approvalComplete'),2);assert.equal(a.f.tableCount('prime_memory_effects'),2)
  fixtures.assertSaved(await save(fresh,'facade-after-forget-recovery'))
})

test('H lost logout reply ends local access, does not redispatch, and permits an ordinary fresh login',async t=>{
  const a=await assembled(t),m=a.mount();await m.login()
  const token=a.f.replies.find(reply=>reply.method==='owner.loginComplete').result.session_token
  a.f.delivery.set('owner.logout',()=>{throw new Error('test-only actual logout reply delivery interruption')})
  const result=await m.client.logout();assert.equal(result.error_code,'OUTCOME_UNKNOWN')
  assert.equal(m.controller.getSnapshot().owner,null);assert.equal(m.controller.getSnapshot().logout_status,'unknown')
  assert.equal(a.f.auth.service.authenticateSession({session_token:token}).ok,false)
  assert.deepEqual(await m.client.logout(),result);assert.equal(a.f.count('owner.logout'),1)
  a.f.delivery.delete('owner.logout');await m.login()
  fixtures.assertSaved(await save(m,'facade-after-unknown-logout'))
})
