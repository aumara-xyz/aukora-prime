// SPDX-License-Identifier: AGPL-3.0-or-later
// SOURCE ONLY: raw bridge + actual C passkey/stores + actual D expanded capture.
// The existing fixture's B controller is used for owner login only. This is
// NOT a B expanded-review join; no B review/display behavior is asserted.
// Disposable credentials and SQLite do not qualify deployed owner/process
// isolation, human review comprehension or PostgreSQL durability.
import {test} from 'node:test'
import assert from 'node:assert/strict'
import * as contracts from '../../contracts/src/runtime.mjs'
import {sha256} from '../../memory/src/codecs.mjs'
import {fixture,ok} from './owner-memory-fixture.mjs'

const TABLES=['prime_runtime_workflows','prime_memory_intents','prime_memory_effects','prime_memory_records',
  'prime_memory_requests','prime_memory_events','prime_memory_heads','prime_memory_chain','prime_memory_outbox']
const session=f=>f.replies.find(reply=>reply.method==='owner.loginComplete'&&reply.result.ok).result.session_token
const sourceEvent=f=>{
  const bytes=f.host.events.find(value=>sha256(Buffer.from(value))===f.host.source.sha256)
  assert.ok(bytes,'the quote must come from actual selected host event bytes')
  return {bytes:Buffer.from(bytes),event:JSON.parse(Buffer.from(bytes).toString('utf8'))}
}
const rowBytes=row=>Object.fromEntries(Object.entries(row).map(([key,value])=>[key,
  ArrayBuffer.isView(value)?Buffer.from(value.buffer,value.byteOffset,value.byteLength).toString('hex'):value]))
const databaseFacts=f=>Object.fromEntries(TABLES.map(table=>[table,f.pool.db.prepare('SELECT * FROM '+table).all().map(rowBytes)]))
const consumption=f=>{
  const state=f.state()
  return structuredClone({prepared:state.prepared,consumedIds:state.state.consumedIds,receiptHead:state.state.receiptHead})
}
const counter=f=>Object.values(Object.values(f.state().broker.owners).find(owner=>owner.owner_id===f.auth.identity.owner_id).passkey_counters)

test('raw bridge expanded capture binds four independent review fields, seven parameters and actual P-256 approval to a genuine saved receipt and exact retry',async t=>{
  const f=await fixture(t);await f.login()
  const session_token=session(f),selected=sourceEvent(f)
  const statement='  Café <tag>&\n\t🍌 👩‍💻  ',idempotency_key='raw-expanded-review-save'
  const extraction_json=JSON.stringify({statement})
  // Expectations come from the extraction and selected original source event,
  // independently of the operation/proof the services will return.
  const metadata={profile:'prime-pilot-memory-capture/v1',category:'fact',valid_from:f.host.source.at.slice(0,10),
    observed_at:f.host.source.at,confidence_percent:70,sensitivity:'none'}
  const expectedCapture={statement,attributed_to:'owner',capture_metadata:metadata,evidence_quote:selected.event.text}
  assert.notEqual(expectedCapture.statement,expectedCapture.evidence_quote)
  const proposed=ok(await f.bridgeCall('memory.proposeSave',{session_token,extraction_json,idempotency_key}))
  const operation=proposed.operation,parameters=operation.canonical_parameters,digest=contracts.operationDigest(operation)
  assert.deepEqual(Object.keys(proposed.memory_capture).sort(),['attributed_to','capture_metadata','evidence_quote','statement'])
  assert.deepEqual(Object.keys(parameters).sort(),['attributed_to','capture_metadata','capture_sha256','evidence_quote','heads','idempotency_key_sha256','statement'])
  assert.deepEqual(Object.keys(proposed.capture_metadata).sort(),['category','confidence_percent','observed_at','profile','sensitivity','valid_from'])
  assert.deepEqual(Object.keys(parameters.capture_metadata).sort(),Object.keys(metadata).sort())
  assert.deepEqual(proposed.memory_capture,expectedCapture)
  assert.deepEqual(proposed.capture_metadata,metadata)
  assert.deepEqual({statement:parameters.statement,attributed_to:parameters.attributed_to,
    capture_metadata:parameters.capture_metadata,evidence_quote:parameters.evidence_quote},expectedCapture)
  assert.equal(parameters.idempotency_key_sha256,sha256(Buffer.from(idempotency_key)))
  assert.match(parameters.capture_sha256,/^[a-f0-9]{64}$/);assert.deepEqual(parameters.heads,{})
  assert.equal(f.operationState(operation.operation_id).status,'PROPOSED')
  const review=ok(await f.bridgeCall('owner.approvalChallenge',{session_token,operation}))
  assert.deepEqual(review.operation,operation)
  assert.equal(review.operation_digest,digest);assert.equal(review.approval_request.operationDigest,digest.slice(7))
  assert.equal(review.proof_template.operation_digest,digest)
  assert.equal(review.proof_template.nonce,review.approval_request.challenge)
  assert.equal(review.proof_template.material.kind,'passkey')
  assert.equal(review.public_key.rpId,f.auth.config.webauthn.rp_id)
  assert.deepEqual(counter(f),[1],'only the ordinary login assertion has been verified so far')
  let approvalSignatures=0
  approvalSignatures++
  const material=f.auth.assertion(review.public_key.challenge)
  const proof={...review.proof_template,material}
  contracts.validateContract('ApprovalProof',proof)
  const clientData=JSON.parse(Buffer.from(material.client_data_json,'base64url').toString('utf8'))
  assert.equal(clientData.challenge,review.public_key.challenge);assert.equal(clientData.type,'webauthn.get')
  assert.equal(clientData.origin,f.auth.config.webauthn.origins[0])
  assert.equal(Buffer.from(material.authenticator_data,'base64url').readUInt32BE(33),2)
  const approved=ok(await f.bridgeCall('owner.approvalComplete',{session_token,operation,proof}))
  assert.equal(approved.status,'APPROVED');assert.deepEqual(approved.approval_proof,proof)
  assert.equal(f.operationState(operation.operation_id).status,'APPROVED');assert.deepEqual(counter(f),[2])
  assert.deepEqual(consumption(f).consumedIds,[],'approval verification has not reserved an effect')
  const saveInput={session_token,operation,approval_proof:approved.approval_proof,extraction_json,idempotency_key}
  const saved=ok(await f.bridgeCall('memory.save',saveInput))
  contracts.validateContract('MemoryRecord',saved.record)
  assert.equal(saved.record.storage_status,'saved');assert.equal(saved.record.index_status,'pending')
  assert.equal(saved.authority_settlement,'completed');assert.equal(saved.reconciliation_required,false)
  assert.equal(saved.receipt.operation_id,operation.operation_id);assert.equal(saved.receipt.operation_digest,digest)
  assert.equal(saved.receipt.grant_id,'grant:'+proof.nonce);assert.deepEqual(saved.receipt.result,saved.record)
  const note=JSON.parse(saved.record.canonical_bytes)
  assert.equal(note.statement,expectedCapture.statement);assert.equal(note.attributedTo,expectedCapture.attributed_to)
  assert.equal(note.evidence[0].quote,expectedCapture.evidence_quote)
  assert.deepEqual({profile:metadata.profile,category:note.category,valid_from:note.validFrom,observed_at:note.observedAt,
    confidence_percent:note.confidence*100,sensitivity:note.sensitivity},metadata)
  assert.equal(saved.record.source_event_digest,'sha256:'+sha256(selected.bytes))
  const citation=ok(await f.bridgeCall('memory.cite',{session_token,record_id:saved.record.record_id,
    revision:saved.record.revision,retained_head:null})).citation
  assert.equal(citation.verdict,'VERIFIED');assert.equal(citation.grants_authority,false)
  assert.equal(citation.record_id,saved.record.record_id);assert.equal(citation.revision,saved.record.revision)
  const facts=databaseFacts(f),reserved=consumption(f),authority=structuredClone(f.state().broker.operations)
  assert.ok(reserved.consumedIds.includes('approval:'+proof.nonce));assert.equal(reserved.prepared.length,1)
  for(const rows of Object.values(facts))assert.equal(rows.length,1)
  assert.equal(facts.prime_memory_events[0].bytes,selected.bytes.toString('hex'),'D retains the exact original selected event bytes')
  assert.notDeepEqual(Object.fromEntries(facts.prime_memory_heads.map(head=>[head.chain_domain,head.hash])),parameters.heads)
  const effect=facts.prime_memory_effects[0]
  assert.deepEqual(JSON.parse(Buffer.from(effect.result_bytes,'hex').toString('utf8')),saved.record)
  assert.deepEqual(JSON.parse(Buffer.from(effect.receipt_bytes,'hex').toString('utf8')),saved.receipt)
  assert.deepEqual(JSON.parse(Buffer.from(effect.operation_bytes,'hex').toString('utf8')),operation)
  assert.equal(effect.request_id,saved.receipt.request_id);assert.equal(effect.request_digest,saved.receipt.request_digest)
  assert.equal(f.operationState(operation.operation_id).status,'COMPLETED')
  const retry=ok(await f.bridgeCall('memory.save',structuredClone(saveInput)))
  assert.deepEqual(retry.record,saved.record);assert.deepEqual(retry.receipt,saved.receipt)
  assert.equal(retry.receipt_digest,saved.receipt_digest)
  assert.equal(retry.authority_settlement,'completed');assert.equal(retry.reconciliation_required,false)
  assert.deepEqual(databaseFacts(f),facts,'factual retry preserves all actual D bytes, heads, references and effect counts')
  assert.deepEqual(consumption(f),reserved);assert.deepEqual(f.state().broker.operations,authority)
  assert.deepEqual(counter(f),[2]);assert.equal(approvalSignatures,1);assert.equal(f.signerCalls(),1)
  assert.equal(f.count('owner.approvalChallenge'),1);assert.equal(f.count('owner.approvalComplete'),1)
  assert.equal(f.count('memory.proposeSave'),1);assert.equal(f.count('memory.save'),2)
  assert.equal(f.controller.getSnapshot().phase,'authenticated','B remains at login; expanded review used raw bridge calls')
  assert.equal((await f.bridge.capability()).state,'unqualified')
})

test('ordinary NFD and refused-format new statements or selected source quotes fail before SQL, intent or authority consumption',async t=>{
  const f=await fixture(t);await f.login()
  const session_token=session(f),selected=sourceEvent(f),originalSource=structuredClone(f.host.source)
  const before=consumption(f),operations=structuredClone(f.state().broker.operations)
  const cases=[
    {name:'NFD statement',statement:'Cafe\u0301',quote:selected.event.text},
    {name:'format-control statement',statement:'Cafe\u200b',quote:selected.event.text},
    {name:'NFD source quote',statement:'Café note',quote:'Cafe\u0301 source'},
    {name:'format-control source quote',statement:'Café note',quote:'Cafe\u200b source'},
  ]
  for(const [index,input]of cases.entries()) {
    // These are actual selected synthetic event bytes with their genuine hash;
    // no operation parameters, receipt or D database row are fabricated.
    const bytes=Buffer.from(JSON.stringify({...selected.event,text:input.quote})+'\n')
    f.host.events=[bytes];f.host.source={...originalSource,sha256:sha256(bytes)}
    const sql=[],query=f.pool.query
    f.pool.query=function(...args){sql.push(args[0]);return Reflect.apply(query,this,args)}
    let result
    try {result=await f.bridgeCall('memory.proposeSave',{session_token,
      extraction_json:JSON.stringify({statement:input.statement}),idempotency_key:'expanded-refused-text-'+index})}
    finally {f.pool.query=query}
    assert.equal(result.ok,false,input.name);assert.equal(result.error_code,'INVALID',input.name)
    assert.deepEqual(sql,[],input.name+' must be refused before any workflow or D SQL')
    for(const table of TABLES)assert.equal(f.tableCount(table),0,input.name+' must leave '+table+' empty')
    assert.deepEqual(consumption(f),before);assert.deepEqual(f.state().broker.operations,operations)
    assert.deepEqual(counter(f),[1]);assert.equal(f.signerCalls(),1)
    assert.equal(f.count('owner.approvalChallenge'),0);assert.equal(f.count('owner.approvalComplete'),0)
    assert.equal(f.count('memory.save'),0)
  }
  f.host.events=[selected.bytes];f.host.source=originalSource
  assert.equal((await f.bridge.capability()).public_routes,'unavailable')
})
