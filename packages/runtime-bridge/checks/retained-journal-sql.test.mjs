import assert from 'node:assert/strict'
import test from 'node:test'
import {createHash} from 'node:crypto'
import {canonicalJson} from '../../contracts/src/runtime.mjs'
import {canonicalJSON} from '../../memory/genesis/plugins/aukora-kira/lib/record.mjs'
import {closureAttemptId,workflowDigest,progressDigest} from '../src/closure-v2.mjs'
import {RETAINED_JOURNAL_SCHEMA,RETAINED_JOURNAL_STATEMENTS as S,RETAINED_JOURNAL_DESCRIPTORS,mutateRetainedWorkflow,mutateRetainedClosure,assertRetainedAdmission} from '../src/retained-journal-sql.mjs'
const F='owner_subject,owner_id,task_id,operation_id,operation_digest,action_type,idempotency_key_sha256,record_id,phase,request_id,request_digest,receipt_digest,created_at'.split(',')
const P='owner_subject,owner_id,task_id,operation_id,progress_bytes,progress_digest'.split(',')
const reference={owner_id:'sql-owner',owner_subject:'aukora:1:'+'a'.repeat(64),task_id:'sql-task',operation_id:'sql-op',operation_digest:'sha256:'+'b'.repeat(64),action_type:'memory.save'}
const host={owner_id:reference.owner_id,owner_subject:reference.owner_subject,task_id:reference.task_id,authorization_epoch:3}
const row={...reference,idempotency_key_sha256:'c'.repeat(64),record_id:null,phase:'proposed',request_id:null,request_digest:null,receipt_digest:null,created_at:'2026-10-02T00:00:00.000Z'}
const hash=(domain,value,encode=canonicalJson)=>'sha256:'+createHash('sha256').update(domain+'\0').update(encode(value)).digest('hex')
const clone=value=>Buffer.isBuffer(value)?Buffer.from(value):Array.isArray(value)?value.map(clone)
  :value&&typeof value==='object'?Object.fromEntries(Object.entries(value).map(([key,child])=>[key,clone(child)])):value
const sameBytes=(a,b)=>Buffer.isBuffer(a)&&Buffer.isBuffer(b)&&a.equals(b)
function db(workflows=[],progress=[],counts=true) {
  let w=clone(workflows),p=clone(progress)
  const names=new Map(Object.entries(S).map(([name,sql])=>[sql,name]))
  const tx=Object.freeze({async query(sql,v) {
    const name=names.get(sql);assert(name,'only an exact fixed statement is accepted')
    assert.equal(v[0],host.owner_subject);assert.equal(v[1],host.owner_id)
    const scoped=r=>r.owner_subject===v[0]&&r.owner_id===v[1]
    const keyed=r=>scoped(r)&&r.task_id===v[2]&&r.operation_id===v[3]
    const wi=w.findIndex(keyed),pi=p.findIndex(keyed)
    let rows=[]
    if(name==='lockWorkflow')rows=wi<0?[]:[w[wi]]
    else if(name==='lockProgress')rows=pi<0?[]:[p[pi]]
    else if(name==='lockOwnerWorkflows')rows=w.filter(scoped)
    else if(name==='lockOwnerProgress')rows=p.filter(scoped)
    else if(name==='insertWorkflow') {
      if(wi<0){const next=Object.fromEntries(F.map((k,i)=>[k,v[i]]));w.push(next);rows=[next]}
    } else if(name==='updateWorkflow') {
      if(wi>=0&&canonicalJson(F.map(k=>w[wi][k]))===canonicalJson(v.slice(0,13))) {
        const next={...w[wi],...Object.fromEntries(['record_id','phase','request_id','request_digest','receipt_digest'].map((k,i)=>[k,v[13+i]]))}
        w[wi]=next;rows=[next]
      }
    } else if(name==='insertProgress') {
      if(pi<0){const next=Object.fromEntries(P.map((k,i)=>[k,v[i]]));p.push(next);rows=[next]}
    } else if(name==='updateProgress') {
      if(pi>=0&&sameBytes(p[pi].progress_bytes,v[4])&&p[pi].progress_digest===v[5]&&JSON.parse(p[pi].progress_bytes).stage===v[6]) {
        p[pi]={...p[pi],progress_bytes:v[7],progress_digest:v[8]};rows=[p[pi]]
      }
    } else if(name==='completeProgress') {
      assert(sql.includes('AND EXISTS (SELECT 1 FROM prime_runtime_workflow_closure_progress_v2'))
      if(wi>=0&&pi>=0&&w[wi].phase==='attempted'&&canonicalJson(F.map(k=>w[wi][k]))===canonicalJson(v.slice(0,13))
        &&sameBytes(p[pi].progress_bytes,v[13])&&p[pi].progress_digest===v[14]&&JSON.parse(p[pi].progress_bytes).stage===v[15]) {
        w[wi]={...w[wi],phase:'known_unsent'};p[pi]={...p[pi],progress_bytes:v[16],progress_digest:v[17]};rows=[p[pi]]
      }
    } else assert.fail('unhandled fixed statement')
    return counts?{rows:clone(rows),rowCount:rows.length}:{rows:clone(rows)}
  }})
  return {tx,snapshot:()=>clone({w,p})}
}
const normal=(target,previous)=>({version:3,kind:'prime-runtime-workflow-mutation/v3',memory_store_id:'d'.repeat(64),reference,
  idempotency_key_sha256:row.idempotency_key_sha256,expected_checkpoint_sha256:'e'.repeat(64),previous_workflow_digest:previous,target_workflow:target})
const base={version:2,kind:'prime-runtime-unsent-closure-progress/v2',reference,idempotency_key_sha256:row.idempotency_key_sha256,
  closure_attempt_id:null,expected_authority_store_id:'f'.repeat(64),expected_memory_store_id:'d'.repeat(64),closing_authorization_epoch:3,
  stage:'started',authority:null,memory:null}
base.closure_attempt_id=closureAttemptId(base)
const cm={version:1,kind:'prime-authority-never-consumed/v1',store_id:base.expected_authority_store_id,owner_id:reference.owner_id,
  owner_subject:reference.owner_subject,task_id:reference.task_id,operation_id:reference.operation_id,operation_digest:reference.operation_digest,
  authorization_epoch:0,closed_at:'2026-10-02T00:00:00.000Z',broker_revision:1,kernel_receipt_count:0,kernel_receipt_head:null}
const authority={closure:cm,closure_digest:hash('aukora-prime.authority-never-consumed.v1',cm)}
const dm={version:2,kind:'prime-memory-writer-closure/v2',store_id:base.expected_memory_store_id,...reference,authorization_epoch:3,
  closure_id:'00000000-0000-4000-8000-000000000001',writer_closed:true,intent_absent:true,effect_absent:true,grants_authority:false}
const md=hash('aukora-prime.memory-writer-closure.v2',dm,canonicalJSON)
const completion={version:2,kind:'prime-memory-writer-completion/v2',store_id:base.expected_memory_store_id,closure_digest:md,
  retention:{version:2,kind:'prime-memory-writer-retention/v2',checkpoint_sha256:'1'.repeat(64),control_sha256:'2'.repeat(64),authorization_epoch:3}}
const memory={closure:dm,closure_digest:md,completion,completion_digest:hash('aukora-prime.memory-writer-completion.v2',completion,canonicalJSON)}
const journal=(target,previous)=>({version:3,kind:'prime-runtime-unsent-journal-transition/v3',memory_store_id:base.expected_memory_store_id,
  reference,idempotency_key_sha256:row.idempotency_key_sha256,expected_checkpoint_sha256:'e'.repeat(64),
  previous_progress_digest:previous,target_stage:target.stage,target_progress:target})
test('fixed borrowed SQL registers and attempts with exact actual-row CAS',async()=>{
  const store=db([],[],false)
  assert.equal(await mutateRetainedWorkflow(store.tx,normal(row,null)),undefined)
  const attempted={...row,phase:'attempted'}
  assert.equal(await mutateRetainedWorkflow(store.tx,normal(attempted,workflowDigest(row))),undefined)
  const prior=store.snapshot()
  await assert.rejects(mutateRetainedWorkflow(store.tx,normal(attempted,'sha256:'+'0'.repeat(64))),/PRIOR_WORKFLOW_CHANGED/)
  await assert.rejects(mutateRetainedWorkflow(store.tx,normal(row,null)),/PRIOR_WORKFLOW_CHANGED/)
  await assert.rejects(mutateRetainedWorkflow(store.tx,normal({...attempted,phase:'known_unsent'},workflowDigest(attempted))),/normal-transition/)
  assert.deepEqual(store.snapshot(),prior)
})
test('closure stage CAS completes progress and attempted phase in one fixed statement',async()=>{
  const attempted={...row,phase:'attempted'},store=db([attempted])
  const a={...base,stage:'authority_confirmed',authority},m={...a,stage:'memory_confirmed',memory},done={...m,stage:'complete'}
  await mutateRetainedClosure(store.tx,journal(base,null))
  await mutateRetainedClosure(store.tx,journal(a,progressDigest(base)))
  const prior=store.snapshot()
  await assert.rejects(mutateRetainedClosure(store.tx,journal(a,progressDigest(base))),/PRIOR_PROGRESS_CHANGED/)
  assert.deepEqual(store.snapshot(),prior)
  await mutateRetainedClosure(store.tx,journal(m,progressDigest(a)))
  assert.equal(await mutateRetainedClosure(store.tx,journal(done,progressDigest(m))),undefined)
  assert.deepEqual(store.snapshot().w,[{...attempted,phase:'known_unsent'}])
  assert.equal(JSON.parse(store.snapshot().p[0].progress_bytes).stage,'complete')
  assert.equal(await mutateRetainedClosure(store.tx,journal(done,progressDigest(done))),undefined)
  const facts=[{reference,progress_digest:progressDigest(done)}]
  assert.equal(await assertRetainedAdmission(store.tx,host,facts),undefined)
  await assert.rejects(assertRetainedAdmission(store.tx,host,[]),/CURRENT_CLOSED_FACTS_REQUIRED/)
  await assert.rejects(assertRetainedAdmission(store.tx,{...host,authorization_epoch:4},facts),/CURRENT_CLOSED_FACTS_REQUIRED/)
  const extra={...row,task_id:'another-task',operation_id:'another-op',phase:'attempted'}
  const all=db([...store.snapshot().w,extra],store.snapshot().p)
  await assert.rejects(assertRetainedAdmission(all.tx,host,facts,{exclude:'another-op'}),/OWNER_RECONCILIATION_REQUIRED/)
})
test('borrowed result booleans and inconsistent row counts are refused',async()=>{
  await assert.rejects(mutateRetainedWorkflow({query:async()=>true},normal(row,null)),/RESULT_INVALID/)
  await assert.rejects(mutateRetainedWorkflow({query:async()=>({rows:[],rowCount:1})},normal(row,null)),/RESULT_INVALID/)
})

test('native progress bytes match D bytea guards and reject text or changed encoding',async()=>{
  assert(RETAINED_JOURNAL_SCHEMA[2].includes('progress_bytes bytea NOT NULL'))
  for(const name of ['updateProgress','completeProgress']) {
    assert(!S[name].includes('progress_bytes::jsonb'))
    assert(S[name].includes("convert_from(progress_bytes,'UTF8')::jsonb"))
  }
  const attempted={...row,phase:'attempted'},bytes=Buffer.from(canonicalJson(base),'utf8')
  const native={owner_subject:row.owner_subject,owner_id:row.owner_id,task_id:row.task_id,operation_id:row.operation_id,
    progress_bytes:bytes,progress_digest:progressDigest(base)}
  const a={...base,stage:'authority_confirmed',authority}
  const store=db([attempted],[native])
  await mutateRetainedClosure(store.tx,journal(a,progressDigest(base)))
  assert(Buffer.isBuffer(store.snapshot().p[0].progress_bytes))
  assert(store.snapshot().p[0].progress_bytes.equals(Buffer.from(canonicalJson(a),'utf8')))
  for(const invalid of [bytes.toString('utf8'),new Uint8Array(bytes),Buffer.concat([bytes,Buffer.from('\n')]),
    Buffer.concat([bytes.subarray(0,bytes.length-1),Buffer.from([0xff]),bytes.subarray(bytes.length-1)])]) {
    const rejected=db([attempted],[{...native,progress_bytes:invalid}]),prior=rejected.snapshot()
    await assert.rejects(mutateRetainedClosure(rejected.tx,journal(a,progressDigest(base))))
    assert.deepEqual(rejected.snapshot(),prior)
  }
  let reads=0
  const hostile={...native};Object.defineProperty(hostile,'progress_bytes',{enumerable:true,get(){reads++;return bytes}})
  const tx={query:async sql=>({rows:sql===S.lockWorkflow?[attempted]:[hostile]})}
  await assert.rejects(mutateRetainedClosure(tx,journal(a,progressDigest(base))))
  assert.equal(reads,0)
})

test('fixed descriptors preserve D-agreed names, SQL, ordered selectors and deep freezing',()=>{
  // Selector contract read from D42196940; no sibling checkout/runtime fixture.
  const names=['lockWorkflow','lockProgress','lockOwnerWorkflows','lockOwnerProgress',
    'insertWorkflow','updateWorkflow','insertProgress','updateProgress','completeProgress']
  const ownerReference=['host.owner_subject','host.owner_id','host.task_id','transition.reference.operation_id']
  const remainingWorkflow=['operation_digest','action_type','idempotency_key_sha256','record_id','phase',
    'request_id','request_digest','receipt_digest','created_at']
  const targetWorkflow=[...ownerReference,...remainingWorkflow.map(key=>'transition.target_workflow.'+key)]
  const priorWorkflow=[...ownerReference,...remainingWorkflow.map(key=>'baseline.workflow.'+key)]
  const mutable=['transition.target_workflow.record_id','transition.target_workflow.phase',
    'transition.target_workflow.request_id','transition.target_workflow.request_digest','transition.target_workflow.receipt_digest']
  const priorProgress=['baseline.progress.progress_bytes','baseline.progress.progress_digest','baseline.progress.stage']
  const targetProgress=['transition.target_progress','derived.target_progress_digest']
  const selectors={
    lockWorkflow:ownerReference,
    lockProgress:ownerReference,
    lockOwnerWorkflows:['host.owner_subject','host.owner_id'],
    lockOwnerProgress:['host.owner_subject','host.owner_id'],
    insertWorkflow:targetWorkflow,
    updateWorkflow:[...priorWorkflow,...mutable],
    insertProgress:[...ownerReference,...targetProgress],
    updateProgress:[...ownerReference,...priorProgress,...targetProgress],
    completeProgress:[...priorWorkflow,...priorProgress,...targetProgress],
  }
  assert.equal(Object.isFrozen(RETAINED_JOURNAL_DESCRIPTORS),true)
  assert.deepEqual(RETAINED_JOURNAL_DESCRIPTORS.map(descriptor=>descriptor.name),names)
  for(const descriptor of RETAINED_JOURNAL_DESCRIPTORS) {
    assert.deepEqual(Reflect.ownKeys(descriptor).sort(),['name','parameters','text'])
    assert.equal(descriptor.text,S[descriptor.name])
    assert.deepEqual(descriptor.parameters,selectors[descriptor.name])
    assert.equal(Object.isFrozen(descriptor),true)
    assert.equal(Object.isFrozen(descriptor.parameters),true)
    assert.throws(()=>{descriptor.text='caller SQL'},TypeError)
    assert.throws(()=>descriptor.parameters.push('caller.parameter'),TypeError)
  }
})
