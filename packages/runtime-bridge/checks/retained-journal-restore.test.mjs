// SPDX-License-Identifier: AGPL-3.0-or-later
// Original fourteen pure guards plus directly attached byte-boundary negatives.
// This facade establishes no C/D, PG,
// retained publication, native writer qualification or deployment evidence.
import assert from 'node:assert/strict'
import {createHash} from 'node:crypto'
const base=new URL('../../',import.meta.url).href
const {restoreRetainedJournal}=await import(base+'runtime-bridge/src/retained-journal-restore.mjs')
const {RETAINED_JOURNAL_STATEMENTS:SQL}=await import(base+'runtime-bridge/src/retained-journal-sql.mjs')
const {canonicalJson}=await import(base+'contracts/src/runtime.mjs')
const {canonicalJSON:dc}=await import(base+'memory/genesis/plugins/aukora-kira/lib/record.mjs')
const {closureAttemptId,progressDigest,WORKFLOW_FIELDS}=await import(base+'runtime-bridge/src/closure-v2.mjs')
const clone=x=>Buffer.isBuffer(x)?Buffer.from(x):Array.isArray(x)?x.map(clone)
  :x&&typeof x==='object'?Object.fromEntries(Object.entries(x).map(([key,value])=>[key,clone(value)])):x
const eq=(a,b)=>canonicalJson(a)===canonicalJson(b)
const h=(domain,value,encoder=dc)=>createHash('sha256').update(domain).update(encoder(value)).digest('hex')
const encode=bytes=>({bytes_base64:bytes.toString('base64'),sha256:createHash('sha256').update(bytes).digest('hex')})
const profile={version:2,kind:'prime-private-unsent-closure/v2',expected_authority_store_id:'a'.repeat(64),expected_memory_store_id:'b'.repeat(64),retention_profile:'required-retained/v2'}
const reference={owner_id:'owner',owner_subject:'aukora:1:'+'c'.repeat(64),task_id:'task',operation_id:'operation',operation_digest:'sha256:'+'d'.repeat(64),action_type:'memory.save'}
const row={...reference,idempotency_key_sha256:'e'.repeat(64),record_id:null,phase:'proposed',request_id:null,request_digest:null,receipt_digest:null,created_at:'2026-10-02T12:00:00.000Z'}
const binding={reference,idempotency_key_sha256:row.idempotency_key_sha256,expected_authority_store_id:profile.expected_authority_store_id,expected_memory_store_id:profile.expected_memory_store_id,closing_authorization_epoch:0}
const started={version:2,kind:'prime-runtime-unsent-closure-progress/v2',...binding,closure_attempt_id:closureAttemptId(binding),stage:'started',authority:null,memory:null}
const c={version:1,kind:'prime-authority-never-consumed/v1',store_id:profile.expected_authority_store_id,owner_id:reference.owner_id,owner_subject:reference.owner_subject,task_id:reference.task_id,operation_id:reference.operation_id,operation_digest:reference.operation_digest,authorization_epoch:0,closed_at:'2026-10-02T12:00:01.000Z',broker_revision:1,kernel_receipt_count:0,kernel_receipt_head:null}
const cp={closure:c,closure_digest:'sha256:'+h('aukora-prime.authority-never-consumed.v1\0',c,canonicalJson)}
const d={version:2,kind:'prime-memory-writer-closure/v2',store_id:profile.expected_memory_store_id,...reference,authorization_epoch:0,closure_id:'11111111-1111-4111-8111-111111111111',writer_closed:true,intent_absent:true,effect_absent:true,grants_authority:false}
const dd='sha256:'+h('aukora-prime.memory-writer-closure.v2\0',d)
const completion={version:2,kind:'prime-memory-writer-completion/v2',store_id:profile.expected_memory_store_id,closure_digest:dd,retention:{version:2,kind:'prime-memory-writer-retention/v2',checkpoint_sha256:'1'.repeat(64),control_sha256:'2'.repeat(64),authorization_epoch:0}}
const dp={closure:d,closure_digest:dd,completion,completion_digest:'sha256:'+h('aukora-prime.memory-writer-completion.v2\0',completion)}
const confirmed={...started,stage:'authority_confirmed',authority:cp}
const memory={...confirmed,stage:'memory_confirmed',memory:dp}
const complete={...memory,stage:'complete'}
const pRow=p=>({owner_subject:reference.owner_subject,owner_id:reference.owner_id,task_id:reference.task_id,operation_id:reference.operation_id,
  progress_bytes:encode(Buffer.from(canonicalJson(p),'utf8')),progress_digest:progressDigest(p)})
const nativeP=row=>({...clone(row),progress_bytes:Buffer.from(row.progress_bytes?.bytes_base64??'','base64')})
function control(workflows,progress=[]) {
 const metadata={version:1,kind:'prime-memory-logical-store/v1',store_id:profile.expected_memory_store_id}
 const body={schema:'aukora-prime-memory-control-state/v3',owner_subject:reference.owner_subject,owner_id:reference.owner_id,logical_store:{metadata,metadata_digest:'sha256:'+h('aukora-prime.memory-logical-store.v1\0',metadata)},closure_profile:profile,heads:{},tables:Object.fromEntries(['purges','requests','intents','effects','tombstones','controls','redactions','replay_fences','unsent_closures','runtime_workflows','workflow_closure_progress'].map(k=>[k,k==='runtime_workflows'?workflows:k==='workflow_closure_progress'?progress:[]]))}
 return {...body,control_sha256:h('aukora-prime.memory-control-state.v3\0',body)}
}
const attempted={...row,phase:'attempted'},closed={...row,phase:'known_unsent'}
const path=[control([row]),control([attempted]),control([attempted],[pRow(started)]),control([attempted],[pRow(confirmed)]),control([attempted],[pRow(memory)]),control([closed],[pRow(complete)])]
function facade(state,{casFail=false}={}) {
 const tx={w:clone(state.tables.runtime_workflows),p:state.tables.workflow_closure_progress.map(nativeP),calls:[],writes:0,async query(sql,params) {
  this.calls.push(sql);assert.ok(Object.values(SQL).includes(sql),'only fixed borrowed statements')
  if(sql===SQL.lockOwnerWorkflows)return {rows:clone(this.w)}
  if(sql===SQL.lockOwnerProgress)return {rows:clone(this.p)}
  this.writes++
  if(casFail)return {rows:[]}
  const oldW=()=>WORKFLOW_FIELDS.every((k,i)=>eq(this.w[0][k],params[i]))
  if(sql===SQL.insertWorkflow) {const newRow=Object.fromEntries(WORKFLOW_FIELDS.map((k,i)=>[k,params[i]]));this.w.push(newRow);return {rows:[clone(newRow)]}}
  if(sql===SQL.updateWorkflow) {assert.ok(oldW());for(const [i,k] of ['record_id','phase','request_id','request_digest','receipt_digest'].entries())this.w[0][k]=params[13+i];return {rows:[clone(this.w[0])]}}
  if(sql===SQL.insertProgress) {assert.ok(Buffer.isBuffer(params[4]));const p=Object.fromEntries(['owner_subject','owner_id','task_id','operation_id','progress_bytes','progress_digest'].map((k,i)=>[k,clone(params[i])]));this.p.push(p);return {rows:[clone(p)]}}
  if(sql===SQL.updateProgress) {assert.ok(Buffer.isBuffer(params[4])&&Buffer.isBuffer(params[7]));assert.deepEqual(this.p[0].progress_bytes,params[4]);assert.equal(this.p[0].progress_digest,params[5]);assert.equal(JSON.parse(this.p[0].progress_bytes.toString('utf8')).stage,params[6]);this.p[0].progress_bytes=Buffer.from(params[7]);this.p[0].progress_digest=params[8];return {rows:[clone(this.p[0])]}}
  if(sql===SQL.completeProgress) {assert.ok(oldW());assert.ok(Buffer.isBuffer(params[13])&&Buffer.isBuffer(params[16]));assert.equal(this.w[0].phase,'attempted');assert.deepEqual(this.p[0].progress_bytes,params[13]);assert.equal(this.p[0].progress_digest,params[14]);assert.equal(JSON.parse(this.p[0].progress_bytes.toString('utf8')).stage,params[15]);this.w[0].phase='known_unsent';this.p[0].progress_bytes=Buffer.from(params[16]);this.p[0].progress_digest=params[17];return {rows:[clone(this.p[0])]}}
  throw Error('unsupported statement')
 }};return tx
}
let passed=0
const pass=label=>{passed++;console.log('PASS '+label)}
let tx=facade(path[0]);assert.equal(await restoreRetainedJournal(tx,path,profile),undefined);assert.deepEqual(tx.w,[closed]);assert.deepEqual(tx.p,[nativeP(pRow(complete))]);assert.equal(tx.writes,5);pass('adjacent ordinary and closure steps reach exact complete pair')
tx=facade(path.at(-1));await restoreRetainedJournal(tx,[path.at(-1)],profile);assert.equal(tx.writes,0);pass('identical anchor only reads locked exact journal')
const saved={...attempted,phase:'saved',record_id:'rem:'+'3'.repeat(64),request_id:'request',request_digest:'sha256:'+'4'.repeat(64),receipt_digest:'sha256:'+'5'.repeat(64)}
tx=facade(control([]));await restoreRetainedJournal(tx,[control([]),control([row]),control([attempted]),control([saved])],profile);assert.deepEqual(tx.w,[saved]);pass('normal new row and factual terminal advance use exact fixed CAS')
async function reject(label,bad,start=bad[0]) {const tx=facade(start);await assert.rejects(restoreRetainedJournal(tx,bad,profile));assert.equal(tx.writes,0);pass(label)}
await reject('missing intermediate progress stage refused before SQL',[path[2],path[4]])
await reject('proposal cannot be promoted directly to closure',[path[0],path[2]])
await reject('completed row and progress cannot be dropped',[path.at(-1),control([])])
await reject('workflow immutable key cannot change',[path[0],control([{...attempted,idempotency_key_sha256:'6'.repeat(64)}])])
await reject('established exact C proof cannot change',[path[3],control([attempted],[pRow({...memory,authority:{...cp,closure:{...c,closed_at:'2026-10-02T12:00:02.000Z'},closure_digest:'sha256:'+h('aukora-prime.authority-never-consumed.v1\0',{...c,closed_at:'2026-10-02T12:00:02.000Z'},canonicalJson)}})])])
await reject('original13 extra column refused',[control([{...row,operation:{}}])])
await reject('progress6 extra column refused',[control([attempted],[{...pRow(started),extra:true}])])
await reject('logical store/pin mismatch refused',[{...path[0],closure_profile:{...profile,expected_memory_store_id:'7'.repeat(64)}}])
await reject('local extra history refuses exact baseline',[path[0]],control([row,{...row,operation_id:'extra',idempotency_key_sha256:'8'.repeat(64)}]))
tx=facade(path[0],{casFail:true});await assert.rejects(restoreRetainedJournal(tx,path.slice(0,2),profile));assert.equal(tx.w[0].phase,'proposed');pass('failed actual-row CAS does not claim restoration')
let getterCalls=0;const hostile=[path[0]];Object.defineProperty(hostile,'0',{enumerable:true,get(){getterCalls++;return path[0]}});await assert.rejects(restoreRetainedJournal(facade(path[0]),hostile,profile));assert.equal(getterCalls,0);pass('accessor ancestry never executes')
await reject('unselected retained buffer representation refused',[control([attempted],[{...pRow(started),progress_bytes:{$buffer:pRow(started).progress_bytes.bytes_base64}}])])
await reject('noncanonical Base64 refused',[control([attempted],[{...pRow(started),progress_bytes:{...pRow(started).progress_bytes,bytes_base64:pRow(started).progress_bytes.bytes_base64+'\n'}}])])
await reject('encoded byte hash mismatch refused',[control([attempted],[{...pRow(started),progress_bytes:{...pRow(started).progress_bytes,sha256:'0'.repeat(64)}}])])
await reject('malformed UTF8 refused without replacement',[control([attempted],[{...pRow(started),progress_bytes:encode(Buffer.from([0xc3,0x28]))}])])
await reject('valid noncanonical progress bytes refused',[control([attempted],[{...pRow(started),progress_bytes:encode(Buffer.from(canonicalJson(started)+'\n','utf8'))}])])
tx=facade(path[2]);tx.p[0].progress_bytes=canonicalJson(started);await assert.rejects(restoreRetainedJournal(tx,[path[2]],profile));assert.equal(tx.writes,0);pass('native TEXT progress row refused instead of bytea')
console.log(JSON.stringify({passed,scope:'pure fixed-SQL synthetic facade only; no D authentication, services, PostgreSQL, retained custody or deployment proof'}))
