#!/usr/bin/env node
// SPDX-License-Identifier: AGPL-3.0-or-later
// Ordinary actual C/D source join. Durable SQLite/file bytes are real; PostgreSQL
// session replies and retention UID/setgid metadata are explicitly modeled.
import assert from 'node:assert/strict'
import {createHash,generateKeyPairSync,randomBytes,randomUUID,sign} from 'node:crypto'
import {DatabaseSync} from 'node:sqlite'
import {mkdirSync,mkdtempSync,readFileSync,realpathSync,rmSync,statSync} from 'node:fs'
import retentionFiles from 'node:fs/promises'
import {join} from 'node:path'
import {fileURLToPath} from 'node:url'
import {mock} from 'node:test'
import * as contracts from '../contracts/src/runtime.mjs'
import {createAuthorityService,provisionNewAuthorityStore,loginSigningBytes,approvalSigningBytes,executionReceiptDigest,memoryEffectReceiptDigest} from './src/index.mjs'
import {webauthnChallenge} from './src/webauthn.mjs'
import {PrimeApprovalStateStore} from './src/state-store.mjs'
import {ApprovalStateStore} from './upstream/scripts/aukora/approval-state-store.mjs'
import {didKeyFromEd25519PublicKey} from './upstream/plugins/aukora-aumlok/lib/did-key.mjs'
import {createPostgresMemory} from '../memory/src/index.mjs'
import {createFileControlRetentionPublisher,createFileControlRetentionReader} from '../memory/src/control-retention.mjs'
import {createControlRetentionCoordinator} from '../memory/src/control-retention-coordinator.mjs'
import {canonicalJSON} from '../memory/genesis/plugins/aukora-kira/lib/record.mjs'

const hash=v=>createHash('sha256').update(v).digest('hex')
const opKey=op=>hash(contracts.canonicalJson([op.owner_id,op.operation_id]))
let nextPid=49000
// Adapted from D's owned memory.test.mjs. These replies are not actual PG evidence.
class SQLiteSessionPool {
 constructor(path,fault,events) {this.db=new DatabaseSync(path);this.fault=fault;this.events=events;this.queue=Promise.resolve();this.sessions=new Map()}
 async connect() {
  const previous=this.queue;let releaseQueue
  this.queue=new Promise(resolve=>{releaseQueue=resolve});await previous
  const session={backend_pid:++nextPid,locks:new Map(),active:true};this.sessions.set(session.backend_pid,session)
  return {query:(sql,values)=>this.query(sql,values,session),release:()=>{
   assert.equal(session.active,true);session.active=false;session.locks.clear();this.sessions.delete(session.backend_pid);releaseQueue()
  }}
 }
 close(){this.db.close()}
 async query(sql,values=[],session) {
  if(sql.startsWith('SELECT pg_advisory_lock(')||sql.startsWith('SELECT pg_backend_pid()')||sql.startsWith('SELECT pg_advisory_unlock(')) {
   assert.equal(session?.active,true);assert.equal(values.length,1)
   const held=session.locks.get(values[0])??0
   if(sql.startsWith('SELECT pg_backend_pid()'))return {rows:[{backend_pid:session.backend_pid,held:held>0}]}
   if(sql.startsWith('SELECT pg_advisory_lock(')){session.locks.set(values[0],held+1);return {rows:[{backend_pid:session.backend_pid}]}}
   if(held)session.locks.set(values[0],held-1)
   return {rows:[{unlocked:held>0}]}
  }
  if(sql.startsWith('SELECT current_setting'))return {rows:[{fsync:'on',full_page_writes:'on'}]}
  if(/^SET LOCAL|^SELECT pg_advisory_xact_lock/.test(sql))return {rows:[]}
  if(sql.startsWith('INSERT INTO prime_memory_intents')) {
   this.events.push('intent-write')
   if(this.fault.mode==='intent-before')throw new Error('ordinary injected intent write failure')
  }
  if(sql.startsWith('INSERT INTO prime_memory_outbox')&&this.fault.mode==='effect-before')throw new Error('ordinary injected effect write failure')
  sql=sql.replace('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY','BEGIN')
   .replace("document tsvector GENERATED ALWAYS AS (to_tsvector('simple',statement)) STORED",'document text GENERATED ALWAYS AS (statement) STORED')
   .replace('USING gin(document)','(document)').replace(/::integer/g,'')
   .replace(/=ANY\((\$\d+)::text\[\]\)/g,' IN (SELECT value FROM json_each($1))')
   .replace("f.document @@ plainto_tsquery('simple',$6)","f.statement LIKE '%' || $6 || '%'")
   .replace("ts_rank(f.document,plainto_tsquery('simple',$6))",'length(f.statement)')
   .replace(' FOR UPDATE SKIP LOCKED','')
  let result
  if(!values.length){this.db.exec(sql);result={rows:[]}}
  else {
   const ordered=[]
   sql=sql.replace(/\$(\d+)/g,(_,n)=>{const v=values[Number(n)-1];ordered.push(Array.isArray(v)?JSON.stringify(v):v);return '?'})
   result={rows:this.db.prepare(sql).all(...ordered).map(r=>({...r,...(r.searchable!==undefined?{searchable:Boolean(r.searchable)}:{})}))}
  }
  if(sql==='COMMIT'&&this.fault.mode&&this.db.prepare("SELECT count(*) AS n FROM sqlite_master WHERE name='prime_memory_intents'").get().n) {
   const intents=this.db.prepare('SELECT count(*) AS n FROM prime_memory_intents').get().n,effects=this.db.prepare('SELECT count(*) AS n FROM prime_memory_effects').get().n
   if((this.fault.mode==='intent-commit-reply'&&intents&&!effects)||(this.fault.mode==='effect-commit-reply'&&effects)) {
    this.fault.mode=null;throw new Error('ordinary injected committed transaction reply lost')
   }
  }
  return result
 }
}

export async function runRetainedMemoryChecks() {
 let checks=0,cases=0
 const allPatches=[]
 const check=(value,message)=>{assert(value,message);checks++}
 const same=(a,b,message)=>{assert.deepEqual(a,b,message);checks++}
 const ok=value=>{check(value?.ok===true,JSON.stringify(value));return value}
 const no=value=>{check(value?.ok===false,JSON.stringify(value));return value}
 const root=mkdtempSync(join(realpathSync('/tmp'),'prime-retained-cd-'))
 const keys=generateKeyPairSync('ed25519'),raw=Buffer.from(keys.publicKey.export({format:'jwk'}).x,'base64url').toString('hex')
 const identity={owner_id:'retained-cd-owner',subject:'aukora:1:'+'a'.repeat(64),approval_key_did:didKeyFromEd25519PublicKey(raw),control_digest:'b'.repeat(64),authorization_epoch:0}
 const at='2026-10-02T01:00:00Z',statement='Disposable public retained join banana.'
 const bytes=Buffer.from(JSON.stringify({type:'turn',text:statement,seq:0,at})+'\n')
 const host={owner_subject:identity.subject,owner_id:identity.owner_id,authorization_epoch:0,task_id:'retained-cd-task',privacy:'local',scope:'owner',attributedTo:'owner',source:{sessionId:'retained-cd-session',seq:0,at,sha256:hash(bytes)},events:[bytes]}
 const retainedHost={owner_id:identity.owner_id,owner_subject:identity.subject,authorization_epoch:0}
 const input={category:'fact',statement,validFrom:'2026-10-02',observedAt:at,confidence:0.7,sensitivity:'none'}
 async function fixture(name,{kind='owner_key'}={}) {
  const dir=join(root,name);mkdirSync(dir,{mode:0o700})
  const directory=join(dir,'retained');mkdirSync(directory,{mode:0o750})
  const stateRoot=join(dir,'state');mkdirSync(stateRoot,{mode:0o700})
  const actualUid=process.getuid(),publisherUid=actualUid+100000,gid=statSync(directory).gid,patches=[]
  const patch=(o,k,fn)=>{const p=mock.method(o,k,fn);patches.push(p);allPatches.push(p);return p}
  const uid=patch(process,'getuid',()=>actualUid),euid=patch(process,'geteuid',()=>actualUid)
  patch(process,'getgroups',()=>[gid])
  const role=value=>{uid.mock.mockImplementation(()=>value);euid.mock.mockImplementation(()=>value)}
  // Only retention path ownership/setgid is modeled; C paths retain real stat/UID.
  const metadata=(filename,stat)=>String(filename).startsWith(directory)||[root,dir].includes(String(filename))?Object.assign(Object.create(Object.getPrototypeOf(stat)),stat,{uid:typeof stat.uid==='bigint'?BigInt(publisherUid):publisherUid,...(String(filename)===directory?{mode:typeof stat.mode==='bigint'?stat.mode|0o2000n:stat.mode|0o2000}:{})}):stat
  const lstat=retentionFiles.lstat,open=retentionFiles.open
  patch(retentionFiles,'lstat',async(filename,...args)=>metadata(filename,await lstat(filename,...args)))
  patch(retentionFiles,'open',async(filename,...args)=>{const handle=await open(filename,...args),stat=handle.stat.bind(handle);handle.stat=async(...args)=>metadata(filename,await stat(...args));return handle})
  const config={directory,publisher_uid:publisherUid,reader_uid:actualUid,retention_gid:gid,contracts}
  // In-process synthetic authenticator only: no navigator, enrollment or human-presence claim.
  const ec=kind==='passkey'?generateKeyPairSync('ec',{namedCurve:'prime256v1'}):null,jwk=ec?.publicKey.export({format:'jwk'})
  const credential=ec?{owner_id:identity.owner_id,credential_id:randomBytes(32).toString('base64url'),public_key_hex:'04'+Buffer.from(jwk.x,'base64url').toString('hex')+Buffer.from(jwk.y,'base64url').toString('hex'),user_handle:randomBytes(32).toString('base64url'),sign_count:0,backup_eligible:false}:null
  const webauthn=ec?{rp_id:'prime-retained-fixture.test',origins:['https://prime-retained-fixture.test'],credentials:[credential]}:undefined
  let counter=0
  const assertion=challenge=>{const client=Buffer.from(JSON.stringify({type:'webauthn.get',challenge,origin:webauthn.origins[0],crossOrigin:false})),auth=Buffer.alloc(37);Buffer.from(hash(webauthn.rp_id),'hex').copy(auth);auth[32]=5;auth.writeUInt32BE(++counter,33);return {kind:'passkey',credential_id:credential.credential_id,client_data_json:client.toString('base64url'),authenticator_data:auth.toString('base64url'),signature:sign('sha256',Buffer.concat([auth,Buffer.from(hash(client),'hex')]),ec.privateKey).toString('base64url'),user_handle:credential.user_handle}}
  const fault={mode:null},events=[],calls={reserve:0,dispatch:0,settle:0,unknown:0},bindings={}
  let pool=new SQLiteSessionPool(join(dir,'memory.sqlite'),fault,events),memory,service,publisher
  role(publisherUid);publisher=createFileControlRetentionPublisher(config);role(actualUid)
  const plain=createPostgresMemory({pool,contracts});await plain.migrate()
  role(publisherUid)
  try{await publisher.publish({host:retainedHost,control_state:await plain.exportControlState(host),expected_checkpoint_sha256:null})}
  finally{role(actualUid)}
  const reader=createFileControlRetentionReader(config)
  const statePath=join(stateRoot,'authority.json'),readC=()=>JSON.parse(readFileSync(statePath,'utf8'))
  let operation,baseline={intents:0,effects:0,consumed:0}
  const row=()=>readC().broker.operations[opKey(operation)]
  const counts=()=>Object.fromEntries(['intents','effects','records'].map(k=>[k,pool.db.prepare('SELECT count(*) AS n FROM prime_memory_'+k).get().n]))
  const privatePublisher=Object.fromEntries(['beginMutation','retainPrepared','publishMutation'].map(method=>[method,async args=>{
   events.push(method+'-attempt')
   if(method==='beginMutation') {
    same(row().status,'APPROVED','marker precedes C prepared')
    same(readC().state.consumedIds.length,baseline.consumed,'marker must precede kernel consumption')
    same(readFileSync(statePath+'.lock','utf8'),String(process.pid),'C holds original state writer lock while awaiting marker')
    same(readFileSync(join(dir,'witness','writer.lock'),'utf8'),String(process.pid),'C holds original witness writer lock while awaiting marker')
    if(fault.mode==='marker-before')throw new Error('ordinary injected marker write failure')
   }
   if(method==='retainPrepared') {
    same(row().status,'PREPARED','intent checkpoint follows C PREPARED')
    same(counts().intents,baseline.intents+1,'intent checkpoint follows SQL intent commit')
    same(counts().effects,baseline.effects,'prepared checkpoint precedes effects')
    if(fault.mode==='prepared-before')throw new Error('ordinary injected prepared generation write failure')
   }
   if(method==='publishMutation') {
    check(['DISPATCHED','OUTCOME_UNKNOWN'].includes(row().status),'final checkpoint precedes C terminal settlement')
    same(counts().effects,baseline.effects+1,'actual SQL effect must precede final checkpoint')
    check(row().operation?.canonical_parameters?.statement===operation.canonical_parameters.statement,'unsettled memory payload must survive')
    if(fault.mode==='final-before')throw new Error('ordinary injected final publication failure')
   }
   role(publisherUid)
   let result
   try{result=await publisher[method](args)}finally{role(actualUid)}
   events.push(method+'-durable')
   if(method==='beginMutation') {
    same(readFileSync(statePath+'.lock','utf8'),String(process.pid),'C original state writer lock survives awaited marker publication')
    same(readFileSync(join(dir,'witness','writer.lock'),'utf8'),String(process.pid),'C original witness writer lock survives awaited marker publication')
    // Disposable controller clock only: resume C after the original session/proof expired.
    if(fault.mode==='expire-after-marker')Date.now=()=>Date.parse(sessionExpiry)+1
   }
   if((method==='beginMutation'&&fault.mode==='marker-reply')||(method==='retainPrepared'&&fault.mode==='prepared-reply')||(method==='publishMutation'&&fault.mode==='final-reply'))throw new Error('ordinary injected durable publisher reply lost')
   return result
  }]))
  const authority={
   async reserveRetained(args){calls.reserve++;events.push('reserve-attempt');const result=await service.reserveRetained(args);bindings.reserveReply=result;if(result.ok)events.push('C-PREPARED');if(fault.mode==='reserve-reply')throw new Error('ordinary injected C reserve reply lost');return result},
   async claimDispatchRetained(args){bindings.dispatch=args;calls.dispatch++;events.push('dispatch-attempt');const observed=await reader.inspectPending(retainedHost);check(observed.prepared!==null,'dispatch requires immutable prepared generation');same(observed.current.checkpoint_sha256,observed.predecessor.checkpoint_sha256,'prepared generation must not advance pointer');same(observed.prepared.control_state.tables.intents.length,baseline.intents+1,'dispatch requires retained exact intent');check(observed.prepared.control_state.tables.intents.some(r=>r.operation_id===args.operation.operation_id),'retained intent binds current operation');if(fault.mode==='dispatch-before')throw new Error('ordinary injected C dispatch request failure');const result=await service.claimDispatchRetained(args);if(result.ok)events.push('C-DISPATCHED');if(fault.mode==='dispatch-reply')throw new Error('ordinary injected C dispatch reply lost');return result},
   async settleMemoryRetained(args){bindings.settle=args;calls.settle++;events.push('settle-attempt');const current=await reader.readCurrent(retainedHost);check(current.control_state.tables.effects.some(r=>r.operation_id===args.operation.operation_id),'terminal settlement requires retained actual matching effect');if(fault.mode==='settle-before')throw new Error('ordinary injected C settlement request failure');const result=await service.settleMemoryRetained(args);if(result.ok)events.push('C-COMPLETED');if(fault.mode==='settle-reply')throw new Error('ordinary injected C settlement reply lost');return result},
   markOutcomeUnknown(args){calls.unknown++;return service.markOutcomeUnknown(args)}
  }
  const makeMemory=()=>{memory=createPostgresMemory({pool,authority,contracts,controlRetentionCoordinator:createControlRetentionCoordinator({reader,publisher:privatePublisher,contracts})});return memory}
  makeMemory()
  const authorityOptions={statePath,stateRoot,witnessDir:join(dir,'witness'),audience:'aukora-prime.memory',identities:[identity],loginKinds:[kind],...(webauthn?{webauthn}:{}),provisionTrustedState:true,retainedMemoryParticipant:memory.retainedMemoryParticipant,
   policy:{version:'retained-cd-v1',actions:['memory.save'],agents:['retained-cd-agent'],data_scope:['public'],maximum_cost:{currency:'USD',amount:'0'}},
   authorizeTask:op=>({authenticated:true,task:{version:1,task_id:host.task_id,owner_id:op.owner_id,agent_id:'retained-cd-agent',conversation_id:'retained-cd-conversation',status:'running',created_at:new Date().toISOString(),route_id:null,allowed_data_classes:['public'],max_input_tokens:0,max_output_tokens:0,max_requests:0,task_spend_ceiling:{currency:'USD',amount:'0'}}}),
   observeTarget:op=>memory.authorityTargetObservation(op)}
  ok(provisionNewAuthorityStore(authorityOptions));service=createAuthorityService(authorityOptions)
  const login=ok(service.loginChallenge({owner_id:identity.owner_id,kind})),challenge=login.challenge
  if(kind==='passkey')same(login.public_key.challenge,webauthnChallenge(loginSigningBytes(challenge)),'P256 login assertion binds exact C login domain')
  const loginResult=ok(service.loginComplete({challenge,material:kind==='passkey'?assertion(login.public_key.challenge):{kind:'owner_key',signature:sign(null,loginSigningBytes(challenge),keys.privateKey).toString('hex')}})),token=loginResult.session_token,sessionExpiry=loginResult.expiry
  const binding=await memory.prepareCaptureBinding(host,input,'retained-key')
  operation={version:1,operation_id:'retained-op-'+name,task_id:host.task_id,owner_id:identity.owner_id,agent_id:'retained-cd-agent',audience:'aukora-prime.memory',action_type:'memory.save',target_identity:binding.target_identity,canonical_parameters:binding.canonical_parameters,data_scope:['public'],expected_state_version:binding.state_version,provider_and_region:{provider:'none',region:'local'},maximum_cost:{currency:'USD',amount:'0'},expiry:new Date(Date.now()+600000).toISOString(),nonce:randomBytes(32).toString('hex'),policy_version:'retained-cd-v1',authorization_epoch:0}
  const approval_proof=await memory.withAuthorityTargetObservation(host,operation,async()=>{
   ok(service.propose({session_token:token,operation}));const r=ok(service.approvalChallenge({session_token:token,operation}))
   if(kind==='passkey')same(r.public_key.challenge,webauthnChallenge(approvalSigningBytes(r.approval_request)),'P256 approval assertion binds exact C approval domain')
   const proof={...r.proof_template,material:kind==='passkey'?assertion(r.public_key.challenge):{kind:'owner_key',request:r.approval_request,signature:sign(null,approvalSigningBytes(r.approval_request),keys.privateKey).toString('hex')}}
   ok(service.approvalComplete({session_token:token,proof}));return proof
  })
  const options={operation,approval_proof}
  return {reader,fault,events,calls,bindings,counts,row,readC,options,token,sessionExpiry,authorityOptions,get service(){return service},get memory(){return memory},
   execute:()=>memory.captureAuthorizedRemembered(host,input,'retained-key',options),
   async seedLegacyTerminal() {
    // Obtain the full row, receipt and kernel consumption from a genuine signed
    // non-retained C/D save; the original journal restores only its legacy shape.
    const {retainedMemoryParticipant,...legacyOptions}=authorityOptions
    let legacyMemory,legacyService,captured
    const legacyAuthority={reserve:args=>legacyService.reserve(args),claimDispatch:args=>legacyService.claimDispatch(args),
     settleMemory:args=>{captured=structuredClone(row());return legacyService.settleMemory(args)},markOutcomeUnknown:args=>legacyService.markOutcomeUnknown(args)}
    legacyMemory=createPostgresMemory({pool,authority:legacyAuthority,contracts})
    legacyService=createAuthorityService({...legacyOptions,observeTarget:op=>legacyMemory.authorityTargetObservation(op)})
    const saved=await legacyMemory.captureAuthorizedRemembered(host,input,'retained-key',options)
    same(saved.authority_settlement,'completed','legacy fixture uses a real non-retained signed C/D effect')
    same(row().schema,'prime-terminal-operation-v1','ordinary old profile accepted the exact actual receipt')
    captured.status='COMPLETED';captured.dispatch.receipt=structuredClone(saved.receipt)
    captured.dispatch.receipt_digest=memoryEffectReceiptDigest(saved.receipt);captured.dispatch.settlement_digests.push(captured.dispatch.receipt_digest)
    const store=new PrimeApprovalStateStore({statePath,stateRoot,witnessDir:authorityOptions.witnessDir})
    try {
     store.open();store.load();const broker=structuredClone(store.broker);broker.operations[opKey(operation)]=captured;broker.revision++
     ApprovalStateStore.prototype.commit.call(store,{...store.currentRecord,broker})
     store.retainBrokerRevision(broker.revision)
    }finally{store.close()}
    service=createAuthorityService(authorityOptions)
    return {saved,captured}
   },
   async executeIndependent() {
    const first=operation,firstBaseline=baseline,text='Second disposable retained join fruit.',eventBytes=Buffer.from(JSON.stringify({type:'turn',text,seq:0,at})+'\n')
    const secondHost={...host,source:{...host.source,sessionId:'retained-cd-second-session',sha256:hash(eventBytes)},events:[eventBytes]},secondInput={...input,statement:text}
    const secondBinding=await memory.prepareCaptureBinding(secondHost,secondInput,'independent-key')
    baseline={...counts(),consumed:readC().state.consumedIds.length}
    operation={...first,operation_id:first.operation_id+'-independent',canonical_parameters:secondBinding.canonical_parameters,expected_state_version:secondBinding.state_version,nonce:randomBytes(32).toString('hex')}
    try {
     const secondProof=await memory.withAuthorityTargetObservation(secondHost,operation,async()=>{
      ok(service.propose({session_token:token,operation}));const r=ok(service.approvalChallenge({session_token:token,operation}))
      const proof={...r.proof_template,material:kind==='passkey'?assertion(r.public_key.challenge):{kind:'owner_key',request:r.approval_request,signature:sign(null,approvalSigningBytes(r.approval_request),keys.privateKey).toString('hex')}}
      ok(service.approvalComplete({session_token:token,proof}));return proof
     })
     return await memory.captureAuthorizedRemembered(secondHost,secondInput,'independent-key',{operation,approval_proof:secondProof})
    }finally{operation=first;baseline=firstBaseline}
   },
   async reopen(){pool.close();pool=new SQLiteSessionPool(join(dir,'memory.sqlite'),fault,events);makeMemory();service=createAuthorityService({...authorityOptions,retainedMemoryParticipant:memory.retainedMemoryParticipant});return memory},
   freshPublisher(){role(publisherUid);try{publisher=createFileControlRetentionPublisher(config)}finally{role(actualUid)}},
   close(){role(actualUid);pool.close();for(const patch of patches.reverse())patch.mock.restore();rmSync(dir,{recursive:true,force:true})}}
 }
 try {
  const good=await fixture('ordered')
  try {
   no(good.service.reserve(good.options));same(good.readC().state.consumedIds.length,0,'legacy reserve cannot bypass retained profile')
   const saved=await good.execute();same(saved.authority_settlement,'completed');same(good.row().status,'COMPLETED')
   const terminalBefore=canonicalJSON(good.row())
   no(good.service.claimDispatch(good.bindings.dispatch));no(good.service.settleMemory(good.bindings.settle));same(canonicalJSON(good.row()),terminalBefore,'legacy retained bypass refusals preserve durable terminal fact')
   const b=good.bindings.dispatch,op=b.operation,receipt={version:1,receipt_id:randomUUID(),operation_id:op.operation_id,task_id:op.task_id,owner_id:op.owner_id,operation_digest:b.consumed_grant.operation_digest,grant_id:b.consumed_grant.grant_id,request_id:b.request_id,status:'completed',stdout:'',stderr:'',exit_code:0,rpc_completion:'complete',output_truncated:false,sandbox:null,cleanup:'confirmed_absent',started_at:null,finished_at:new Date().toISOString(),error_code:null,reconciliation_required:false}
   const generic={...b,receipt,receipt_digest:executionReceiptDigest(receipt)}
   no(good.service.settle(generic));no(good.service.reconcileSettlement(generic));same(canonicalJSON(good.row()),terminalBefore,'execution receipt cannot bypass memory retained settlement')
   assert.throws(()=>createAuthorityService({...good.authorityOptions,retainedMemoryParticipant:{...good.memory.retainedMemoryParticipant}}));checks++
   same(good.row().schema,'prime-retained-terminal-operation-v1','terminal memory compacts only after retained settlement')
   check(!JSON.stringify(good.row()).includes(statement),'terminal row retains no literal memory statement')
   same(good.events,['reserve-attempt','beginMutation-attempt','beginMutation-durable','C-PREPARED','intent-write','retainPrepared-attempt','retainPrepared-durable','dispatch-attempt','C-DISPATCHED','publishMutation-attempt','publishMutation-durable','settle-attempt','C-COMPLETED'],'exact actual C/D order')
   const current=await good.reader.readCurrent(retainedHost);same(current.control_state.tables.intents.length,1);same(current.control_state.tables.effects.length,1)
   const prior={...good.calls};await good.reopen()
   same((await good.memory.cite(host,saved.record.record_id)).verdict,'VERIFIED','cold original bytes remain cited')
   const reconciled=await good.memory.reconcileEffect(host,good.options.operation.operation_id)
   same(reconciled.authority_settlement,'completed');same(good.calls.reserve,prior.reserve);same(good.calls.dispatch,prior.dispatch)
   const firstSettlement=good.bindings.settle,priorCheckpoint=(await good.reader.readCurrent(retainedHost)).checkpoint_sha256
   same((await good.executeIndependent()).authority_settlement,'completed')
   check((await good.reader.readCurrent(retainedHost)).checkpoint_sha256!==priorCheckpoint,'independent genuine operation advances retained checkpoint')
   const currentBefore=canonicalJSON(good.row()),duplicate=ok(await good.service.settleMemoryRetained(firstSettlement))
   same(duplicate.idempotent,true,'old known terminal receipt remains factual after newer owner checkpoint');same(canonicalJSON(good.row()),currentBefore,'terminal duplicate is read-only')
   await assert.rejects(good.memory.prepareRestoreBinding(host,await good.memory.exportSnapshot(host)),{code:'memory:retained-restore-lineage-unqualified'});checks++
   cases++
  }finally{good.close()}
  const p256=await fixture('p256',{kind:'passkey'})
  try {
   const saved=await p256.execute();same(saved.authority_settlement,'completed');same(p256.row().schema,'prime-retained-terminal-operation-v1')
   const prior={...p256.calls};await p256.reopen()
   same((await p256.memory.cite(host,saved.record.record_id)).verdict,'VERIFIED','genuine P256 cold original record citation')
   const reconciled=await p256.memory.reconcileEffect(host,p256.options.operation.operation_id)
   same(reconciled.authority_settlement,'completed');same(p256.calls.reserve,prior.reserve);same(p256.calls.dispatch,prior.dispatch);same(p256.counts().effects,1);cases++
  }finally{p256.close()}
  const expires=await fixture('expires-after-marker'),realNow=Date.now
  try {
   expires.fault.mode='expire-after-marker'
   await assert.rejects(expires.execute(),{code:'memory:authority-effect-outcome-unknown'});checks++
   check(Date.now()>Date.parse(expires.sessionExpiry)&&Date.now()>Date.parse(expires.options.approval_proof.expiry),'controller shift expires both review proof and original owner session')
   no(expires.bindings.reserveReply);same(expires.bindings.reserveReply.error_code,'EXPIRED');same(expires.bindings.reserveReply.reason,'adapter:approval-expired')
   same(expires.row().status,'APPROVED');same(expires.readC().state.consumedIds.length,0);same(expires.readC().prepared.length,0);same(expires.counts(),{intents:0,effects:0,records:0})
   same(expires.calls.dispatch,0);same(expires.calls.settle,0);check(expires.events.includes('beginMutation-durable'),'expiry occurs after marker is durable')
   const pending=await expires.reader.inspectPending(retainedHost);same(pending.prepared,null);same(pending.marker.operation_id,expires.options.operation.operation_id)
   await assert.rejects(expires.reader.readCurrent(retainedHost),{code:'memory:control-retention-update-pending'});checks++
   cases++
  }finally{Date.now=realNow;expires.close()}
  const legacy=await fixture('legacy-full-terminal')
  try {
   const {captured}=await legacy.seedLegacyTerminal(),before=canonicalJSON(legacy.row()),kernelBefore=canonicalJSON({state:legacy.readC().state,prepared:legacy.readC().prepared})
   same(legacy.row(),captured);same(legacy.row().status,'COMPLETED');check(!Object.hasOwn(legacy.row(),'schema'),'legacy terminal fixture keeps valid full row')
   check(legacy.row().operation.canonical_parameters.statement===statement&&legacy.row().dispatch.receipt.result.canonical_bytes.includes(statement),'legacy full operation/result payload is present before logout')
   same(ok(legacy.service.logoutSession({session_token:legacy.token})).status,'LOGGED_OUT')
   same(canonicalJSON(legacy.row()),before,'retained-profile logout preserves valid full terminal memory without retained evidence')
   same(canonicalJSON({state:legacy.readC().state,prepared:legacy.readC().prepared}),kernelBefore,'logout preserves genuine old consumed kernel/prepared obligations')
   no(legacy.service.authenticateSession({session_token:legacy.token}));same(legacy.calls,{reserve:0,dispatch:0,settle:0,unknown:0},'logout never fabricated retained participant evidence');cases++
  }finally{legacy.close()}
  for(const mode of ['marker-before','marker-reply','reserve-reply','intent-before','intent-commit-reply','prepared-before','prepared-reply','dispatch-before','dispatch-reply','effect-before','effect-commit-reply','final-before','final-reply','settle-before','settle-reply']) {
   const f=await fixture(mode)
   try {
    f.fault.mode=mode
    let result,error
    try{result=await f.execute()}catch(e){error=e}
    if(mode.startsWith('settle-')){same(result?.authority_settlement,'pending','settlement reply failure reports pending');check(!error,'committed effect is not retried on settlement error')}
    else {check(error,'ordinary interruption must refuse');if(mode!=='marker-before'){same(error.code,'memory:authority-effect-outcome-unknown');same(error.automatic_retry,false)}}
    const facts=f.counts(),prior={...f.calls},state=f.row().status,consumed=f.readC().state.consumedIds.length
    same(facts.records,facts.effects,'rolled back record/control effect remains atomic in SQLite fixture')
    if(['marker-before','marker-reply'].includes(mode)){same(consumed,0);same(state,'APPROVED')}
    else {same(consumed,1,'prepared approval stays one-use across interruption');check(['PREPARED','DISPATCHED','OUTCOME_UNKNOWN','COMPLETED'].includes(state),'durable authority obligation remains')}
    if(state!=='COMPLETED')check(f.row().operation?.canonical_parameters?.statement===statement,'nonterminal/unknown retains full reconciliation payload')
    if(mode==='settle-before') {
     ok(f.service.logoutSession({session_token:f.token}));same(f.row().status,'DISPATCHED');check(f.row().operation?.canonical_parameters?.statement===statement,'unrelated logout must not compact unretained terminal row')
    }
    f.fault.mode=null;f.freshPublisher();await f.reopen()
    if(facts.effects) {
     const reconciled=await f.memory.reconcileEffect(host,f.options.operation.operation_id)
     same(reconciled.authority_settlement,'completed','only factual committed receipt settles cold authority')
     same(f.row().status,'COMPLETED');same(f.row().schema,'prime-retained-terminal-operation-v1')
     same((await f.reader.readCurrent(retainedHost)).control_state.tables.effects.length,1)
    } else {
     if(facts.intents){const unresolved=await f.memory.reconcileEffect(host,f.options.operation.operation_id);same(unresolved.status,'unresolved');same(unresolved.automatic_retry,false)}
     else {await assert.rejects(f.memory.reconcileEffect(host,f.options.operation.operation_id),{code:'memory:effect-missing-outcome-unknown'});checks++}
     if(mode==='marker-before')same((await f.reader.readCurrent(retainedHost)).control_state.tables.effects.length,0)
     else {await assert.rejects(f.reader.readCurrent(retainedHost),{code:'memory:control-retention-update-pending'});checks++}
     same(f.row().status,state,'unresolved reconciliation cannot dispatch or clear authority')
     if(mode!=='marker-before') {await assert.rejects(f.execute());checks++;same(f.row().status,state,'repeated effect cannot clear an unresolved retained obligation')}
    }
    same(f.calls.reserve,prior.reserve,'cold reconcile never reserves');same(f.calls.dispatch,prior.dispatch,'cold reconcile never dispatches');same(f.counts(),facts,'cold reconcile never reruns effect');same(f.readC().state.consumedIds.length,consumed,'cold reconcile never unconsumes')
    cases++
   }finally{f.close()}
  }
  return {status:'PASS',checks,cases,groups:['actual signed Ed25519 and P256 C kernel/store with D branded participant','marker before PREPARED; immutable intent before dispatch; final checkpoint before terminal compaction','ordinary interruptions preserve one-use/unknown/pending duties; fresh at-use session/proof expiry after marker','receipt-only cold reconciliation without effect relaunch; old terminal receipt after later checkpoint','retained-profile logout preserves valid full legacy terminal memory','retained restore unavailable; legacy and generic receipt bypasses gated'],limits:'SQLite dialect fixture and modeled PostgreSQL session/retention UID/setgid metadata under one actual UID; synthetic P256 assertion is no browser/enrollment/human-presence proof. Clock shift is test-process-only; production TTL unchanged. No real PostgreSQL, distinct UID, IPC, power-loss proof, live runtime or real keys. No stopped adversarial audit or mutants.'}
 }finally{for(const patch of allPatches.reverse())patch.mock.restore();rmSync(root,{recursive:true,force:true})}
}
if(process.argv[1]===fileURLToPath(import.meta.url)) {
 try{process.stdout.write(JSON.stringify(await runRetainedMemoryChecks())+'\n')}
 catch(error){process.stderr.write(String(error.stack)+'\n');process.exitCode=1}
}
