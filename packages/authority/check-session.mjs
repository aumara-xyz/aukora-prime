#!/usr/bin/env node
// Disposable signed session/logout regression; no application, DB or runtime is touched.
import assert from 'node:assert/strict'
import {createHash,generateKeyPairSync,randomBytes,randomUUID,sign} from 'node:crypto'
import {mkdirSync,mkdtempSync,readFileSync,realpathSync,rmSync,writeFileSync} from 'node:fs'
import {tmpdir} from 'node:os'
import {join} from 'node:path'
import {fileURLToPath} from 'node:url'
import {canonicalJson} from '../contracts/src/runtime.mjs'
import {createAuthorityService,provisionNewAuthorityStore,loginSigningBytes,approvalSigningBytes,operationDigest,memoryResultDigest} from './src/index.mjs'
import {didKeyFromEd25519PublicKey} from './upstream/plugins/aukora-aumlok/lib/did-key.mjs'

export function runSessionChecks() {
 const root=mkdtempSync(join(realpathSync(tmpdir()),'prime-session-'))
 let checks=0
 const ok=v=>{assert.equal(v.ok,true,JSON.stringify(v));checks++;return v}
 const no=(v,code)=>{assert.equal(v.ok,false,JSON.stringify(v));if(code)assert.equal(v.error_code,code,JSON.stringify(v));checks++;return v}
 const check=(condition,message)=>{assert(condition,message);checks++}
 const owners=[1,2].map(n=>{
  const keys=generateKeyPairSync('ed25519')
  const raw=Buffer.from(keys.publicKey.export({format:'jwk'}).x,'base64url').toString('hex')
  return {keys,identity:{owner_id:'fixture-owner-'+n,subject:'aukora:1:'+String(n).repeat(64),approval_key_did:didKeyFromEd25519PublicKey(raw),control_digest:String(n+2).repeat(64),authorization_epoch:0}}
 })
 function setup(name) {
  const dir=join(root,name),state=join(dir,'state');mkdirSync(dir,{mode:0o700});mkdirSync(state,{mode:0o700})
  const config={statePath:join(state,'authority.json'),stateRoot:state,witnessDir:join(dir,'witness'),audience:'prime:session-fixture',identities:owners.map(x=>x.identity),loginKinds:['owner_key'],provisionTrustedState:true,
   policy:{version:'fixture-v1',actions:['memory.save'],agents:['fixture-agent'],data_scope:['public'],maximum_cost:{currency:'USD',amount:'0'}},
   authorizeTask:op=>({authenticated:true,task:{version:1,task_id:'fixture-task',owner_id:op.owner_id,agent_id:'fixture-agent',conversation_id:'fixture-conversation',status:'running',created_at:new Date(Date.now()).toISOString(),route_id:null,allowed_data_classes:['public'],max_input_tokens:0,max_output_tokens:0,max_requests:0,task_spend_ceiling:{currency:'USD',amount:'0'}}}),
   observeTarget:op=>({target_identity:op.target_identity,state_version:'fixture-r1'})}
  ok(provisionNewAuthorityStore(config));return {config,service:createAuthorityService(config)}
 }
 function login(s,owner=owners[0]) {
  const challenge=ok(s.loginChallenge({owner_id:owner.identity.owner_id,kind:'owner_key'})).challenge
  return ok(s.loginComplete({challenge,material:{kind:'owner_key',signature:sign(null,loginSigningBytes(challenge),owner.keys.privateKey).toString('hex')}}))
 }
 function operation(id,owner=owners[0]) {return {version:1,operation_id:id,task_id:'fixture-task',owner_id:owner.identity.owner_id,agent_id:'fixture-agent',audience:'prime:session-fixture',action_type:'memory.save',target_identity:{kind:'prime-memory',owner_subject:owner.identity.subject},canonical_parameters:{statement:'Disposable public session fixture'},data_scope:['public'],expected_state_version:'fixture-r1',provider_and_region:{provider:'none',region:'local'},maximum_cost:{currency:'USD',amount:'0'},expiry:new Date(Date.now()+600000).toISOString(),nonce:randomBytes(32).toString('hex'),policy_version:'fixture-v1',authorization_epoch:0}}
 function review(s,token,op,owner=owners[0]) {
  ok(s.propose({session_token:token,operation:op}))
  const r=ok(s.approvalChallenge({session_token:token,operation:op}))
  return {...r.proof_template,material:{kind:'owner_key',request:r.approval_request,signature:sign(null,approvalSigningBytes(r.approval_request),owner.keys.privateKey).toString('hex')}}
 }
 function approved(s,token,op) {const proof=review(s,token,op);ok(s.approvalComplete({session_token:token,proof}));return proof}
 function prepare(s,token,op) {
  const proof=approved(s,token,op)
  return {operation:op,consumed_grant:ok(s.reserve({operation:op,approval_proof:proof})).consumed_grant,request_id:randomUUID(),request_digest:'sha256:'+createHash('sha256').update('aukora-prime.memory.effect.v1\0'+canonicalJson({operation:op})).digest('hex')}
 }
 function receipt(b) {const result={storage_status:'saved',index_status:'pending',record_id:'public-fixture'};return {version:1,kind:'prime-memory-effect/v1',operation_id:b.operation.operation_id,operation_digest:operationDigest(b.operation),grant_id:b.consumed_grant.grant_id,request_id:b.request_id,request_digest:b.request_digest,owner_subject:b.operation.target_identity.owner_subject,action_type:b.operation.action_type,status:'applied',result_digest:memoryResultDigest(result),result}}
 const read=f=>JSON.parse(readFileSync(f.config.statePath,'utf8'))
 function unchanged(f,call) {
  const before=readFileSync(f.config.statePath),witness=readFileSync(join(f.config.witnessDir,'kernel-high-water.json'))
  call();check(readFileSync(f.config.statePath).equals(before),'refused call changed state');check(readFileSync(join(f.config.witnessDir,'kernel-high-water.json')).equals(witness),'refused call changed witness')
 }
 try {
  const f=setup('logout'),s=f.service,token=login(s).session_token,other=login(s).session_token,cross=login(s,owners[1]).session_token
  for(const input of [{},{session_token:'bad'},{session_token:'0'.repeat(64)},{session_token:token,owner_id:owners[1].identity.owner_id}])unchanged(f,()=>no(s.logoutSession(input)))
  const pending=operation('pending'),pendingProof=review(s,token,pending)
  const app=operation('approved'),proof=approved(s,token,app)
  const prep=prepare(s,token,operation('prepared')),dispatched=prepare(s,token,operation('dispatched'))
  ok(s.claimDispatch(dispatched))
  const consumedBefore=read(f).state.consumedIds.slice(),beforeLogout=readFileSync(f.config.statePath)
  check(ok(s.logoutSession({session_token:token})).status==='LOGGED_OUT','logout status')
  const reopened=createAuthorityService(f.config)
  unchanged(f,()=>no(reopened.authenticateSession({session_token:token}),'UNAUTHORIZED'))
  unchanged(f,()=>no(reopened.logoutSession({session_token:token}),'UNAUTHORIZED'))
  unchanged(f,()=>no(reopened.propose({session_token:token,operation:operation('after-logout')}),'UNAUTHORIZED'))
  unchanged(f,()=>no(reopened.approvalComplete({session_token:token,proof:pendingProof}),'UNAUTHORIZED'))
  unchanged(f,()=>no(reopened.reserve({operation:app,approval_proof:proof}),'UNAUTHORIZED'))
  unchanged(f,()=>no(reopened.claimDispatch(prep),'UNAUTHORIZED'))
  check(read(f).state.consumedIds.length===consumedBefore.length,'logout consumed or unconsumed approval')
  check(ok(reopened.authenticateSession({session_token:other})).owner_id===owners[0].identity.owner_id,'logout revoked different session')
  check(ok(reopened.authenticateSession({session_token:cross})).owner_id===owners[1].identity.owner_id,'logout revoked different owner')
  const fresh=login(reopened).session_token
  unchanged(f,()=>no(reopened.reserve({operation:app,approval_proof:proof}),'UNAUTHORIZED'))
  ok(reopened.propose({session_token:fresh,operation:operation('fresh-session')}))
  check(ok(reopened.status({session_token:fresh,operation_id:prep.operation.operation_id})).status==='PREPARED','prepared duty lost at logout')
  ok(reopened.markOutcomeUnknown(dispatched))
  check(ok(reopened.settleMemory({...dispatched,receipt:receipt(dispatched)})).status==='COMPLETED','logout blocked factual settlement')
  check(ok(createAuthorityService(f.config).settleMemory({...dispatched,receipt:receipt(dispatched)})).idempotent===true,'logout blocked duplicate factual evidence')
  check(JSON.stringify(read(f).state.consumedIds)===JSON.stringify(consumedBefore),'logout/reconciliation changed consumption')
  // Retained broker witness makes rollback to the pre-logout token state fail closed.
  writeFileSync(f.config.statePath,beforeLogout,{mode:0o600})
  no(createAuthorityService(f.config).authenticateSession({session_token:token}),'RECONCILIATION_REQUIRED')

  const e=setup('session-expiry'),realNow=Date.now,start=realNow()
  try {
   Date.now=()=>start
   const entry=login(e.service);check(Date.parse(entry.expiry)-start===300000,'production session TTL changed')
   Date.now=()=>Date.parse(entry.expiry)-30000
   const expOp=operation('approval-outlasts-session'),expProof=approved(e.service,entry.session_token,expOp)
   Date.now=()=>Date.parse(entry.expiry)+1
   check(Date.parse(expProof.expiry)>Date.now(),'fixture approval already expired')
   unchanged(e,()=>no(e.service.reserve({operation:expOp,approval_proof:expProof}),'UNAUTHORIZED'))
   check(read(e).state.consumedIds.length===0,'expired session approval consumed')
  } finally {Date.now=realNow}
  return {status:'PASS',checks,groups:['durable current-token logout; other session/owner unaffected','post-logout proposal/review/reserve/dispatch refusal and no new consumption','fresh login cannot revive old approval; prepared duties retained','dispatched factual settlement/replay survive logout','pre-logout rollback rejected by retained witness','active approval cannot outlive its five-minute owner session'],limits:'Synthetic in-process keys/disposable paths only; no public route, deployment or audit.'}
 } finally {rmSync(root,{recursive:true,force:true})}
}
if(process.argv[1]===fileURLToPath(import.meta.url)) {
 try {process.stdout.write(JSON.stringify(runSessionChecks())+'\n')}
 catch(error){process.stderr.write(String(error.stack)+'\n');process.exitCode=1}
}
