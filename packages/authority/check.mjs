import assert from 'node:assert/strict'
import { createHash, generateKeyPairSync, sign, randomBytes, randomUUID } from 'node:crypto'
import { mkdtempSync,mkdirSync,readFileSync,writeFileSync,rmSync,realpathSync,cpSync,symlinkSync,existsSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join,dirname } from 'node:path'
import { spawn } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import { createAuthorityService,provisionNewAuthorityStore,loginSigningBytes,approvalSigningBytes,operationDigest,executorRequestDigest,executionReceiptDigest,memoryResultDigest } from './src/index.mjs'
import { runKernelGuardChecks } from './check-kernel-guards.mjs'
import { didKeyFromEd25519PublicKey } from './upstream/plugins/aukora-aumlok/lib/did-key.mjs'
import { p256 } from './upstream/vendor/authority/deps/@noble/curves@2.2.0/nist.js'
import { verifyWebauthnAssertion,prepareWebauthnConfig } from './src/webauthn.mjs'
import { decideApproval } from './upstream/scripts/aukora/decide.mjs'
import { PrimeApprovalStateStore } from './src/state-store.mjs'
const trustedTask=(owner_id='fixture-owner')=>({authenticated:true,task:{version:1,task_id:'fixture-task',owner_id,agent_id:'fixture-agent',conversation_id:'fixture-conversation',status:'running',created_at:new Date().toISOString(),route_id:null,allowed_data_classes:['public'],max_input_tokens:0,max_output_tokens:0,max_requests:0,task_spend_ceiling:{currency:'USD',amount:'0'}}})
if(process.argv[2]==='reserve-child') {
 const v=JSON.parse(readFileSync(process.argv[3],'utf8'))
 const s=createAuthorityService({...v.config,authorizeTask:()=>trustedTask(),observeTarget:op=>({target_identity:op.target_identity,state_version:'r1'})})
 console.log(JSON.stringify(s.reserve(v.input)));process.exit(0)
}
const root=mkdtempSync(join(realpathSync(tmpdir()),'prime-authority-fixture-'))
const sha=x=>createHash('sha256').update(x).digest()
const clone=structuredClone
let checks=0
const ok=(r)=>{assert.equal(r.ok,true,JSON.stringify(r));return r}
const no=(r,code)=>{assert.equal(r.ok,false,JSON.stringify(r));if(code)assert.equal(r.error_code,code,JSON.stringify(r));checks++}
const ed=generateKeyPairSync('ed25519') // synthetic private key lives only in this process
const raw=Buffer.from(ed.publicKey.export({format:'jwk'}).x,'base64url').toString('hex')
const id={owner_id:'fixture-owner',subject:'aukora:1:'+'1'.repeat(64),approval_key_did:didKeyFromEd25519PublicKey(raw),control_digest:'2'.repeat(64),authorization_epoch:0}
let targetVersion='r1'
function setup(name,extra={}) {
 const path=join(root,name);mkdirSync(path,{mode:0o700});mkdirSync(join(path,'state'),{mode:0o700})
 const config={statePath:join(path,'state','authority.json'),stateRoot:join(path,'state'),witnessDir:join(path,'witness'),audience:'prime:test',identities:[id],loginKinds:['owner_key','passkey'],policy:{version:'p1',actions:['memory.save'],agents:['fixture-agent'],data_scope:['public'],maximum_cost:{currency:'USD',amount:'0'}},provisionTrustedState:true,authorizeTask:()=>trustedTask(),observeTarget:op=>({target_identity:op.target_identity,state_version:targetVersion}),...extra}
 ok(provisionNewAuthorityStore(config))
 return {config,service:createAuthorityService(config)}
}
const op=(name)=>({version:1,operation_id:name,task_id:'fixture-task',owner_id:id.owner_id,agent_id:'fixture-agent',audience:'prime:test',action_type:'memory.save',target_identity:{store:'fixture-memory',record:'note1'},canonical_parameters:{content:'public synthetic note'},data_scope:['public'],expected_state_version:'r1',provider_and_region:{provider:'none',region:'local'},maximum_cost:{currency:'USD',amount:'0'},expiry:new Date(Date.now()+60000).toISOString(),nonce:randomBytes(32).toString('hex'),policy_version:'p1',authorization_epoch:0})
const sessions=new WeakMap()
function login(service,ownerId=id.owner_id) {
 const challenge=ok(service.loginChallenge({owner_id:ownerId,kind:'owner_key'})).challenge
 const input={challenge,material:{kind:'owner_key',signature:sign(null,loginSigningBytes(challenge),ed.privateKey).toString('hex')}}
 const accepted=ok(service.loginComplete(input));no(service.loginComplete(input),'REPLAYED')
 const byOwner=sessions.get(service)??new Map();byOwner.set(ownerId,accepted.session_token);sessions.set(service,byOwner)
 return accepted.session_token
}
function propose(service,operation) {
 const ownerId=Object.getOwnPropertyDescriptor(operation,'owner_id')?.value??id.owner_id
 const session_token=sessions.get(service)?.get(ownerId)??login(service,ownerId)
 return service.propose({session_token,operation})
}
function approve(service,token,operation) {
 const challenge=ok(service.approvalChallenge({session_token:token,operation}))
 const proof={...challenge.proof_template,material:{kind:'owner_key',request:challenge.approval_request,signature:sign(null,approvalSigningBytes(challenge.approval_request),ed.privateKey).toString('hex')}}
 no(service.approvalComplete({session_token:'0'.repeat(64),proof}),'UNAUTHORIZED')
 ok(service.approvalComplete({session_token:token,proof}))
 return proof
}
try {
 const f=setup('core'),s=f.service
 const defaultLogin=setup('default-login',{loginKinds:undefined})
 no(defaultLogin.service.loginChallenge({owner_id:id.owner_id,kind:'owner_key'}),'UNAVAILABLE')
 no(s.loginChallenge({owner_id:id.owner_id,kind:'passkey'}),'UNAVAILABLE')
 const operation=op('one');ok(propose(s,operation))
 const fake={version:1,operation_id:operation.operation_id,operation_digest:operationDigest(operation),owner_id:id.owner_id,audience:operation.audience,authorization_epoch:0,expiry:operation.expiry,nonce:randomBytes(32).toString('hex'),material:{kind:'owner_key',request:{},signature:'0'.repeat(128)}}
 no(s.reserve({operation,approval_proof:fake}),'INVALID') // malformed proof never reaches authority
 const token=login(s),proof=approve(s,token,operation)
 const unsignedApprovalOperation=op('not-completed-review'),incomplete=ok(s.approvalChallenge({session_token:token,operation:unsignedApprovalOperation}))
 const signedButNotApproved={...incomplete.proof_template,material:{kind:'owner_key',request:incomplete.approval_request,signature:sign(null,approvalSigningBytes(incomplete.approval_request),ed.privateKey).toString('hex')}}
 no(s.reserve({operation:unsignedApprovalOperation,approval_proof:signedButNotApproved}),'UNAUTHORIZED')
 for(const [field,value] of [['target_identity',{store:'elsewhere'}],['canonical_parameters',{content:'changed'}],['data_scope',['secret']],['expected_state_version','r2'],['maximum_cost',{currency:'USD',amount:'1'}],['nonce','changed'],['expiry',new Date(Date.now()+120000).toISOString()],['agent_id','elsewhere'],['task_id','elsewhere'],['audience','wrong'],['authorization_epoch',1],['policy_version','p2']]) {
  no(s.reserve({operation:{...operation,[field]:value},approval_proof:proof}))
 }
 targetVersion='r2';no(s.reserve({operation,approval_proof:proof}),'TARGET_MISMATCH');targetVersion='r1'
 const before=readFileSync(f.config.statePath)
 const prepared=ok(s.reserve({operation,approval_proof:proof}));assert.equal(prepared.status,'PREPARED');checks++
 const durable=JSON.parse(readFileSync(f.config.statePath));assert.equal(durable.prepared.length,1);assert(durable.state.consumedIds.includes('approval:'+proof.nonce));assert.equal(Object.values(durable.broker.operations)[0].status,'PREPARED');checks++
 const restarted=createAuthorityService({...f.config,provisionTrustedState:false})
 no(restarted.reserve({operation,approval_proof:proof}),'REPLAYED')
 const req={operation,consumed_grant:prepared.consumed_grant,request_id:randomUUID(),image_digest:'sha256:'+'a'.repeat(64),policy_digest:'sha256:'+'b'.repeat(64),wall_time_ms:1000,max_output_bytes:1024}
 const claim={operation,consumed_grant:prepared.consumed_grant,request_id:req.request_id,request_digest:executorRequestDigest(req)}
 ok(restarted.claimDispatch(claim));no(restarted.claimDispatch(claim),'REPLAYED')
 writeFileSync(f.config.statePath,before,{mode:0o600});no(restarted.reserve({operation,approval_proof:proof}),'RECONCILIATION_REQUIRED')
 const d=setup('deny'),dt=login(d.service),dop=op('deny'),dp=approve(d.service,dt,dop)
 ok(d.service.declineApproval({session_token:dt,operation_id:dop.operation_id}));no(createAuthorityService(d.config).reserve({operation:dop,approval_proof:dp}),'CANCELLED')
 const e=setup('epoch'),et=login(e.service),eop=op('epoch'),ep=approve(e.service,et,eop),oldEpoch=readFileSync(e.config.statePath)
 no(e.service.advanceAuthorizationEpoch({session_token:et}),'UNAVAILABLE')
 const epochStore=new PrimeApprovalStateStore({statePath:e.config.statePath,stateRoot:e.config.stateRoot,witnessDir:e.config.witnessDir})
 try {epochStore.open();epochStore.load();Object.values(epochStore.broker.owners)[0].authorization_epoch++;epochStore.commitBroker()}finally{epochStore.close()}
 no(e.service.reserve({operation:eop,approval_proof:ep}),'REVOKED')
 writeFileSync(e.config.statePath,oldEpoch,{mode:0o600});no(e.service.reserve({operation:eop,approval_proof:ep}),'RECONCILIATION_REQUIRED') // receipt count unchanged; broker revision catches rewind
 no(propose(d.service,{...op('expired'),expiry:new Date(Date.now()-1000).toISOString()}),'EXPIRED')
 const sparse=op('sparse');sparse.data_scope=Array(1);no(propose(d.service,sparse))
 const decoratedSparse=op('decorated-sparse');decoratedSparse.canonical_parameters={a:Object.assign(Array(1),{extra:'collision'})};no(propose(d.service,decoratedSparse),'INVALID')
 const accessor=op('accessor');Object.defineProperty(accessor,'canonical_parameters',{get(){throw new Error('getter must never run')},enumerable:true});no(propose(d.service,accessor))
 const ec=generateKeyPairSync('ec',{namedCurve:'prime256v1'}) // disposable authenticator fixture
 const jwk=ec.publicKey.export({format:'jwk'}),publicHex='04'+Buffer.from(jwk.x,'base64url').toString('hex')+Buffer.from(jwk.y,'base64url').toString('hex')
 const cred={owner_id:id.owner_id,credential_id:randomBytes(32).toString('base64url'),public_key_hex:publicHex,user_handle:Buffer.from('fixture-owner').toString('base64url'),sign_count:0,backup_eligible:false}
 const wc={rp_id:'prime.example.test',origins:['https://prime.example.test'],credentials:[cred]}
 prepareWebauthnConfig(wc);assert(p256.Point.fromBytes(Buffer.from(publicHex,'hex')));checks++
 function assertion(challenge,count,change={}) {
  const client=Buffer.from(JSON.stringify({type:'webauthn.get',challenge,origin:wc.origins[0],crossOrigin:false,...change.client}))
  const auth=Buffer.alloc(37);sha(change.rp_id??wc.rp_id).copy(auth);auth[32]=change.flags??5;auth.writeUInt32BE(count,33)
  return {kind:'passkey',credential_id:cred.credential_id,client_data_json:client.toString('base64url'),authenticator_data:auth.toString('base64url'),signature:sign('sha256',Buffer.concat([auth,sha(client)]),ec.privateKey).toString('base64url'),user_handle:cred.user_handle,...change.material}
 }
 const pilot={...wc,profile:'localhost-pilot-v1',rp_id:'localhost',origins:['http://localhost:18731']}
 prepareWebauthnConfig(pilot);checks++
 for(const bad of [{...pilot,profile:'https'},{...pilot,rp_id:'127.0.0.1',origins:['http://127.0.0.1:18731']},{...pilot,origins:['http://localhost:18732']},{...pilot,origins:['https://localhost:18731']},{...pilot,rp_id:'sub.localhost',origins:['http://sub.localhost:18731']}]) {assert.throws(()=>prepareWebauthnConfig(bad),TypeError);checks++}
 const pilotChallenge=Buffer.from('synthetic-pilot-challenge').toString('base64url'),pilotMaterial=assertion(pilotChallenge,1,{client:{origin:pilot.origins[0]},rp_id:'localhost'})
 verifyWebauthnAssertion({material:pilotMaterial,config:pilot,ownerId:id.owner_id,challenge:pilotChallenge,counter:0});checks++
 assert.throws(()=>verifyWebauthnAssertion({material:assertion(pilotChallenge,1,{client:{origin:'http://127.0.0.1:18731'},rp_id:'localhost'}),config:pilot,ownerId:id.owner_id,challenge:pilotChallenge,counter:0}),/ORIGIN_MISMATCH/);checks++
 const w=setup('passkey',{webauthn:wc}),ws=w.service
 const ch=ok(ws.loginChallenge({owner_id:id.owner_id,kind:'passkey'}))
 assert.equal(ch.public_key.userVerification,'required');checks++
 const a=assertion(ch.public_key.challenge,1)
 no(ws.loginComplete({challenge:ch.challenge,material:{...a,client_data_json:Buffer.from('null').toString('base64url')}}),'UNAUTHORIZED')
 for(const material of [assertion(ch.public_key.challenge,1,{client:{origin:'https://evil.example.test'}}),assertion('wrong',1),assertion(ch.public_key.challenge,1,{flags:1}),assertion(ch.public_key.challenge,1,{rp_id:'evil.example.test'}),{...a,credential_id:randomBytes(32).toString('base64url')},{...a,user_handle:Buffer.from('wrong').toString('base64url')},{...a,signature:randomBytes(70).toString('base64url')},assertion(ch.public_key.challenge,1,{client:{crossOrigin:true}})]) no(ws.loginComplete({challenge:ch.challenge,material}),'UNAUTHORIZED')
 const wt=ok(ws.loginComplete({challenge:ch.challenge,material:a})).session_token
 no(ws.loginComplete({challenge:ch.challenge,material:a}),'REPLAYED')
 const countCh=ok(ws.loginChallenge({owner_id:id.owner_id,kind:'passkey'}));no(ws.loginComplete({challenge:countCh.challenge,material:assertion(countCh.public_key.challenge,1)}),'UNAUTHORIZED')
 const wo=op('passkey-save'),review=ok(ws.approvalChallenge({session_token:wt,operation:wo}))
 const wp={...review.proof_template,material:assertion(review.public_key.challenge,2)}
 no(ws.approvalComplete({session_token:wt,proof:{...wp,operation_digest:'sha256:'+'f'.repeat(64)}}),'INVALID')
 ok(ws.approvalComplete({session_token:wt,proof:wp}))
 no(ws.reserve({operation:{...wo,canonical_parameters:{content:'changed synthetic command'}},approval_proof:wp}),'INVALID') // passkey exact-operation regression
 if(process.argv[2]==='mutation-child') {console.log('DIGEST MUTATION PROTECTED');rmSync(root,{recursive:true,force:true});process.exit(0)}
 const wg=ok(ws.reserve({operation:wo,approval_proof:wp}));assert.equal(wg.status,'PREPARED');assert.equal(JSON.parse(readFileSync(w.config.statePath)).prepared.length,1);checks++
 no(createAuthorityService({...w.config,provisionTrustedState:false}).reserve({operation:wo,approval_proof:wp}),'REPLAYED')
 no(ws.reserve({operation:op('unapproved-passkey'),approval_proof:wp}))
 assert.throws(()=>verifyWebauthnAssertion({material:a,config:wc,ownerId:id.owner_id,challenge:ch.public_key.challenge,counter:1}),/COUNTER_REPLAYED/);checks++
 const race=setup('race'),rt=login(race.service),ro=op('race'),rp=approve(race.service,rt,ro)
 const payload=join(root,'race-input.json');writeFileSync(payload,JSON.stringify({config:race.config,input:{operation:ro,approval_proof:rp}}),{mode:0o600})
 const runChild=()=>new Promise((resolve,reject)=>{
  const child=spawn(process.execPath,[fileURLToPath(import.meta.url),'reserve-child',payload],{stdio:['ignore','pipe','pipe']})
  let stdout='',stderr='';child.stdout.on('data',b=>stdout+=b);child.stderr.on('data',b=>stderr+=b)
  child.on('error',reject);child.on('close',code=>code===0?resolve(JSON.parse(stdout)):reject(new Error(stderr)))
 })
 const raced=await Promise.all([runChild(),runChild()]);assert.equal(raced.filter(x=>x.ok).length,1);assert(raced.filter(x=>!x.ok).every(x=>['REPLAYED','UNAVAILABLE'].includes(x.error_code)));checks++
 no(createAuthorityService(race.config).reserve({operation:ro,approval_proof:rp}),'REPLAYED')
 const crash=setup('crash'),ct=login(crash.service),co=op('crash'),cp=approve(crash.service,ct,co)
 const cr=Object.values(JSON.parse(readFileSync(crash.config.statePath)).broker.operations)[0].approval.receipt
 const crp=join(root,'public-fixture-receipt.json');writeFileSync(crp,JSON.stringify(cr),{mode:0o600})
 class FsyncFailStore extends PrimeApprovalStateStore {constructor(opts){super({...opts,crashHook:step=>{if(step==='dir-fsync')throw new Error('fixture fsync interrupted')}})}}
 const failed=decideApproval({approvalPath:crp,approverDid:id.approval_key_did,operationDigest:operationDigest(co).slice(7),subject:id.subject,controlDigest:id.control_digest,consumedIdsPath:crash.config.statePath,stateRoot:crash.config.stateRoot,witnessDirectory:crash.config.witnessDir,Store:FsyncFailStore})
 assert.equal(failed.decision,'DENY');checks++
 no(crash.service.reserve({operation:co,approval_proof:cp}),'RECONCILIATION_REQUIRED')
 const exp=setup('expiry'),xt=login(exp.service),xo={...op('expiry'),expiry:new Date(Date.now()+2100).toISOString()},xp=approve(exp.service,xt,xo)
 await new Promise(resolve=>setTimeout(resolve,2200))
 no(exp.service.reserve({operation:xo,approval_proof:xp}),'EXPIRED')
 const moved=setup('moved'),mt=login(moved.service),mo=op('move'),mp=approve(moved.service,mt,mo),oldMoved=readFileSync(moved.config.statePath)
 ok(moved.service.reserve({operation:mo,approval_proof:mp}))
 const movedDir=join(root,'moved-copy');mkdirSync(movedDir,{mode:0o700});writeFileSync(join(movedDir,'authority.json'),oldMoved,{mode:0o600})
 no(createAuthorityService({...moved.config,statePath:join(movedDir,'authority.json'),stateRoot:movedDir,provisionTrustedState:false}).reserve({operation:mo,approval_proof:mp}),'RECONCILIATION_REQUIRED')
 const link=join(root,'ancestor-link');symlinkSync(dirname(moved.config.stateRoot),link)
 no(createAuthorityService({...moved.config,statePath:join(link,'state','authority.json'),stateRoot:join(link,'state')}).reserve({operation:mo,approval_proof:mp}),'UNAVAILABLE')
 rmSync(join(moved.config.witnessDir,'kernel-high-water.json'))
 no(moved.service.reserve({operation:mo,approval_proof:mp}),'RECONCILIATION_REQUIRED');assert(!existsSync(join(moved.config.witnessDir,'kernel-high-water.json')));checks++
 const missingBroker=setup('missing-broker-witness');ok(propose(missingBroker.service,op('broker-only-history')))
 rmSync(join(missingBroker.config.witnessDir,'kernel-high-water.json'))
 no(propose(missingBroker.service,op('no-rebaseline')),'RECONCILIATION_REQUIRED')
 const unowned=setup('unowned',{authorizeTask:()=>true});no(propose(unowned.service,op('bare-true-task')),'UNAUTHORIZED')
 const wrongOwnerTask=setup('wrong-owner-task',{authorizeTask:()=>trustedTask('other-owner')});no(propose(wrongOwnerTask.service,op('wrong-owned-task')),'UNAUTHORIZED')
 const id2={...id,owner_id:'fixture-owner-2',subject:'aukora:1:'+'3'.repeat(64)}
 const scoped=setup('owner-scoped',{identities:[id,id2],authorizeTask:x=>trustedTask(x.owner_id)})
 ok(propose(scoped.service,op('shared-operation-id')));ok(propose(scoped.service,{...op('shared-operation-id'),owner_id:id2.owner_id}));assert.equal(Object.keys(JSON.parse(readFileSync(scoped.config.statePath)).broker.operations).length,2);checks++
 const quota=setup('quota')
 for(let i=0;i<32;i++)ok(quota.service.loginChallenge({owner_id:id.owner_id,kind:'owner_key'}))
 const quotaBefore=readFileSync(quota.config.statePath)
 for(let i=0;i<16;i++) {const result=quota.service.loginChallenge({owner_id:id.owner_id,kind:'owner_key'});assert.equal(result.error_code,'UNAVAILABLE');assert.equal(result.reason,'LOGIN_CHALLENGE_QUOTA_REACHED')}
 assert.deepEqual(readFileSync(quota.config.statePath),quotaBefore);checks++
 for(let i=0;i<1952;i++) {const result=quota.service.loginChallenge({owner_id:id.owner_id,kind:'owner_key'});if(!result.ok){assert.equal(result.error_code,'UNAVAILABLE');assert.equal(result.reason,'LOGIN_CHALLENGE_QUOTA_REACHED')}}
 const quotaAfter=readFileSync(quota.config.statePath);assert(quotaAfter.length<32768);assert(Object.keys(JSON.parse(quotaAfter).broker.logins).length<=32);checks++
 const pruneStore=new PrimeApprovalStateStore({statePath:quota.config.statePath,stateRoot:quota.config.stateRoot,witnessDir:quota.config.witnessDir})
 try {pruneStore.open();pruneStore.load();for(const x of Object.values(pruneStore.broker.logins))x.challenge.expiry='2000-01-01T00:00:00.000Z';pruneStore.commitBroker()}finally{pruneStore.close()}
 ok(quota.service.loginChallenge({owner_id:id.owner_id,kind:'owner_key'}));assert.equal(Object.keys(JSON.parse(readFileSync(quota.config.statePath)).broker.logins).length,1);checks++
 const small=setup('operation-quota',{limits:{operations_per_owner:2,operations_total:2,operation_bytes:1024}})
 ok(propose(small.service,op('quota-a')));ok(propose(small.service,op('quota-b')));const smallBefore=readFileSync(small.config.statePath)
 no(propose(small.service,op('quota-c')),'UNAVAILABLE');assert.deepEqual(readFileSync(small.config.statePath),smallBefore);checks++
 no(propose(small.service,{...op('oversize'),canonical_parameters:{content:'x'.repeat(2048)}}),'INVALID')
 function preparedCase(name,operation=op(name)) {
  const fixture=setup(name),sessionToken=login(fixture.service),approval=approve(fixture.service,sessionToken,operation),preparedGrant=ok(fixture.service.reserve({operation,approval_proof:approval})).consumed_grant
  const request={operation,consumed_grant:preparedGrant,request_id:randomUUID(),image_digest:'sha256:'+'a'.repeat(64),policy_digest:'sha256:'+'b'.repeat(64),wall_time_ms:1000,max_output_bytes:1024}
  const binding={operation,consumed_grant:preparedGrant,request_id:request.request_id,request_digest:executorRequestDigest(request)}
  const receipt={version:1,receipt_id:randomUUID(),operation_id:operation.operation_id,task_id:operation.task_id,owner_id:operation.owner_id,operation_digest:operationDigest(operation),grant_id:preparedGrant.grant_id,request_id:request.request_id,status:'outcome_unknown',stdout:'',stderr:'',exit_code:null,rpc_completion:'not_started',output_truncated:false,sandbox:null,cleanup:'not_created',started_at:null,finished_at:new Date().toISOString(),error_code:'OUTCOME_UNKNOWN',reconciliation_required:true}
  return {...fixture,sessionToken,binding,receipt}
 }
 const settlement=preparedCase('settlement')
 const authBefore=readFileSync(settlement.config.statePath);const who=ok(settlement.service.authenticateSession({session_token:settlement.sessionToken}));assert.equal(who.subject,id.subject);assert.deepEqual(readFileSync(settlement.config.statePath),authBefore);checks++
 no(settlement.service.authenticateSession({session_token:'0'.repeat(64)}),'UNAUTHORIZED')
 no(settlement.service.claimDispatch({operation:settlement.binding.operation,consumed_grant:settlement.binding.consumed_grant}),'INVALID')
 ok(settlement.service.claimDispatch(settlement.binding));no(settlement.service.claimDispatch(settlement.binding),'REPLAYED')
 function settleInput(f,receipt=f.receipt) {return {...f.binding,receipt,receipt_digest:executionReceiptDigest(receipt)}}
 const unknown=ok(settlement.service.settle(settleInput(settlement)));assert.equal(unknown.status,'OUTCOME_UNKNOWN');checks++
 assert.equal(ok(settlement.service.settle(settleInput(settlement))).idempotent,true);checks++
 no(settlement.service.settle({...settleInput(settlement),request_id:randomUUID()}),'UNAUTHORIZED')
 no(settlement.service.settle({...settleInput(settlement),receipt_digest:'sha256:'+'0'.repeat(64)}),'INVALID')
 ok(settlement.service.requestCancel({operation:settlement.binding.operation,consumed_grant:settlement.binding.consumed_grant,request_id:settlement.binding.request_id,reason:'caller'}))
 const began=preparedCase('cancel-after-start');ok(began.service.claimDispatch(began.binding));ok(began.service.requestCancel({operation:began.binding.operation,consumed_grant:began.binding.consumed_grant,request_id:began.binding.request_id,reason:'caller'}))
 const uncertainReceipt={...began.receipt,status:'cancelled',cleanup:'confirmed_absent',rpc_completion:'transport_failed',started_at:new Date().toISOString(),reconciliation_required:false,error_code:'CANCELLED'}
 assert.equal(ok(began.service.settle(settleInput(began,uncertainReceipt))).status,'OUTCOME_UNKNOWN');checks++
 const completed={...uncertainReceipt,status:'completed',exit_code:0,rpc_completion:'complete',error_code:null,stdout:'synthetic result'}
 no(began.service.settle(settleInput(began,completed)),'STALE')
 const revokeStore=new PrimeApprovalStateStore({statePath:began.config.statePath,stateRoot:began.config.stateRoot,witnessDir:began.config.witnessDir})
 try {revokeStore.open();revokeStore.load();Object.values(revokeStore.broker.owners)[0].authorization_epoch++;revokeStore.commitBroker()}finally{revokeStore.close()}
 assert.equal(ok(began.service.reconcileSettlement(settleInput(began,completed))).status,'COMPLETED');checks++
 assert.equal(ok(began.service.requestCancel({operation:began.binding.operation,consumed_grant:began.binding.consumed_grant,request_id:began.binding.request_id,reason:'dispose'})).cancel_recorded,false);checks++
 no(began.service.reconcileSettlement(settleInput(began,{...completed,stdout:'conflicting result'})),'STALE')
 const notStarted=preparedCase('cancel-not-started');ok(notStarted.service.claimDispatch(notStarted.binding));ok(notStarted.service.requestCancel({operation:notStarted.binding.operation,consumed_grant:notStarted.binding.consumed_grant,request_id:notStarted.binding.request_id,reason:'caller'}))
 assert.equal(ok(notStarted.service.settle(settleInput(notStarted,{...notStarted.receipt,status:'cancelled',error_code:'CANCELLED',reconciliation_required:false}))).status,'CANCELLED');checks++
 const memOp={...op('memory-settle'),target_identity:{kind:'prime-memory',owner_subject:id.subject}},memory=preparedCase('memory-settlement',memOp)
 ok(memory.service.claimDispatch(memory.binding));ok(memory.service.markOutcomeUnknown(memory.binding))
 const actualResult={storage_status:'saved',revision:'synthetic-r2'},memoryReceipt={version:1,kind:'prime-memory-effect/v1',operation_id:memOp.operation_id,operation_digest:operationDigest(memOp),grant_id:memory.binding.consumed_grant.grant_id,request_id:memory.binding.request_id,request_digest:memory.binding.request_digest,owner_subject:id.subject,action_type:memOp.action_type,status:'applied',result_digest:memoryResultDigest(actualResult),result:actualResult}
 no(memory.service.settleMemory({...memory.binding,receipt:{...memoryReceipt,result_digest:'sha256:'+'0'.repeat(64)}}),'INVALID')
 assert.equal(ok(memory.service.settleMemory({...memory.binding,receipt:memoryReceipt})).status,'COMPLETED');checks++
 assert.equal(ok(memory.service.settleMemory({...memory.binding,receipt:memoryReceipt})).idempotent,true);checks++
 no(memory.service.settleMemory({...memory.binding,receipt:{...memoryReceipt,result:{storage_status:'failed'},result_digest:memoryResultDigest({storage_status:'failed'})}}),'STALE')
 if(process.argv[2]!=='mutation-child') {
  const pkg=dirname(fileURLToPath(import.meta.url)),mutant=join(root,'mutant','packages','authority');cpSync(pkg,mutant,{recursive:true});cpSync(join(pkg,'..','contracts'),join(root,'mutant','packages','contracts'),{recursive:true})
  const serviceFile=join(mutant,'src','service.mjs'),adapterFile=join(mutant,'upstream','scripts','aukora','decide.mjs')
  let source=readFileSync(serviceFile,'utf8'),early="    if(row.operation_digest!==operationDigest(op)||!equal(row.operation,op)) refuse('INVALID','EXACT_OPERATION_CHANGED')"
  assert(source.includes(early));source=source.replace(early,'    // mutation: earlier exact-row guard removed');writeFileSync(serviceFile,source)
  const runMutant=()=>new Promise(resolve=>{const child=spawn(process.execPath,[join(mutant,'check.mjs'),'mutation-child'],{stdio:['ignore','pipe','pipe']});let output='';child.stdout.on('data',b=>output+=b);child.stderr.on('data',b=>output+=b);child.on('close',code=>resolve({code,output}));child.on('error',e=>resolve({code:-1,output:String(e)}))})
  const single=await runMutant();assert.equal(single.code,0,single.output);checks++
  source=source.replace("          if(proof.operation_digest!==row.operation_digest||proof.operation_digest!==operationDigest(op)) refuse('INVALID','VERIFIED_OPERATION_DIGEST_MISMATCH')",'          // mutation: bind digest guard removed')
  writeFileSync(serviceFile,source)
  const adapter=readFileSync(adapterFile,'utf8');assert(adapter.includes('proof?.operation_digest!==`sha256:${operationDigest}`'));writeFileSync(adapterFile,adapter.replace('proof?.operation_digest!==`sha256:${operationDigest}` || ',''))
  const disabled=await runMutant();assert.notEqual(disabled.code,0);assert(disabled.output.includes('changed synthetic command')||disabled.output.includes('AssertionError'));checks++
  console.log('MUTATION PASS: earlier row guard removed still refuses; removing all digest boundaries is caught')
  console.log(JSON.stringify({kernel_guards:await runKernelGuardChecks()}))
  if(process.argv[2]!=='core-only') {
   const {runAdmissionChecks}=await import('./check-admission.mjs')
   console.log(JSON.stringify({admission:await runAdmissionChecks()}))
  }
 }
 console.log(JSON.stringify({status:'PASS',checks,scope:'synthetic owner-key + ES256 passkey assertions; copied durable stores/kernel; replay/denial/epoch/restore; no external effects',limits:['no real enrollment','same UID can rewrite state and witness','no deployed broker IPC/UID separation','assertion does not prove comprehension','no OpenShell execution or signing keys in guest']}))
} finally {rmSync(root,{recursive:true,force:true})}
