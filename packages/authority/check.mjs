import assert from 'node:assert/strict'
import { createHash, generateKeyPairSync, sign, randomBytes } from 'node:crypto'
import { mkdtempSync,mkdirSync,readFileSync,writeFileSync,rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { spawn } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import { createAuthorityService,loginSigningBytes,approvalSigningBytes,operationDigest } from './src/index.mjs'
import { didKeyFromEd25519PublicKey } from './upstream/plugins/aukora-aumlok/lib/did-key.mjs'
import { p256 } from './upstream/vendor/authority/deps/@noble/curves@2.2.0/nist.js'
import { verifyWebauthnAssertion,prepareWebauthnConfig } from './src/webauthn.mjs'
import { decideApproval } from './upstream/scripts/aukora/decide.mjs'
import { PrimeApprovalStateStore } from './src/state-store.mjs'
if(process.argv[2]==='reserve-child') {
 const v=JSON.parse(readFileSync(process.argv[3],'utf8'))
 const s=createAuthorityService({...v.config,authorizeTask:()=>true,observeTarget:op=>({target_identity:op.target_identity,state_version:'r1'})})
 console.log(JSON.stringify(s.reserve(v.input)));process.exit(0)
}
const root=mkdtempSync(join(tmpdir(),'prime-authority-fixture-'))
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
 const config={statePath:join(path,'state','authority.json'),stateRoot:join(path,'state'),witnessDir:join(path,'witness'),audience:'prime:test',identities:[id],loginKinds:['owner_key','passkey'],policy:{version:'p1',actions:['memory.save'],agents:['fixture-agent'],data_scope:['public'],maximum_cost:{currency:'USD',amount:'0'}},provisionTrustedState:true,authorizeTask:op=>op.task_id==='fixture-task',observeTarget:op=>({target_identity:op.target_identity,state_version:targetVersion}),...extra}
 return {config,service:createAuthorityService(config)}
}
const op=(name)=>({version:1,operation_id:name,task_id:'fixture-task',owner_id:id.owner_id,agent_id:'fixture-agent',audience:'prime:test',action_type:'memory.save',target_identity:{store:'fixture-memory',record:'note1'},canonical_parameters:{content:'public synthetic note'},data_scope:['public'],expected_state_version:'r1',provider_and_region:{provider:'none',region:'local'},maximum_cost:{currency:'USD',amount:'0'},expiry:new Date(Date.now()+60000).toISOString(),nonce:randomBytes(32).toString('hex'),policy_version:'p1',authorization_epoch:0})
function login(service) {
 const challenge=ok(service.loginChallenge({owner_id:id.owner_id,kind:'owner_key'})).challenge
 const input={challenge,material:{kind:'owner_key',signature:sign(null,loginSigningBytes(challenge),ed.privateKey).toString('hex')}}
 const accepted=ok(service.loginComplete(input));no(service.loginComplete(input),'REPLAYED')
 return accepted.session_token
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
 const operation=op('one');ok(s.propose(operation))
 const fake={version:1,operation_id:operation.operation_id,operation_digest:operationDigest(operation),owner_id:id.owner_id,audience:operation.audience,authorization_epoch:0,expiry:operation.expiry,nonce:randomBytes(32).toString('hex'),material:{kind:'owner_key',request:{},signature:'0'.repeat(128)}}
 no(s.reserve({operation,approval_proof:fake}),'UNAUTHORIZED') // schema-valid request is never approval
 const token=login(s),proof=approve(s,token,operation)
 for(const [field,value] of [['target_identity',{store:'elsewhere'}],['canonical_parameters',{content:'changed'}],['data_scope',['secret']],['expected_state_version','r2'],['maximum_cost',{currency:'USD',amount:'1'}],['nonce','changed'],['expiry',new Date(Date.now()+120000).toISOString()],['agent_id','elsewhere'],['task_id','elsewhere'],['audience','wrong'],['authorization_epoch',1],['policy_version','p2']]) {
  no(s.reserve({operation:{...operation,[field]:value},approval_proof:proof}))
 }
 targetVersion='r2';no(s.reserve({operation,approval_proof:proof}),'TARGET_MISMATCH');targetVersion='r1'
 const before=readFileSync(f.config.statePath)
 const prepared=ok(s.reserve({operation,approval_proof:proof}));assert.equal(prepared.status,'PREPARED');checks++
 const durable=JSON.parse(readFileSync(f.config.statePath));assert.equal(durable.prepared.length,1);assert(durable.state.consumedIds.includes('approval:'+proof.nonce));assert.equal(Object.values(durable.broker.operations)[0].status,'PREPARED');checks++
 const restarted=createAuthorityService({...f.config,provisionTrustedState:false})
 no(restarted.reserve({operation,approval_proof:proof}),'REPLAYED')
 ok(restarted.claimDispatch({operation,consumed_grant:prepared.consumed_grant}));no(restarted.claimDispatch({operation,consumed_grant:prepared.consumed_grant}),'REPLAYED')
 writeFileSync(f.config.statePath,before,{mode:0o600});no(restarted.reserve({operation,approval_proof:proof}),'RECONCILIATION_REQUIRED')
 const d=setup('deny'),dt=login(d.service),dop=op('deny'),dp=approve(d.service,dt,dop)
 ok(d.service.declineApproval({session_token:dt,operation_id:dop.operation_id}));no(createAuthorityService(d.config).reserve({operation:dop,approval_proof:dp}),'CANCELLED')
 const e=setup('epoch'),et=login(e.service),eop=op('epoch'),ep=approve(e.service,et,eop),oldEpoch=readFileSync(e.config.statePath)
 ok(e.service.advanceAuthorizationEpoch({session_token:et}));no(e.service.reserve({operation:eop,approval_proof:ep}),'REVOKED')
 writeFileSync(e.config.statePath,oldEpoch,{mode:0o600});no(e.service.reserve({operation:eop,approval_proof:ep}),'RECONCILIATION_REQUIRED') // receipt count unchanged; broker revision catches rewind
 no(d.service.propose({...op('expired'),expiry:new Date(Date.now()-1000).toISOString()}),'EXPIRED')
 const sparse=op('sparse');sparse.data_scope=Array(1);no(d.service.propose(sparse))
 const decoratedSparse=op('decorated-sparse');decoratedSparse.canonical_parameters={a:Object.assign(Array(1),{extra:'collision'})};no(d.service.propose(decoratedSparse),'INVALID')
 const accessor=op('accessor');Object.defineProperty(accessor,'canonical_parameters',{get(){throw new Error('getter must never run')},enumerable:true});no(d.service.propose(accessor))
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
 console.log(JSON.stringify({status:'PASS',checks,scope:'synthetic owner-key + ES256 passkey assertions; copied durable stores/kernel; replay/denial/epoch/restore; no external effects',limits:['no real enrollment','same UID can rewrite state and witness','no deployed broker IPC/UID separation','assertion does not prove comprehension','no OpenShell execution or signing keys in guest']}))
} finally {rmSync(root,{recursive:true,force:true})}
