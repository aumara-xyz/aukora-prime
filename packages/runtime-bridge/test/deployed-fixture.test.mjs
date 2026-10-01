// SPDX-License-Identifier: AGPL-3.0-or-later
// TEST ONLY: disposable P-256 keys, actual C protected stores and D memory.
// Injected same-process channels and a SQLite SQL shim are not SSH, IPC peer
// authentication, PostgreSQL durability/restart, OS UID/ACL or host acceptance.
import {test} from 'node:test'
import assert from 'node:assert/strict'
import {mkdtempSync,mkdirSync,realpathSync,rmSync,readFileSync,existsSync} from 'node:fs'
import {tmpdir} from 'node:os'
import {join} from 'node:path'
import {PassThrough} from 'node:stream'
import * as contracts from '../../contracts/src/runtime.mjs'
import {createAuthorityService,provisionNewAuthorityStore,loginSigningBytes} from '../../authority/src/index.mjs'
import {webauthnChallenge} from '../../authority/src/webauthn.mjs'
import {createPostgresMemory} from '../../memory/src/index.mjs'
import {parseOriginal} from '../../memory/src/codecs.mjs'
import {memoryEffectDigest,memoryReceiptDigest,memoryResultDigest} from '../../memory/src/authorization.mjs'
import {planWorkerPostgresFixture,validateWorkerPostgresSaveExpectation} from '../../memory/test/worker-postgres-fixture.mjs'
import {createRuntimeBridge,createTrustedTaskRegistry} from '../src/index.mjs'
import {FixturePool} from './sql-fixture.mjs'
import {runFixtureActor} from './deployed-actor.mjs'
import {buildAuthorityWorker,buildMemoryWorker} from './deployed-bootstrap.mjs'
import {createFixtureSigner} from './deployed-controller.mjs'
import {createFixturePipe} from './deployed-pipes.mjs'
import {PG_CONFIG,PHASES,IDS,sha,createProfile,validateProfile,validateSigner,authorityConfig,
  fixturePaths,registryEntries,scenario,credentialId,memoryCredentialId,access,
  readPrivateJson,writePrivateJson} from './deployed-profile.mjs'

const clone=value=>structuredClone(value)
const ok=result=>{assert.equal(result?.ok,true,JSON.stringify(result));return result}
const at='2026-10-01T11:03:00Z'
const refuse=async(promise,reason)=>assert.rejects(promise,error=>{
  assert.ok(error instanceof Error)
  if(reason){assert.equal(error.code,'SYNTHETIC_FIXTURE_REFUSED');assert.equal(error.message,reason)}
  return true
})

function workerInputs(profile){
  const paths=fixturePaths(profile)
  const authority={version:1,kind:'prime-private-cd-pg-authority/v1',synthetic_fixture:true,profile,
    ipc:{socketPath:paths.authoritySocket,credentials:[{id:memoryCredentialId(profile),role:'memory_effect',secret:'a'.repeat(64)}],
      socketAccess:access(IDS.authority,IDS.memory,IDS.authorityIpc)}}
  const memory={version:1,kind:'prime-private-cd-pg-memory/v1',synthetic_fixture:true,profile,
    ipc:{socketPath:paths.memorySocket,credentials:['primary','secondary'].map((owner,i)=>({id:credentialId(profile,owner),role:'owner_control',secret:(i?'c':'b').repeat(64)})),
      socketAccess:access(IDS.memory,IDS.app,IDS.memoryIpc)},
    authority_channel:{socketPath:paths.authoritySocket,credential:{id:memoryCredentialId(profile),secret:'a'.repeat(64)},
      socketAccess:access(IDS.authority,IDS.memory,IDS.authorityIpc)}}
  return {authority,memory}
}

async function fixture(t){
  const root=mkdtempSync(join(realpathSync(tmpdir()),'prime-deployed-source-test-'))
  let pool=null,memory=null,authority=null,bridge=null
  t.after(()=>{pool?.close();rmSync(root,{recursive:true,force:true})})
  const planned=planWorkerPostgresFixture({config:{...PG_CONFIG},statePath:join(root,'public-fixture.json')})
  assert.equal(planned.PostgreSQL_connected,false)
  const {profile,signer}=await createProfile({fixture:planned.fixture,postgres:{...PG_CONFIG},at})
  const signerPath=join(root,'signer.json'),witnessPath=join(root,'actor-witness.json'),databasePath=join(root,'memory.sqlite')
  await writePrivateJson(signerPath,signer,{exclusive:true})
  const taskRegistry=createTrustedTaskRegistry(registryEntries(profile)),inputs=workerInputs(profile)
  const authorityWorker=await buildAuthorityWorker(inputs.authority),memoryWorker=await buildMemoryWorker(inputs.memory)
  assert.deepEqual(authorityWorker.authorityConfig,authorityConfig(profile))
  mkdirSync(join(root,'state'),{mode:0o700})
  const config={...authorityWorker.authorityConfig,stateRoot:join(root,'state'),statePath:join(root,'state','authority.json'),
    witnessDir:join(root,'protected-witness'),authorizeTask:taskRegistry.authorizeTask,
    observeTarget:operation=>memory.authorityTargetObservation(operation)}
  // Ordinary creation does not provision. The setup-only C API runs once.
  const unprovisioned=createAuthorityService(config)
  assert.equal(unprovisioned.loginChallenge({owner_id:profile.identities[0].owner_id,kind:'passkey'}).ok,false)
  assert.equal(existsSync(config.statePath),false)
  assert.equal(ok(provisionNewAuthorityStore({...config,provisionTrustedState:true})).status,'PROVISIONED')
  const connect=()=>{
    memory=createPostgresMemory({pool,authority,contracts,indexTarget:memoryWorker.indexTarget,indexGeneration:memoryWorker.indexGeneration})
    bridge=createRuntimeBridge({authority,memory,taskRegistry,resolveHostContext:memoryWorker.resolveHostContext})
  }
  authority=createAuthorityService(config);pool=new FixturePool(databasePath);connect();await memory.migrate()
  const calls=[]
  const connections=Object.fromEntries(['primary','secondary'].map(owner=>[owner,{request:async(method,input)=>{
    const result=await bridge.handleTrusted(method,input,{role:'owner_control',request:{transport:'ipc',credential_id:credentialId(profile,owner)}})
    calls.push({owner,method,input:clone(input),result:clone(result)});return result
  }}]))
  const persist=async value=>writePrivateJson(signerPath,value)
  return {root,profile,inputs,authorityWorker,memoryWorker,taskRegistry,config,signerPath,witnessPath,calls,connections,persist,
    get pool(){return pool},get memory(){return memory},get authority(){return authority},get bridge(){return bridge},
    readSigner:()=>readPrivateJson(signerPath),
    witness:{read:()=>readPrivateJson(witnessPath),write:value=>writePrivateJson(witnessPath,value,{exclusive:true})},
    coldReopen(){pool.close();pool=new FixturePool(databasePath);authority=createAuthorityService(config);connect()},
  }
}

async function runPhase(f,phase){
  const firstCall=f.calls.length
  const signer=validateSigner(await f.readSigner(),f.profile)
  assert.ok(!signer.attempted_phases.includes(phase))
  assert.deepEqual(signer.completed_phases,PHASES.slice(0,PHASES.indexOf(phase)))
  signer.attempted_phases.push(phase);await f.persist(signer)
  const durable=[]
  const signing=createFixtureSigner({profile:f.profile,signer,phase,persist:async value=>{
    await f.persist(value);durable.push(clone(await f.readSigner()))
  }})
  const actorToController=new PassThrough(),controllerToActor=new PassThrough()
  const actorPipe=createFixturePipe({readable:controllerToActor,writable:actorToController,timeoutMs:5000})
  const controllerPipe=createFixturePipe({readable:actorToController,writable:controllerToActor,timeoutMs:5000})
  const frames=[]
  const controller=(async()=>{
    while(!signing.complete){
      const frame=await controllerPipe.read();frames.push(clone(frame.payload))
      const response=await signing.handle(frame.payload)
      if(response.type==='assertion'){
        const owner=frame.payload.owner,material=response.material
        assert.equal(Buffer.from(material.authenticator_data,'base64url').readUInt32BE(33),durable.at(-1).owners[owner].counter,
          'released assertion must already have its counter persisted')
      }
      await controllerPipe.respond(frame.sequence,response)
    }
  })()
  const actor=runFixtureActor({profile:f.profile,phase,pipe:actorPipe,connections:f.connections,witness:f.witness})
  try{
    const [report]=await Promise.all([actor,controller])
    assert.equal(signing.complete,true);assert.deepEqual(signing.result,report)
    signer.completed_phases.push(phase);await f.persist(signer)
    return {report,frames,durable,calls:f.calls.slice(firstCall)}
  }finally{actorPipe.close();controllerPipe.close();await Promise.allSettled([actor,controller])}
}

function committedFacts(f,expected){
  validateWorkerPostgresSaveExpectation(expected,f.profile.fixture)
  const rows=f.pool.db.prepare('SELECT * FROM prime_memory_effects').all()
  assert.equal(rows.length,1)
  const effect=rows[0],decode=name=>contracts.parseStrictJson(Buffer.from(effect[name]).toString('utf8'))
  const operation=decode('operation_bytes'),grant=decode('grant_bytes'),request=decode('request_bytes'),receipt=decode('receipt_bytes'),record=decode('result_bytes')
  assert.equal(contracts.operationDigest(operation),expected.operation_digest)
  assert.equal(operation.owner_id,f.profile.fixture.owners.primary.owner_id)
  assert.notEqual(operation.owner_id,record.owner_subject)
  assert.equal(operation.task_id,f.profile.fixture.owners.primary.task_id)
  assert.equal(effect.operation_digest,expected.operation_digest)
  assert.equal(grant.grant_id,expected.receipt.grant_id)
  assert.equal(grant.operation_id,operation.operation_id);assert.equal(grant.operation_digest,expected.operation_digest)
  assert.equal(grant.owner_id,operation.owner_id);assert.equal(grant.audience,operation.audience)
  assert.equal(request.owner_subject,f.profile.fixture.owners.primary.owner_subject)
  assert.equal(request.operation_id,operation.operation_id);assert.equal(request.operation_digest,expected.operation_digest)
  assert.deepEqual(request.parameters,operation.canonical_parameters)
  assert.equal(memoryEffectDigest(request),expected.receipt.request_digest)
  assert.equal(memoryReceiptDigest(receipt),expected.receipt.receipt_digest)
  assert.equal(memoryResultDigest(record),expected.receipt.result_digest)
  assert.equal(receipt.request_id,expected.receipt.request_id);assert.equal(receipt.grant_id,grant.grant_id)
  assert.equal(receipt.request_digest,expected.receipt.request_digest);assert.equal(receipt.result_digest,expected.receipt.result_digest)
  assert.deepEqual(receipt.result,record)
  assert.equal(receipt.status,'applied')
  assert.equal(record.record_id,expected.record_id)
  assert.equal(sha(record.canonical_bytes),expected.canonical_sha256)
  assert.equal(record.storage_status,'saved');assert.equal(record.index_status,'pending');assert.equal(record.grants_authority,false)
  const retained=parseOriginal(Buffer.from(record.canonical_bytes)),s=scenario(f.profile,'primary')
  assert.equal(retained.statement,s.memory_capture.statement);assert.equal(retained.attributedTo,'owner')
  assert.equal(f.pool.db.prepare('SELECT count(*) AS n FROM prime_memory_records').get().n,1)
  assert.equal(f.pool.db.prepare('SELECT count(*) AS n FROM prime_memory_intents').get().n,1)
  const intent=f.pool.db.prepare('SELECT * FROM prime_memory_intents').get()
  for(const field of ['operation_bytes','grant_bytes','request_bytes','operation_digest','request_id','request_digest'])assert.deepEqual(intent[field],effect[field])
  return record
}

test('fixture actor/controller completes actual C/D save and all retained phases with cold C and SQLite stores; no deployed acceptance',async t=>{
  const f=await fixture(t),saved=await runPhase(f,'save'),expected=saved.report.expected
  assert.deepEqual(saved.report.authority_status,{ok:true,status:'COMPLETED',operation_digest:expected.operation_digest,reconciliation_required:false})
  const record=committedFacts(f,expected),witness=await f.witness.read()
  assert.deepEqual(witness.expected,expected);assert.equal(contracts.operationDigest(witness.operation),expected.operation_digest)
  assert.deepEqual(saved.durable.map(s=>[s.owners.primary.counter,s.owners.secondary.counter]),[[1,0],[2,0],[2,1],[2,1]])
  const perPhase=[saved]
  for(const phase of PHASES.slice(1)){
    f.coldReopen()
    const retained=await runPhase(f,phase)
    perPhase.push(retained)
    assert.deepEqual(retained.report.expected,expected)
    assert.deepEqual(retained.report.authority_status,saved.report.authority_status)
    assert.equal(committedFacts(f,expected).canonical_bytes,record.canonical_bytes)
    assert.deepEqual(await f.witness.read(),witness)
  }
  const signer=await f.readSigner()
  assert.deepEqual(signer.attempted_phases,PHASES);assert.deepEqual(signer.completed_phases,PHASES)
  assert.equal(signer.owners.primary.counter,5);assert.equal(signer.owners.secondary.counter,4)
  assert.deepEqual(signer.expected,expected)
  assert.equal((await f.bridge.capability()).state,'unqualified')
  assert.equal((await f.bridge.handlePublic('owner.loginChallenge',{owner_id:f.profile.identities[0].owner_id,kind:'passkey'})).ok,false)
  for(const phase of perPhase){
    for(const method of ['memory.status','memory.cite','owner.status'])assert.ok(phase.calls.some(call=>call.owner==='secondary'&&call.method===method&&call.result.ok===false))
    const capability=phase.calls.find(call=>call.method==='capability.status').result
    assert.equal(capability.available,false);assert.equal(capability.public_routes,'unavailable')
  }
  const controls=f.calls.filter(call=>call.owner==='primary'&&call.method==='memory.save'&&call.result.ok===false)
  assert.equal(controls.length,3)
  for(const call of f.calls.filter(call=>call.owner==='secondary'&&['memory.status','memory.cite','owner.status','owner.approvalChallenge'].includes(call.method)))assert.equal(call.result.ok,false)
})

test('bootstrap builders bind only the fixed synthetic profile and closed owner channel associations',async t=>{
  const f=await fixture(t),worker=f.memoryWorker,primary=f.profile.fixture.owners.primary
  assert.equal(worker.initializeSchema,false);assert.equal(worker.indexTarget,'postgres:fts:simple:v1');assert.equal(worker.indexGeneration,'1')
  assert.deepEqual(worker.registryEntries,registryEntries(f.profile))
  const request={transport:'ipc',credential_id:credentialId(f.profile,'primary')}
  assert.deepEqual(worker.resolveHostContext({request,session:null}),{login_owner_id:primary.owner_id})
  const session={owner_id:primary.owner_id,subject:primary.owner_subject}
  assert.deepEqual(worker.resolveHostContext({request,session}),{task_id:primary.task_id,memory_host:scenario(f.profile,'primary').host})
  assert.throws(()=>worker.resolveHostContext({request:{...request,credential_id:credentialId(f.profile,'secondary')},session}),/FIXTURE_CHANNEL_OWNER_REQUIRED/)
  assert.throws(()=>worker.resolveHostContext({request:{...request,credential_id:'caller-selected'},session:null}),/AUTHENTICATED_FIXTURE_ACTOR_REQUIRED/)
  await refuse(buildMemoryWorker({...f.inputs.memory,initializeSchema:true}))
  await refuse(buildAuthorityWorker({...f.inputs.authority,provisionTrustedState:true}))
  await refuse(validateProfile({...clone(f.profile),synthetic_fixture:false}),'EXPLICIT_SYNTHETIC_PROFILE_REQUIRED')
  const text=readFileSync(join(f.root,'public-fixture.json'),'utf8')
  assert.ok(!text.includes('private_key'));assert.ok(!text.includes(f.profile.credentials[0].credential_id))
})

async function reviewFixture(t){
  const f=await fixture(t),signer=await f.readSigner(),snapshots=[]
  signer.attempted_phases.push('save');await f.persist(signer)
  const signing=createFixtureSigner({profile:f.profile,signer,phase:'save',persist:async value=>{await f.persist(value);snapshots.push(clone(value))}})
  const challenge=ok(await f.connections.primary.request('owner.loginChallenge',{owner_id:f.profile.identities[0].owner_id,kind:'passkey'}))
  const login={type:'sign',owner:'primary',purpose:'login',request:challenge.challenge,public_key:challenge.public_key,proof_template:null}
  const signed=await signing.handle(login)
  const session=ok(await f.connections.primary.request('owner.loginComplete',{challenge:challenge.challenge,material:signed.material})).session_token
  const s=scenario(f.profile,'primary')
  const proposed=ok(await f.connections.primary.request('memory.proposeSave',{session_token:session,extraction_json:s.extraction_json,idempotency_key:s.idempotency_key}))
  const reviewed={type:'review',owner:'primary',operation:proposed.operation,memory_capture:proposed.memory_capture}
  const challengeApproval=ok(await f.connections.primary.request('owner.approvalChallenge',{session_token:session,operation:proposed.operation}))
  const approval={type:'sign',owner:'primary',purpose:'approval',request:challengeApproval.approval_request,public_key:challengeApproval.public_key,proof_template:challengeApproval.proof_template}
  return {...f,signer,signing,snapshots,login,session,reviewed,approval}
}

test('controller refuses changed D capture, idempotency, task, target, heads and attribution before signing',async t=>{
  const f=await reviewFixture(t)
  await refuse(f.signing.handle(f.approval),'NO_ARBITRARY_SIGNING_OR_REPLAY')
  const changes=[
    op=>{op.canonical_parameters.capture_sha256='f'.repeat(64)},
    op=>{op.canonical_parameters.idempotency_key_sha256='e'.repeat(64)},
    op=>{op.task_id=f.profile.fixture.owners.secondary.task_id},
    op=>{op.target_identity.owner_subject=f.profile.fixture.owners.secondary.owner_subject},
    op=>{op.canonical_parameters.heads={remembered:'d'.repeat(64)}},
    op=>{op.canonical_parameters.attributed_to='agent'},
    op=>{op.canonical_parameters.statement='Different reviewed text.'},
    op=>{op.expected_state_version='sha256:'+'c'.repeat(64)},
    op=>{op.provider_and_region={provider:'untrusted',region:'elsewhere'}},
  ]
  for(const change of changes){
    const payload=clone(f.reviewed);change(payload.operation)
    await refuse(f.signing.handle(payload))
    assert.equal(f.snapshots.length,1);assert.equal((await f.readSigner()).owners.primary.counter,1)
  }
  assert.deepEqual(await f.signing.handle(f.reviewed),{type:'reviewed',operation_digest:contracts.operationDigest(f.reviewed.operation)})
  assert.equal(f.snapshots.length,1,'review never consumes a signer counter')
})

test('controller recomputes C challenge/options and binds the entire reviewed proposal and proof template before releasing an assertion',async t=>{
  const f=await reviewFixture(t)
  await f.signing.handle(f.reviewed)
  const mutations=[
    payload=>{payload.request.operationDigest='f'.repeat(64)},
    payload=>{payload.public_key.challenge='A'.repeat(43)},
    payload=>{payload.public_key.rpId='other.example.test'},
    payload=>{payload.public_key.allowCredentials[0].id=f.profile.credentials[1].credential_id},
    payload=>{payload.public_key.userVerification='preferred'},
    payload=>{payload.public_key.extra='caller-selected'},
    payload=>{payload.proof_template.operation_id='00000000-0000-4000-8000-000000000000'},
    payload=>{payload.proof_template.operation_digest='sha256:'+'e'.repeat(64)},
    payload=>{payload.proof_template.owner_id=f.profile.identities[1].owner_id},
    payload=>{payload.proof_template.nonce='d'.repeat(64)},
    payload=>{payload.proof_template.material={kind:'owner_key'}},
  ]
  for(const mutate of mutations){
    const payload=clone(f.approval);mutate(payload)
    await refuse(f.signing.handle(payload))
    assert.equal(f.snapshots.length,1);assert.equal((await f.readSigner()).owners.primary.counter,1)
  }
  const exact=await f.signing.handle(f.approval)
  assert.equal(exact.type,'assertion');assert.equal(f.snapshots.length,2)
  assert.equal(Buffer.from(exact.material.authenticator_data,'base64url').readUInt32BE(33),2)
  const proof={...clone(f.approval.proof_template),material:exact.material}
  assert.equal(ok(await f.connections.primary.request('owner.approvalComplete',{session_token:f.session,operation:f.reviewed.operation,proof})).status,'APPROVED')
  await refuse(f.signing.handle(f.approval),'NO_ARBITRARY_SIGNING_OR_REPLAY')
  assert.equal((await f.readSigner()).owners.primary.counter,2)
})

test('controller refuses a malformed login version even when caller recomputes its WebAuthn challenge',async t=>{
  const f=await fixture(t),signer=await f.readSigner(),persisted=[]
  const signing=createFixtureSigner({profile:f.profile,signer,phase:'save',persist:async value=>persisted.push(clone(value))})
  const challenge=ok(await f.connections.primary.request('owner.loginChallenge',{owner_id:f.profile.identities[0].owner_id,kind:'passkey'}))
  const request={...clone(challenge.challenge),version:2}
  const public_key={...clone(challenge.public_key),challenge:webauthnChallenge(loginSigningBytes(request))}
  await refuse(signing.handle({type:'sign',owner:'primary',purpose:'login',request,public_key,proof_template:null}))
  assert.equal(persisted.length,0);assert.equal(signer.owners.primary.counter,0)
})

test('controller refuses changed completion, receipt and control evidence and preserves the retained expectation on restart',async t=>{
  const f=await fixture(t),saved=await runPhase(f,'save'),signer=await f.readSigner(),durable=[]
  const signing=createFixtureSigner({profile:f.profile,signer,phase:'save',persist:async value=>durable.push(clone(value))})
  for(const payload of saved.frames.slice(0,-1))await signing.handle(payload)
  assert.equal(durable.length,3)
  const original=saved.frames.at(-1),mutations=[
    [payload=>{payload.report.expected.owner='secondary'},'EXACT_SAVED_PENDING_RESULT_REQUIRED'],
    [payload=>{payload.report.expected.index_status='indexed'},'EXACT_SAVED_PENDING_RESULT_REQUIRED'],
    [payload=>{payload.report.authority_status.status='APPROVED'},'ACTUAL_C_COMPLETION_RESULT_REQUIRED'],
    [payload=>{payload.report.authority_status.operation_digest='sha256:'+'f'.repeat(64)},'ACTUAL_C_COMPLETION_RESULT_REQUIRED'],
    [payload=>{payload.report.checks.reverse()},'EXACT_PHASE_CONTROLS_REQUIRED'],
    [payload=>{payload.report.expected.receipt.grant_id='grant:'+'e'.repeat(64)},'SIGNED_EFFECT_RECEIPT_BINDING_REQUIRED'],
    [payload=>{payload.report.expected.receipt.request_digest='sha256:'+'d'.repeat(64)},'SIGNED_EFFECT_RECEIPT_BINDING_REQUIRED'],
  ]
  for(const [mutate,reason] of mutations){
    const payload=clone(original);mutate(payload)
    await refuse(signing.handle(payload),reason)
    assert.equal(durable.length,3);assert.equal(signing.complete,false);assert.equal(signing.result,null)
  }
  assert.deepEqual(await signing.handle(original),{type:'accepted'})
  assert.equal(signing.complete,true);assert.equal(durable.length,4)

  const restartSigner=await f.readSigner();restartSigner.attempted_phases.push('after-authority-restart')
  const restarted=createFixtureSigner({profile:f.profile,signer:restartSigner,phase:'after-authority-restart',persist:async value=>durable.push(clone(value))})
  await restarted.handle(saved.frames[0]);await restarted.handle(saved.frames[3])
  const restart=clone(original)
  restart.report.phase='after-authority-restart'
  restart.report.checks=['restart-canonical-bytes','restart-retained-citation','restart-c-completion','cross-owner-read-cite-status-refused','public-unqualified']
  const changed=clone(restart);changed.report.expected.canonical_sha256='c'.repeat(64)
  await refuse(restarted.handle(changed),'RESTART_EXPECTATION_CHANGED')
  assert.equal(restarted.complete,false);assert.equal(restarted.result,null)
  assert.deepEqual(restartSigner.expected,saved.report.expected)
  assert.deepEqual(await restarted.handle(restart),{type:'accepted'})
})

test('a failed durable counter write releases no assertion and does not complete the signing phase',async t=>{
  const f=await fixture(t),signer=await f.readSigner()
  signer.attempted_phases.push('save');await f.persist(signer)
  const signing=createFixtureSigner({profile:f.profile,signer,phase:'save',persist:async()=>{throw new Error('test durable counter write refused')}})
  const challenge=ok(await f.connections.primary.request('owner.loginChallenge',{owner_id:f.profile.identities[0].owner_id,kind:'passkey'}))
  const payload={type:'sign',owner:'primary',purpose:'login',request:challenge.challenge,public_key:challenge.public_key,proof_template:null}
  await assert.rejects(signing.handle(payload),/test durable counter write refused/)
  assert.equal(signing.complete,false);assert.equal(signing.result,null)
  assert.equal(signer.owners.primary.counter,1,'failed durability must not rewind an attempted counter')
  assert.equal((await f.readSigner()).owners.primary.counter,0,'no successful durable publication occurred')
  assert.deepEqual((await f.readSigner()).completed_phases,[])
})
