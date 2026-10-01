// SPDX-License-Identifier: AGPL-3.0-or-later
// SYNTHETIC app actor. Receives assertion material, never private signing keys.
import {resolve} from 'node:path'
import {fileURLToPath} from 'node:url'
import * as contracts from '../../contracts/src/runtime.mjs'
import {memoryReceiptDigest} from '../../memory/src/authorization.mjs'
import {createPrimeTransport} from '../../ui/adapters/transport.mjs'
import {createUiAdapters} from '../src/ui-adapter.mjs'
import {createIpcClient} from '../src/ipc.mjs'
import {closed} from '../src/registry.mjs'
import {createFixturePipe} from './deployed-pipes.mjs'
import {IDS,PHASES,sha,dFixture,validateProfile,validateActorConfig,readRootJson,readPrivateJson,writePrivateJson,scenario,must} from './deployed-profile.mjs'
const ok=result=>{must(result?.ok===true,'AUTHENTICATED_WORKER_CALL_REFUSED');return result}
const denied=result=>must(result?.ok===false,'NEGATIVE_CONTROL_ACCEPTED')
export async function runFixtureActor({profile,phase,pipe,connections,witness}){
  must(PHASES.includes(phase),'EXACT_FIXTURE_PHASE_REQUIRED');await validateProfile(profile)
  const checks=[],sessions={},adapters={},ui={};let template=null
  for(const owner of ['primary','secondary']){
    adapters[owner]=createUiAdapters({call:async(method,input)=>{
      const result=await connections[owner].request(method,input)
      if(method==='owner.loginComplete'&&result?.ok===true)sessions[owner]=result.session_token
      if(method==='owner.approvalChallenge'&&result?.ok===true)template=result.proof_template
      return result
    }})
    ui[owner]=createPrimeTransport({authority:adapters[owner].authority,contracts,passkeySigner:async({purpose,request,public_key})=>{
      const reply=await pipe.request({type:'sign',owner,purpose,request,public_key,proof_template:purpose==='approval'?template:null})
      must(reply?.type==='assertion','FIXTURE_SIGNER_REFUSED');return reply.material
    }})
  }
  await ui.primary.login({owner_id:profile.fixture.owners.primary.owner_id})
  let expected,operation,authority_status
  if(phase==='save'){
    const s=scenario(profile,'primary'),draft={extraction_json:s.extraction_json,idempotency_key:s.idempotency_key}
    const proposed=ok(await adapters.primary.memory.proposeSave(draft));operation=proposed.operation
    const reviewed=await pipe.request({type:'review',owner:'primary',operation,memory_capture:proposed.memory_capture})
    must(reviewed?.type==='reviewed'&&reviewed.operation_digest===contracts.operationDigest(operation),'INDEPENDENT_REVIEW_REFUSED')
    const prepared=await ui.primary.prepareApproval(operation,{memoryCapture:proposed.memory_capture}),approved=await ui.primary.approve(prepared)
    const direct={...draft,session_token:sessions.primary,operation,approval_proof:approved.approval_proof}
    for(const field of ['statement','attributed_to']){
      const altered=structuredClone(operation);altered.canonical_parameters[field]=field==='statement'?'Altered synthetic statement.':'agent'
      denied(await connections.primary.request('memory.save',{...direct,operation:altered}))
      const state=ok(await connections.primary.request('owner.status',{session_token:sessions.primary,operation_id:operation.operation_id}))
      must(state.status==='APPROVED'&&state.operation_digest===contracts.operationDigest(operation),'TAMPER_CONSUMED_APPROVAL');checks.push('preconsume-'+field+'-refused')
    }
    denied(await connections.primary.request('memory.save',{...direct,extraction_json:JSON.stringify({...s.extraction,statement:'Altered actual capture.'})}))
    must(ok(await connections.primary.request('owner.status',{session_token:sessions.primary,operation_id:operation.operation_id})).status==='APPROVED','ALTERED_CAPTURE_CONSUMED_APPROVAL');checks.push('preconsume-extraction-refused')
    await ui.secondary.login({owner_id:profile.fixture.owners.secondary.owner_id})
    denied(await connections.secondary.request('owner.approvalChallenge',{session_token:sessions.secondary,operation}))
    denied(await connections.secondary.request('memory.save',{...direct,session_token:sessions.secondary}))
    denied(await connections.secondary.request('owner.status',{session_token:sessions.secondary,operation_id:operation.operation_id}));checks.push('preconsume-cross-owner-refused')
    const saved=ok(await adapters.primary.memory.save({...draft,operation,approval_proof:approved.approval_proof}))
    must(saved.authority_settlement==='completed'&&saved.reconciliation_required===false&&saved.record.storage_status==='saved'&&saved.record.index_status==='pending','SAVED_PENDING_WITH_ACTUAL_C_SETTLEMENT_REQUIRED')
    const citation=ok(await adapters.primary.memory.cite({record_id:saved.record.record_id,revision:null,retained_head:null})).citation
    must(citation.verdict==='VERIFIED'&&citation.grants_authority===false,'GENUINE_RETAINED_HEAD_CITATION_REQUIRED')
    expected={version:1,owner:'primary',operation_id:operation.operation_id,operation_digest:contracts.operationDigest(operation),record_id:saved.record.record_id,canonical_sha256:sha(saved.record.canonical_bytes),retained_head:citation.verified_head,storage_status:'saved',index_status:'pending',receipt:{request_id:saved.receipt.request_id,request_digest:saved.receipt.request_digest,receipt_digest:memoryReceiptDigest(saved.receipt),grant_id:saved.receipt.grant_id,result_digest:saved.receipt.result_digest},settlement_binding:{authority_settlement:'completed',reconciliation_required:false,receipt_digest:saved.receipt_digest}}
    ;(await dFixture()).validateWorkerPostgresSaveExpectation(expected,profile.fixture)
    authority_status=ok(await connections.primary.request('owner.status',{session_token:sessions.primary,operation_id:operation.operation_id}))
    must(authority_status.status==='COMPLETED'&&authority_status.operation_digest===expected.operation_digest&&authority_status.reconciliation_required===false,'INDEPENDENT_ACTUAL_C_COMPLETION_REQUIRED')
    checks.push('real-c-proof-save-settlement','saved-distinct-from-indexed','genuine-citation')
    await witness.write({version:1,kind:'prime-private-cd-pg-witness/v1',synthetic_fixture:true,run_id:profile.fixture.run_id,expected,operation})
  }else{
    const retained=await witness.read();closed(retained,['version','kind','synthetic_fixture','run_id','expected','operation'])
    must(retained?.version===1&&retained.kind==='prime-private-cd-pg-witness/v1'&&retained.synthetic_fixture===true&&retained.run_id===profile.fixture.run_id,'FIXTURE_RETAINED_WITNESS_REQUIRED')
    expected=retained.expected;operation=retained.operation;(await dFixture()).validateWorkerPostgresSaveExpectation(expected,profile.fixture)
    contracts.validateContract('OperationProposal',operation);must(contracts.operationDigest(operation)===expected.operation_digest&&operation.operation_id===expected.operation_id,'RETAINED_OPERATION_BINDING_REQUIRED')
    const read={record_id:expected.record_id,revision:null},state=ok(await adapters.primary.memory.status(read))
    must(state.saved===true&&state.indexed===false&&state.searchable===false&&state.record.storage_status==='saved'&&state.record.index_status===expected.index_status&&sha(state.record.canonical_bytes)===expected.canonical_sha256,'RESTART_RECORD_OR_INDEX_STATE_CHANGED')
    const cite=ok(await adapters.primary.memory.cite({...read,retained_head:expected.retained_head})).citation
    must(cite.verdict==='VERIFIED'&&cite.grants_authority===false&&cite.verified_head===expected.retained_head,'RESTART_RETAINED_CITATION_CHANGED')
    authority_status=ok(await connections.primary.request('owner.status',{session_token:sessions.primary,operation_id:expected.operation_id}))
    must(authority_status.status==='COMPLETED'&&authority_status.operation_digest===expected.operation_digest&&authority_status.reconciliation_required===false,'RESTART_C_SETTLEMENT_CHANGED')
    await ui.secondary.login({owner_id:profile.fixture.owners.secondary.owner_id});checks.push('restart-canonical-bytes','restart-retained-citation','restart-c-completion')
  }
  denied(await adapters.secondary.memory.status({record_id:expected.record_id,revision:null}))
  denied(await adapters.secondary.memory.cite({record_id:expected.record_id,revision:null,retained_head:expected.retained_head}))
  denied(await connections.secondary.request('owner.status',{session_token:sessions.secondary,operation_id:expected.operation_id}));checks.push('cross-owner-read-cite-status-refused')
  const capability=await connections.primary.request('capability.status',{})
  must(capability.state==='unqualified'&&capability.available===false&&capability.public_routes==='unavailable','SYNTHETIC_FIXTURE_CANNOT_QUALIFY_PUBLIC_ROUTES');checks.push('public-unqualified')
  const report={version:1,kind:'prime-private-cd-pg-actor-result/v1',synthetic_fixture:true,phase,run_id:profile.fixture.run_id,expected,authority_status,checks}
  const ack=await pipe.request({type:'result',report});must(ack?.type==='accepted','FIXTURE_RESULT_NOT_ACCEPTED');return report
}
async function main(){
  const args=process.argv.slice(2);must(args.length===4&&args[0]==='--config'&&args[2]==='--phase'&&PHASES.includes(args[3]),'CLOSED_APP_ACTOR_COMMAND_REQUIRED')
  const groups=process.getgroups?.()??[];must(groups.includes(IDS.memoryIpc)&&![IDS.authorityIpc,IDS.postgresSocket,IDS.authorityGroup,IDS.memoryGroup].some(g=>groups.includes(g)),'APP_ACTOR_HAS_NO_PRIVATE_EFFECT_OR_PG_GROUPS')
  const config=validateActorConfig(await readRootJson(args[1],IDS.app,IDS.appGroup));await validateProfile(config.profile)
  const pipe=createFixturePipe({readable:process.stdin,writable:process.stdout}),connections={}
  try{
    for(const owner of ['primary','secondary'])connections[owner]=await createIpcClient(config[owner])
    await runFixtureActor({profile:config.profile,phase:args[3],pipe,connections,witness:{read:()=>readPrivateJson(config.witness_path),write:value=>writePrivateJson(config.witness_path,value,{exclusive:true})}})
  }finally{await Promise.allSettled(Object.values(connections).map(c=>c.close()));pipe.close()}
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url))main().catch(error=>{process.stderr.write('SYNTHETIC_APP_ACTOR_REFUSED:'+String(error.code??'UNAVAILABLE')+'\n');process.exitCode=1})
