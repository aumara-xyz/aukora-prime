// SPDX-License-Identifier: AGPL-3.0-or-later
// Disposable tests ONLY. This subclass explicitly simulates admission to exercise
// the lifecycle; it is not exported by the production package and cannot supply
// runtime qualification evidence. Inject real C for the separate joined check.
import { mkdtemp,realpath } from 'node:fs/promises'
import { mkdirSync,readFileSync,writeFileSync,openSync,fsyncSync,closeSync,renameSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { randomUUID } from 'node:crypto'
import { once } from 'node:events'
import { OpenShellOwnedExecutor,OwnedLedger,SdkTransport,policyDigest,executorRequestDigest,executionReceiptDigest } from '../src/index.mjs'
import { operationDigest,canonicalJson } from '../../contracts/src/runtime.mjs'
import { expectedConfigIdentity } from '../src/effective-policy.mjs'
export const settings={workspace:'disposable-protocol',logical_workspace_root:'/logical/project',image_digest:'example.invalid/workload@sha256:'+'a'.repeat(64),control_timeout_ms:1000,cleanup_timeout_ms:150,poll_ms:2}
export function request(overrides={}) {
  const operation={version:1,operation_id:randomUUID(),task_id:'synthetic-task',owner_id:'synthetic-owner',agent_id:'synthetic-agent',audience:'synthetic-executor',
    action_type:'shell.bash.foreground',target_identity:{backend:'openshell-linux',workspace:settings.workspace,image_digest:settings.image_digest,policy_digest:policyDigest('read-only'),logical_workspace_root:settings.logical_workspace_root},
    canonical_parameters:{command:'synthetic inert command',workdir:settings.logical_workspace_root,sandbox_mode:'read-only',stdin:'',env:{},dsh_env:{},timeout_ms:500,max_output_bytes:128},
    data_scope:[],expected_state_version:'synthetic-1',provider_and_region:{provider:'synthetic',region:'disposable'},maximum_cost:{currency:'USD',amount:'0'},expiry:new Date(Date.now()+60_000).toISOString(),nonce:randomUUID(),policy_version:'synthetic-1',authorization_epoch:1}
  const consumed_grant={version:1,grant_id:randomUUID(),operation_id:operation.operation_id,operation_digest:operationDigest(operation),owner_id:operation.owner_id,audience:operation.audience,authorization_epoch:1,prepared_at:new Date().toISOString(),reservation_id:randomUUID()}
  return {operation,consumed_grant,request_id:randomUUID(),image_digest:settings.image_digest,policy_digest:policyDigest('read-only'),wall_time_ms:500,max_output_bytes:128,...overrides}
}
export function mock({exit=0,trailerFailure=false,createFailure=false,invisibleCreate=false,cleanupFailure=false,identityMismatch=false,waitAbort=false,afterDelete=0,events,afterCreate,crashAfterExit=false,configurationHook}={}) {
  let sandbox=null,config=null,pendingDeletion=0,configurationReads=0;const calls=[]
  const raw={
    async createSandbox(r){calls.push(['create',r]);const identity=expectedConfigIdentity(r.spec.policy),epoch=randomUUID(),instance=randomUUID()
      config={policy:structuredClone(r.spec.policy),version:1,policyHash:identity.policy_hash,settings:Object.fromEntries(['ocsf_json_enabled','ocsf_schema_version','agent_policy_proposals_enabled','proposal_approval_mode'].map(key=>[key,{scope:0}])),configRevision:BigInt(identity.config_revision),policySource:1,globalPolicyVersion:0,providerEnvRevision:BigInt(identity.provider_env_revision),supervisorMiddlewareServices:[],workspace:r.workspaceScope.selection.value,policyValidationFailureMode:'fail_closed',extensionAuthenticationEnabled:false,providerAttachmentEpoch:epoch,configurationAdmitted:true,configurationError:'',configurationInstanceId:instance}
      sandbox={metadata:{id:randomUUID(),name:r.name,workspace:r.workspaceScope.selection.value,labels:{...r.labels}},spec:{...r.spec,providerAttachmentEpoch:epoch},status:{phase:2,configurationAdmission:{instanceId:instance,state:2,policyVersion:1,policyHash:identity.policy_hash,configRevision:config.configRevision,providerEnvRevision:config.providerEnvRevision,error:''}}};afterCreate?.();if(createFailure)throw Object.assign(new Error('mock transport loss'),{name:'SdkError',code:'rpc'});return {sandbox}},
    async getSandbox(r){calls.push(['get',r]);return {sandbox:identityMismatch?{...sandbox,metadata:{...sandbox.metadata,id:randomUUID()}}:sandbox}},
    async getSandboxConfig(r){calls.push(['config',r]);configurationReads++;const copy=structuredClone(config);return configurationHook?configurationHook({config:copy,sandbox,read:configurationReads}):copy},
    async listSandboxes(r){calls.push(['list',r]);if(cleanupFailure)throw new Error('synthetic inventory unavailable');if(pendingDeletion&&--pendingDeletion===0)sandbox=null;return {sandboxes:invisibleCreate?[]:sandbox?[sandbox]:[],nextPageToken:''}},
    async deleteSandbox(r){calls.push(['delete',r]);const id=sandbox.metadata.id;if(afterDelete)pendingDeletion=afterDelete;else sandbox=null;return {outcome:2,sandboxId:id}},
    async *execSandbox(r,{signal}){calls.push(['exec',r]);if(waitAbort){if(!signal.aborted)await once(signal,'abort');throw Object.assign(new Error('mock canceled'),{name:'SdkError',code:'canceled'})}
      if(events){for(const event of events)yield event}else{yield {payload:{case:'stdout',value:{data:Buffer.from('retained synthetic output')}}};yield {payload:{case:'stderr',value:{data:Buffer.from('retained error')}}};yield {payload:{case:'exit',value:{exitCode:exit}}}}
      if(crashAfterExit)process.exit(0)
      if(trailerFailure)throw Object.assign(new Error('synthetic final RPC status failed'),{name:'SdkError',code:'rpc'})
    }
  }
  return {raw,calls,setCleanup(value){cleanupFailure=value},getSandbox:()=>sandbox}
}

export class MockedDurableBroker {
  constructor(root){this.file=join(root,'mock-broker.json');if(!this.read())this.write({rows:{},calls:[]})}
  read(){try{return JSON.parse(readFileSync(this.file,'utf8'))}catch{return null}}
  write(value){const path=this.file+'.next';writeFileSync(path,JSON.stringify(value),{mode:0o600});const fd=openSync(path,'r');fsyncSync(fd);closeSync(fd);renameSync(path,this.file);const dir=openSync(this.file.slice(0,this.file.lastIndexOf('/')),'r');fsyncSync(dir);closeSync(dir)}
  prepare(request){const state=this.read();if(!state.rows[request.operation.operation_id]){state.rows[request.operation.operation_id]={request:JSON.parse(canonicalJson((({signal,...r})=>r)(request))),status:'PREPARED',cancel:false,receipt:null};this.write(state)}}
  claimDispatch(input){const state=this.read();state.calls.push(['claimDispatch',input]);const row=state.rows[input.operation.operation_id];let result
    if(!row||row.status!=='PREPARED')result={ok:false,error_code:'REPLAYED',reason:'synthetic one-use fence'}
    else if(canonicalJson(row.request.operation)!==canonicalJson(input.operation)||canonicalJson(row.request.consumed_grant)!==canonicalJson(input.consumed_grant)||row.request.request_id!==input.request_id||executorRequestDigest(row.request)!==input.request_digest)result={ok:false,error_code:'UNAUTHORIZED',reason:'synthetic binding mismatch'}
    else {row.status='DISPATCHED';row.binding=input;result={ok:true,status:'DISPATCHED',consumed_grant:input.consumed_grant,request_id:input.request_id,request_digest:input.request_digest}}
    this.write(state);return result}
  requestCancel(input){const state=this.read(),row=state.rows[input.operation.operation_id];state.calls.push(['requestCancel',input]);if(!row?.binding)return {ok:false,error_code:'UNAVAILABLE',reason:'not dispatched'}
    const terminal=['COMPLETED','FAILED','CANCELLED','UNAVAILABLE'].includes(row.status);if(!terminal){row.cancel=true;row.status='CANCEL_REQUESTED'}this.write(state)
    return {ok:true,status:row.status,request_id:input.request_id,cancel_recorded:!terminal}}
  settle(input){return this.saveReceipt(input,false)}
  reconcileSettlement(input){return this.saveReceipt(input,true)}
  saveReceipt(input,reconcile){const state=this.read(),row=state.rows[input.operation.operation_id];state.calls.push([reconcile?'reconcileSettlement':'settle',input]);if(!row?.binding||row.binding.request_digest!==input.request_digest||row.binding.request_id!==input.request_id)return {ok:false,error_code:'UNAUTHORIZED',reason:'dispatch binding missing'}
    if(executionReceiptDigest(input.receipt)!==input.receipt_digest)return {ok:false,error_code:'INVALID',reason:'receipt digest mismatch'}
    const idempotent=row.receipt_digest===input.receipt_digest
    if(row.receipt&&!idempotent&&(!reconcile||row.status!=='OUTCOME_UNKNOWN'))return {ok:false,error_code:'REPLAYED',reason:'receipt conflict'}
    row.receipt=input.receipt;row.receipt_digest=input.receipt_digest;row.status=input.receipt.status.toUpperCase();this.write(state)
    return {ok:true,status:row.status,request_id:input.request_id,request_digest:input.request_digest,receipt_digest:input.receipt_digest,idempotent,reconciliation_required:row.status==='OUTCOME_UNKNOWN'}}
}
export class MockedProtocolExecutor extends OpenShellOwnedExecutor {
  constructor(options){super({...options,qualification:null});this.protocolAdmission=options.protocolAdmission??(()=>true)}
  get capability(){return this.disposed||this.protocolAdmission()!==true?'unavailable':'qualified'}
  admission(){return this.capability==='qualified'}
  // Explicit fixture-only simulation. No provider implements these methods;
  // it cannot turn an acceptance callback or API absence into runtime proof.
  requireIndependentLifetime() {}
  requireAtomicConfiguration() {}
  requireIndependentCleanup() {}
  confirmOwnedCleanup(job) {
    if(job.public_cleanup_observation?.state!=='api_absent'||job.public_cleanup_observation.sandbox_uid!==job.id)throw new Error('synthetic cleanup observation differs')
    job.receipt.cleanup='confirmed_absent';job.stage='cleaned'
  }
  availability(){return {...super.availability(),state:'unavailable',protocol:'mocked',runtime:'unavailable',runtimeEnforcementVerified:false}}
  async execute(request){this.broker.prepare?.(request);return super.execute(request)}
}
export async function fixture(options={},hooks={}) {
  const root=await realpath(await mkdtemp(join(tmpdir(),'prime-execution-protocol-')))
  const ledger=new OwnedLedger(root,{initialize:true}),protocol=mock(options),transport=new SdkTransport(protocol.raw,{gatewayIdentity:'https://synthetic.invalid:19443/'}),base=hooks.broker??new MockedDurableBroker(root)
  const broker={...Object.fromEntries(['claimDispatch','requestCancel','settle','reconcileSettlement'].map(k=>[k,base[k].bind(base)])),prepare:base.prepare?.bind(base)}
  if(hooks.beforeClaim){const call=broker.claimDispatch;broker.claimDispatch=async input=>{if(await hooks.beforeClaim(input.operation,input.consumed_grant)===false)return {ok:false,error_code:'UNAUTHORIZED',reason:'synthetic negative callback'};return call(input)}}
  const executor=new MockedProtocolExecutor({settings,transport,ledger,broker,protocolAdmission:hooks.protocolAdmission})
  return {root,ledger,protocol,transport,executor,broker:base}
}
