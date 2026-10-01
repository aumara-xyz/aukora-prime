// SPDX-License-Identifier: AGPL-3.0-or-later
import {randomUUID,randomBytes} from 'node:crypto'
import {canonicalJson,parseStrictJson,validateContract,operationDigest} from '../../contracts/src/runtime.mjs'
import {parseOriginal} from '../../memory/src/codecs.mjs'
import {closed,copy,freeze,createTrustedTaskRegistry} from './registry.mjs'
import {IPC_METHOD_ROLES,PUBLIC_METHODS} from './ipc.mjs'
export {createTrustedTaskRegistry,PUBLIC_METHODS}

class BridgeRefusal extends Error {
  constructor(error_code,reason){super(reason);this.error_code=error_code}
}
const fail=(code,reason)=>{throw new BridgeRefusal(code,reason)}
const requireMethod=(service,name)=>{if(typeof service?.[name]!=='function')fail('UNAVAILABLE','BRIDGE_SERVICE_UNMOUNTED:'+name)}
const token=value=>{if(typeof value!=='string'||!/^[a-f0-9]{64}$/.test(value))fail('UNAUTHORIZED','OWNER_SESSION_REQUIRED')}
const text=(value,max=1024)=>{if(typeof value!=='string'||!value.length||Buffer.byteLength(value)>max)fail('INVALID','BRIDGE_STRING_BOUND')}
const errorResult=error=>({ok:false,error_code:error.error_code??(error.reconciliation_required?'OUTCOME_UNKNOWN':error instanceof TypeError?'INVALID':'UNAVAILABLE'),reason:error instanceof BridgeRefusal?error.message:typeof error.code==='string'&&error.code.startsWith('memory:')?error.code:'BRIDGE_SERVICE_REFUSED',...(error.reconciliation_required?{reconciliation_required:true,operation_id:error.operation_id,request_id:error.request_id,request_digest:error.request_digest}:{})})
const unwrap=result=>{if(result?.ok!==true)fail(result?.error_code??'UNAVAILABLE',result?.reason??'BRIDGE_SERVICE_REFUSED');return result}
function extraction(textValue){text(textValue,16_384);return freeze(parseOriginal(Buffer.from(textValue,'utf8')))}
function trustedContext(value) {
  // Trusted source events are byte arrays; they are not transport JSON. Check
  // only the outer host record before cloning D's byte-bearing context.
  if(!value||Object.getPrototypeOf(value)!==Object.prototype||Reflect.ownKeys(value).length!==2||!['task_id','memory_host'].every(key=>Object.hasOwn(value,key)&&Object.hasOwn(Object.getOwnPropertyDescriptor(value,key),'value')))fail('UNAVAILABLE','TRUSTED_HOST_CONTEXT_REQUIRED')
  return value
}

/** All services, registry and context resolver are host inputs. This creates no
 * listener, credentials, state, database, owner identity or authorization kernel. */
export function createRuntimeBridge({authority,memory,taskRegistry,resolveHostContext,verifyHostQualification}={}) {
  const authorityMethods=['authenticateSession','propose','loginChallenge','loginComplete','approvalChallenge','approvalComplete','declineApproval','status','reserve','claimDispatch','settleMemory','markOutcomeUnknown']
  const memoryMethods=['prepareCaptureBinding','captureAuthorizedRemembered','withAuthorityTargetObservation','status','cite','recall']
  const mounted=authorityMethods.every(k=>typeof authority?.[k]==='function')&&memoryMethods.every(k=>typeof memory?.[k]==='function')&&typeof taskRegistry?.getOwned==='function'&&typeof taskRegistry?.authorizeTask==='function'&&typeof resolveHostContext==='function'
  async function accepted() {
    if(!mounted || typeof verifyHostQualification!=='function')return null
    // H owns acceptance. A boolean or a synthetic profile cannot qualify public routes.
    const value=await verifyHostQualification()
    if(!value || typeof value!=='object')return null
    const record=copy(value)
    closed(record,['profile','environment','accepted','app_uid','broker_uid','transport','owner_enrollment','postgres_runtime','source_commit','release_digest'])
    if(record.profile!=='prime-separated-runtime-host/v1' || record.environment!=='production' || record.accepted!==true || !Number.isSafeInteger(record.app_uid)||record.app_uid<0||!Number.isSafeInteger(record.broker_uid)||record.broker_uid<0||record.app_uid===record.broker_uid || record.transport!=='authenticated-ipc' || record.owner_enrollment!=='qualified' || record.postgres_runtime!=='qualified' || !/^[a-f0-9]{40}$/.test(record.source_commit??'') || !/^sha256:[a-f0-9]{64}$/.test(record.release_digest??''))return null
    return record
  }
  async function capability() {
    const qualification=await accepted()
    return {ok:true,version:1,state:!mounted?'unmounted':qualification?'available':'unqualified',available:qualification!==null,
      public_routes:qualification?'available':'unavailable',qualification,postgres_runtime:qualification?'qualified':'unperformed',runtime_isolation:qualification?'qualified':'unverified'}
  }
  async function session(input) {
    token(input.session_token);requireMethod(authority,'authenticateSession')
    const found=unwrap(await authority.authenticateSession({session_token:input.session_token}))
    closed(found,['ok','owner_id','subject','authorization_epoch','expiry'])
    text(found.owner_id);if(!/^aukora:1:[a-f0-9]{64}$/.test(found.subject)||!Number.isSafeInteger(found.authorization_epoch)||found.authorization_epoch<0||!Number.isFinite(Date.parse(found.expiry))||Date.parse(found.expiry)<=Date.now())fail('UNAUTHORIZED','OWNER_SESSION_INVALID')
    return copy(found)
  }
  async function context(request,identity) {
    if(typeof resolveHostContext!=='function')fail('UNAVAILABLE','TRUSTED_HOST_CONTEXT_UNMOUNTED')
    const resolved=await resolveHostContext({request,session:identity})
    if(!identity) {closed(resolved,['login_owner_id']);text(resolved.login_owner_id);return copy(resolved)}
    trustedContext(resolved)
    requireMethod(taskRegistry,'getOwned')
    const entry=taskRegistry.getOwned(resolved.task_id,identity.owner_id)
    if(!entry)fail('UNAUTHORIZED','TRUSTED_OWNER_TASK_REQUIRED')
    // Derive both identifiers from C, after the host has selected the task and source event.
    // Caller data can never override owner, task or policy/source provenance.
    const host=structuredClone(resolved.memory_host)
    if(!host || typeof host!=='object'||Array.isArray(host))fail('UNAVAILABLE','TRUSTED_MEMORY_CONTEXT_REQUIRED')
    if(host.owner_subject!==undefined&&host.owner_subject!==identity.subject || host.owner_id!==undefined&&host.owner_id!==identity.owner_id || host.task_id!==undefined&&host.task_id!==entry.task.task_id)fail('UNAUTHORIZED','TRUSTED_CONTEXT_OWNER_MISMATCH')
    host.owner_id=identity.owner_id;host.owner_subject=identity.subject;host.task_id=entry.task.task_id
    return {entry,host}
  }
  function operationForContext(operation,identity,entry) {
    validateContract('OperationProposal',operation)
    if(operation.owner_id!==identity.owner_id||operation.authorization_epoch!==identity.authorization_epoch||operation.action_type!=='memory.save'||taskRegistry.authorizeTask(operation)?.authenticated!==true||operation.task_id!==entry.task.task_id)fail('UNAUTHORIZED','EXACT_OWNED_OPERATION_REQUIRED')
    return copy(operation)
  }
  async function targetScope(host,operation,fn) {
    requireMethod(memory,'withAuthorityTargetObservation')
    return memory.withAuthorityTargetObservation(host,operation,fn)
  }
  async function dispatch(method,input,{request,role='read_only'}={}) {
    if(!PUBLIC_METHODS.includes(method))fail('INVALID','BRIDGE_METHOD_NOT_PUBLIC')
    if(!IPC_METHOD_ROLES[method].includes(role))fail('UNAUTHORIZED','BRIDGE_CHANNEL_ROLE_REFUSED')
    if(method==='capability.status'){closed(input,[]);return capability()}
    if(!mounted)fail('UNAVAILABLE','BRIDGE_SERVICES_UNMOUNTED')
    if(method==='owner.loginChallenge') {
      closed(input,['owner_id','kind']);if(input.kind!=='passkey')fail('UNAVAILABLE','BRIDGE_PASSKEY_REQUIRED')
      const host=await context(request,null)
      if(input.owner_id!==host.login_owner_id)fail('UNAUTHORIZED','TRUSTED_LOGIN_OWNER_REQUIRED')
      requireMethod(authority,'loginChallenge');return authority.loginChallenge(input)
    }
    if(method==='owner.loginComplete') {
      closed(input,['challenge','material']);const host=await context(request,null)
      if(input.challenge?.owner_id!==host.login_owner_id||input.material?.kind!=='passkey')fail('UNAUTHORIZED','TRUSTED_PASSKEY_OWNER_REQUIRED')
      requireMethod(authority,'loginComplete');return authority.loginComplete(input)
    }
    const identity=await session(input)
    if(method==='owner.status'||method==='owner.declineApproval') {
      closed(input,['session_token','operation_id']);text(input.operation_id)
      const name=method==='owner.status'?'status':'declineApproval';requireMethod(authority,name);return authority[name](input)
    }
    const {entry,host}=await context(request,identity)
    if(method==='memory.proposeSave') {
      closed(input,['session_token','extraction_json','idempotency_key']);text(input.idempotency_key)
      requireMethod(memory,'prepareCaptureBinding');requireMethod(authority,'propose')
      const binding=await memory.prepareCaptureBinding(host,extraction(input.extraction_json),input.idempotency_key)
      closed(binding,['target_identity','state_version','canonical_parameters'])
      const operation=copy({version:1,operation_id:randomUUID(),task_id:entry.task.task_id,owner_id:identity.owner_id,agent_id:entry.task.agent_id,
        audience:entry.audience,action_type:'memory.save',target_identity:binding.target_identity,canonical_parameters:binding.canonical_parameters,
        data_scope:entry.data_scope,expected_state_version:binding.state_version,provider_and_region:entry.provider_and_region,
        maximum_cost:{currency:'USD',amount:'0'},expiry:new Date(Math.min(Date.now()+120_000,Date.parse(identity.expiry))).toISOString(),nonce:randomBytes(32).toString('hex'),policy_version:entry.policy_version,authorization_epoch:identity.authorization_epoch})
      validateContract('OperationProposal',operation)
      return authority.propose(operation)
    }
    if(method==='owner.approvalChallenge') {
      closed(input,['session_token','operation']);const operation=operationForContext(input.operation,identity,entry)
      requireMethod(authority,'approvalChallenge')
      return targetScope(host,operation,()=>authority.approvalChallenge({session_token:input.session_token,operation}))
    }
    if(method==='owner.approvalComplete') {
      // Operation is supplied by the owner client, compared to persisted C review;
      // used here only to scope D's current exact target observation.
      closed(input,['session_token','operation','proof']);const operation=operationForContext(input.operation,identity,entry)
      validateContract('ApprovalProof',input.proof);requireMethod(authority,'approvalComplete')
      if(input.proof.operation_id!==operation.operation_id||input.proof.operation_digest!==operationDigest(operation)||input.proof.owner_id!==identity.owner_id||input.proof.audience!==operation.audience||input.proof.authorization_epoch!==operation.authorization_epoch)fail('INVALID','EXACT_APPROVAL_BINDING_REQUIRED')
      return targetScope(host,operation,()=>authority.approvalComplete({session_token:input.session_token,proof:input.proof}))
    }
    if(method==='memory.save') {
      closed(input,['session_token','operation','approval_proof','extraction_json','idempotency_key'])
      const operation=operationForContext(input.operation,identity,entry);validateContract('ApprovalProof',input.approval_proof);text(input.idempotency_key)
      requireMethod(memory,'captureAuthorizedRemembered')
      const result=await memory.captureAuthorizedRemembered(host,extraction(input.extraction_json),input.idempotency_key,{operation,approval_proof:input.approval_proof})
      validateContract('MemoryRecord',result.record)
      return {ok:true,...result}
    }
    if(method==='memory.status') {
      closed(input,['session_token','record_id','revision']);text(input.record_id);if(input.revision!==null)text(input.revision)
      requireMethod(memory,'status');return {ok:true,...await memory.status(host,input.record_id,input.revision??undefined)}
    }
    if(method==='memory.cite') {
      closed(input,['session_token','record_id','revision','retained_head']);text(input.record_id);if(input.revision!==null)text(input.revision);if(input.retained_head!==null)text(input.retained_head)
      requireMethod(memory,'cite');return {ok:true,citation:await memory.cite(host,input.record_id,input.revision??undefined,input.retained_head??undefined)}
    }
    closed(input,['session_token','query','limit']);text(input.query,4096)
    if(!Number.isSafeInteger(input.limit)||input.limit<1||input.limit>100)fail('INVALID','BRIDGE_RECALL_LIMIT')
    requireMethod(memory,'recall');return {ok:true,...await memory.recall(host,{query:input.query,limit:input.limit,scope:host.scope??'owner',permittedPrivacy:host.permittedPrivacy??['local']})}
  }
  async function handleTrusted(method,input,contextValue={}) {
    try {
      // Every caller value is detached before the first asynchronous operation.
      const detached=parseStrictJson(canonicalJson(input),{maxBytes:65_536,maxDepth:32})
      const boundContext=parseStrictJson(canonicalJson(contextValue),{maxBytes:8192,maxDepth:8})
      return copy(await dispatch(method,detached,boundContext))
    } catch(error){return errorResult(error)}
  }
  async function handlePublic(method,input,contextValue={}) {
    let detached,boundContext
    try {
      detached=parseStrictJson(canonicalJson(input),{maxBytes:65_536,maxDepth:32})
      boundContext=parseStrictJson(canonicalJson(contextValue),{maxBytes:8192,maxDepth:8})
    } catch(error){return errorResult(error)}
    if(method==='capability.status')return handleTrusted(method,detached,boundContext)
    try {if(!await accepted())return {ok:false,error_code:'UNAVAILABLE',reason:'SEPARATED_HOST_QUALIFICATION_REQUIRED'};return await handleTrusted(method,detached,boundContext)}
    catch{return {ok:false,error_code:'UNAVAILABLE',reason:'HOST_QUALIFICATION_UNAVAILABLE'}}
  }
  return Object.freeze({handleTrusted,handlePublic,capability})
}
