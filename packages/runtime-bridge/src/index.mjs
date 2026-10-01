// SPDX-License-Identifier: AGPL-3.0-or-later
import {randomUUID,randomBytes} from 'node:crypto'
import {canonicalJson,parseStrictJson,validateContract,operationDigest} from '../../contracts/src/runtime.mjs'
import {parseOriginal} from '../../memory/src/codecs.mjs'
import {validateCaptureDraft,validateCaptureReview} from '../../memory/src/capture-review.mjs'
import {closed,copy,freeze,createTrustedTaskRegistry} from './registry.mjs'
import {IPC_METHOD_ROLES,PUBLIC_METHODS} from './ipc.mjs'
import {preparePilotCapture} from './pilot-capture.mjs'
import {isWorkflowStore} from './workflow-store.mjs'
import {createRecovery} from './recovery.mjs'
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
export function createRuntimeBridge({authority,memory,workflowStore,taskRegistry,resolveHostContext,verifyHostQualification}={}) {
  const authorityMethods=['authenticateSession','logoutSession','propose','loginChallenge','loginComplete','approvalChallenge','approvalComplete','declineApproval','status','reserve','claimDispatch','settleMemory','markOutcomeUnknown']
  const memoryMethods=['prepareCaptureBinding','captureAuthorizedRemembered','withAuthorityTargetObservation','status','cite','recall','prepareRecordMutationBinding','forgetRecord','reconcileEffect']
  const mounted=authorityMethods.every(k=>typeof authority?.[k]==='function')&&memoryMethods.every(k=>typeof memory?.[k]==='function')&&isWorkflowStore(workflowStore)&&typeof taskRegistry?.getOwned==='function'&&typeof taskRegistry?.authorizeTask==='function'&&typeof resolveHostContext==='function'
  // Only exact approved save/forget, factual receipt reconciliation and reads
  // are retained. Raw writers, purge, import and restore remain outside dispatch.
  memory=Object.freeze(Object.fromEntries(memoryMethods.filter(name=>typeof memory?.[name]==='function').map(name=>[name,memory[name].bind(memory)])))
  const inFlight=new Set(),recovery=createRecovery({authority,memory,workflowStore,inFlight})
  async function requireRecovered(host,session_token,exclude=null) {
    const blocked=await recovery.pending(host,session_token,{exclude})
    if(blocked)fail('RECONCILIATION_REQUIRED','DURABLE_MEMORY_OUTCOME_UNRESOLVED')
  }
  async function requireLiveProposal(host,operation) {
    const reference=await workflowStore.get(host,operation.operation_id)
    if(reference.operation_digest!==operationDigest(operation)||reference.phase!=='proposed')fail('REPLAYED','DURABLE_MEMORY_PROPOSAL_CLOSED')
  }
  async function completed(host,session_token,operation,effect) {
    if(effect.authority_settlement!=='completed')return
    const row=await workflowStore.get(host,operation.operation_id)
    const fact=recovery.verifiedEffect(host,row,effect)
    const status=await authority.status({session_token,operation_id:operation.operation_id})
    // Logout/expiry can end read access after D's factual settlement. Preserve
    // the genuine result; a fresh session will reconcile its pending reference.
    if(status?.ok!==true)return
    if(status.status!=='COMPLETED'||status.operation_digest!==row.operation_digest||status.reconciliation_required!==false)fail('OUTCOME_UNKNOWN','DURABLE_MEMORY_SETTLEMENT_REQUIRED')
    await workflowStore.mark(host,operation.operation_id,operation.action_type==='memory.save'?'saved':'forgotten',{
      record_id:fact.result.record_id,request_id:fact.receipt.request_id,request_digest:fact.receipt.request_digest,receipt_digest:fact.receiptDigest})
  }
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
    if(operation.owner_id!==identity.owner_id||operation.authorization_epoch!==identity.authorization_epoch||!['memory.save','memory.forget'].includes(operation.action_type)||taskRegistry.authorizeTask(operation)?.authenticated!==true||operation.task_id!==entry.task.task_id)fail('UNAUTHORIZED','EXACT_OWNED_OPERATION_REQUIRED')
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
    if(method==='owner.logout') {
      closed(input,['session_token']);requireMethod(authority,'logoutSession')
      const result=await authority.logoutSession({session_token:input.session_token})
      if(result?.ok===true){closed(result,['ok','status']);if(result.status!=='LOGGED_OUT')fail('OUTCOME_UNKNOWN','OWNER_LOGOUT_NOT_CONFIRMED')}
      return result
    }
    if(method==='owner.status'||method==='owner.declineApproval') {
      closed(input,['session_token','operation_id']);text(input.operation_id)
      const name=method==='owner.status'?'status':'declineApproval';requireMethod(authority,name);return authority[name](input)
    }
    const {entry,host}=await context(request,identity)
    if(method==='memory.recover') {
      closed(input,['session_token','operation_id']);if(input.operation_id!==null)text(input.operation_id)
      requireMethod(memory,'reconcileEffect')
      return recovery.recover(host,input.session_token,input.operation_id)
    }
    if(method==='memory.proposeSave') {
      closed(input,['session_token','extraction_json','idempotency_key']);text(input.idempotency_key)
      requireMethod(memory,'prepareCaptureBinding');requireMethod(authority,'propose')
      await requireRecovered(host,input.session_token)
      const {capture:captured,metadata}=preparePilotCapture(extraction(input.extraction_json),host.source?.at)
      // Expected review text comes from the detached actual extraction and the
      // trusted host attribution, independently of any proposed parameters.
      const memoryCapture=validateCaptureDraft({statement:captured.statement,attributed_to:host.attributedTo})
      const binding=await memory.prepareCaptureBinding(host,captured,input.idempotency_key)
      closed(binding,['target_identity','state_version','canonical_parameters','memory_capture'])
      if(canonicalJson(validateCaptureDraft(binding.memory_capture))!==canonicalJson(memoryCapture))fail('INVALID','EXACT_HOST_CAPTURE_DRAFT_REQUIRED')
      validateCaptureReview(binding.canonical_parameters,memoryCapture)
      const operation=copy({version:1,operation_id:randomUUID(),task_id:entry.task.task_id,owner_id:identity.owner_id,agent_id:entry.task.agent_id,
        audience:entry.audience,action_type:'memory.save',target_identity:binding.target_identity,canonical_parameters:binding.canonical_parameters,
        data_scope:entry.data_scope,expected_state_version:binding.state_version,provider_and_region:entry.provider_and_region,
        maximum_cost:{currency:'USD',amount:'0'},expiry:new Date(Math.min(Date.now()+120_000,Date.parse(identity.expiry))).toISOString(),nonce:randomBytes(32).toString('hex'),policy_version:entry.policy_version,authorization_epoch:identity.authorization_epoch})
      validateContract('OperationProposal',operation)
      await workflowStore.insert(host,{operation,idempotency_key_sha256:binding.canonical_parameters.idempotency_key_sha256,record_id:null})
      const proposed=await authority.propose({session_token:input.session_token,operation})
      return proposed?.ok===true?{...proposed,memory_capture:memoryCapture,capture_metadata:metadata}:proposed
    }
    if(method==='memory.proposeForget') {
      closed(input,['session_token','record_id']);text(input.record_id)
      requireMethod(memory,'prepareRecordMutationBinding')
      await requireRecovered(host,input.session_token)
      // The host chooses the second-resolution effect time. The guest names
      // only a record reference; D checks its owner/scope and exact byte digest.
      const at=new Date().toISOString().slice(0,19)+'Z'
      const binding=await memory.prepareRecordMutationBinding(host,input.record_id,{action:'memory.forget',at})
      closed(binding,['target_identity','state_version','canonical_parameters','record_summary'])
      closed(binding.canonical_parameters,['profile','record_id','revision','canonical_sha256','at','heads','statement','attributed_to'])
      closed(binding.record_summary,['record_id','revision','statement','attributed_to'])
      if(binding.canonical_parameters.profile!=='prime-logical-forget/v1'||binding.canonical_parameters.record_id!==input.record_id
        ||binding.canonical_parameters.at!==at||binding.record_summary.record_id!==input.record_id
        ||binding.record_summary.revision!==binding.canonical_parameters.revision||binding.record_summary.statement!==binding.canonical_parameters.statement
        ||binding.record_summary.attributed_to!==binding.canonical_parameters.attributed_to||!/^([a-f0-9]{64})$/.test(binding.canonical_parameters.canonical_sha256))fail('INVALID','EXACT_FORGET_BINDING_REQUIRED')
      const operation=copy({version:1,operation_id:randomUUID(),task_id:entry.task.task_id,owner_id:identity.owner_id,agent_id:entry.task.agent_id,
        audience:entry.audience,action_type:'memory.forget',target_identity:binding.target_identity,canonical_parameters:binding.canonical_parameters,
        data_scope:entry.data_scope,expected_state_version:binding.state_version,provider_and_region:entry.provider_and_region,
        maximum_cost:{currency:'USD',amount:'0'},expiry:new Date(Math.min(Date.now()+120_000,Date.parse(identity.expiry))).toISOString(),nonce:randomBytes(32).toString('hex'),policy_version:entry.policy_version,authorization_epoch:identity.authorization_epoch})
      validateContract('OperationProposal',operation)
      await workflowStore.insert(host,{operation,idempotency_key_sha256:null,record_id:input.record_id})
      const proposed=await authority.propose({session_token:input.session_token,operation})
      return proposed?.ok===true?{...proposed,record_summary:binding.record_summary}:proposed
    }
    if(method==='owner.approvalChallenge') {
      closed(input,['session_token','operation']);const operation=operationForContext(input.operation,identity,entry)
      await requireLiveProposal(host,operation)
      requireMethod(authority,'approvalChallenge')
      return targetScope(host,operation,()=>authority.approvalChallenge({session_token:input.session_token,operation}))
    }
    if(method==='owner.approvalComplete') {
      // Operation is supplied by the owner client, compared to persisted C review;
      // used here only to scope D's current exact target observation.
      closed(input,['session_token','operation','proof']);const operation=operationForContext(input.operation,identity,entry)
      validateContract('ApprovalProof',input.proof);requireMethod(authority,'approvalComplete')
      if(input.proof.operation_id!==operation.operation_id||input.proof.operation_digest!==operationDigest(operation)||input.proof.owner_id!==identity.owner_id||input.proof.audience!==operation.audience||input.proof.authorization_epoch!==operation.authorization_epoch)fail('INVALID','EXACT_APPROVAL_BINDING_REQUIRED')
      await requireLiveProposal(host,operation)
      return targetScope(host,operation,()=>authority.approvalComplete({session_token:input.session_token,proof:input.proof}))
    }
    if(method==='memory.save') {
      closed(input,['session_token','operation','approval_proof','extraction_json','idempotency_key'])
      const operation=operationForContext(input.operation,identity,entry);if(operation.action_type!=='memory.save')fail('INVALID','EXACT_SAVE_ACTION_REQUIRED')
      validateContract('ApprovalProof',input.approval_proof);text(input.idempotency_key)
      requireMethod(memory,'captureAuthorizedRemembered')
      const {capture:captured}=preparePilotCapture(extraction(input.extraction_json),host.source?.at)
      await requireRecovered(host,input.session_token,operation.operation_id)
      // Refuse known input/state mismatches before recording an attempted
      // effect. D repeats this exact check under its dispatch/effect lock.
      const binding=await memory.prepareCaptureBinding(host,captured,input.idempotency_key)
      if(canonicalJson(binding.canonical_parameters)!==canonicalJson(operation.canonical_parameters)
        ||binding.state_version!==operation.expected_state_version||canonicalJson(binding.target_identity)!==canonicalJson(operation.target_identity))fail('TARGET_MISMATCH','EXACT_SAVE_PREFLIGHT_REQUIRED')
      await workflowStore.attempt(host,operation.operation_id,operationDigest(operation))
      const ref=host.owner_subject+'\0'+operation.operation_id;inFlight.add(ref)
      try {
        const result=await memory.captureAuthorizedRemembered(host,captured,input.idempotency_key,{operation,approval_proof:input.approval_proof})
        validateContract('MemoryRecord',result.record)
        await completed(host,input.session_token,operation,{...result,result:result.record})
        return {ok:true,...result}
      } finally {inFlight.delete(ref)}
    }
    if(method==='memory.forget') {
      closed(input,['session_token','operation','approval_proof'])
      const operation=operationForContext(input.operation,identity,entry)
      if(operation.action_type!=='memory.forget')fail('INVALID','EXACT_FORGET_ACTION_REQUIRED')
      validateContract('ApprovalProof',input.approval_proof)
      closed(operation.canonical_parameters,['profile','record_id','revision','canonical_sha256','at','heads','statement','attributed_to'])
      if(operation.canonical_parameters.profile!=='prime-logical-forget/v1')fail('INVALID','EXACT_FORGET_PROFILE_REQUIRED')
      const id=operation.canonical_parameters.record_id;text(id)
      requireMethod(memory,'forgetRecord');requireMethod(memory,'reconcileEffect')
      await requireRecovered(host,input.session_token,operation.operation_id)
      const binding=await memory.prepareRecordMutationBinding(host,id,{action:'memory.forget',at:operation.canonical_parameters.at})
      if(canonicalJson(binding.canonical_parameters)!==canonicalJson(operation.canonical_parameters)
        ||binding.state_version!==operation.expected_state_version||canonicalJson(binding.target_identity)!==canonicalJson(operation.target_identity))fail('TARGET_MISMATCH','EXACT_FORGET_PREFLIGHT_REQUIRED')
      await workflowStore.attempt(host,operation.operation_id,operationDigest(operation))
      const ref=host.owner_subject+'\0'+operation.operation_id;inFlight.add(ref)
      try {
        const result=await memory.forgetRecord(host,id,{operation,approval_proof:input.approval_proof,include_receipt:true})
        if(!result.receipt||!result.result)fail('OUTCOME_UNKNOWN','FORGET_COMMITTED_RECEIPT_REQUIRED')
        await completed(host,input.session_token,operation,result)
        return {ok:true,...result}
      } finally {inFlight.delete(ref)}
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
