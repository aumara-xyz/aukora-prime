// SPDX-License-Identifier: AGPL-3.0-or-later
// Explicit host-configured workers. No credentials, UID, database or task discovery.
import {pathToFileURL,fileURLToPath} from 'node:url'
import {lstat,realpath} from 'node:fs/promises'
import {resolve,dirname} from 'node:path'
import * as contracts from '../../contracts/src/runtime.mjs'
import {createAuthorityService} from '../../authority/src/index.mjs'
import {createPostgresMemory} from '../../memory/src/index.mjs'
import {createRuntimeBridge,createTrustedTaskRegistry} from './index.mjs'
import {closed,copy} from './registry.mjs'
import {validateAuthorityUnconsumedClosure} from './unsent-closure.mjs'
import {createPostgresWorkflowStore} from './workflow-store.mjs'
import {createIpcServer,createAuthorityClosureIpcServer as createAuthorityIpcServer,
  createAuthorityClosureIpcClient as createAuthorityIpcClient,PRIVATE_AUTHORITY_CLOSURE_METHODS as PRIVATE_AUTHORITY_METHODS,
  PRIVATE_AUTHORITY_CLOSURE_VERSION,PRIVATE_AUTHORITY_CLOSURE_PROFILE} from './ipc.mjs'

const METHODS=Object.freeze({propose:'authority.propose',loginChallenge:'authority.loginChallenge',loginComplete:'authority.loginComplete',authenticateSession:'authority.authenticateSession',logoutSession:'authority.logoutSession',approvalChallenge:'authority.approvalChallenge',approvalComplete:'authority.approvalComplete',declineApproval:'authority.declineApproval',status:'authority.status',reserve:'authority.reserve',claimDispatch:'authority.claimDispatch',settleMemory:'authority.settleMemory',markOutcomeUnknown:'authority.markOutcomeUnknown',closeUnconsumedOperation:'authority.closeUnconsumedOperation',readUnconsumedClosure:'authority.readUnconsumedClosure'})
const closures=new Set(['closeUnconsumedOperation','readUnconsumedClosure'])
const live=new Set(['approvalChallenge','approvalComplete','reserve','claimDispatch'])
const factual=new Set(['settleMemory','markOutcomeUnknown'])
const refuse=(reason)=>Object.assign(new Error(reason),{error_code:'UNAUTHORIZED'})
function configRecord(value,required,optional=[]) {
  if(!value||Object.getPrototypeOf(value)!==Object.prototype||Reflect.ownKeys(value).some(key=>typeof key!=='string'||![...required,...optional].includes(key)||!Object.hasOwn(Object.getOwnPropertyDescriptor(value,key),'value'))||required.some(key=>!Object.hasOwn(value,key)))throw new TypeError('INVALID: closed trusted worker config')
}
function requireMemoryOperation(operation,registry,identities,{factualOnly=false}={}) {
  contracts.validateContract('OperationProposal',operation)
  closed(operation.target_identity,['kind','owner_subject'])
  const identity=identities.get(operation.owner_id)
  if(operation.audience!=='aukora-prime.memory'||!['memory.save','memory.forget'].includes(operation.action_type)||operation.target_identity.kind!=='prime-memory'||operation.target_identity.owner_subject!==identity?.subject||(!factualOnly&&registry.authorizeTask(operation)?.authenticated!==true))throw refuse('WORKER_EXACT_MEMORY_TASK_REQUIRED')
  return operation
}
function requireClosureRequest(input) {
  closed(input,['session_token','reference'])
  const reference=closed(input.reference,['owner_id','owner_subject','task_id','operation_id','operation_digest','action_type'])
  if(typeof input.session_token!=='string'||!/^[a-f0-9]{64}$/.test(input.session_token)
    ||['owner_id','owner_subject','task_id','operation_id'].some(key=>typeof reference[key]!=='string'||!reference[key].length
      ||Buffer.byteLength(reference[key],'utf8')>1024||/[\x00-\x1f\x7f]/u.test(reference[key]))
    ||typeof reference.owner_subject!=='string'||!/^aukora:1:[a-f0-9]{64}$/.test(reference.owner_subject)
    ||typeof reference.operation_digest!=='string'||!/^sha256:[a-f0-9]{64}$/.test(reference.operation_digest)
    ||!['memory.save','memory.forget'].includes(reference.action_type))throw refuse('WORKER_EXACT_CLOSURE_REFERENCE_REQUIRED')
  return reference
}
function requireClosureOwner(reference,registry,identities) {
  const identity=identities.get(reference.owner_id),entry=registry.getOwned(reference.task_id,reference.owner_id)
  if(!identity||identity.subject!==reference.owner_subject||!entry||entry.audience!=='aukora-prime.memory')
    throw refuse('WORKER_EXACT_MEMORY_TASK_REQUIRED')
}
function requireClosureReply(reply,reference,registry,identities) {
  if(reply?.ok!==true)return reply
  const validated=validateAuthorityUnconsumedClosure(reference,reply)
  requireMemoryOperation(validated.operation,registry,identities)
  return validated
}

export async function startAuthorityWorker(config) {
  configRecord(config,['kind','ipc','registryEntries','authorityConfig'])
  if(config.kind!=='authority')throw new TypeError('INVALID: authority worker kind')
  const registry=createTrustedTaskRegistry(config.registryEntries)
  const identities=new Map(config.authorityConfig.identities.map(identity=>[identity.owner_id,copy(identity)]))
  let scope=null,authorityCallActive=false
  const authority=createAuthorityService({...config.authorityConfig,authorizeTask:registry.authorizeTask,
    observeTarget(operation) {
      if(!scope||contracts.operationDigest(operation)!==scope.digest||contracts.canonicalJson(operation)!==scope.operation_json)throw refuse('WORKER_TARGET_SCOPE_REQUIRED')
      return copy(scope.observation)
    }})
  const handler=async(method,input,{role}={})=>{
    if(role!=='memory_effect'||!PRIVATE_AUTHORITY_METHODS.includes(method))throw refuse('WORKER_PRIVATE_ROLE_REQUIRED')
    // One direct C call owns the observation for its whole promise lifetime.
    // Refuse overlapping calls; neither timeout nor disconnection clears it.
    if(authorityCallActive)throw refuse('WORKER_TARGET_SCOPE_REENTRANT')
    // IPC has already performed strict textual parsing, MAC and exact method ACL.
    const name=Object.keys(METHODS).find(key=>METHODS[key]===method)
    if(closures.has(name)) {
      const wrapper=copy(closed(input,['version','profile','input','operation','operation_digest','observation']))
      if(wrapper.version!==PRIVATE_AUTHORITY_CLOSURE_VERSION||wrapper.profile!==PRIVATE_AUTHORITY_CLOSURE_PROFILE
        ||wrapper.operation!==null||wrapper.operation_digest!==null||wrapper.observation!==null)
        throw refuse('WORKER_PRIVATE_CLOSURE_PROFILE_REQUIRED')
      const reference=requireClosureRequest(wrapper.input)
      requireClosureOwner(reference,registry,identities)
      if(typeof authority[name]!=='function')return {ok:false,error_code:'UNAVAILABLE',reason:'WORKER_AUTHORITY_SERVICE_UNMOUNTED:'+name}
      // C authenticates this session while loading its original retained record.
      // A separate ordinary session read could prune that record before closure.
      // No live target observation, caller operation, or review cache is involved.
      authorityCallActive=true
      try {return requireClosureReply(copy(await authority[name](wrapper.input)),reference,registry,identities)}
      finally {authorityCallActive=false}
    }
    const wrapper=copy(closed(input,['input','operation','operation_digest','observation']))
    const operation=wrapper.operation
    if(name==='logoutSession') {
      closed(wrapper.input,['session_token'])
      if(operation!==null||wrapper.operation_digest!==null||wrapper.observation!==null)throw refuse('WORKER_LOGOUT_SCOPE_UNEXPECTED')
    }
    if(operation!==null) {
      requireMemoryOperation(operation,registry,identities,{factualOnly:factual.has(name)})
      if(wrapper.operation_digest!==contracts.operationDigest(operation))throw refuse('WORKER_OPERATION_DIGEST_REQUIRED')
      if(name==='propose')closed(wrapper.input,['session_token','operation'])
      if(wrapper.input.operation&&contracts.canonicalJson(wrapper.input.operation)!==contracts.canonicalJson(operation))throw refuse('WORKER_OPERATION_BINDING_REQUIRED')
    } else if(wrapper.operation_digest!==null)throw refuse('WORKER_OPERATION_DIGEST_UNEXPECTED')
    if(typeof authority[name]!=='function')return {ok:false,error_code:'UNAVAILABLE',reason:'WORKER_AUTHORITY_SERVICE_UNMOUNTED:'+name}
    if(live.has(name)) {
      if(!operation)throw refuse('WORKER_REVIEWED_OPERATION_REQUIRED')
      const observed=copy(closed(wrapper.observation,['target_identity','state_version']))
      if(contracts.canonicalJson(observed.target_identity)!==contracts.canonicalJson(operation.target_identity)||observed.state_version!==operation.expected_state_version)throw refuse('WORKER_TARGET_STATE_MISMATCH')
      if(name==='approvalComplete') {
        const proof=wrapper.input.proof;contracts.validateContract('ApprovalProof',proof)
        if(proof.operation_id!==operation.operation_id||proof.owner_id!==operation.owner_id||proof.operation_digest!==wrapper.operation_digest||proof.audience!==operation.audience||proof.authorization_epoch!==operation.authorization_epoch)throw refuse('WORKER_REVIEW_PROOF_BINDING_REQUIRED')
      }
      if(scope)throw refuse('WORKER_TARGET_SCOPE_REENTRANT')
      // Keep the exact detached observation through awaited C rechecks.
      scope={digest:wrapper.operation_digest,operation_json:contracts.canonicalJson(operation),observation:observed}
      authorityCallActive=true
      try {return await authority[name](wrapper.input)} finally {scope=null;authorityCallActive=false}
    }
    if(wrapper.observation!==null)throw refuse('WORKER_OBSERVATION_UNEXPECTED')
    if(['propose',...factual].includes(name)&&!operation)throw refuse('WORKER_OPERATION_REQUIRED')
    authorityCallActive=true
    try {return await authority[name](wrapper.input)} finally {authorityCallActive=false}
  }
  const server=await createAuthorityIpcServer({...config.ipc,handlePublic:handler})
  return Object.freeze({close:()=>server.close(),status:()=>({kind:'authority',qualification:'unqualified',socket:server.address})})
}

export async function startMemoryWorker(config) {
  return startConfiguredMemoryWorker(config,false)
}

/** Explicit public composition. Every call uses the existing handlePublic gate;
 * an internal/synthetic worker cannot opt into this dispatch marker by input. */
export async function startPublicMemoryWorker(config) {
  return startConfiguredMemoryWorker(config,true)
}

async function startConfiguredMemoryWorker(config,publicDispatch) {
  configRecord(config,['kind','ipc','authorityChannel','registryEntries','resolveHostContext','createPgPool',...(publicDispatch?['verifyHostQualification']:[])],['initializeSchema','indexTarget','indexGeneration','indexProjection'])
  if(config.kind!==(publicDispatch?'public-memory':'memory')||typeof config.resolveHostContext!=='function'||typeof config.createPgPool!=='function'
    ||publicDispatch&&typeof config.verifyHostQualification!=='function'||(config.initializeSchema!==undefined&&typeof config.initializeSchema!=='boolean'))throw new TypeError('INVALID: memory worker config')
  let projectionLimit=null
  if(config.indexProjection!==undefined){
    closed(config.indexProjection,['profile','batch_limit'])
    if(config.indexProjection.profile!=='prime-memory-outbox-projector/v1'||!Number.isSafeInteger(config.indexProjection.batch_limit)
      ||config.indexProjection.batch_limit<1||config.indexProjection.batch_limit>100)throw new TypeError('INVALID: memory index projection config')
    projectionLimit=config.indexProjection.batch_limit
  }
  const registry=createTrustedTaskRegistry(config.registryEntries)
  const reviews=new Map()
  const projectionQueue=new Map()
  let projectionFlight=null,projectionScheduled=null,projectionStopping=false
  let memory,pool,server
  const proxy=Object.freeze(Object.fromEntries(Object.entries(METHODS).map(([name,method])=>[name,async input=>{
    const detached=copy(input)
    if(name==='logoutSession')closed(detached,['session_token'])
    if(closures.has(name))requireClosureRequest(detached)
    let operation=detached.operation??null
    if(name==='approvalComplete') {
      const proof=detached.proof
      operation=reviews.get(proof?.owner_id+'\0'+proof?.operation_id+'\0'+proof?.operation_digest)??null
      if(!operation)throw refuse('WORKER_RETAINED_REVIEW_REQUIRED')
    }
    const observation=live.has(name)?memory.authorityTargetObservation(operation):null
    // Dispatch binding comes only from D's committed intent and genuine D path;
    // no app/public method reaches this proxy or supplies this wrapper directly.
    // A fresh channel is opened only for this unsent call. A closed/idle/bounded
    // channel never poisons subsequent independent calls, including C restart.
    // There is one request and no replay after an uncertain response.
    const wrapper={input:detached,operation,operation_digest:operation?contracts.operationDigest(operation):null,observation,
      ...(closures.has(name)?{version:PRIVATE_AUTHORITY_CLOSURE_VERSION,profile:PRIVATE_AUTHORITY_CLOSURE_PROFILE}:{})}
    const channel=await createAuthorityIpcClient(config.authorityChannel)
    try {return await channel.request(method,wrapper)}
    finally {await channel.close()}
  }])))
  try {
    pool=await config.createPgPool()
    memory=createPostgresMemory({pool,authority:proxy,contracts,indexTarget:config.indexTarget,indexGeneration:config.indexGeneration})
    const workflowStore=createPostgresWorkflowStore({pool})
    if(config.initializeSchema===true){await memory.migrate();await workflowStore.migrate()}
    function rememberCommitted(host,effect){
      // Keep projection off the completed receipt's return path. Coalesce by
      // owner, bound this private queue, and retain pending outbox work if full.
      if(!projectionStopping&&projectionLimit!==null&&effect?.authority_settlement==='completed'&&effect.reconciliation_required===false
        &&effect.receipt?.action_type==='memory.save'&&effect.receipt.status==='applied'){
        if(projectionQueue.has(host.owner_subject)||projectionQueue.size<32)projectionQueue.set(host.owner_subject,
          Object.freeze({owner_id:host.owner_id,owner_subject:host.owner_subject,task_id:host.task_id}))
      }
      return effect
    }
    function scheduleProjection(){
      if(projectionStopping||projectionFlight||projectionScheduled||!projectionQueue.size)return
      // IPC's fulfilled-handler continuation writes its bounded response before
      // this check-phase callback starts D's separate owner-locked projection.
      projectionScheduled=setImmediate(()=>{
        projectionScheduled=null
        if(projectionStopping||!projectionQueue.size)return
        const [owner,host]=projectionQueue.entries().next().value;projectionQueue.delete(owner)
        projectionFlight=Promise.resolve().then(()=>memory.drainOutbox(host,projectionLimit))
          .catch(()=>{/* D's pending/failed index state remains independently readable. */})
          .finally(()=>{projectionFlight=null;scheduleProjection()})
      })
    }
    const localMemory=Object.freeze({prepareCaptureBinding:memory.prepareCaptureBinding,
      ...(typeof memory.closeUnsentOperation==='function'?{closeUnsentOperation:(host,reference)=>memory.closeUnsentOperation(host,reference)}:{}),
      async captureAuthorizedRemembered(host,...args){return rememberCommitted(host,await memory.captureAuthorizedRemembered(host,...args))},
      prepareRecordMutationBinding:memory.prepareRecordMutationBinding,forgetRecord:memory.forgetRecord,
      async reconcileEffect(host,...args){return rememberCommitted(host,await memory.reconcileEffect(host,...args))},
      status:memory.status,cite:memory.cite,recall:memory.recall,async withAuthorityTargetObservation(host,operation,fn){
      const op=copy(operation),key=op.owner_id+'\0'+op.operation_id+'\0'+contracts.operationDigest(op)
      return memory.withAuthorityTargetObservation(host,op,async()=>{
        if(reviews.has(key))throw refuse('WORKER_REVIEW_SCOPE_REENTRANT')
        reviews.set(key,op)
        try {return await fn()} finally {reviews.delete(key)}
      })
    }})
    const bridge=createRuntimeBridge({authority:proxy,memory:localMemory,workflowStore,taskRegistry:registry,resolveHostContext:config.resolveHostContext,
      ...(publicDispatch?{verifyHostQualification:config.verifyHostQualification}:{})})
    // Internal IPC uses the trusted service seam. Public composition rechecks
    // qualification on every call; capability preflight grants no authority.
    const handler=async(method,input,context)=>{
      const result=await (publicDispatch?bridge.handlePublic:bridge.handleTrusted)(method,input,context)
      scheduleProjection()
      return publicDispatch&&method==='capability.status'&&result?.ok===true?{...result,public_dispatch:'qualified-owner-memory/v1'}:result
    }
    server=await createIpcServer({...config.ipc,handlePublic:handler})
    return Object.freeze({async close(){projectionStopping=true;if(projectionScheduled)clearImmediate(projectionScheduled);projectionQueue.clear();await server.close();await projectionFlight;await pool.end?.()},status:()=>({kind:config.kind,qualification:publicDispatch?'per-request':'unqualified',socket:server.address,
      ...(publicDispatch?{public_dispatch:'qualified-owner-memory/v1'}:{})}),bridge})
  } catch(error){await server?.close();await pool?.end?.();throw error}
}

export async function startWorker(config) {
  if(config?.kind==='authority')return startAuthorityWorker(config)
  if(config?.kind==='memory')return startMemoryWorker(config)
  if(config?.kind==='public-memory')return startPublicMemoryWorker(config)
  throw new TypeError('INVALID: worker kind')
}

async function main() {
  const args=process.argv.slice(2)
  if(args.length!==2||args[0]!=='--config'||resolve(args[1])!==args[1])throw new TypeError('INVALID: explicit absolute worker config required')
  const configPath=args[1],stat=await lstat(configPath)
  const primaryGid=process.getgid?.(),workerUid=process.getuid?.()
  if(!Number.isSafeInteger(primaryGid)||!Number.isSafeInteger(workerUid)||workerUid===0||!stat.isFile()||stat.isSymbolicLink()||await realpath(configPath)!==configPath||(stat.mode&0o7777)!==0o440||stat.uid!==0||stat.gid!==primaryGid)throw refuse('WORKER_ROOT_PROTECTED_CONFIG_REQUIRED')
  let parent=dirname(configPath),direct=true
  for(;;) {
    const directory=await lstat(parent)
    if(!directory.isDirectory()||directory.isSymbolicLink()||await realpath(parent)!==parent||directory.uid!==0||(directory.mode&0o022)||direct&&((directory.mode&0o7777)!==0o750||directory.gid!==primaryGid))throw refuse('WORKER_ROOT_PROTECTED_CONFIG_PARENT_REQUIRED')
    if(parent===dirname(parent))break
    parent=dirname(parent);direct=false
  }
  const imported=await import(pathToFileURL(configPath).href),worker=await startWorker(imported.default)
  process.stdout.write(JSON.stringify({status:'STARTED',...worker.status()})+'\n')
  let closing=false
  const stop=async()=>{if(closing)return;closing=true;await worker.close();process.exit(0)}
  process.once('SIGTERM',stop);process.once('SIGINT',stop)
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url))main().catch(error=>{process.stderr.write('WORKER_START_REFUSED:'+String(error.error_code??error.code??'UNAVAILABLE')+'\n');process.exitCode=1})
