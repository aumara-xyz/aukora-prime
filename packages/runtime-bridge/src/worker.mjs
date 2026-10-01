// SPDX-License-Identifier: AGPL-3.0-or-later
// Explicit host-configured workers. No credentials, UID, database or task discovery.
import {pathToFileURL,fileURLToPath} from 'node:url'
import {lstat,realpath} from 'node:fs/promises'
import {resolve} from 'node:path'
import * as contracts from '../../contracts/src/runtime.mjs'
import {createAuthorityService} from '../../authority/src/index.mjs'
import {createPostgresMemory} from '../../memory/src/index.mjs'
import {createRuntimeBridge,createTrustedTaskRegistry} from './index.mjs'
import {closed,copy} from './registry.mjs'
import {createIpcServer,createAuthorityIpcServer,createAuthorityIpcClient,PRIVATE_AUTHORITY_METHODS} from './ipc.mjs'

const METHODS=Object.freeze({propose:'authority.propose',loginChallenge:'authority.loginChallenge',loginComplete:'authority.loginComplete',authenticateSession:'authority.authenticateSession',approvalChallenge:'authority.approvalChallenge',approvalComplete:'authority.approvalComplete',declineApproval:'authority.declineApproval',status:'authority.status',reserve:'authority.reserve',claimDispatch:'authority.claimDispatch',settleMemory:'authority.settleMemory',markOutcomeUnknown:'authority.markOutcomeUnknown'})
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
  if(operation.audience!=='aukora-prime.memory'||operation.action_type!=='memory.save'||operation.target_identity.kind!=='prime-memory'||operation.target_identity.owner_subject!==identity?.subject||(!factualOnly&&registry.authorizeTask(operation)?.authenticated!==true))throw refuse('WORKER_EXACT_MEMORY_TASK_REQUIRED')
  return operation
}

export async function startAuthorityWorker(config) {
  configRecord(config,['kind','ipc','registryEntries','authorityConfig'])
  if(config.kind!=='authority')throw new TypeError('INVALID: authority worker kind')
  const registry=createTrustedTaskRegistry(config.registryEntries)
  const identities=new Map(config.authorityConfig.identities.map(identity=>[identity.owner_id,copy(identity)]))
  let scope=null
  const authority=createAuthorityService({...config.authorityConfig,authorizeTask:registry.authorizeTask,
    observeTarget(operation) {
      if(!scope||contracts.operationDigest(operation)!==scope.digest||contracts.canonicalJson(operation)!==scope.operation_json)throw refuse('WORKER_TARGET_SCOPE_REQUIRED')
      return copy(scope.observation)
    }})
  const handler=(method,input,{role}={})=>{
    if(role!=='memory_effect'||!PRIVATE_AUTHORITY_METHODS.includes(method))throw refuse('WORKER_PRIVATE_ROLE_REQUIRED')
    // IPC has already performed strict textual parsing, MAC and exact method ACL.
    const wrapper=copy(closed(input,['input','operation','operation_digest','observation']))
    const name=Object.keys(METHODS).find(key=>METHODS[key]===method)
    const operation=wrapper.operation
    if(operation!==null) {
      requireMemoryOperation(operation,registry,identities,{factualOnly:factual.has(name)})
      if(wrapper.operation_digest!==contracts.operationDigest(operation))throw refuse('WORKER_OPERATION_DIGEST_REQUIRED')
      if(name==='propose'&&contracts.canonicalJson(wrapper.input)!==contracts.canonicalJson(operation))throw refuse('WORKER_PROPOSAL_BINDING_REQUIRED')
      if(wrapper.input.operation&&contracts.canonicalJson(wrapper.input.operation)!==contracts.canonicalJson(operation))throw refuse('WORKER_OPERATION_BINDING_REQUIRED')
    } else if(wrapper.operation_digest!==null)throw refuse('WORKER_OPERATION_DIGEST_UNEXPECTED')
    if(live.has(name)) {
      if(!operation)throw refuse('WORKER_REVIEWED_OPERATION_REQUIRED')
      const observed=copy(closed(wrapper.observation,['target_identity','state_version']))
      if(contracts.canonicalJson(observed.target_identity)!==contracts.canonicalJson(operation.target_identity)||observed.state_version!==operation.expected_state_version)throw refuse('WORKER_TARGET_STATE_MISMATCH')
      if(name==='approvalComplete') {
        const proof=wrapper.input.proof;contracts.validateContract('ApprovalProof',proof)
        if(proof.operation_id!==operation.operation_id||proof.owner_id!==operation.owner_id||proof.operation_digest!==wrapper.operation_digest||proof.audience!==operation.audience||proof.authorization_epoch!==operation.authorization_epoch)throw refuse('WORKER_REVIEW_PROOF_BINDING_REQUIRED')
      }
      if(scope)throw refuse('WORKER_TARGET_SCOPE_REENTRANT')
      // No await/interleaving occurs between install, direct C call and clearing.
      scope={digest:wrapper.operation_digest,operation_json:contracts.canonicalJson(operation),observation:observed}
      try {return authority[name](wrapper.input)} finally {scope=null}
    }
    if(wrapper.observation!==null)throw refuse('WORKER_OBSERVATION_UNEXPECTED')
    if(['propose',...factual].includes(name)&&!operation)throw refuse('WORKER_OPERATION_REQUIRED')
    return authority[name](wrapper.input)
  }
  const server=await createAuthorityIpcServer({...config.ipc,handlePublic:handler})
  return Object.freeze({close:()=>server.close(),status:()=>({kind:'authority',qualification:'unqualified',socket:server.address})})
}

export async function startMemoryWorker(config) {
  configRecord(config,['kind','ipc','authorityChannel','registryEntries','resolveHostContext','createPgPool'],['initializeSchema','indexTarget','indexGeneration'])
  if(config.kind!=='memory'||typeof config.resolveHostContext!=='function'||typeof config.createPgPool!=='function'||(config.initializeSchema!==undefined&&typeof config.initializeSchema!=='boolean'))throw new TypeError('INVALID: memory worker config')
  const registry=createTrustedTaskRegistry(config.registryEntries)
  const reviews=new Map()
  let memory,pool,server
  const proxy=Object.freeze(Object.fromEntries(Object.entries(METHODS).map(([name,method])=>[name,async input=>{
    const detached=copy(input)
    let operation=name==='propose'?detached:detached.operation??null
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
    const channel=await createAuthorityIpcClient(config.authorityChannel)
    try {return await channel.request(method,{input:detached,operation,operation_digest:operation?contracts.operationDigest(operation):null,observation})}
    finally {await channel.close()}
  }])))
  try {
    pool=await config.createPgPool()
    memory=createPostgresMemory({pool,authority:proxy,contracts,indexTarget:config.indexTarget,indexGeneration:config.indexGeneration})
    if(config.initializeSchema===true)await memory.migrate()
    const localMemory=Object.freeze({...memory,async withAuthorityTargetObservation(host,operation,fn){
      const op=copy(operation),key=op.owner_id+'\0'+op.operation_id+'\0'+contracts.operationDigest(op)
      return memory.withAuthorityTargetObservation(host,op,async()=>{
        if(reviews.has(key))throw refuse('WORKER_REVIEW_SCOPE_REENTRANT')
        reviews.set(key,op)
        try {return await fn()} finally {reviews.delete(key)}
      })
    }})
    const bridge=createRuntimeBridge({authority:proxy,memory:localMemory,taskRegistry:registry,resolveHostContext:config.resolveHostContext})
    // Trusted internal service IPC, not a qualified HTTP/public app mount. Every
    // call still passes C sessions/proofs and the fixed channel role allowlist.
    server=await createIpcServer({...config.ipc,handlePublic:bridge.handleTrusted})
    return Object.freeze({async close(){await server.close();await pool.end?.()},status:()=>({kind:'memory',qualification:'unqualified',socket:server.address}),bridge})
  } catch(error){await server?.close();await pool?.end?.();throw error}
}

export async function startWorker(config) {
  if(config?.kind==='authority')return startAuthorityWorker(config)
  if(config?.kind==='memory')return startMemoryWorker(config)
  throw new TypeError('INVALID: worker kind')
}

async function main() {
  const args=process.argv.slice(2)
  if(args.length!==2||args[0]!=='--config'||resolve(args[1])!==args[1])throw new TypeError('INVALID: explicit absolute worker config required')
  const configPath=args[1],stat=await lstat(configPath)
  if(!stat.isFile()||stat.isSymbolicLink()||await realpath(configPath)!==configPath||(stat.mode&0o7777)!==0o600||process.getuid&&![0,process.getuid()].includes(stat.uid))throw refuse('WORKER_PRIVATE_CONFIG_REQUIRED')
  const imported=await import(pathToFileURL(configPath).href),worker=await startWorker(imported.default)
  process.stdout.write(JSON.stringify({status:'STARTED',...worker.status()})+'\n')
  let closing=false
  const stop=async()=>{if(closing)return;closing=true;await worker.close();process.exit(0)}
  process.once('SIGTERM',stop);process.once('SIGINT',stop)
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url))main().catch(error=>{process.stderr.write('WORKER_START_REFUSED:'+String(error.error_code??error.code??'UNAVAILABLE')+'\n');process.exitCode=1})
