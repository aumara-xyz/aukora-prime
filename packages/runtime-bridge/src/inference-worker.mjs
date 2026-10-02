// SPDX-License-Identifier: AGPL-3.0-or-later
// Explicit separated C profile. No CLI, provisioning, reset or public mount.
import {validateContract} from '../../contracts/src/runtime.mjs'
import {createAuthorityService} from '../../authority/src/index.mjs'
import {createTrustedTaskRegistry} from './registry.mjs'
import {createInferenceAuthorityIpcServer,INFERENCE_AUTHORITY_METHODS} from './ipc.mjs'
import {canonicalJson,operationDigest,closed,configRecord,data,loadInferenceContracts,
  ownerMappings,requireOwnedOperation,refusal,unavailableStatus} from './inference-support.mjs'

const LIVE=new Set(['approvalChallenge','approvalComplete','reserve','claimDispatch'])
const FACTUAL=new Set(['settleInference','reconcileInferenceSettlement'])
const INPUTS=Object.freeze({propose:['session_token','operation'],loginChallenge:['owner_id','kind'],
  loginComplete:['challenge','material'],authenticateSession:['session_token'],logoutSession:['session_token'],
  approvalChallenge:['session_token','operation'],approvalComplete:['session_token','proof'],
  declineApproval:['session_token','operation_id'],status:['session_token','operation_id'],
  reserve:['operation','approval_proof'],claimDispatch:['operation','consumed_grant','request_id','request_digest'],
  settleInference:['operation','consumed_grant','request_id','request_digest','receipt','receipt_digest'],
  reconcileInferenceSettlement:['operation','consumed_grant','request_id','request_digest','receipt','receipt_digest']})
const NEEDS_OPERATION=new Set(['propose',...LIVE,...FACTUAL])

/** NEXT configures actual C state/pins/registry and a separately protected IPC
 * channel. C's real service must expose the full accepted lifecycle first.
 * Current parser-only C checkpoints refuse before a listener can be created.
 * The E peer owns its policy/intent fences; authenticated IPC is not UID proof. */
export async function startInferenceAuthorityWorker(config) {
  configRecord(config,['kind','ipc','registryEntries','authorityConfig'])
  if(config.kind!=='inference-authority')throw refusal('INVALID','INFERENCE_AUTHORITY_WORKER_KIND_REQUIRED')
  const trustedConfig=data(config.authorityConfig),ipc=data(config.ipc)
  if(trustedConfig.audience!=='aukora-prime.inference'||trustedConfig.retainedMemoryParticipant!==undefined)
    throw refusal('INVALID','INFERENCE_SEPARATE_AUTHORITY_PROFILE_REQUIRED')
  const registry=createTrustedTaskRegistry(config.registryEntries)
  if(!Array.isArray(trustedConfig.identities))throw refusal('UNAVAILABLE','INFERENCE_C_OWNER_MAPPING_UNMOUNTED')
  const owners=ownerMappings(trustedConfig.identities.map(({owner_id,subject})=>({owner_id,subject})))
  let scope=null,active=false
  const authority=createAuthorityService({...trustedConfig,authorizeTask:registry.authorizeTask,
    observeTarget(operation) {
      if(!scope||operationDigest(operation)!==scope.digest||canonicalJson(operation)!==scope.operation_json)
        throw refusal('UNAUTHORIZED','INFERENCE_WORKER_TARGET_SCOPE_REQUIRED')
      return data(scope.observation)
    }})
  const names=INFERENCE_AUTHORITY_METHODS.map(method=>method.slice('authority.'.length))
  if(names.some(name=>typeof authority[name]!=='function'))
    throw refusal('UNAVAILABLE','INFERENCE_C_LIFECYCLE_UNMOUNTED')
  if(trustedConfig.inferenceProfile===undefined)
    throw refusal('UNAVAILABLE','INFERENCE_C_PROFILE_UNMOUNTED')
  const parser=await loadInferenceContracts()
  const handler=async(method,input,{role}={})=>{
    if(role!=='inference_effect'||!INFERENCE_AUTHORITY_METHODS.includes(method))
      throw refusal('UNAUTHORIZED','INFERENCE_WORKER_PRIVATE_ROLE_REQUIRED')
    if(active)throw refusal('UNAVAILABLE','INFERENCE_WORKER_SCOPE_REENTRANT')
    // Claim the single scope before parsing, with no intervening await.
    active=true
    try {
      const wrapper=closed(data(input),['input','operation','operation_digest','observation'])
      const name=method.slice('authority.'.length),v=closed(wrapper.input,INPUTS[name])
      let operation=null
      if(NEEDS_OPERATION.has(name)) {
        operation=parser.parseInferenceOperation(wrapper.operation)
        requireOwnedOperation(operation,registry,owners,{factualOnly:FACTUAL.has(name)})
        if(wrapper.operation_digest!==operationDigest(operation))
          throw refusal('UNAUTHORIZED','INFERENCE_WORKER_OPERATION_DIGEST_REQUIRED')
        if(Object.hasOwn(v,'operation')&&canonicalJson(v.operation)!==canonicalJson(operation))
          throw refusal('UNAUTHORIZED','INFERENCE_WORKER_OPERATION_BINDING_REQUIRED')
      } else if(wrapper.operation!==null||wrapper.operation_digest!==null)
        throw refusal('INVALID','INFERENCE_WORKER_OPERATION_UNEXPECTED')
      if(name==='approvalComplete'||name==='reserve') {
        const proof=name==='approvalComplete'?v.proof:v.approval_proof
        validateContract('ApprovalProof',proof)
        if(proof.operation_id!==operation.operation_id||proof.operation_digest!==wrapper.operation_digest
          ||proof.owner_id!==operation.owner_id||proof.audience!==operation.audience
          ||proof.authorization_epoch!==operation.authorization_epoch)
          throw refusal('UNAUTHORIZED','INFERENCE_WORKER_PROOF_BINDING_REQUIRED')
      }
      if(name==='claimDispatch'||FACTUAL.has(name)) {
        const admission=parser.parseInferenceAdmission({...operation.canonical_parameters.binding,operation,
          consumed_grant:v.consumed_grant,request_digest:v.request_digest})
        if(v.request_id!==admission.request_uuid)throw refusal('INVALID','INFERENCE_WORKER_ORIGINAL_REQUEST_REQUIRED')
      }
      if(LIVE.has(name)) {
        const observed=closed(data(wrapper.observation),['target_identity','state_version'])
        if(canonicalJson(observed.target_identity)!==canonicalJson(operation.target_identity)
          ||observed.state_version!==operation.expected_state_version)
          throw refusal('TARGET_MISMATCH','INFERENCE_WORKER_TARGET_STATE_MISMATCH')
        scope={digest:wrapper.operation_digest,operation_json:canonicalJson(operation),observation:observed}
      } else if(wrapper.observation!==null)throw refusal('INVALID','INFERENCE_WORKER_OBSERVATION_UNEXPECTED')
      // Exact C input: approvalComplete remains session/proof only. The detached
      // operation lives solely in this request-local observeTarget scope.
      // A disconnect/timeout never clears the scope of a still-running C call.
      return await authority[name](v)
    } finally {scope=null;active=false}
  }
  const server=await createInferenceAuthorityIpcServer({...ipc,handlePublic:handler})
  return Object.freeze({close:()=>server.close(),status:()=>({...unavailableStatus(),kind:'inference-authority',socket:server.address})})
}
