// SPDX-License-Identifier: AGPL-3.0-or-later
// Private monitor records convey no approval, dispatch or runtime acceptance.
import { createHash } from 'node:crypto'
import { canonicalJson,operationDigest,validateContract } from '../../../contracts/src/runtime.mjs'
import { executorRequestDigest } from '../binding.mjs'
import { createTemplate,createProfileDigest,guestWorkdir,assertCreateBounds } from '../create-profile.mjs'
import { inspectLocalLifetime } from '../lifetime-safety.mjs'
import { policyDigest } from '../owned-executor.mjs'
import { validateSpec,refused } from '../policy.mjs'

export const copy=value=>JSON.parse(canonicalJson(value))
export const digest=value=>'sha256:'+createHash('sha256').update('aukora-prime.guardian-registration.v1\0'+canonicalJson(value)).digest('hex')
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu
const HASH=/^sha256:[a-f0-9]{64}$/u
export function closed(value,keys) {
  if(!value||typeof value!=='object'||Array.isArray(value)||Object.keys(value).sort().join(',')!==[...keys].sort().join(','))throw refused('closed guardian record required','INVALID')
}
export function validateScope(value) {
  closed(value,['version','ledger_id','gateway_identity','deployment_digest','host_profile_digest','workspace','image_digest','logical_workspace_root'])
  const endpoint=new URL(value.gateway_identity)
  if(value.version!==1||!UUID.test(value.ledger_id)||!HASH.test(value.deployment_digest)||!HASH.test(value.host_profile_digest)
    ||endpoint.protocol!=='https:'||endpoint.href!==value.gateway_identity||endpoint.username||endpoint.password||endpoint.pathname!=='/'||endpoint.search||endpoint.hash
    ||!/^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$/u.test(value.workspace))throw refused('guardian deployment binding required','INVALID')
  createTemplate(value.image_digest);guestWorkdir(value.logical_workspace_root,value.logical_workspace_root)
  return copy(value)
}
export function validateRegistration(input,scope) {
  const r=copy(input)
  closed(r,['version','request','request_digest','ledger_id','gateway_identity','deployment_digest','host_profile_digest','name','token','create_request_id','delete_request_id','create_template','create_profile_digest','guest_workdir','lifetime','lifetime_digest'])
  if(r.version!==1)throw refused('guardian registration version differs','INVALID')
  for(const key of ['ledger_id','gateway_identity','deployment_digest','host_profile_digest'])if(r[key]!==scope[key])throw refused('guardian deployment differs','TARGET_MISMATCH')
  for(const key of ['token','create_request_id','delete_request_id'])if(!UUID.test(r[key]))throw refused('guardian launch identity required','INVALID')
  if(r.name!==`prime-bash-${r.token}`)throw refused('exact guardian owned name required','INVALID')
  closed(r.request,['operation','consumed_grant','request_id','image_digest','policy_digest','wall_time_ms','max_output_bytes'])
  const request=r.request,op=request.operation,grant=request.consumed_grant
  validateContract('OperationProposal',op);validateContract('ConsumedGrant',grant);assertCreateBounds(request)
  if(!UUID.test(request.request_id)||executorRequestDigest(request)!==r.request_digest||grant.operation_digest!==operationDigest(op))throw refused('guardian original request binding differs','UNAUTHORIZED')
  for(const key of ['operation_id','owner_id','audience','authorization_epoch'])if(op[key]!==grant[key])throw refused('guardian original grant differs','UNAUTHORIZED')
  closed(op.target_identity,['backend','workspace','image_digest','policy_digest','logical_workspace_root'])
  const target=op.target_identity
  if(op.action_type!=='shell.bash.foreground'||target.backend!=='openshell-linux'||target.workspace!==scope.workspace
    ||target.logical_workspace_root!==scope.logical_workspace_root||target.image_digest!==scope.image_digest||request.image_digest!==scope.image_digest
    ||target.policy_digest!==request.policy_digest)throw refused('guardian target differs','TARGET_MISMATCH')
  closed(op.canonical_parameters,['command','workdir','sandbox_mode','stdin','env','dsh_env','timeout_ms','max_output_bytes'])
  const p=op.canonical_parameters
  validateSpec({command:p.command,workdir:p.workdir,stdin:p.stdin,env:p.env,dshEnv:p.dsh_env,timeoutMs:p.timeout_ms,stdoutMaxBytes:p.max_output_bytes,
    sandboxPolicy:{mode:p.sandbox_mode,workspaceRoot:scope.logical_workspace_root}},{workspaceRoot:scope.logical_workspace_root})
  if(request.wall_time_ms!==p.timeout_ms||request.max_output_bytes!==p.max_output_bytes||request.policy_digest!==policyDigest(p.sandbox_mode)
    ||r.create_profile_digest!==createProfileDigest(scope.image_digest)||canonicalJson(r.create_template)!==canonicalJson(createTemplate(scope.image_digest))
    ||r.guest_workdir!==guestWorkdir(p.workdir,scope.logical_workspace_root))throw refused('guardian approved profile differs','TARGET_MISMATCH')
  const lifetime=inspectLocalLifetime({request,request_id:request.request_id,request_digest:r.request_digest,lifetime:r.lifetime,lifetime_digest:r.lifetime_digest})
  if(lifetime.status==='invalid')throw refused('guardian original lifetime differs','INVALID')
  return r
}
