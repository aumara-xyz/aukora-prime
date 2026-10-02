// SPDX-License-Identifier: AGPL-3.0-or-later
// Private, unmounted host composition. No keys, owner-proof generation or SDK bypass.
import { createHash, randomUUID } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { canonicalJson, operationDigest } from '../../contracts/src/runtime.mjs'
import { assertData, deepFreeze, detachContract } from '../../authority/src/operation.mjs'
import { executorRequestDigest } from '../../authority/src/execution.mjs'
import { OpenShellOwnedExecutor, policyDigest } from '../../execution/src/index.mjs'

export const SERVICE_NAME = 'aukoraCordisProbe'
export const TOOL_NAME = 'prime_cordis_probe'
export const MEANING_ID = 'prime.cordis.read-only-printf.v1'
export const PROBE_COMMAND = "/usr/bin/printf 'prime-cordis-probe-v1\\n'"
const PARAMETERS = {command:PROBE_COMMAND,sandbox_mode:'read-only',stdin:'',env:{},dsh_env:{},timeout_ms:1000,max_output_bytes:1024}
const DIGEST = /^sha256:[a-f0-9]{64}$/
const BROKER_METHODS = ['reserve','claimDispatch','requestCancel','settle','reconcileSettlement']
const refusal = (code, message) => Object.assign(new Error(message), {code})
function closed(value, keys) {
  assertData(value)
  if (!value || Array.isArray(value) || typeof value !== 'object'
      || Object.keys(value).sort().join(',') !== [...keys].sort().join(',')) throw refusal('INVALID','Closed probe input required')
}
const snapshot = value => deepFreeze(JSON.parse(canonicalJson(value)))

/** Review/build input only. Reading source does NOT attest loaded bytes or a
 * qualified installation. H must bind its actual release in C.observeTarget. */
export function probeSourceDigest() {
  return 'sha256:' + createHash('sha256').update(readFileSync(new URL('./index.mjs',import.meta.url))).digest('hex')
}

/** Trusted host constructs one proposal; there is no approval or launch here.
 * Identity/task/policy fields come from C's protected host configuration. */
export function createProbeOperation(input) {
  closed(input,['operation_id','task_id','owner_id','agent_id','audience','workspace','image_digest',
    'logical_workspace_root','policy_version','authorization_epoch','expiry','nonce','provider_build_digest'])
  if (!DIGEST.test(input.provider_build_digest)) throw refusal('INVALID','Exact provider build digest required')
  const {workspace,image_digest,logical_workspace_root,provider_build_digest,...identity} = input
  return snapshot(detachContract('OperationProposal',{
    version:1,...identity,action_type:'shell.bash.foreground',
    target_identity:{backend:'openshell-linux',workspace,image_digest,
      policy_digest:policyDigest('read-only'),logical_workspace_root},
    canonical_parameters:{...PARAMETERS,workdir:logical_workspace_root},
    expected_state_version:`${MEANING_ID}@${provider_build_digest}`,
    data_scope:['public'],provider_and_region:{provider:'none',region:'local'},maximum_cost:{currency:'USD',amount:'0'}
  }))
}

function exactProbe(input) {
  const op = detachContract('OperationProposal',input)
  const expected = createProbeOperation({
    ...Object.fromEntries(['operation_id','task_id','owner_id','agent_id','audience','policy_version',
      'authorization_epoch','expiry','nonce'].map(key=>[key,op[key]])),
    workspace:op.target_identity.workspace,image_digest:op.target_identity.image_digest,
    logical_workspace_root:op.target_identity.logical_workspace_root,
    provider_build_digest:op.expected_state_version.slice(`${MEANING_ID}@`.length)
  })
  if (canonicalJson(op)!==canonicalJson(expected)) throw refusal('TARGET_MISMATCH','Only the exact fixed probe is supported')
  return expected
}

/** All options are private, trusted H inputs, never plugin/model configuration.
 * readApproval only retrieves an independently obtained C ApprovalProof. Its
 * return value cannot authorize anything: C.reserve must verify and consume it.
 * F must share this exact broker; only F calls claimDispatch and settlement.
 * The executor must be dedicated to this provider because unload requests its
 * disposal. F, not Cordis, owns deletion, expiry and remote absence evidence. */
export function createCordisToolProvider(options = {}) {
  const {authority,executor,readApproval} = options
  const operation = options.operation === undefined ? null : exactProbe(options.operation)
  const configured = !!operation && executor instanceof OpenShellOwnedExecutor
    && executor.broker === authority && BROKER_METHODS.every(key=>typeof authority?.[key]==='function')
    && typeof readApproval === 'function'
  const admissible = () => configured && executor.capability==='qualified'
    && ['workspace','image_digest','logical_workspace_root'].every(key=>executor.settings[key]===operation.target_identity[key])
    && executor.admission({policy_digest:operation.target_identity.policy_digest,
      wall_time_ms:operation.canonical_parameters.timeout_ms,max_output_bytes:operation.canonical_parameters.max_output_bytes})
  let mounted = false
  return {
    name:'prime-cordis-tool-provider',inject:['tools'],
    apply(ctx) {
      if (mounted) throw refusal('UNAVAILABLE','A provider factory can mount only once')
      if (typeof ctx?.provide!=='function' || typeof ctx?.effect!=='function'
          || typeof ctx.tools?.register!=='function') throw refusal('UNAVAILABLE','Pinned Cordis/tools lifecycle required')
      mounted = true
      let active = true, pending = false, reserveAttempted = false, cleanup
      const lifetime = new AbortController()
      const checkpoint = signal => {
        if (!active) throw refusal('REVOKED','Probe provider disposed')
        if (!admissible()) throw refusal('UNAVAILABLE','Qualified private authority/executor configuration required')
        if (signal?.aborted) throw refusal('CANCELLED','Probe invocation cancelled')
      }
      const dispose = () => {
        active = false // captured references refuse synchronously, before await
        lifetime.abort()
        return cleanup ??= Promise.resolve().then(()=>configured ? executor.dispose() : undefined)
      }
      // Other Cordis effects unload concurrently; this effect owns revocation
      // and one shared cleanup request, never a claim of remote guest absence.
      ctx.effect(()=>dispose,'private Cordis probe cleanup request')

      const service = Object.freeze({
        proposal:operation,
        availability:()=>({state:active&&admissible()?'awaiting_authority':'unavailable',
          disposed:!active,executor:configured?executor.availability():null}),
        async invoke(args = {}, callerSignal) {
          closed(args,[])
          if (callerSignal!==undefined && !(callerSignal instanceof AbortSignal)) throw refusal('INVALID','AbortSignal required')
          const signal = callerSignal ? AbortSignal.any([lifetime.signal,callerSignal]) : lifetime.signal
          checkpoint(signal)
          if (pending || reserveAttempted) throw refusal('REPLAYED','This provider owns one reservation attempt')
          pending = true
          try {
            const supplied = await readApproval(operation,{signal})
            checkpoint(signal)
            if (supplied==null) throw refusal('UNAUTHORIZED','Independent owner approval proof required')
            const proof = snapshot(detachContract('ApprovalProof',supplied))
            if (proof.operation_digest!==operationDigest(operation)) throw refusal('TARGET_MISMATCH','Approval belongs to another operation')
            // An uncertain reservation cannot be retried through this provider.
            // Any retained PREPARED state belongs to C, even if unload follows.
            reserveAttempted = true
            const reserved = await authority.reserve({operation,approval_proof:proof})
            checkpoint(signal)
            if (reserved?.ok!==true) throw refusal(reserved?.error_code??'RECONCILIATION_REQUIRED',reserved?.reason??'Authority reservation uncertain')
            if (reserved.status!=='PREPARED') throw refusal('RECONCILIATION_REQUIRED','Expected authority PREPARED checkpoint')
            const consumed_grant = snapshot(detachContract('ConsumedGrant',reserved.consumed_grant))
            if (consumed_grant.operation_digest!==operationDigest(operation)) throw refusal('TARGET_MISMATCH','Reserved operation differs')
            const request = snapshot({operation,consumed_grant,request_id:randomUUID(),
              image_digest:operation.target_identity.image_digest,policy_digest:operation.target_identity.policy_digest,
              wall_time_ms:operation.canonical_parameters.timeout_ms,max_output_bytes:operation.canonical_parameters.max_output_bytes})
            executorRequestDigest(request) // existing closed request validator
            checkpoint(signal)
            // No async gap here before F. F rechecks actual C dispatch admission
            // at its effect boundary and retains factual receipts/uncertainty.
            return await executor.execute({...request,signal})
          } finally { pending = false }
        }
      })
      ctx.provide(SERVICE_NAME,service)
      ctx.tools.register({
        name:TOOL_NAME,
        description:'Run the single owner-approved private read-only printf probe. Requires independent authority approval and qualified execution; otherwise unavailable.',
        parameters:{type:'object',properties:{},additionalProperties:false},
        output:{schema:{type:'object',properties:{receipt:{type:'object',additionalProperties:true}},required:['receipt'],additionalProperties:false},
          render:(_args,value)=>[{type:'text',text:canonicalJson(value)}]},
        async execute(args,exec) {
          const receipt=await service.invoke(args,exec.signal)
          if (['outcome_unknown','unavailable'].includes(receipt.status)||receipt.reconciliation_required) {
            throw Object.assign(refusal(receipt.error_code??'OUTCOME_UNKNOWN','Probe did not settle; exact receipt retained by executor/authority'),{executionReceipt:receipt})
          }
          return {receipt}
        }
      })
    }
  }
}
