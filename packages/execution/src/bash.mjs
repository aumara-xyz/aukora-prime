// SPDX-License-Identifier: AGPL-3.0-or-later
// Foreground ownership seam carried from Genesis 1cde243. Host composition
// imports the pinned third-party base explicitly; no repository layout guesses.
import { validateSpec, refused } from './policy.mjs'
import { canonicalJson } from '../../contracts/src/runtime.mjs'

function freeze(value) {
  if(value&&typeof value==='object'){for(const child of Object.values(value))freeze(child);Object.freeze(value)}
  return value
}

function runOwned(executor,resolveOperation) {
  return async input=>{
    if(executor.capability!=='qualified')throw refused('OpenShell runtime/image unqualified','UNAVAILABLE')
    validateSpec(input)
    const {signal,...rest}=input
    const spec=freeze(JSON.parse(JSON.stringify(rest)))
    const request=await resolveOperation(spec)
    const expected={command:spec.command,workdir:spec.workdir,sandbox_mode:spec.sandboxPolicy.mode,
      stdin:spec.stdin??'',env:spec.env??{},dsh_env:spec.dshEnv??{},timeout_ms:spec.timeoutMs,max_output_bytes:spec.stdoutMaxBytes}
    if(canonicalJson(request?.operation?.canonical_parameters)!==canonicalJson(expected))throw refused('broker operation differs from resolved Bash spec','TARGET_MISMATCH')
    const receipt=await executor.execute({...request,signal})
    if(receipt.status==='outcome_unknown'||receipt.status==='unavailable'||receipt.reconciliation_required) {
      throw Object.assign(refused('owned execution did not settle; receipt retained',receipt.error_code??'OUTCOME_UNKNOWN'),{executionReceipt:receipt})
    }
    const cause=executor.cancellationCause?.(receipt.request_id)
    return {exitCode:receipt.exit_code,signal:null,timedOut:cause==='timeout',aborted:receipt.status==='cancelled'&&cause!=='timeout',timeoutMs:spec.timeoutMs,
      stdout:{text:receipt.stdout,truncated:receipt.output_truncated},stderr:{text:receipt.stderr,truncated:receipt.output_truncated},
      sandbox:{mode:spec.sandboxPolicy.mode,denied:false,enforcement:'partial'},executionReceipt:receipt}
  }
}

/** H supplies ShellExecutor from @deepseek-ai/dsh-shell, and resolveSpec from
 * its pinned defaults/caps implementation. Only this class registers ctx.shell.
 * resolveOperation is a trusted host callback, never caller/model config. */
export function createDshOpenShellExecutor({ShellExecutor,resolveSpec,executor,resolveOperation}) {
  if(typeof ShellExecutor!=='function'||typeof resolveSpec!=='function'||typeof resolveOperation!=='function'
    ||typeof executor?.execute!=='function')throw refused('trusted DSH/Bash ownership join missing','UNAVAILABLE')
  const run=runOwned(executor,resolveOperation)
  return class OpenShellBashExecutor extends ShellExecutor {
    static inject=['sandboxPolicy']
    get sandboxMode() {return this.ctx.sandboxPolicy.defaultMode}
    resolve(request) {
      const policy=Object.hasOwn(request,'sandboxPolicy')?request.sandboxPolicy:this.ctx.sandboxPolicy.resolve()
      const spec={...resolveSpec(request),sandboxPolicy:policy}
      validateSpec(spec)
      return spec
    }
    async run(spec) {return run(spec)}
    async start() {throw refused('background Bash ownership is unqualified','UNAVAILABLE')}
  }
}

export async function installOwnedBash(ctx,options) {
  const {executor}=options
  const service=Object.freeze({backend:'openshell-linux',executionModel:'owned-bash',
    confine:async()=>{throw refused('argv-only native launch lacks lifecycle ownership','UNAVAILABLE')},
    runShell:runOwned(executor,options.resolveOperation),availability:()=>executor.availability()})
  const Executor=createDshOpenShellExecutor(options)
  ctx.provide('aukoraConfinement',service)
  ctx.on('dispose',()=>executor.dispose())
  await ctx.plugin(Executor)
  return service
}
