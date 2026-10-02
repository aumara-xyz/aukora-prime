// SPDX-License-Identifier: AGPL-3.0-or-later
// Disposable source/protocol observations, never runtime qualification.
import assert from 'node:assert/strict'
import { rm } from 'node:fs/promises'
import { pilotPlan,proposedCreateTemplate,proposedPolicy,pilotBounds } from '../runtime/pilot-profile.mjs'
import { createDshOpenShellExecutor } from '../src/index.mjs'
import { fixture,request } from './harness.mjs'

const plan=pilotPlan(),template=proposedCreateTemplate('sha256:'+'a'.repeat(64))
assert.equal(plan.status,'PROPOSED_UNAVAILABLE');assert.equal(plan.runtime_qualified,false)
assert.equal(template.resources.limits.cpu,'500m');assert.equal(template.resources.limits.memory,'512Mi')
assert.equal(template.driverConfig.docker.mounts.reduce((sum,m)=>sum+m.size_bytes,0),pilotBounds.scratch_bytes)
assert(template.driverConfig.docker.mounts.every(m=>m.target.startsWith('/sandbox/')||m.target==='/tmp'))
assert.equal(proposedPolicy('workspace-write').filesystem.includeWorkdir,false)
assert(!proposedPolicy('workspace-write').filesystem.readWrite.includes('/sandbox'))
assert.deepEqual(proposedPolicy('read-only').filesystem.readWrite,['/dev/null'])
assert.throws(()=>proposedCreateTemplate('workload:latest'))
console.log('PASS closed proposed resource/mount/profile fields; no authority or backend')

let resolved=0,executed=0,effects=0
class ShellExecutor {constructor(ctx){this.ctx=ctx}}
const unavailable={capability:'unavailable',execute:async()=>{executed++;throw new Error('unexpected execution')},dispose:async()=>{}}
const Executor=createDshOpenShellExecutor({ShellExecutor,executor:unavailable,resolveSpec:spec=>spec,
  resolveOperation:async()=>{resolved++;throw new Error('unexpected authority resolver')}})
const shell=new Executor({effect(){effects++},sandboxPolicy:{defaultMode:'read-only',resolve:()=>({mode:'read-only',workspaceRoot:'/sandbox/work'})}})
const spec=shell.resolve({command:plan.allowed_probe.command,workdir:'/sandbox/work',timeoutMs:30000,stdoutMaxBytes:65536})
await assert.rejects(shell.run(spec),error=>error.code==='UNAVAILABLE')
assert.equal(resolved,0);assert.equal(executed,0)
console.log('PASS unavailable direct ShellExecutor foreground call before resolver/executor')
assert.equal(effects,1)
console.log('PASS mounted factory registers one owned Cordis effect disposer')

// This models the pinned gateway's indistinguishable synthetic124+RPCsuccess.
// Full RPC completion cannot disambiguate gateway timeout from command124.
const f=await fixture({exit:124})
try {
  const receipt=await f.executor.execute(request())
  assert.equal(receipt.exit_code,null);assert.equal(receipt.rpc_completion,'complete')
  assert.equal(receipt.status,'outcome_unknown');assert.equal(receipt.reconciliation_required,true)
  console.log('PASS ambiguous gateway exit124 remains OUTCOME_UNKNOWN after drained RPC and confirmed cleanup')
} finally {f.ledger.close();await rm(f.root,{recursive:true,force:true})}
console.log('SOURCE_READINESS BLOCKED; no runtime qualification or host changes')
