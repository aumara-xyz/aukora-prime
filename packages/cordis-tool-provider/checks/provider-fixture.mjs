// SPDX-License-Identifier: AGPL-3.0-or-later
// TEST ONLY: actual C proof/kernel/store and F lifecycle; ephemeral synthetic
// signer, simulated target, mocked SDK and explicitly mocked F qualification.
import assert from 'node:assert/strict'
import { generateKeyPairSync, randomUUID, sign } from 'node:crypto'
import { mkdirSync, mkdtempSync, realpathSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createAuthorityService, provisionNewAuthorityStore, loginSigningBytes, approvalSigningBytes } from '../../authority/src/index.mjs'
import { didKeyFromEd25519PublicKey } from '../../authority/upstream/plugins/aukora-aumlok/lib/did-key.mjs'
import { OwnedLedger, SdkTransport } from '../../execution/src/index.mjs'
import { settings, mock, MockedProtocolExecutor } from '../../execution/checks/harness.mjs'
import { createProbeOperation, createCordisToolProvider, probeSourceDigest, SERVICE_NAME } from '../src/index.mjs'

export const accepted = value => { assert.equal(value.ok,true,JSON.stringify(value)); return value }
export function gate() {
  let release,enter
  const entered=new Promise(resolve=>{enter=resolve}),blocked=new Promise(resolve=>{release=resolve})
  return {entered,release,wait:async()=>{enter();await blocked}}
}
export function mounted(plugin) {
  const effects=[],services={},tools=[]
  plugin.apply({effect:body=>effects.push(body()),provide:(key,value)=>{services[key]=value},tools:{register:tool=>tools.push(tool)}})
  return {service:services[SERVICE_NAME],tool:tools[0],dispose:()=>Promise.all(effects.map(fn=>fn()))}
}
export function providerFixture(hooks={}) {
  const root=mkdtempSync(join(realpathSync(tmpdir()),'prime-cordis-provider-'))
  mkdirSync(join(root,'state'),{mode:0o700});mkdirSync(join(root,'executor'),{mode:0o700})
  const operation=createProbeOperation({operation_id:randomUUID(),task_id:'synthetic-task',owner_id:'synthetic-owner',
    agent_id:'synthetic-agent',audience:'synthetic-executor',workspace:settings.workspace,image_digest:settings.image_digest,
    logical_workspace_root:settings.logical_workspace_root,policy_version:'synthetic-policy',authorization_epoch:1,
    expiry:new Date(Date.now()+60_000).toISOString(),nonce:randomUUID(),provider_build_digest:probeSourceDigest()})
  const keys=generateKeyPairSync('ed25519'),publicHex=Buffer.from(keys.publicKey.export({format:'jwk'}).x,'base64url').toString('hex')
  const identity={owner_id:operation.owner_id,subject:'aukora:1:'+'1'.repeat(64),approval_key_did:didKeyFromEd25519PublicKey(publicHex),control_digest:'2'.repeat(64),authorization_epoch:1}
  const task={version:1,task_id:operation.task_id,owner_id:identity.owner_id,agent_id:operation.agent_id,
    conversation_id:'synthetic-conversation',status:'running',created_at:new Date().toISOString(),route_id:null,
    allowed_data_classes:['public'],max_input_tokens:0,max_output_tokens:0,max_requests:0,task_spend_ceiling:{currency:'USD',amount:'0'}}
  let target=structuredClone(operation.target_identity),stateVersion=operation.expected_state_version,qualified=true,taskActive=true,proof=null
  const config={stateRoot:join(root,'state'),statePath:join(root,'state','authority.json'),witnessDir:join(root,'witness'),
    audience:operation.audience,identities:[identity],loginKinds:['owner_key'],provisionTrustedState:true,
    policy:{version:operation.policy_version,actions:['shell.bash.foreground'],agents:[task.agent_id],data_scope:['public'],maximum_cost:{currency:'USD',amount:'0'}},
    authorizeTask:()=>({authenticated:taskActive,task}),observeTarget:()=>({target_identity:target,state_version:stateVersion})}
  accepted(provisionNewAuthorityStore(config))
  const real=createAuthorityService(config),calls=[]
  // Same broker object goes to provider and F. Only these test wrappers pause or
  // trace; every decision is the actual C service, never the harness mock broker.
  const authority={...real,...Object.fromEntries(['reserve','claimDispatch','requestCancel','settle','reconcileSettlement'].map(method=>[method,async input=>{
    await hooks['before'+method]?.(input)
    const result=real[method](input);calls.push({method,input:structuredClone(input),result:structuredClone(result)})
    await hooks['after'+method]?.(result)
    return result
  }]))}
  const challenge=accepted(real.loginChallenge({owner_id:identity.owner_id,kind:'owner_key'})).challenge
  const token=accepted(real.loginComplete({challenge,material:{kind:'owner_key',signature:sign(null,loginSigningBytes(challenge),keys.privateKey).toString('hex')}})).session_token
  const protocol=mock(hooks.protocol),transport=new SdkTransport(protocol.raw,{gatewayIdentity:'https://synthetic.invalid:19443/'})
  const ledger=new OwnedLedger(join(root,'executor'),{initialize:true})
  const executor=new MockedProtocolExecutor({settings,transport,ledger,broker:authority,protocolAdmission:()=>qualified})
  const readApproval=async()=>{await hooks.readApproval?.();return proof}
  const makePlugin=()=>createCordisToolProvider({operation,authority,executor,readApproval})
  return {root,operation,real,authority,calls,protocol,transport,ledger,executor,readApproval,makePlugin,
    propose:()=>accepted(real.propose({session_token:token,operation})),
    approve:()=>{
      const review=accepted(real.approvalChallenge({session_token:token,operation}))
      proof={...review.proof_template,material:{kind:'owner_key',request:review.approval_request,
        signature:sign(null,approvalSigningBytes(review.approval_request),keys.privateKey).toString('hex')}}
      accepted(real.approvalComplete({session_token:token,proof}));return proof
    },
    alterProof:fn=>{proof=fn(structuredClone(proof))},
    status:()=>accepted(real.status({session_token:token,operation_id:operation.operation_id})),
    logout:()=>accepted(real.logoutSession({session_token:token})),
    qualify:value=>{qualified=value},taskActive:value=>{taskActive=value},
    changeTarget:fn=>{target=fn(structuredClone(target))},changeState:value=>{stateVersion=value},
    cleanup:async({allowPending=false}={})=>{
      try { await executor.dispose() }
      catch(error) { if(!allowPending||error.code!=='RECONCILIATION_REQUIRED')throw error }
      finally { ledger.close();rmSync(root,{recursive:true,force:true}) }
    }
  }
}
