// SPDX-License-Identifier: AGPL-3.0-or-later
// Keyless check of actual C's unavailable source. No store/enrollment/server.
import {test} from 'node:test'
import assert from 'node:assert/strict'
import {mkdtemp,realpath,rm,access} from 'node:fs/promises'
import {join} from 'node:path'
import {didKeyFromEd25519PublicKey} from '../../authority/upstream/plugins/aukora-aumlok/lib/did-key.mjs'
import {createTrustedInferenceObserver,createInferenceAuthorityConnection,startInferenceAuthorityWorker} from '../src/inference.mjs'

const owner={owner_id:'source-only-owner',subject:'aukora:1:'+'a'.repeat(64)}
const task={version:1,task_id:'source-task',owner_id:owner.owner_id,agent_id:'source-agent',conversation_id:'source-conversation',
  status:'running',created_at:'2026-10-02T00:00:00.000Z',route_id:'externalDeepSeek',allowed_data_classes:['conversation'],
  max_input_tokens:4096,max_output_tokens:256,max_requests:1,task_spend_ceiling:{currency:'USD',amount:'0.010000'}}
const registryEntries=[{task,provider_and_region:{provider:'deepseek',region:'source-region'},
  audience:'aukora-prime.inference',policy_version:'source-policy',data_scope:['conversation']}]

test('missing E adapters remain unavailable without policy reads or IPC',async()=>{
  const observer=createTrustedInferenceObserver({registryEntries,ownerMappings:[owner]})
  assert.equal(observer.status().state,'unavailable')
  await assert.rejects(observer.withObservation({},()=>{}),error=>error.error_code==='UNAVAILABLE'
    &&error.message==='INFERENCE_TRUSTED_STATE_ADAPTER_UNMOUNTED')
  const connection=createInferenceAuthorityConnection({observer,authorityChannel:{socketPath:'/tmp/unused-source.sock',
    credential:{id:'source-fixture',secret:'0'.repeat(64)}}})
  assert.equal(connection.status().qualification,'unqualified')
  await assert.rejects(connection.withDispatch({}),error=>error.message==='INFERENCE_DURABLE_DISPATCH_ADAPTER_UNMOUNTED')
  await assert.rejects(connection.settleInference({operation:{},consumed_grant:{},request_id:'source',request_digest:'source',
    receipt:{},receipt_digest:'source'}),error=>error.message==='INFERENCE_COMMITTED_SETTLEMENT_ADAPTER_UNMOUNTED')
  connection.dispose()
})

test('absent C lifecycle or explicit inference profile refuses before socket/store/witness creation',async()=>{
  const root=await realpath(await mkdtemp('/tmp/prime-inference-unmounted-'))
  const socket=join(root,'c.sock'),state=join(root,'authority.json'),witness=join(root,'witness')
  try {
    // Public test bytes only. There is no matching private owner key or state.
    await assert.rejects(startInferenceAuthorityWorker({kind:'inference-authority',registryEntries,
      ipc:{socketPath:socket,credentials:[{id:'source-fixture',role:'inference_effect',secret:'0'.repeat(64)}]},
      authorityConfig:{audience:'aukora-prime.inference',statePath:state,stateRoot:root,witnessDir:witness,
        identities:[{...owner,approval_key_did:didKeyFromEd25519PublicKey('1'.repeat(64)),control_digest:'2'.repeat(64),authorization_epoch:0}],
        policy:{version:'source-policy',actions:['inference.generate'],agents:['source-agent'],data_scope:['conversation'],
          maximum_cost:{currency:'USD',amount:'0.010000'}}}}),error=>error.error_code==='UNAVAILABLE'
      &&['INFERENCE_C_LIFECYCLE_UNMOUNTED','INFERENCE_C_PROFILE_UNMOUNTED'].includes(error.message))
    for(const path of [socket,state,witness])await assert.rejects(access(path),error=>error.code==='ENOENT')
  } finally {await rm(root,{recursive:true,force:true})}
})
