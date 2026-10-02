// SPDX-License-Identifier: AGPL-3.0-or-later
// Pinned adapter/strict ingress only; no SDK connection or control operation.
import assert from 'node:assert/strict'
import { PinnedGuardianBackend } from '../src/guardian/pinned-backend.mjs'
import { decodeMessage } from '../src/guardian/ipc.mjs'

const cases={
  async paginated_observation_does_not_invent_create_provenance() {
    const calls=[],scope={workspace:'synthetic'},registration={name:'synthetic-owned'}
    const transport={inventory:async(s,token)=>{
      calls.push([s,token]);return token?{sandboxes:[{metadata:{name:registration.name,id:'synthetic-uid',workspace:scope.workspace,labels:{'aukora.openshell/owner':'synthetic-token'}}}],nextPageToken:''}
        :{sandboxes:[{metadata:{name:'unrelated'}}],nextPageToken:'page2'}
    }}
    const backend=new PinnedGuardianBackend(transport,scope),result=await backend.observe(registration,{signal:new AbortController().signal})
    assert.equal(calls.length,2);assert.equal(result.inventory_complete,true);assert.equal(result.sandboxes.length,1)
    assert.equal(result.sandboxes[0].origin_request_id,null)
  },
  async incomplete_or_cyclic_inventory_refuses() {
    for(const result of [{sandboxes:[],nextPageToken:1},{sandboxes:null,nextPageToken:''},{sandboxes:[],nextPageToken:'cycle'}]) {
      const backend=new PinnedGuardianBackend({inventory:async()=>result},{workspace:'synthetic'})
      await assert.rejects(backend.observe({name:'synthetic'},{signal:new AbortController().signal}),e=>e.code==='RECONCILIATION_REQUIRED')
    }
  },
  async pinned_reclamation_cannot_use_a_name_delete_workaround() {
    const calls=[]
    const transport=Object.fromEntries(['inventory','get','delete','create','execStream'].map(method=>[method,()=>{calls.push(method);throw new Error('unexpected control call')}]))
    await assert.rejects(new PinnedGuardianBackend(transport,{workspace:'synthetic'}).reclaim(),e=>e.code==='UNAVAILABLE')
    assert.deepEqual(calls,[])
  },
  strict_private_ingress_refuses_duplicate_keys_and_malformed_utf8() {
    for(const data of [Buffer.from('{"method":"inspect","method":"cancel"}'),Buffer.from([0x7b,0x22,0xc0,0xaf,0x22,0x3a,0x30,0x7d]),Buffer.from('\uFEFF{}')])assert.throws(()=>decodeMessage(data))
    assert.deepEqual(decodeMessage(Buffer.from('{"version":1,"method":"inspect"}')),{version:1,method:'inspect'})
  },
}
for(const [name,run] of Object.entries(cases)){await run();console.log('PASS '+name)}
console.log('PASS guardian boundary 4 cases; pinned mutations unavailable, no runtime qualification')
