// SPDX-License-Identifier: AGPL-3.0-or-later
// Actual authority and memory child workers. Test-only SQLite factory; same UID.
import {test} from 'node:test'
import assert from 'node:assert/strict'
import {mkdtempSync,realpathSync,mkdirSync,writeFileSync,rmSync,chmodSync} from 'node:fs'
import {tmpdir} from 'node:os'
import {join} from 'node:path'
import {pathToFileURL,fileURLToPath} from 'node:url'
import {spawn} from 'node:child_process'
import {randomBytes} from 'node:crypto'
import {once} from 'node:events'
import * as contracts from '../../contracts/src/runtime.mjs'
import {createPrimeTransport} from '../../ui/adapters/transport.mjs'
import {createUiAdapters} from '../src/ui-adapter.mjs'
import {createIpcClient} from '../src/ipc.mjs'
import {authorityFixture} from './authority-fixture.mjs'
import {sha256} from '../../memory/src/codecs.mjs'
const workerPath=fileURLToPath(new URL('../src/worker.mjs',import.meta.url))
const sqlFixture=pathToFileURL(fileURLToPath(new URL('./sql-fixture.mjs',import.meta.url))).href
async function child(config) {
  const processChild=spawn(process.execPath,[workerPath,'--config',config],{stdio:['ignore','pipe','pipe']})
  let output='',error=''
  processChild.stderr.on('data',b=>{error+=b})
  const result=await new Promise((done,reject)=>{
    const timer=setTimeout(()=>{processChild.kill('SIGTERM');reject(new Error('worker fixture startup deadline:'+error))},5000)
    processChild.once('exit',code=>{clearTimeout(timer);reject(new Error('worker fixture exited:'+code+':'+error))})
    processChild.stdout.on('data',b=>{output+=b;if(output.includes('\n')){clearTimeout(timer);done(JSON.parse(output.trim()))}})
  })
  assert.equal(result.status,'STARTED');assert.equal(result.qualification,'unqualified')
  return processChild
}
async function stop(processChild){if(!processChild||processChild.exitCode!==null)return;const closed=once(processChild,'exit');processChild.kill('SIGTERM');await closed}
test('worker and synthetic client refuse readable secret-bearing config before importing it',async()=>{
  const root=mkdtempSync(join(realpathSync(tmpdir()),'prime-config-')),config=join(root,'readable.mjs')
  writeFileSync(config,"throw new Error('CONFIG_MUST_NOT_BE_IMPORTED');\n",{mode:0o600});chmodSync(config,0o644)
  try {
    for(const [source,args] of [[workerPath,['--config',config]],[fileURLToPath(new URL('../src/verify-deployed.mjs',import.meta.url)),['--config',config,'--phase','save']]]) {
      const spawned=spawn(process.execPath,[source,...args],{stdio:['ignore','pipe','pipe']})
      let output='';spawned.stderr.on('data',b=>{output+=b})
      assert.equal((await once(spawned,'exit'))[0],1)
      assert(!output.includes('CONFIG_MUST_NOT_BE_IMPORTED'));assert.match(output,/REFUSED|NOT_VERIFIED/)
    }
  } finally {rmSync(root,{recursive:true,force:true})}
})
test('actual separate C/D worker processes preserve real passkey + locked observation + save/settle/cited restart; no PG or UID proof',async()=>{
  const root=mkdtempSync(join(realpathSync(tmpdir()),'prime-workers-'));mkdirSync(join(root,'c'),{mode:0o700});mkdirSync(join(root,'d'),{mode:0o700})
  const fixture=authorityFixture({root,audience:'aukora-prime.memory',authorizeTask:()=>null,observeTarget:()=>null})
  const at='2026-10-01T11:03:00Z',task={version:1,task_id:'synthetic-task',owner_id:fixture.identity.owner_id,agent_id:'synthetic-agent',conversation_id:'synthetic-conversation',status:'running',created_at:at,route_id:null,allowed_data_classes:['synthetic'],max_input_tokens:100,max_output_tokens:100,max_requests:5,task_spend_ceiling:{currency:'USD',amount:'0'}}
  const registryEntries=[{task,provider_and_region:{provider:'local',region:'local'},audience:'aukora-prime.memory',policy_version:'synthetic-policy',data_scope:['synthetic']}]
  const privateSecret=randomBytes(32).toString('hex'),publicSecret=randomBytes(32).toString('hex'),cSocket=join(root,'c','c.sock'),dSocket=join(root,'d','d.sock')
  const cConfig=join(root,'c-config.mjs'),dConfig=join(root,'d-config.mjs')
  const {authorizeTask,observeTarget,...authorityConfig}=fixture.config
  writeFileSync(cConfig,'export default '+JSON.stringify({kind:'authority',ipc:{socketPath:cSocket,credentials:[{id:'memory',role:'memory_effect',secret:privateSecret}]},registryEntries,authorityConfig})+'\n',{mode:0o600})
  const event=Buffer.from(JSON.stringify({type:'turn',text:'Synthetic owner likes banana.',seq:0,at})+'\n')
  const host={privacy:'local',scope:'owner',attributedTo:'owner',source:{sessionId:'synthetic-session',seq:0,at,sha256:sha256(event)}}
  const config={kind:'memory',ipc:{socketPath:dSocket,credentials:[{id:'app',role:'owner_control',secret:publicSecret}]},authorityChannel:{socketPath:cSocket,credential:{id:'memory',secret:privateSecret},limits:{maxRequestsPerConnection:1}},registryEntries,initializeSchema:true}
  writeFileSync(dConfig,`import {FixturePool} from ${JSON.stringify(sqlFixture)};\nconst cfg=${JSON.stringify(config)};\nconst host=${JSON.stringify(host)};host.events=[Buffer.from(${JSON.stringify(event.toString('base64'))},'base64')];\ncfg.createPgPool=()=>new FixturePool(${JSON.stringify(join(root,'memory.sqlite'))});\ncfg.resolveHostContext=({session})=>session?{task_id:'synthetic-task',memory_host:host}:{login_owner_id:${JSON.stringify(fixture.identity.owner_id)}};\nexport default cfg;\n`,{mode:0o600})
  let c,d,client
  try {
    c=await child(cConfig);d=await child(dConfig);assert.notEqual(c.pid,d.pid);assert.notEqual(c.pid,process.pid)
    client=await createIpcClient({socketPath:dSocket,credential:{id:'app',secret:publicSecret}})
    const adapters=createUiAdapters({call:(method,input)=>client.request(method,input)})
    const ui=createPrimeTransport({authority:adapters.authority,contracts,passkeySigner:({public_key})=>fixture.assertion(public_key.challenge)})
    await ui.login({owner_id:fixture.identity.owner_id})
    const draft={extraction_json:JSON.stringify({category:'fact',statement:'banana',validFrom:'2026-10-01',observedAt:at,confidence:0.7,sensitivity:'none'}),idempotency_key:'worker-synthetic-save'}
    const proposed=await adapters.memory.proposeSave(draft);assert.equal(proposed.ok,true,JSON.stringify(proposed))
    const approved=await ui.approve(await ui.prepareApproval(proposed.operation))
    const saved=await adapters.memory.save({...draft,operation:proposed.operation,approval_proof:approved.approval_proof})
    assert.equal(saved.ok,true,JSON.stringify(saved));assert.equal(saved.authority_settlement,'completed');assert.equal(saved.record.storage_status,'saved');assert.equal(saved.record.index_status,'pending')
    const record=saved.record,read={record_id:record.record_id,revision:null}
    const cited=await adapters.memory.cite({...read,retained_head:null});assert.equal(cited.citation.verdict,'VERIFIED')
    assert.equal((await client.request('capability.status',{})).state,'unqualified')
    // One private request per connection forces rotation across this workflow.
    // C-only restart must not require D restart or replay any previous call.
    const memoryPid=d.pid;await stop(c);c=null
    assert.equal((await adapters.memory.status(read)).ok,false)
    c=await child(cConfig);assert.equal(d.pid,memoryPid)
    const afterAuthorityRestart=await adapters.memory.status(read)
    assert.equal(afterAuthorityRestart.ok,true,JSON.stringify(afterAuthorityRestart));assert.equal(afterAuthorityRestart.record.canonical_bytes,record.canonical_bytes)
    await client.close();await stop(d);await stop(c);client=null
    c=await child(cConfig);d=await child(dConfig)
    client=await createIpcClient({socketPath:dSocket,credential:{id:'app',secret:publicSecret}})
    const reopened=await adapters.memory.status(read);assert.equal(reopened.ok,true,JSON.stringify(reopened));assert.equal(reopened.record.canonical_bytes,record.canonical_bytes)
    const cold=await adapters.memory.cite({...read,retained_head:cited.citation.verified_head});assert.equal(cold.citation.verdict,'VERIFIED')
  } finally {await client?.close();await stop(d);await stop(c);rmSync(root,{recursive:true,force:true})}
})
