// SPDX-License-Identifier: AGPL-3.0-or-later
// Source fixtures only: no SSH, VM, socket, group or deployed acceptance.
import {test} from 'node:test'
import assert from 'node:assert/strict'
import {mkdtemp,rm,lstat} from 'node:fs/promises'
import {realpathSync} from 'node:fs'
import {tmpdir} from 'node:os'
import {join} from 'node:path'
import {EventEmitter} from 'node:events'
import {PG_CONFIG,dFixture,createProfile,writePrivateJson,readPrivateJson} from './deployed-profile.mjs'
import {acquireFixturePhase,sshActorLaunch,trackFixtureChild,waitFixtureChild} from './deployed-controller.mjs'
async function fixture(t){const root=await mkdtemp(join(realpathSync(tmpdir()),'prime-deployed-lifecycle-'));t.after(()=>rm(root,{recursive:true,force:true}));const planned=(await dFixture()).planWorkerPostgresFixture({config:PG_CONFIG,statePath:join(root,'fixture.json')});return {root,...await createProfile({fixture:planned.fixture,postgres:PG_CONFIG})}}
test('phase lock reads current counters and admission before durably allowing one launch',async t=>{
  const {root,profile,signer}=await fixture(t),path=join(root,'signer.json');await writePrivateJson(path,signer,{exclusive:true})
  const stale=await readPrivateJson(path),first=await acquireFixturePhase({signerPath:path,profile,phase:'save'})
  assert.deepEqual(first.signer.attempted_phases,['save']);assert.deepEqual((await readPrivateJson(path)).attempted_phases,['save'])
  await assert.rejects(acquireFixturePhase({signerPath:path,profile,phase:'save'}),/EEXIST/)
  first.signer.owners.primary.counter=3;await writePrivateJson(path,first.signer);await first.close()
  assert.equal(stale.owners.primary.counter,0)
  await assert.rejects(acquireFixturePhase({signerPath:path,profile,phase:'save'}),/PHASE_RETRY_OR_REORDER_REFUSED/)
  assert.equal((await readPrivateJson(path)).owners.primary.counter,3)
  await assert.rejects(acquireFixturePhase({signerPath:path,profile,phase:'after-authority-restart'}),/PHASE_RETRY_OR_REORDER_REFUSED/)
  first.signer.completed_phases=['save'];await writePrivateJson(path,first.signer)
  const next=await acquireFixturePhase({signerPath:path,profile,phase:'after-authority-restart'});assert.equal(next.signer.owners.primary.counter,3);await next.close()
})
test('uncertain disable marker prevents signing even when private key state remains present',async t=>{
  const {root,profile,signer}=await fixture(t),path=join(root,'signer.json');await writePrivateJson(path,signer,{exclusive:true});await writePrivateJson(path+'.disabled.json',{private_key_file_unlinked:false},{exclusive:true})
  await assert.rejects(acquireFixturePhase({signerPath:path,profile,phase:'save'}),/SIGNER_DISABLE_INTENT_REQUIRES_RECONCILIATION/)
  assert((await lstat(path)).isFile());assert.equal((await readPrivateJson(path)).owners.primary.counter,0)
})
test('SSH launch is pinned to protected app actor, exact host and strict existing authentication',async t=>{
  const {root,profile}=await fixture(t),sourceHash='a'.repeat(64),source='/opt/aukora-prime-acceptance/'+sourceHash+'/source'
  const config={version:1,kind:'prime-private-cd-pg-controller/v1',synthetic_fixture:true,backend:'mac-strict-ssh-v1',postgres:PG_CONFIG,fixture_path:join(root,'fixture.json'),profile_path:join(root,'profile.json'),signer_path:join(root,'signer.json'),source_root:source,node_path:'/opt/aukora-prime-acceptance/'+sourceHash+'/tools/node',actor_config_path:'/etc/aukora-prime/acceptance-'+profile.fixture.run_id+'/app/actor.json',ssh_identity_path:'/absolute/operator-controlled/ssh-identity',ssh_known_hosts_path:'/absolute/operator-controlled/ssh-known-hosts',deployment:{kind:'prime-private-cd-pg-h-stage/v1',source_sha256:sourceHash,actor_sha256:'b'.repeat(64),node_sha256:'c'.repeat(64),actor_config_sha256:'d'.repeat(64),protected_stage_verified:true,actor_uid:997,actor_gid:987,signer_location:'mac-private-controller'}}
  const launch=sshActorLaunch(config,'save',profile);assert.equal(launch.file,'/usr/bin/ssh');assert.equal(launch.args.at(-2),'ubuntu@192.0.2.1');assert.equal(launch.args.at(-1),'/usr/bin/sudo -n -u prime-app -g prime-app '+config.node_path+' '+source+'/packages/runtime-bridge/test/deployed-actor.mjs --config '+config.actor_config_path+' --phase save')
  for(const option of ['BatchMode=yes','StrictHostKeyChecking=yes','ClearAllForwardings=yes','ForwardAgent=no','PermitLocalCommand=no','ControlMaster=no','IdentitiesOnly=yes'])assert(launch.args.includes(option))
  for(const change of [{backend:'ubuntu-local'}, {actor_config_path:'/tmp/other'}, {node_path:config.node_path+';touch /tmp/no'}, {source_root:source+'/../elsewhere'}, {deployment:null}, {ssh_identity_path:'/tmp/other-key'}, {ssh_known_hosts_path:'/tmp/other-known-hosts'}])assert.throws(()=>sshActorLaunch({...config,...change},'save',profile))
  assert.throws(()=>sshActorLaunch(config,'execute-other',profile));assert.throws(()=>sshActorLaunch({...config,deployment:{...config.deployment,actor_uid:1000}},'save',profile))
})
test('spawn errors are handled and stalled local SSH child exit is bounded with escalation',async()=>{
  const failed=new EventEmitter(),completion=trackFixtureChild(failed);failed.emit('error',new Error('synthetic spawn refusal'));assert.deepEqual(await completion,{code:null,error:true})
  const child=new EventEmitter(),signals=[];child.exitCode=null;child.signalCode=null;child.kill=signal=>{signals.push(signal);if(signal==='SIGKILL'){child.signalCode=signal;child.emit('exit',null,signal)}}
  const exit=trackFixtureChild(child);await assert.rejects(waitFixtureChild(child,exit,10),/FIXTURE_CHILD_EXIT_DEADLINE/)
  const observed=await exit;assert.deepEqual(signals,['SIGTERM','SIGKILL']);assert.equal(observed.signal,'SIGKILL')
})
