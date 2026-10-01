// SPDX-License-Identifier: AGPL-3.0-or-later
// SYNTHETIC Mac signer/controller. No key crosses SSH or enters app/C/D/F.
import {spawn} from 'node:child_process'
import {createHash,createPrivateKey,sign} from 'node:crypto'
import {open,unlink,lstat,realpath} from 'node:fs/promises'
import {resolve,dirname} from 'node:path'
import {constants} from 'node:fs'
import {isIP} from 'node:net'
import {fileURLToPath} from 'node:url'
import * as contracts from '../../contracts/src/runtime.mjs'
import {loginSigningBytes,approvalSigningBytes} from '../../authority/src/index.mjs'
import {webauthnChallenge} from '../../authority/src/webauthn.mjs'
import {memoryEffectDigest} from '../../memory/src/authorization.mjs'
import {closed,copy} from '../src/registry.mjs'
import {createFixturePipe} from './deployed-pipes.mjs'
import {PHASES,IDS,dFixture,absolute,validatePg,validateProfile,createProfile,validateSigner,validateReview,readPrivateJson,writePrivateJson,rootProtectedPath,must} from './deployed-profile.mjs'

// This path is part of the protected operator trust boundary. Neither the run
// config nor the process environment can select a different approval record.
export const SSH_APPROVAL_PATH='/private/etc/aukora-prime/acceptance-ssh-approval.json'
export function validateSshApproval(approval){
  must(approval&&typeof approval==='object'&&!Array.isArray(approval),'PROTECTED_SSH_APPROVAL_REQUIRED')
  closed(approval,['version','kind','controller_uid','controller_gid','ssh_host','ssh_identity_path','ssh_known_hosts_path'])
  must(approval.version===1&&approval.kind==='prime-private-cd-pg-ssh-approval/v1'&&Number.isSafeInteger(approval.controller_uid)&&approval.controller_uid>0&&Number.isSafeInteger(approval.controller_gid)&&approval.controller_gid>0,'EXACT_CONTROLLER_SSH_APPROVAL_REQUIRED')
  const host=approval.ssh_host
  must(typeof host==='string'&&host.length<=253&&(isIP(host)===4||host.includes('.')&&host.split('.').every(label=>/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label))),'EXACT_APPROVED_SSH_HOST_REQUIRED')
  for(const name of ['ssh_identity_path','ssh_known_hosts_path']){absolute(approval[name]);must(/^\/[A-Za-z0-9_./-]+$/.test(approval[name]),'EXACT_APPROVED_SSH_PATH_REQUIRED')}
  must(approval.ssh_identity_path!==approval.ssh_known_hosts_path,'DISTINCT_APPROVED_SSH_FILES_REQUIRED')
  return approval
}
export async function readProtectedSshApproval(){
  const uid=process.getuid?.(),gid=process.getgid?.()
  must(process.platform==='darwin'&&Number.isSafeInteger(uid)&&uid>0&&uid===process.geteuid?.()&&Number.isSafeInteger(gid)&&gid>0&&gid===process.getegid?.(),'MAC_PRIVATE_CONTROLLER_ONLY')
  await rootProtectedPath(SSH_APPROVAL_PATH,{fileMode:0o440,parentMode:0o750,gid})
  const file=await open(SSH_APPROVAL_PATH,constants.O_RDONLY|constants.O_NOFOLLOW)
  try{
    const stat=await file.stat()
    must(stat.isFile()&&stat.uid===0&&stat.gid===gid&&(stat.mode&0o7777)===0o440&&stat.size<=16384,'ROOT_PROTECTED_SSH_APPROVAL_REQUIRED')
    const approval=validateSshApproval(contracts.parseStrictJson(await file.readFile('utf8'),{maxBytes:16384,maxDepth:8}))
    must(approval.controller_uid===uid&&approval.controller_gid===gid,'APPROVED_SSH_CONTROLLER_IDENTITY_REQUIRED')
    return approval
  }finally{await file.close()}
}
export function validateControllerConfig(config,sshApproval){
  validateSshApproval(sshApproval)
  closed(config,['version','kind','synthetic_fixture','backend','postgres','fixture_path','profile_path','signer_path','source_root','node_path','actor_config_path','ssh_identity_path','ssh_known_hosts_path','deployment'])
  must(config.version===1&&config.kind==='prime-private-cd-pg-controller/v1'&&config.synthetic_fixture===true&&config.backend==='mac-strict-ssh-v1','MAC_ISOLATED_SYNTHETIC_CONTROLLER_REQUIRED')
  validatePg(config.postgres)
  for(const name of ['fixture_path','profile_path','signer_path','source_root','node_path','ssh_identity_path','ssh_known_hosts_path'])absolute(config[name])
  if(config.actor_config_path!==null)absolute(config.actor_config_path)
  must(new Set([config.fixture_path,config.profile_path,config.signer_path]).size===3&&dirname(config.fixture_path)===dirname(config.profile_path)&&dirname(config.profile_path)===dirname(config.signer_path),'ONE_PRIVATE_CONTROLLER_NAMESPACE_REQUIRED')
  must(/^\/opt\/aukora-prime-acceptance\/[a-f0-9]{64}\/source$/.test(config.source_root)&&config.node_path===dirname(config.source_root)+'/tools/node','EXACT_PROTECTED_STAGE_REQUIRED')
  must(config.ssh_identity_path===sshApproval.ssh_identity_path&&config.ssh_known_hosts_path===sshApproval.ssh_known_hosts_path,'EXISTING_APPROVED_SSH_PATHS_REQUIRED')
  must(config.deployment===null||typeof config.deployment==='object','DEPLOYMENT_RECORD_REQUIRED');return config
}
export function sshActorLaunch(config,phase,profile,sshApproval){
  validateControllerConfig(config,sshApproval);must(PHASES.includes(phase),'EXACT_FIXTURE_PHASE_REQUIRED')
  const expectedConfig='/etc/aukora-prime/acceptance-'+profile.fixture.run_id+'/app/actor.json'
  must(config.actor_config_path===expectedConfig,'EXACT_ACTOR_CONFIG_REQUIRED')
  closed(config.deployment,['kind','source_sha256','actor_sha256','node_sha256','actor_config_sha256','protected_stage_verified','actor_uid','actor_gid','signer_location'])
  must(config.deployment.kind==='prime-private-cd-pg-h-stage/v1'&&config.deployment.protected_stage_verified===true&&config.deployment.actor_uid===IDS.app&&config.deployment.actor_gid===IDS.appGroup&&config.deployment.signer_location==='mac-private-controller'&&['source_sha256','actor_sha256','node_sha256','actor_config_sha256'].every(field=>/^[a-f0-9]{64}$/.test(config.deployment[field]))&&config.source_root==='/opt/aukora-prime-acceptance/'+config.deployment.source_sha256+'/source','H_REVIEWED_BYTE_EQUAL_STAGE_REQUIRED')
  const actor=config.source_root+'/packages/runtime-bridge/test/deployed-actor.mjs'
  // Every remote token is fixed or selected from this closed path/phase grammar.
  // SSH invokes a remote shell, so no caller-selected argv or shell metacharacters survive.
  const command=['/usr/bin/sudo','-n','-u','prime-app','-g','prime-app',config.node_path,actor,'--config',expectedConfig,'--phase',phase].join(' ')
  return {file:'/usr/bin/ssh',args:['-F','/dev/null','-T','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes','-o','ClearAllForwardings=yes','-o','ForwardAgent=no','-o','PermitLocalCommand=no','-o','ControlMaster=no','-o','ControlPath=none','-o','IdentitiesOnly=yes','-o','UserKnownHostsFile='+config.ssh_known_hosts_path,'-i',config.ssh_identity_path,'ubuntu@'+sshApproval.ssh_host,command]}
}
export function createFixtureSigner({profile,signer,phase,persist}){
  validateSigner(signer,profile);must(PHASES.includes(phase)&&typeof persist==='function','FIXED_SIGNER_PHASE_REQUIRED')
  let step=0,review=null,template=null,result=null
  const sequence=phase==='save'?['login-primary','review-primary','approval-primary','login-secondary','result']:['login-primary','login-secondary','result']
  const hash=bytes=>createHash('sha256').update(bytes).digest()
  async function handle(payload){
    must(payload&&typeof payload==='object'&&!Array.isArray(payload),'CLOSED_FIXTURE_PAYLOAD_REQUIRED')
    if(payload.type==='review'){
      closed(payload,['type','owner','operation','memory_capture']);must(sequence[step]==='review-primary'&&payload.owner==='primary','SINGLE_PHASE_REVIEW_REQUIRED')
      review=await validateReview(profile,payload.owner,payload.operation,payload.memory_capture);step++
      return {type:'reviewed',operation_digest:contracts.operationDigest(review)}
    }
    if(payload.type==='sign'){
      closed(payload,['type','owner','purpose','request','public_key','proof_template']);must(['primary','secondary'].includes(payload.owner)&&['login','approval'].includes(payload.purpose)&&sequence[step]===payload.purpose+'-'+payload.owner,'NO_ARBITRARY_SIGNING_OR_REPLAY')
      const index=payload.owner==='primary'?0:1,identity=profile.identities[index],credential=profile.credentials[index],r=payload.request
      let bytes
      if(payload.purpose==='login'){
        bytes=loginSigningBytes(r)
        must(payload.proof_template===null&&r.version===1&&r.owner_id===identity.owner_id&&r.audience==='aukora-prime.memory'&&r.authorization_epoch===0&&/^[a-f0-9]{64}$/.test(r.challenge)&&Date.parse(r.issued_at)<=Date.now()+1000&&Date.parse(r.issued_at)>Date.now()-60000&&Date.parse(r.expiry)>Date.now()&&Date.parse(r.expiry)<=Date.now()+121000,'REGISTERED_OWNER_LOGIN_ONLY')
      }else{
        must(review&&payload.owner==='primary','EXACT_REVIEW_BEFORE_APPROVAL_REQUIRED');bytes=approvalSigningBytes(r)
        const d=contracts.operationDigest(review);contracts.validateApprovalTemplate(payload.proof_template)
        must(r.subject===identity.subject&&r.activeControlDigest===identity.control_digest&&r.operationDigest===d.slice(7)&&r.issuedAt<=Math.floor(Date.now()/1000)+1&&r.issuedAt>Math.floor(Date.now()/1000)-60&&r.expiresAt*1000>Date.now()&&r.expiresAt*1000<=Date.parse(review.expiry),'EXACT_REVIEW_CHALLENGE_REQUIRED')
        const expected={version:1,operation_id:review.operation_id,operation_digest:d,owner_id:identity.owner_id,audience:review.audience,authorization_epoch:0,expiry:new Date(r.expiresAt*1000).toISOString(),nonce:r.challenge,material:{kind:'passkey'}}
        must(contracts.canonicalJson(payload.proof_template)===contracts.canonicalJson(expected),'EXACT_PROOF_TEMPLATE_REQUIRED');template=copy(expected)
      }
      const expectedKey={challenge:webauthnChallenge(bytes),rpId:'prime.example.test',allowCredentials:[{type:'public-key',id:credential.credential_id}],userVerification:'required',timeout:60000}
      must(contracts.canonicalJson(payload.public_key)===contracts.canonicalJson(expectedKey),'RECOMPUTED_C_WEBAUTHN_OPTIONS_REQUIRED')
      const entry=signer.owners[payload.owner];entry.counter++;validateSigner(signer,profile)
      // A consumed counter is durable before even computing/releasing an assertion.
      // A lost pipe/SSH response never rewinds it or triggers a repeat dispatch.
      await persist(signer)
      const client=Buffer.from(JSON.stringify({type:'webauthn.get',challenge:expectedKey.challenge,origin:'https://prime.example.test',crossOrigin:false})),auth=Buffer.alloc(37)
      hash(expectedKey.rpId).copy(auth);auth[32]=5;auth.writeUInt32BE(entry.counter,33)
      const material={kind:'passkey',credential_id:credential.credential_id,client_data_json:client.toString('base64url'),authenticator_data:auth.toString('base64url'),signature:sign('sha256',Buffer.concat([auth,hash(client)]),createPrivateKey(entry.private_key_pem)).toString('base64url'),user_handle:credential.user_handle}
      step++;return {type:'assertion',material}
    }
    closed(payload,['type','report']);must(payload.type==='result'&&sequence[step]==='result','CLOSED_PHASE_RESULT_REQUIRED')
    const report=payload.report;closed(report,['version','kind','synthetic_fixture','phase','run_id','expected','authority_status','checks'])
    must(report.version===1&&report.kind==='prime-private-cd-pg-actor-result/v1'&&report.synthetic_fixture===true&&report.phase===phase&&report.run_id===profile.fixture.run_id,'FIXTURE_RESULT_BINDING_REQUIRED')
    ;(await dFixture()).validateWorkerPostgresSaveExpectation(report.expected,profile.fixture)
    const expected=report.expected;must(expected.owner==='primary'&&expected.storage_status==='saved'&&expected.index_status==='pending','EXACT_SAVED_PENDING_RESULT_REQUIRED')
    const status=report.authority_status;closed(status,['ok','status','operation_digest','reconciliation_required'])
    must(status.ok===true&&status.status==='COMPLETED'&&status.operation_digest===expected.operation_digest&&status.reconciliation_required===false,'ACTUAL_C_COMPLETION_RESULT_REQUIRED')
    const checks=phase==='save'?['preconsume-statement-refused','preconsume-attributed_to-refused','preconsume-extraction-refused','preconsume-cross-owner-refused','real-c-proof-save-settlement','saved-distinct-from-indexed','genuine-citation','cross-owner-read-cite-status-refused','public-unqualified']:['restart-canonical-bytes','restart-retained-citation','restart-c-completion','cross-owner-read-cite-status-refused','public-unqualified']
    must(contracts.canonicalJson(report.checks)===contracts.canonicalJson(checks),'EXACT_PHASE_CONTROLS_REQUIRED')
    if(phase==='save'){
      must(review&&template&&expected.operation_id===review.operation_id&&expected.operation_digest===contracts.operationDigest(review)&&expected.receipt.grant_id==='grant:'+template.nonce&&expected.receipt.request_digest===memoryEffectDigest({version:1,action_type:'memory.save',owner_subject:profile.fixture.owners.primary.owner_subject,operation_id:review.operation_id,operation_digest:expected.operation_digest,parameters:review.canonical_parameters}),'SIGNED_EFFECT_RECEIPT_BINDING_REQUIRED')
      signer.expected=copy(expected)
    }else must(signer.expected!==null&&contracts.canonicalJson(expected)===contracts.canonicalJson(signer.expected),'RESTART_EXPECTATION_CHANGED')
    await persist(signer);result=copy(report);step++;return {type:'accepted'}
  }
  return {handle,get result(){return result},get complete(){return step===sequence.length}}
}
export function trackFixtureChild(child){
  // Always fulfill: spawn errors cannot become an unhandled rejected exit wait.
  return new Promise(done=>{let settled=false;const finish=value=>{if(!settled){settled=true;done(value)}};child.once('error',()=>finish({code:null,error:true}));child.once('exit',(code,signal)=>finish({code,signal,error:false}))})
}
export async function waitFixtureChild(child,completion,timeoutMs=10000){
  let timer,killTimer
  try{return await Promise.race([completion,new Promise((_,reject)=>{timer=setTimeout(()=>{child.kill('SIGTERM');killTimer=setTimeout(()=>child.kill('SIGKILL'),1000);reject(new Error('FIXTURE_CHILD_EXIT_DEADLINE'))},timeoutMs)})])}
  finally{clearTimeout(timer);if(child.exitCode!==null||child.signalCode!==null)clearTimeout(killTimer)}
}
export async function acquireFixturePhase({signerPath,profile,phase}){
  must(PHASES.includes(phase),'FIXTURE_PHASE_REQUIRED');absolute(signerPath)
  const lockPath=signerPath+'.lock',lock=await open(lockPath,'wx',0o600);let released=false
  const close=async()=>{if(released)return;released=true;await lock.close();await unlink(lockPath)}
  try{
    let disabling=false
    try{await lstat(signerPath+'.disabled.json');disabling=true}catch(error){if(error.code!=='ENOENT')throw error}
    must(!disabling,'SIGNER_DISABLE_INTENT_REQUIRES_RECONCILIATION')
    const signer=validateSigner(await readPrivateJson(signerPath),profile),index=PHASES.indexOf(phase)
    must(!signer.attempted_phases.includes(phase)&&PHASES.slice(0,index).every(p=>signer.completed_phases.includes(p)),'PHASE_RETRY_OR_REORDER_REFUSED')
    signer.attempted_phases.push(phase);await writePrivateJson(signerPath,signer)
    return {signer,close}
  }catch(error){await close();throw error}
}
async function main(){
  const args=process.argv.slice(2);must(args.length===4&&args[0]==='--config'&&args[2]==='--phase'&&['plan','disable',...PHASES].includes(args[3]),'CLOSED_CONTROLLER_COMMAND_REQUIRED')
  must(process.platform==='darwin'&&process.getuid?.()>0&&process.getuid?.()===process.geteuid?.(),'MAC_PRIVATE_CONTROLLER_ONLY')
  const sshApproval=await readProtectedSshApproval()
  const config=validateControllerConfig(await readPrivateJson(args[1]),sshApproval),phase=args[3]
  must(dirname(config.profile_path)===dirname(args[1]),'PRIVATE_CONTROLLER_CONFIG_NAMESPACE_REQUIRED')
  if(phase==='plan'){
    const planned=(await dFixture()).planWorkerPostgresFixture({config:config.postgres,statePath:config.fixture_path})
    const {profile,signer}=await createProfile({fixture:planned.fixture,postgres:config.postgres})
    await writePrivateJson(config.profile_path,profile,{exclusive:true});await writePrivateJson(config.signer_path,signer,{exclusive:true})
    process.stdout.write(JSON.stringify({status:'PLANNED',synthetic_fixture:true,run_id:profile.fixture.run_id,profile_path:config.profile_path,schema_plan_path:planned.schema_plan_path,PostgreSQL_connected:false,worker_started:false})+'\n');return
  }
  const profile=await validateProfile(await readPrivateJson(config.profile_path))
  must(contracts.canonicalJson(config.postgres)===contracts.canonicalJson(profile.postgres),'CONTROLLER_POSTGRES_PROFILE_CHANGED')
  if(phase==='disable'){
    const lockPath=config.signer_path+'.lock',lock=await open(lockPath,'wx',0o600)
    try{
      const signer=validateSigner(await readPrivateJson(config.signer_path),profile)
      const receipt={version:1,kind:'prime-private-cd-pg-signer-disabled/v1',synthetic_fixture:true,run_id:signer.run_id,profile_sha256:signer.profile_sha256,counters:Object.fromEntries(Object.entries(signer.owners).map(([owner,entry])=>[owner,entry.counter])),attempted_phases:signer.attempted_phases,completed_phases:signer.completed_phases,expected:signer.expected,private_key_file_unlinked:false}
      await writePrivateJson(config.signer_path+'.disabled.json',receipt,{exclusive:true});await unlink(config.signer_path)
      const dir=await open(dirname(config.signer_path),'r');try{await dir.sync()}finally{await dir.close()}
      receipt.private_key_file_unlinked=true;await writePrivateJson(config.signer_path+'.disabled.json',receipt)
      process.stdout.write(JSON.stringify({status:'DISABLED',synthetic_fixture:true,run_id:profile.fixture.run_id,private_key_file_unlinked:true,secure_erasure_claimed:false})+'\n');return
    }finally{await lock.close();await unlink(lockPath)}
  }
  const launch=sshActorLaunch(config,phase,profile,sshApproval)
  await rootProtectedPath(launch.file,{executable:true})
  for(const path of [config.ssh_identity_path,config.ssh_known_hosts_path]){const stat=await lstat(path);must(stat.isFile()&&!stat.isSymbolicLink()&&await realpath(path)===path&&stat.uid===process.getuid()&&(stat.mode&0o022)===0&&(path!==config.ssh_identity_path||(stat.mode&0o077)===0),'EXISTING_PRIVATE_SSH_METADATA_REQUIRED')}
  const admission=await acquireFixturePhase({signerPath:config.signer_path,profile,phase});let child,pipe,completion,phaseTimer
  try{
    // Read admission/counters only after taking the exclusive lock. A second
    // controller cannot retain a stale snapshot and overwrite newer consumption.
    const signer=admission.signer
    const signing=createFixtureSigner({profile,signer,phase,persist:value=>writePrivateJson(config.signer_path,value)})
    child=spawn(launch.file,launch.args,{stdio:['pipe','pipe','pipe'],env:{PATH:'/usr/bin:/bin',LANG:'C.UTF-8'}})
    let diagnosticBytes=0;child.stderr.on('data',b=>{diagnosticBytes+=b.length;if(diagnosticBytes>8192)child.kill('SIGTERM')})
    completion=trackFixtureChild(child);pipe=createFixturePipe({readable:child.stdout,writable:child.stdin})
    child.once('error',()=>pipe.close());phaseTimer=setTimeout(()=>{pipe.close();child.kill('SIGTERM')},180000)
    while(!signing.complete){const frame=await pipe.read();await pipe.respond(frame.sequence,await signing.handle(frame.payload))}
    const exited=await waitFixtureChild(child,completion);must(exited.code===0&&exited.error===false,'ACTOR_EXIT_NOT_CONFIRMED')
    signer.completed_phases.push(phase);await writePrivateJson(config.signer_path,signer)
    process.stdout.write(JSON.stringify({status:'PASS',backend:'mac-strict-ssh-v1',...signing.result,PG_restart_independently_verified:false,UID_ACL_independently_verified:false,public_qualification:'unavailable'})+'\n')
  }finally{
    clearTimeout(phaseTimer);pipe?.close()
    if(child&&child.exitCode===null&&child.signalCode===null){child.kill('SIGTERM');await waitFixtureChild(child,completion,2000).catch(()=>{})}
    await admission.close()
  }
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url))main().catch(error=>{process.stderr.write('SYNTHETIC_CONTROLLER_NOT_VERIFIED:'+String(error.code??'UNAVAILABLE')+'\n');process.exitCode=1})
