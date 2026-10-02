// SPDX-License-Identifier: AGPL-3.0-or-later
// SYNTHETIC FIXTURE ONLY. No production qualification or owner enrollment.
import {createHash,generateKeyPairSync,randomBytes,createPrivateKey} from 'node:crypto'
import {lstat,realpath,readFile,open,rename,unlink} from 'node:fs/promises'
import {resolve,dirname,join} from 'node:path'
import * as contracts from '../../contracts/src/runtime.mjs'
import {didKeyFromEd25519PublicKey} from '../../authority/upstream/plugins/aukora-aumlok/lib/did-key.mjs'
import {closed,copy,createTrustedTaskRegistry} from '../src/registry.mjs'
import {memoryStateVersion} from '../../memory/src/authorization.mjs'
import {validateCaptureReview} from '../../memory/src/capture-review.mjs'

export const PG_CONFIG=Object.freeze({host:'/run/aukora-prime/postgres',port:55434,database:'aukora_prime_synthetic',user:'prime_memory',max:4,connectionTimeoutMillis:5000})
export const PHASES=Object.freeze(['save','after-authority-restart','after-memory-restart','after-postgres-restart'])
export const IDS=Object.freeze({controller:1000,app:997,appGroup:987,authority:995,authorityGroup:986,memory:994,memoryGroup:985,memoryIpc:983,authorityIpc:984,postgresSocket:982})
export const sha=value=>createHash('sha256').update(value).digest('hex')
export const digest=value=>'sha256:'+sha(contracts.canonicalJson(value))
export const fault=reason=>Object.assign(new Error(reason),{code:'SYNTHETIC_FIXTURE_REFUSED'})
export const must=(ok,reason)=>{if(!ok)throw fault(reason)}
export function absolute(path){must(typeof path==='string'&&path.startsWith('/')&&resolve(path)===path&&path.length<=4096,'ABSOLUTE_PATH_REQUIRED');return path}
export async function dFixture(){return import('../../memory/test/worker-postgres-fixture.mjs')}
export function validatePg(config){closed(config,Object.keys(PG_CONFIG));must(contracts.canonicalJson({...config,max:4})===contracts.canonicalJson(PG_CONFIG)&&Number.isSafeInteger(config.max)&&config.max>=1&&config.max<=4,'EXACT_POSTGRES_SOCKET_PROFILE_REQUIRED');return copy(config)}

export async function validateProfile(profile){
  closed(profile,['version','kind','synthetic_fixture','fixture','postgres','at','identities','credentials'])
  must(profile.version===1&&profile.kind==='prime-private-cd-pg-profile/v1'&&profile.synthetic_fixture===true,'EXPLICIT_SYNTHETIC_PROFILE_REQUIRED')
  validatePg(profile.postgres);(await dFixture()).validateWorkerPostgresFixture(profile.fixture,profile.postgres)
  must(typeof profile.at==='string'&&/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(profile.at)&&new Date(profile.at).toISOString().replace('.000Z','Z')===profile.at,'FIXED_FIXTURE_TIME_REQUIRED')
  must(Array.isArray(profile.identities)&&profile.identities.length===2&&Array.isArray(profile.credentials)&&profile.credentials.length===2,'TWO_SYNTHETIC_OWNERS_REQUIRED')
  for(const [i,owner] of ['primary','secondary'].entries()){
    const identity=profile.identities[i],credential=profile.credentials[i],registered=profile.fixture.owners[owner]
    closed(identity,['owner_id','subject','approval_key_did','control_digest','authorization_epoch'])
    closed(credential,['owner_id','credential_id','public_key_hex','user_handle','sign_count','backup_eligible'])
    must(identity.owner_id===registered.owner_id&&identity.subject===registered.owner_subject&&identity.authorization_epoch===0&&identity.control_digest===sha('synthetic-control:'+profile.fixture.run_id+':'+owner),'FIXTURE_IDENTITY_BINDING_REQUIRED')
    must(typeof identity.approval_key_did==='string'&&identity.approval_key_did.startsWith('did:key:'),'PUBLIC_DID_REQUIRED')
    must(credential.owner_id===identity.owner_id&&credential.sign_count===0&&credential.backup_eligible===false&&/^04[a-f0-9]{128}$/.test(credential.public_key_hex)&&/^[A-Za-z0-9_-]{43}$/.test(credential.credential_id)&&credential.user_handle===Buffer.from(owner+':'+profile.fixture.run_id).toString('base64url'),'FIXTURE_PUBLIC_CREDENTIAL_REQUIRED')
  }
  must(profile.credentials[0].credential_id!==profile.credentials[1].credential_id,'DISTINCT_CREDENTIALS_REQUIRED')
  return copy(profile)
}
export async function createProfile({fixture,postgres,at=new Date().toISOString().replace(/\.\d{3}Z$/,'Z')}){
  const identities=[],credentials=[],keys={}
  for(const owner of ['primary','secondary']){
    const ec=generateKeyPairSync('ec',{namedCurve:'prime256v1'}),jwk=ec.publicKey.export({format:'jwk'})
    const ed=generateKeyPairSync('ed25519'),edRaw=Buffer.from(ed.publicKey.export({format:'jwk'}).x,'base64url').toString('hex')
    // Ed private material is discarded; the only retained signer is synthetic ES256.
    const identity={owner_id:fixture.owners[owner].owner_id,subject:fixture.owners[owner].owner_subject,approval_key_did:didKeyFromEd25519PublicKey(edRaw),control_digest:sha('synthetic-control:'+fixture.run_id+':'+owner),authorization_epoch:0}
    identities.push(identity);credentials.push({owner_id:identity.owner_id,credential_id:randomBytes(32).toString('base64url'),public_key_hex:'04'+Buffer.from(jwk.x,'base64url').toString('hex')+Buffer.from(jwk.y,'base64url').toString('hex'),user_handle:Buffer.from(owner+':'+fixture.run_id).toString('base64url'),sign_count:0,backup_eligible:false})
    keys[owner]={private_key_pem:ec.privateKey.export({format:'pem',type:'pkcs8'}),counter:0}
  }
  const profile=await validateProfile({version:1,kind:'prime-private-cd-pg-profile/v1',synthetic_fixture:true,fixture,postgres,at,identities,credentials})
  const signer={version:1,kind:'prime-private-cd-pg-signer/v1',synthetic_fixture:true,run_id:fixture.run_id,profile_sha256:sha(contracts.canonicalJson(profile)),owners:keys,attempted_phases:[],completed_phases:[],expected:null}
  return {profile,signer}
}
export function scenario(profile,owner){
  must(['primary','secondary'].includes(owner),'FIXTURE_OWNER_REQUIRED')
  const registered=profile.fixture.owners[owner],statement='Synthetic approved memory '+profile.fixture.run_id+' '+owner+'.'
  const bytes=Buffer.from(JSON.stringify({type:'turn',text:statement,seq:0,at:profile.at})+'\n')
  const host={owner_id:registered.owner_id,owner_subject:registered.owner_subject,task_id:registered.task_id,privacy:'local',scope:'owner',attributedTo:'owner',source:{sessionId:'synthetic-worker-session:'+profile.fixture.run_id+':'+owner,seq:0,at:profile.at,sha256:sha(bytes)},events:[bytes]}
  const extraction={category:'fact',statement,validFrom:profile.at.slice(0,10),observedAt:profile.at,confidence:0.7,sensitivity:'none'}
  // Independent expected review: original extraction, trusted attribution and
  // the full parsed source event. No proposed parameter supplies these values.
  const capture_metadata={profile:'prime-pilot-memory-capture/v1',category:'fact',valid_from:extraction.validFrom,
    observed_at:extraction.observedAt,confidence_percent:70,sensitivity:'none'}
  const memory_capture={statement:extraction.statement,attributed_to:host.attributedTo,capture_metadata,
    evidence_quote:contracts.parseStrictJson(bytes.toString('utf8')).text}
  return {host,extraction,extraction_json:JSON.stringify(extraction),idempotency_key:'synthetic-worker-save:'+profile.fixture.run_id+':'+owner,memory_capture}
}
export function registryEntries(profile){return ['primary','secondary'].map(owner=>({task:{version:1,task_id:profile.fixture.owners[owner].task_id,owner_id:profile.fixture.owners[owner].owner_id,agent_id:'synthetic-agent',conversation_id:profile.fixture.owners[owner].conversation_id,status:'running',created_at:profile.at,route_id:null,allowed_data_classes:['synthetic'],max_input_tokens:100,max_output_tokens:100,max_requests:5,task_spend_ceiling:{currency:'USD',amount:'0'}},provider_and_region:{provider:'local',region:'local'},audience:'aukora-prime.memory',policy_version:'synthetic-policy:'+profile.fixture.run_id,data_scope:['synthetic']}))}
export function fixturePaths(profile){const run=profile.fixture.run_id;return {authoritySocket:'/run/aukora-prime/acceptance-'+run+'/authority/authority.sock',memorySocket:'/run/aukora-prime/acceptance-'+run+'/memory/memory.sock',stateRoot:'/var/lib/aukora-prime/authority/acceptance-'+run,witnessDir:'/var/lib/aukora-prime-witness/pilot/acceptance-'+run,actorWitness:'/var/lib/aukora-prime/app/acceptance-'+run+'/witness.json'}}
export function authorityConfig(profile){const paths=fixturePaths(profile);return {stateRoot:paths.stateRoot,statePath:join(paths.stateRoot,'authority.json'),witnessDir:paths.witnessDir,audience:'aukora-prime.memory',identities:profile.identities,webauthn:{rp_id:'prime.example.test',origins:['https://prime.example.test'],credentials:profile.credentials},loginKinds:['passkey'],policy:{version:'synthetic-policy:'+profile.fixture.run_id,actions:['memory.save'],agents:['synthetic-agent'],data_scope:['synthetic'],maximum_cost:{currency:'USD',amount:'0'}}}}
export function credentialId(profile,owner){return 'fixture-'+owner+'-'+profile.fixture.run_id}
export function memoryCredentialId(profile){return 'fixture-memory-'+profile.fixture.run_id}
export function validateCredential(credential,id){closed(credential,['id','secret']);must(credential.id===id&&typeof credential.id==='string'&&/^[A-Za-z0-9_.-]{1,128}$/.test(credential.id)&&typeof credential.secret==='string'&&/^[a-f0-9]{64}$/.test(credential.secret),'EXACT_FIXTURE_IPC_CREDENTIAL_REQUIRED');return copy(credential)}
export function access(server_uid,client_uid,group_gid){return {server_uid,client_uid,group_gid}}
/** H-local descriptor construction. No key generation, file writes or credential
 * discovery. Inputs are exactly three H-provisioned audience-specific secrets. */
export function makeFixtureDescriptors({profile,credentials}){
  closed(credentials,['memory','primary','secondary']);const paths=fixturePaths(profile)
  for(const owner of ['memory','primary','secondary'])must(typeof credentials[owner]==='string'&&/^[a-f0-9]{64}$/.test(credentials[owner]),'H_PROVISIONED_FIXTURE_SECRET_REQUIRED')
  must(new Set(Object.values(credentials)).size===3,'DISTINCT_CHANNEL_CREDENTIALS_REQUIRED')
  const authority={version:1,kind:'prime-private-cd-pg-authority/v1',synthetic_fixture:true,profile,ipc:{socketPath:paths.authoritySocket,credentials:[{id:memoryCredentialId(profile),role:'memory_effect',secret:credentials.memory}],socketAccess:access(IDS.authority,IDS.memory,IDS.authorityIpc)}}
  const memory={version:1,kind:'prime-private-cd-pg-memory/v1',synthetic_fixture:true,profile,ipc:{socketPath:paths.memorySocket,credentials:['primary','secondary'].map(owner=>({id:credentialId(profile,owner),role:'owner_control',secret:credentials[owner]})),socketAccess:access(IDS.memory,IDS.app,IDS.memoryIpc)},authority_channel:{socketPath:paths.authoritySocket,credential:{id:memoryCredentialId(profile),secret:credentials.memory},socketAccess:access(IDS.authority,IDS.memory,IDS.authorityIpc)}}
  const actor={version:1,kind:'prime-private-cd-pg-actor/v1',synthetic_fixture:true,profile,...Object.fromEntries(['primary','secondary'].map(owner=>[owner,{socketPath:paths.memorySocket,credential:{id:credentialId(profile,owner),secret:credentials[owner]},socketAccess:access(IDS.memory,IDS.app,IDS.memoryIpc)}])),witness_path:paths.actorWitness}
  return copy({authority,memory,actor})
}
function validateChannel(channel,socket,id,expectedAccess){closed(channel,['socketPath','credential','socketAccess']);must(channel.socketPath===socket&&contracts.canonicalJson(channel.socketAccess)===contracts.canonicalJson(expectedAccess),'FIXTURE_SOCKET_ACCESS_REQUIRED');validateCredential(channel.credential,id);return copy(channel)}
export function validateActorConfig(config){closed(config,['version','kind','synthetic_fixture','profile','primary','secondary','witness_path']);must(config.version===1&&config.kind==='prime-private-cd-pg-actor/v1'&&config.synthetic_fixture===true,'FIXTURE_ACTOR_CONFIG_REQUIRED');const paths=fixturePaths(config.profile);for(const owner of ['primary','secondary'])validateChannel(config[owner],paths.memorySocket,credentialId(config.profile,owner),access(IDS.memory,IDS.app,IDS.memoryIpc));must(config.witness_path===paths.actorWitness,'FIXTURE_ACTOR_WITNESS_REQUIRED');return config}
export async function validateReview(profile,owner,operation,memory_capture){
  const s=scenario(profile,owner);contracts.validateContract('OperationProposal',operation)
  validateCaptureReview(operation.canonical_parameters,s.memory_capture);must(contracts.canonicalJson(memory_capture)===contracts.canonicalJson(s.memory_capture),'EXACT_FIXTURE_DRAFT_REQUIRED')
  const registry=createTrustedTaskRegistry(registryEntries(profile)),expected=(await dFixture()).expectedWorkerCaptureDigests({config:profile.postgres,fixture:profile.fixture,owner,host:s.host,extraction:s.extraction,idempotencyKey:s.idempotency_key})
  const expectedParameters={capture_sha256:expected.capture_sha256,idempotency_key_sha256:expected.idempotency_key_sha256,heads:{},...s.memory_capture}
  must(expected.statement===s.memory_capture.statement&&expected.attributed_to===s.memory_capture.attributed_to&&registry.authorizeTask(operation).authenticated===true&&operation.action_type==='memory.save'&&operation.authorization_epoch===0&&contracts.canonicalJson(operation.target_identity)===contracts.canonicalJson({kind:'prime-memory',owner_subject:s.host.owner_subject})&&operation.expected_state_version===memoryStateVersion({})&&contracts.canonicalJson(operation.canonical_parameters)===contracts.canonicalJson(expectedParameters)&&contracts.canonicalJson(operation.maximum_cost)===contracts.canonicalJson({currency:'USD',amount:'0'})&&Date.parse(operation.expiry)>Date.now()&&Date.parse(operation.expiry)<=Date.now()+121000,'EXACT_FRESH_FIXTURE_CAPTURE_REQUIRED')
  return copy(operation)
}
export function validateSigner(signer,profile){
  closed(signer,['version','kind','synthetic_fixture','run_id','profile_sha256','owners','attempted_phases','completed_phases','expected']);closed(signer.owners,['primary','secondary'])
  must(signer.version===1&&signer.kind==='prime-private-cd-pg-signer/v1'&&signer.synthetic_fixture===true&&signer.run_id===profile.fixture.run_id&&signer.profile_sha256===sha(contracts.canonicalJson(profile))&&['attempted_phases','completed_phases'].every(field=>Array.isArray(signer[field])&&signer[field].every(x=>PHASES.includes(x))&&new Set(signer[field]).size===signer[field].length)&&signer.completed_phases.every(x=>signer.attempted_phases.includes(x)),'FIXTURE_SIGNER_BINDING_REQUIRED')
  for(const [i,owner] of ['primary','secondary'].entries()){
    closed(signer.owners[owner],['private_key_pem','counter']);const entry=signer.owners[owner]
    must(typeof entry.private_key_pem==='string'&&entry.private_key_pem.length<4096&&Number.isSafeInteger(entry.counter)&&entry.counter>=0&&entry.counter<0xffffffff,'FIXTURE_COUNTER_REQUIRED')
    const key=createPrivateKey(entry.private_key_pem),jwk=key.export({format:'jwk'}),publicHex='04'+Buffer.from(jwk.x,'base64url').toString('hex')+Buffer.from(jwk.y,'base64url').toString('hex')
    must(key.asymmetricKeyType==='ec'&&jwk.crv==='P-256'&&publicHex===profile.credentials[i].public_key_hex,'FIXTURE_PRIVATE_PUBLIC_KEY_BINDING_REQUIRED')
  }
  return signer
}
export async function readPrivateJson(path,{maxBytes=65536}={}){
  absolute(path);const uid=process.getuid?.(),stat=await lstat(path),parent=await lstat(dirname(path))
  must(Number.isSafeInteger(uid)&&stat.isFile()&&!stat.isSymbolicLink()&&stat.uid===uid&&(stat.mode&0o7777)===0o600&&await realpath(path)===path&&parent.isDirectory()&&!parent.isSymbolicLink()&&parent.uid===uid&&(parent.mode&0o7777)===0o700&&await realpath(dirname(path))===dirname(path),'PRIVATE_FIXTURE_FILE_REQUIRED')
  must(stat.size<=maxBytes,'FIXTURE_FILE_BOUND');return contracts.parseStrictJson(await readFile(path,'utf8'),{maxBytes,maxDepth:32})
}
export async function writePrivateJson(path,value,{exclusive=false}={}){
  absolute(path);const parent=await lstat(dirname(path));must(parent.uid===process.getuid?.()&&(parent.mode&0o7777)===0o700&&parent.isDirectory()&&!parent.isSymbolicLink()&&await realpath(dirname(path))===dirname(path),'PRIVATE_FIXTURE_PARENT_REQUIRED')
  const text=contracts.canonicalJson(value)+'\n';must(Buffer.byteLength(text)<=65536,'FIXTURE_FILE_BOUND')
  const temporary=exclusive?path:path+'.tmp-'+randomBytes(12).toString('hex');let file
  try {file=await open(temporary,'wx',0o600);await file.writeFile(text);await file.sync();await file.close();file=null;if(!exclusive)await rename(temporary,path);const dir=await open(dirname(path),'r');try{await dir.sync()}finally{await dir.close()}}
  catch(error){await file?.close();if(!exclusive)await unlink(temporary).catch(()=>{});throw error}
}
export async function rootProtectedPath(path,{fileMode=null,parentMode=null,gid=null,executable=false}={}){
  absolute(path);const stat=await lstat(path);must(stat.isFile()&&!stat.isSymbolicLink()&&stat.uid===0&&(stat.mode&0o022)===0&&await realpath(path)===path&&(fileMode===null||(stat.mode&0o7777)===fileMode)&&(gid===null||stat.gid===gid)&&(!executable||(stat.mode&0o111)!==0),'ROOT_PROTECTED_FIXTURE_FILE_REQUIRED')
  let parent=dirname(path),direct=true
  for(;;){const d=await lstat(parent);must(d.isDirectory()&&!d.isSymbolicLink()&&d.uid===0&&(d.mode&0o022)===0&&await realpath(parent)===parent&&(!direct||parentMode===null||(d.mode&0o7777)===parentMode&&d.gid===gid),'ROOT_PROTECTED_FIXTURE_PARENT_REQUIRED');if(parent===dirname(parent))break;parent=dirname(parent);direct=false}
}
export async function readRootJson(path,uid,gid){must(process.getuid?.()===uid&&process.geteuid?.()===uid&&process.getgid?.()===gid&&process.getegid?.()===gid,'EXACT_FIXTURE_PROCESS_ID_REQUIRED');await rootProtectedPath(path,{fileMode:0o440,parentMode:0o750,gid});const text=await readFile(path,'utf8');return contracts.parseStrictJson(text,{maxBytes:65536,maxDepth:32})}
